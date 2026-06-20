//! Transaction structures and serialization. Full port of
//! `transaction/transaction.go` — all transaction types (PREMINE, REGISTRATION,
//! COINBASE, NORMAL, BURN, SC), including the asset payloads (Zether `Statement`
//! + Bulletproof `Proof`) for the value-carrying types.

use crate::varint::{put_uvarint, read_uvarint};
use dero_bn256::G1;
use dero_crypto::{base_g, point_to_string, power_of_2, reduced_hash, Proof, Statement};
use num_bigint::BigUint;

/// Go: `TransactionType`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u64)]
pub enum TransactionType {
    Premine = 0,
    Registration = 1,
    Coinbase = 2,
    Normal = 3,
    Burn = 4,
    Sc = 5,
}

impl TransactionType {
    fn from_u64(v: u64) -> Result<TransactionType, &'static str> {
        Ok(match v {
            0 => TransactionType::Premine,
            1 => TransactionType::Registration,
            2 => TransactionType::Coinbase,
            3 => TransactionType::Normal,
            4 => TransactionType::Burn,
            5 => TransactionType::Sc,
            _ => return Err("unknown transaction type"),
        })
    }
}

/// Go: `PAYLOAD_LIMIT` = 1 + 144. The encrypted RPC payload is always this size.
pub const PAYLOAD_LIMIT: usize = 1 + 144;

/// Go: `config.FEE_PER_KB` (atomic units per KB, .00020 DERO).
pub const FEE_PER_KB: u64 = 20;

/// Go: `Blockchain.Calculate_TX_fee` — the consensus fee for a tx of `tx_size`
/// bytes: `ceil(tx_size / 1024) * FEE_PER_KB`.
pub fn calculate_tx_fee(tx_size: u64) -> u64 {
    let mut size_in_kb = tx_size / 1024;
    if tx_size % 1024 != 0 {
        size_in_kb += 1;
    }
    size_in_kb * FEE_PER_KB
}

#[cfg(test)]
mod fee_tests {
    use super::calculate_tx_fee;
    #[test]
    fn tx_fee_matches_go() {
        assert_eq!(calculate_tx_fee(0), 0);
        assert_eq!(calculate_tx_fee(1), 20); // any part of a KB → 1 KB
        assert_eq!(calculate_tx_fee(1024), 20);
        assert_eq!(calculate_tx_fee(1025), 40);
        assert_eq!(calculate_tx_fee(1341), 40); // a real ring-2 transfer (2 KB)
        assert_eq!(calculate_tx_fee(2048), 40);
    }
}

// --- cursor helpers (a `&mut &[u8]` consumed from the front) ---
fn take<'a>(r: &mut &'a [u8], n: usize) -> Result<&'a [u8], &'static str> {
    if r.len() < n {
        return Err("transaction: short read");
    }
    let (a, b) = r.split_at(n);
    *r = b;
    Ok(a)
}

fn rv(r: &mut &[u8]) -> Result<u64, &'static str> {
    let (v, n) = read_uvarint(r);
    if n == 0 {
        return Err("transaction: invalid varint");
    }
    *r = &r[n..];
    Ok(v)
}

/// Go: `AssetPayload`. One per asset moved by a value-carrying transaction;
/// holds the Zether statement (fees, ring, commitments) and the Bulletproof.
#[derive(Clone, Debug)]
pub struct AssetPayload {
    /// Asset id; all-zero for the native DERO asset.
    pub scid: [u8; 32],
    pub burn_value: u64,
    /// Payload type byte (0 = legacy CBOR, 1 = CBOR v2).
    pub rpc_type: u8,
    /// Encrypted RPC payload, exactly [`PAYLOAD_LIMIT`] bytes.
    pub rpc_payload: Vec<u8>,
    pub statement: Statement,
    pub proof: Option<Proof>,
}

impl AssetPayload {
    /// Go: `MarshalHeaderStatement`.
    pub fn marshal_header_statement(&self) -> Result<Vec<u8>, &'static str> {
        if self.rpc_payload.len() != PAYLOAD_LIMIT {
            return Err("rpc_payload must be PAYLOAD_LIMIT bytes");
        }
        let mut w = Vec::new();
        put_uvarint(&mut w, self.burn_value);
        w.extend_from_slice(&self.scid);
        w.push(self.rpc_type);
        w.extend_from_slice(&self.rpc_payload);
        let mut s = self.statement.clone();
        w.extend_from_slice(&s.serialize());
        Ok(w)
    }

    /// Go: `UnmarshalHeaderStatement`.
    pub fn unmarshal_header_statement(r: &mut &[u8]) -> Result<AssetPayload, &'static str> {
        let burn_value = rv(r)?;
        let scid: [u8; 32] = take(r, 32)?.try_into().unwrap();
        let rpc_type = take(r, 1)?[0];
        let rpc_payload = take(r, PAYLOAD_LIMIT)?.to_vec();
        let statement = Statement::deserialize(r)?;
        Ok(AssetPayload {
            scid,
            burn_value,
            rpc_type,
            rpc_payload,
            statement,
            proof: None,
        })
    }

    /// Go: `MarshalProofs`.
    pub fn marshal_proofs(&self) -> Result<Vec<u8>, &'static str> {
        Ok(self.proof.as_ref().ok_or("missing proof")?.serialize())
    }

    /// Go: `Proof.Nonce()` (cryptography/crypto/proof_generate.go:72-74) —
    /// `Keccak256(u.EncodeCompressed())`. The per-payload double-spend key
    /// (derived from roothash/scid/sender secret) the mempool dedups on
    /// (mempool.go:159-175). `None` when the payload's proof is not parsed
    /// (a hand-built header-only payload).
    pub fn proof_nonce(&self) -> Option<[u8; 32]> {
        self.proof.as_ref().map(|p| {
            let u = p.u.compress();
            dero_crypto::keccak256(&[&u])
        })
    }

    /// Go: `UnmarshalProofs` — the proof's ring power is derived from the
    /// statement's pointer list.
    pub fn unmarshal_proofs(&mut self, r: &mut &[u8]) -> Result<(), &'static str> {
        let count =
            self.statement.publickeylist_pointers.len() / self.statement.bytes_per_publickey as usize;
        let m = power_of_2(count) as usize;
        self.proof = Some(Proof::deserialize(r, m)?);
        Ok(())
    }
}

/// A DERO transaction. Mirrors Go's `Transaction` (`Transaction_Prefix` +
/// `Payloads`).
#[derive(Clone, Debug)]
pub struct Transaction {
    pub version: u64,
    pub source_network: u64,
    pub dest_network: u64,
    pub tx_type: TransactionType,
    /// PREMINE / SC gas value.
    pub value: u64,
    /// 33-byte compressed public key (registration / coinbase / premine).
    pub miner_address: [u8; 33],
    /// Schnorr challenge (registration).
    pub c: [u8; 32],
    /// Schnorr response (registration).
    pub s: [u8; 32],
    /// State height (normal / burn / sc).
    pub height: u64,
    /// Reference block id (normal / burn / sc).
    pub blid: [u8; 32],
    pub payloads: Vec<AssetPayload>,
    /// Raw CBOR SC arguments (SC tx). Stored verbatim for byte-exact round-trip.
    pub scdata: Vec<u8>,
}

impl Default for Transaction {
    fn default() -> Self {
        Transaction {
            version: 1,
            source_network: 0,
            dest_network: 0,
            tx_type: TransactionType::Coinbase,
            value: 0,
            miner_address: [0u8; 33],
            c: [0u8; 32],
            s: [0u8; 32],
            height: 0,
            blid: [0u8; 32],
            payloads: Vec::new(),
            scdata: Vec::new(),
        }
    }
}

impl Transaction {
    /// A new coinbase transaction shell. The block's `Miner_TX` is a COINBASE
    /// carrying only the 33-byte miner address — no value, no proof.
    pub fn new_coinbase(miner_address: [u8; 33]) -> Transaction {
        Transaction {
            tx_type: TransactionType::Coinbase,
            miner_address,
            ..Default::default()
        }
    }

    /// A new registration transaction shell (version 1, networks 0).
    pub fn new_registration(miner_address: [u8; 33], c: [u8; 32], s: [u8; 32]) -> Transaction {
        Transaction {
            tx_type: TransactionType::Registration,
            miner_address,
            c,
            s,
            ..Default::default()
        }
    }

    /// Go: `SerializeHeader` — everything except the per-payload proofs.
    pub fn serialize_header(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_uvarint(&mut out, self.version);
        put_uvarint(&mut out, self.source_network);
        put_uvarint(&mut out, self.dest_network);
        put_uvarint(&mut out, self.tx_type as u64);

        if matches!(self.tx_type, TransactionType::Premine | TransactionType::Sc) {
            put_uvarint(&mut out, self.value);
        }
        if matches!(
            self.tx_type,
            TransactionType::Premine | TransactionType::Coinbase | TransactionType::Registration
        ) {
            out.extend_from_slice(&self.miner_address);
        }
        if self.tx_type == TransactionType::Registration {
            out.extend_from_slice(&self.c);
            out.extend_from_slice(&self.s);
        }
        if matches!(
            self.tx_type,
            TransactionType::Burn | TransactionType::Normal | TransactionType::Sc
        ) {
            put_uvarint(&mut out, self.height);
            out.extend_from_slice(&self.blid);
            put_uvarint(&mut out, self.payloads.len() as u64);
            for p in &self.payloads {
                out.extend_from_slice(&p.marshal_header_statement().expect("payload header"));
            }
        }
        if self.tx_type == TransactionType::Sc {
            put_uvarint(&mut out, self.scdata.len() as u64);
            out.extend_from_slice(&self.scdata);
        }
        out
    }

    /// Go: `Serialize` — full tx including proofs.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = self.serialize_header();
        for p in &self.payloads {
            out.extend_from_slice(&p.marshal_proofs().expect("payload proof"));
        }
        out
    }

    /// Go: `SerializeCoreStatement` — excludes proofs (== header). Basis of the txid.
    pub fn serialize_core_statement(&self) -> Vec<u8> {
        self.serialize_header()
    }

    /// Go: `GetHash` (version 1) — Keccak-256 of the core statement.
    pub fn get_hash(&self) -> [u8; 32] {
        dero_crypto::keccak256(&[&self.serialize_core_statement()])
    }

    /// Go: `IsCoinbase` (transaction/transaction.go:204-206).
    pub fn is_coinbase(&self) -> bool {
        self.tx_type == TransactionType::Coinbase
    }
    /// Go: `IsRegistration` (transaction/transaction.go:208-210).
    pub fn is_registration(&self) -> bool {
        self.tx_type == TransactionType::Registration
    }
    /// Go: `IsPremine` (transaction/transaction.go:212-214).
    pub fn is_premine(&self) -> bool {
        self.tx_type == TransactionType::Premine
    }
    /// Go: `IsSC` (transaction/transaction.go:216-219).
    pub fn is_sc(&self) -> bool {
        self.tx_type == TransactionType::Sc
    }
    /// Go: `IsProofRequired` (transaction/transaction.go:221-224) — every type
    /// except COINBASE / REGISTRATION / PREMINE carries Zether proofs.
    pub fn is_proof_required(&self) -> bool {
        !(self.is_coinbase() || self.is_registration() || self.is_premine())
    }

    /// Go: `Transaction.Fees()` (transaction/transaction.go:226-234) — the sum
    /// of the zero-SCID (native DERO) payloads' statement fees; token payloads
    /// carry no fees.
    pub fn fees(&self) -> u64 {
        self.payloads
            .iter()
            .filter(|p| p.scid == [0u8; 32])
            .map(|p| p.statement.fees)
            .sum()
    }

    /// Go: `Transaction.GasStorage()` (transaction/transaction.go:237-255) —
    /// the tx storage gas is currently defined as exactly `tx.Fees()` (the
    /// alternative SC-only computation in the reference is commented out).
    pub fn gas_storage(&self) -> u64 {
        self.fees()
    }

    /// The per-payload double-spend nonces of a fully parsed transaction —
    /// `tx.Payloads[i].Proof.Nonce()` exactly as Go's `Mempool_Add_TX` consumes
    /// them (blockchain/mempool/mempool.go:159-175). Payload-less tx types
    /// (COINBASE/REGISTRATION/PREMINE) yield an empty list; payloads without a
    /// parsed proof are skipped.
    pub fn payload_nonces(&self) -> Vec<[u8; 32]> {
        self.payloads.iter().filter_map(|p| p.proof_nonce()).collect()
    }

    /// Go: `Deserialize` — parse any transaction type. Returns the tx and the
    /// number of bytes consumed (so callers can thread a larger buffer).
    pub fn deserialize(buf: &[u8]) -> Result<(Transaction, usize), &'static str> {
        let mut r = buf;

        let version = rv(&mut r)?;
        if version != 1 {
            return Err("transaction version != 1");
        }
        let source_network = rv(&mut r)?;
        let dest_network = rv(&mut r)?;
        let tx_type = TransactionType::from_u64(rv(&mut r)?)?;

        let mut tx = Transaction {
            version,
            source_network,
            dest_network,
            tx_type,
            ..Default::default()
        };

        if matches!(tx_type, TransactionType::Premine | TransactionType::Sc) {
            tx.value = rv(&mut r)?;
        }
        if matches!(
            tx_type,
            TransactionType::Premine | TransactionType::Coinbase | TransactionType::Registration
        ) {
            tx.miner_address.copy_from_slice(take(&mut r, 33)?);
        }
        if tx_type == TransactionType::Registration {
            tx.c.copy_from_slice(take(&mut r, 32)?);
            tx.s.copy_from_slice(take(&mut r, 32)?);
        }

        if matches!(
            tx_type,
            TransactionType::Burn | TransactionType::Normal | TransactionType::Sc
        ) {
            tx.height = rv(&mut r)?;
            tx.blid.copy_from_slice(take(&mut r, 32)?);
            let asset_count = rv(&mut r)?;
            if asset_count < 1 {
                return Err("invalid asset_count in transaction");
            }
            for _ in 0..asset_count {
                tx.payloads.push(AssetPayload::unmarshal_header_statement(&mut r)?);
            }
        }

        if tx_type == TransactionType::Sc {
            let sc_len = rv(&mut r)? as usize;
            let raw = take(&mut r, sc_len)?;
            // Go keeps SCDATA as a PARSED `rpc.Arguments` (DeserializeHeader →
            // `SCDATA.UnmarshalBinary`, transaction.go:394) and re-marshals it
            // canonically on every SerializeHeader (transaction.go:481-489 →
            // SortCoreDeterministic), so the txid is computed over CANONICAL
            // scdata. Parse-and-recanonicalize at deserialize so our stored bytes
            // are canonical (txid then matches Go) AND malformed scdata is
            // rejected here exactly like Go's UnmarshalBinary. For canonical
            // (real mainnet) scdata this is the identity, so the wire round-trip
            // is unchanged.
            let args = crate::arguments::Arguments::unmarshal_binary_exact(raw)
                .map_err(|_| "tx: invalid scdata")?;
            tx.scdata = args.marshal_binary();
        }

        if matches!(
            tx_type,
            TransactionType::Burn | TransactionType::Normal | TransactionType::Sc
        ) {
            for p in tx.payloads.iter_mut() {
                p.unmarshal_proofs(&mut r)?;
            }
        }

        // Go: PREMINE/COINBASE may leave the buffer with trailing bytes (the
        // block parser stops there); everything else must consume fully.
        if !r.is_empty()
            && !matches!(tx_type, TransactionType::Premine | TransactionType::Coinbase)
        {
            return Err("extra unknown data in transaction");
        }

        let consumed = buf.len() - r.len();
        Ok((tx, consumed))
    }

    /// Go: `IsRegistrationValid` — verify the Schnorr signature.
    /// `c' = ReducedHash(u.String() ‖ (G·s − u·c).String())`, valid iff c' == c.
    pub fn is_registration_valid(&self) -> bool {
        if self.tx_type != TransactionType::Registration {
            return false;
        }
        let u = match G1::decompress(&self.miner_address) {
            Ok(p) => p,
            Err(_) => return false,
        };
        let s = BigUint::from_bytes_be(&self.s);
        let c = BigUint::from_bytes_be(&self.c);

        let gs = base_g().scalar_mult(&s.to_bytes_be());
        let uc = u.scalar_mult(&c.to_bytes_be());
        let neg_uc = G1::neg(&uc);
        let tmppoint = G1::add(&gs, &neg_uc);

        let serialize = format!("{}{}", point_to_string(&u), point_to_string(&tmppoint));
        let c_calculated = reduced_hash(serialize.as_bytes());
        c == c_calculated
    }

    /// Convenience: parse a raw registration tx (kept for existing callers).
    pub fn deserialize_registration(buf: &[u8]) -> Result<Transaction, &'static str> {
        let (tx, _) = Transaction::deserialize(buf)?;
        if tx.tx_type != TransactionType::Registration {
            return Err("not a registration tx");
        }
        Ok(tx)
    }
}

#[cfg(test)]
mod helper_tests {
    use super::*;

    fn tx_of(t: TransactionType) -> Transaction {
        Transaction { tx_type: t, ..Default::default() }
    }

    fn payload(scid: [u8; 32], fees: u64) -> AssetPayload {
        AssetPayload {
            scid,
            burn_value: 0,
            rpc_type: 0,
            rpc_payload: vec![0u8; PAYLOAD_LIMIT],
            statement: dero_crypto::Statement { fees, ..Default::default() },
            proof: None,
        }
    }

    /// Go: transaction.go:204-224 — the type predicates.
    #[test]
    fn type_predicates_match_go() {
        use TransactionType::*;
        for (t, coinbase, reg, premine, sc, proof) in [
            (Premine, false, false, true, false, false),
            (Registration, false, true, false, false, false),
            (Coinbase, true, false, false, false, false),
            (Normal, false, false, false, false, true),
            (Burn, false, false, false, false, true),
            (Sc, false, false, false, true, true),
        ] {
            let tx = tx_of(t);
            assert_eq!(tx.is_coinbase(), coinbase, "{t:?}");
            assert_eq!(tx.is_registration(), reg, "{t:?}");
            assert_eq!(tx.is_premine(), premine, "{t:?}");
            assert_eq!(tx.is_sc(), sc, "{t:?}");
            // Go: IsProofRequired = !(coinbase || registration || premine)
            assert_eq!(tx.is_proof_required(), proof, "{t:?}");
        }
    }

    /// Go: Fees() (transaction.go:226-234) sums only zero-SCID payload fees;
    /// GasStorage() (transaction.go:237-255) is exactly Fees().
    #[test]
    fn fees_and_gas_storage_match_go() {
        let mut tx = tx_of(TransactionType::Sc);
        assert_eq!(tx.fees(), 0); // no payloads
        tx.payloads.push(payload([0u8; 32], 100));
        tx.payloads.push(payload([7u8; 32], 555)); // token payload: ignored
        tx.payloads.push(payload([0u8; 32], 20));
        assert_eq!(tx.fees(), 120);
        assert_eq!(tx.gas_storage(), tx.fees());
    }
}
