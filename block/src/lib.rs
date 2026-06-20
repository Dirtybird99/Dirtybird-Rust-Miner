//! # dero-protocol
//!
//! DERO protocol-level types: bech32 codec, addresses, and (later phases)
//! transaction structures and serialization. Port of `rpc/` and `transaction/`.

pub mod address;
pub mod arguments;
pub mod bech32;
pub mod block;
pub mod miniblock;
pub mod transaction;
pub mod varint;

pub use address::{Address, AddressError};
pub use block::Block;
pub use miniblock::{MiniBlock, MiniBlockKey, MiniBlocksCollection, MINIBLOCK_SIZE};
pub use transaction::{calculate_tx_fee, Transaction, TransactionType};
