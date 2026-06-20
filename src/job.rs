//! Getwork JSON messages — port of `rpc.GetBlockTemplate_Result` and
//! `rpc.SubmitBlock_Params` (derohe-reference/rpc/daemon_rpc.go:109-131).
//!
//! Field names must match the Go json tags byte-for-byte. Every field takes
//! `#[serde(default)]` because Go omits empty fields (`omitempty` on the blob
//! fields) and zero-values everything else; the server's `json.Encoder`
//! appends a trailing `'\n'` inside the text frame (serde tolerates it).

use serde::{Deserialize, Serialize};

/// Go: `rpc.GetBlockTemplate_Result` — one job push from the getwork server
/// (cmd/derod/rpc/websocket_getwork_server.go:141-207), arriving ~every 500ms.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GetBlockTemplateResult {
    /// `"<block_timestamp_ms>.0.notified"` — must be echoed back VERBATIM in
    /// the submit; the server Sscanf's `%d.%d` out of it (server line 239).
    #[serde(default)]
    pub jobid: String,
    /// Never sent on the getwork path (`omitempty`).
    #[serde(default)]
    pub blocktemplate_blob: String,
    /// 96 lowercase hex chars = the 48-byte serialized MiniBlock to grind.
    #[serde(default)]
    pub blockhashing_blob: String,
    /// DECIMAL big-int string. HighDiff ×9 is already pre-multiplied in by the
    /// server (websocket_getwork_server.go:158-160).
    #[serde(default)]
    pub difficulty: String,
    /// Display-only ("NW hashrate"); never used for the PoW check.
    #[serde(default)]
    pub difficultyuint64: u64,
    #[serde(default)]
    pub height: u64,
    #[serde(default)]
    pub prev_hash: String,
    /// Always 0 on the getwork path.
    #[serde(default)]
    pub epochmilli: u64,
    /// Per-session lifetime counters (reset on reconnect) — the ONLY feedback
    /// channel for submitted shares (the server never replies to a submit).
    #[serde(default)]
    pub blocks: u64,
    #[serde(default)]
    pub miniblocks: u64,
    #[serde(default)]
    pub rejected: u64,
    /// e.g. "unregistered miner or you need to wait 15 mins".
    #[serde(default)]
    pub lasterror: String,
    #[serde(default)]
    pub status: String,
}

/// Go: `rpc.SubmitBlock_Params` — the share submit (miner.go:513), a text
/// frame on the same websocket. Field order matters for the byte-exact
/// comparison with Go's `json.Marshal` (declaration order in both).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitBlockParams {
    pub jobid: String,
    /// 96 lowercase hex chars of the mutated 48-byte work buffer.
    pub mbl_blob: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vectors() -> serde_json::Value {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/vectors/minerwork.json");
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    #[test]
    fn job_parses_go_encoder_line() {
        // job_json is the EXACT bytes the Go getwork server puts in the text
        // frame (json.Encoder => trailing '\n', omitempty drops the
        // blocktemplate_blob field).
        let v = vectors();
        let line = v["job_json"].as_str().unwrap();
        assert!(line.ends_with('\n'), "server lines carry a trailing newline");
        let job: GetBlockTemplateResult = serde_json::from_str(line).unwrap();
        assert_eq!(job.jobid, "1748090000123.0.notified");
        assert_eq!(job.blocktemplate_blob, "", "omitempty field defaults");
        assert_eq!(job.blockhashing_blob.len(), 96);
        assert_eq!(job.difficulty, "312979370");
        assert_eq!(job.difficultyuint64, 312979370);
        assert_eq!(job.height, 3528900);
        assert_eq!(job.prev_hash, "7be1d3851b2787140b542525bd21c1b5ab4b938af6eeb85156400a8542c4093e");
        assert_eq!(job.epochmilli, 0);
        assert_eq!(job.blocks, 2);
        assert_eq!(job.miniblocks, 105);
        assert_eq!(job.rejected, 1);
        assert_eq!(job.lasterror, "unregistered miner or you need to wait 15 mins");
        assert_eq!(job.status, "");
        // from_slice path (what the connection loop uses) also tolerates it
        let _: GetBlockTemplateResult = serde_json::from_slice(line.as_bytes()).unwrap();
    }

    #[test]
    fn submit_serializes_byte_exact_vs_go() {
        let v = vectors();
        let want = v["submit_json"].as_str().unwrap();
        let job: GetBlockTemplateResult = serde_json::from_str(v["job_json"].as_str().unwrap()).unwrap();
        let submit = SubmitBlockParams { jobid: job.jobid, mbl_blob: job.blockhashing_blob };
        assert_eq!(serde_json::to_string(&submit).unwrap(), want);
    }
}
