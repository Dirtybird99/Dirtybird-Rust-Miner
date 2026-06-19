//! DERO AstroBWTv3 CPU miner — clean-room Rust port of the validated Zig pipeline.
//!
//! Pipeline: SHA256 -> Salsa20/20 -> RC4 -> FNV1a -> wolfCompute -> suffix array -> SHA256.
//! The suffix-array stage (≈85% of cost) is FFI-linked from the same vendored C/C++ the
//! Zig and C++ reference miners use (vendor/v114 descriptor SA + libsais fallback); the
//! rest is Rust-native so whole-binary Rust PGO can optimize it (the margin lever over Zig).
//!
//! Correctness is gated on the KAT `pow("a") == 54e2324d…` plus per-stage golden vectors
//! and differential fuzzing against the Zig oracle. A faster wrong hash is a rejected share.

pub mod codelut;
pub mod config;
pub mod difficulty;
pub mod mining;
pub mod net;
pub mod pipeline;
pub mod primitives;
pub mod sa;
pub mod sha_hw;
pub mod state;
pub mod sys;
pub mod term;
pub mod wolf;

pub use pipeline::{hash, hash2, hash_once};
pub use wolf::Worker;
pub use codelut::Reglut;
