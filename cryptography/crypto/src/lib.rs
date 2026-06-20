//! # dero-crypto
//!
//! Rust port of DERO HE's `cryptography/crypto` package: Keccak hashing,
//! hash-to-point, deterministic generators, key derivation, and (in later
//! phases) ElGamal, Pedersen commitments, Bulletproofs and the Zether sigma
//! protocol.
//!
//! Phase 2 surface (verified byte-exact vs the Go reference): keccak,
//! hash-to-number, hash-to-point, generators G/H/Gs/Hs, and public-key
//! derivation.

pub mod balance_decoder;
pub mod cipher;
pub mod elgamal;
pub mod field_vector;
pub mod generators;
pub mod hashtopoint;
pub mod inner_product;
pub mod keccak;
pub mod keys;
pub mod point_vector;
pub mod polynomial;
pub mod proof;
pub mod read;
pub mod scalar;
pub mod statement;

pub use balance_decoder::{BalanceDecoder, DEFAULT_TABLE_SIZE};
pub use cipher::{encrypt_decrypt_user_data, generate_shared_secret, shake_xof};
pub use dero_bn256::{field_prime, group_order, G1};
pub use elgamal::{ElGamal, ElGamalError, NonceBalance};
pub use field_vector::{fft_field_vector, FieldVector, FieldVectorPolynomial};
pub use generators::{base_g, base_h, gs, gs_all, gsum, hs, hs_all, pedersen_commit, GENERATOR_COUNT};
pub use point_vector::{convolution, fft_generator_vector, PointVector};
pub use polynomial::{polynomial_mul, recursive_polynomials, transpose_polynomials};
pub use proof::{generate_proof, DeterministicRng, Proof, ScalarRng};
pub use statement::{graviton_sum, power_of_2, Statement, Witness};
pub use hashtopoint::{hash_to_number, hash_to_point, reduced_hash, PROTOCOL_CONSTANT};
pub use inner_product::InnerProduct;
pub use keccak::{keccak256, keccak256_64, keccak512, sha3_256};
pub use keys::{derive_public_key, point_to_string, reduce_scalar};
