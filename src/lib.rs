//! # hybridkem
//!
//! **Educational, not audited.** This crate is a study implementation. It has not been
//! reviewed by cryptographers, its constant-time properties are checked only by code review
//! and a statistical timing test, and it must not protect real data.
//!
//! What is inside:
//!
//! * [`mlkem`] — ML-KEM-512/768/1024 written from FIPS 203: NTT, sampling, compression, the
//!   K-PKE scheme and the Fujisaki-Okamoto transform with implicit rejection. Validated
//!   against NIST ACVP vectors and cross-checked against the RustCrypto `ml-kem` crate.
//! * [`hybrid`] — X25519 + ML-KEM hybrid KEMs: exact X-Wing (draft-connolly-cfrg-xwing-kem-06)
//!   and a transcript-hashing combiner for every ML-KEM parameter set.
//! * [`noise`] — a Noise-style handshake engine with post-quantum KEM tokens (`pqIK`,
//!   `pqXX`), ChaCha20-Poly1305 transport and length-prefixed framing over any byte stream.
//! * [`kem`] — the [`kem::Kem`] trait tying these together, plus runtime algorithm selection.
//! * [`dudect`] — a dudect-style fixed-vs-random timing-leak detector.
//! * [`bench`](mod@bench) — a median-of-N timing harness for the per-parameter-set table.
//! * [`kat`] — loaders and runners for the pinned known-answer vectors.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod bench;
pub mod dudect;
pub mod error;
pub mod hybrid;
pub mod kat;
pub mod kem;
pub mod mlkem;
pub mod noise;
mod secret;

pub use error::{Error, Result};
pub use secret::SharedSecret;
