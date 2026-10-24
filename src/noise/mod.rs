//! A Noise-style authenticated key exchange built on KEMs, with ChaCha20-Poly1305 transport.
//!
//! The symmetric core (`CipherState`, `SymmetricState`, `HKDF`, `Split`) follows the Noise
//! Protocol Framework rev. 34. The handshake tokens are the KEM tokens of PQNoise
//! (see [`pattern`]), so the engine works with any [`Kem`](crate::kem::Kem): pure ML-KEM,
//! the X25519+ML-KEM hybrids, or the classical X25519 baseline.
//!
//! Token processing rules used here:
//!
//! | token | writer | reader |
//! |---|---|---|
//! | `e` | generate ephemeral pair; send `pk`; `MixHash(pk)` | store `re`; `MixHash(re)` |
//! | `s` | send `EncryptAndHash(s.pk)` | `rs = DecryptAndHash(..)`; apply trust policy |
//! | `ekem` | `(ct, ss) = Encaps(re)`; send `EncryptAndHash(ct)`; `MixKey(ss)` | `ct = DecryptAndHash(..)`; `MixKey(Decaps(e, ct))` |
//! | `skem` | `(ct, ss) = Encaps(rs)`; send `EncryptAndHash(ct)`; `MixKey(ss)` | `ct = DecryptAndHash(..)`; `MixKey(Decaps(s, ct))` |
//!
//! Every message ends with `EncryptAndHash(payload)`.
//!
//! ```
//! use hybridkem::hybrid::XWing;
//! use hybridkem::noise::{Builder, Pattern, StaticKeypair};
//!
//! let mut rng = rand::rng();
//! let server = StaticKeypair::<XWing>::generate(&mut rng);
//! let client = StaticKeypair::<XWing>::generate(&mut rng);
//!
//! let mut i = Builder::new(Pattern::IK)
//!     .local_static(client.clone())
//!     .remote_static(&server.public)
//!     .build_initiator()?;
//! let mut r = Builder::new(Pattern::IK)
//!     .local_static(server)
//!     .pin_peer(&client.public)
//!     .build_responder()?;
//!
//! let m1 = i.write_message(b"hello", &mut rng)?;
//! assert_eq!(r.read_message(&m1)?, b"hello");
//! let m2 = r.write_message(b"welcome", &mut rng)?;
//! assert_eq!(i.read_message(&m2)?, b"welcome");
//!
//! let (mut ti, mut tr) = (i.into_transport()?, r.into_transport()?);
//! let ct = ti.encrypt(b"post-quantum secret")?;
//! assert_eq!(tr.decrypt(&ct)?, b"post-quantum secret");
//! # Ok::<(), hybridkem::Error>(())
//! ```

pub mod cipher;
mod handshake;
pub mod pattern;
mod stream;
mod transport;

pub use handshake::{protocol_name, Builder, HandshakeState, PeerVerifier, StaticKeypair};
pub use pattern::{Pattern, Role, Token};
pub use stream::{read_frame, run_handshake, write_frame, HandshakeStats, SecureStream};
pub use transport::{TransportState, MAX_PLAINTEXT_LEN};

/// Maximum size of any Noise message (handshake or transport), per the Noise specification.
pub const MAX_MESSAGE_LEN: usize = 65535;

#[cfg(test)]
mod tests;
