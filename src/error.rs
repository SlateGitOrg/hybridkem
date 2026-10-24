//! The crate-wide error type.

use thiserror::Error;

/// Everything that can go wrong in this crate.
///
/// Note what is *not* here: ML-KEM decapsulation of a well-sized but forged ciphertext is not
/// an error. FIPS 203 uses implicit rejection, returning a pseudorandom key instead, so a
/// caller learns about tampering only when the derived keys fail to authenticate later.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// An input had the wrong size.
    #[error("invalid {what} length: expected {expected} bytes, got {actual}")]
    InvalidLength {
        /// Which input was malformed.
        what: &'static str,
        /// Required length.
        expected: usize,
        /// Length actually supplied.
        actual: usize,
    },

    /// An encapsulation key failed the FIPS 203 modulus check (a coefficient was `>= q`).
    #[error("encapsulation key is not canonical (FIPS 203 modulus check failed)")]
    EncapsulationKeyNotCanonical,

    /// An expanded decapsulation key failed the FIPS 203 hash check (`H(ek) != h`).
    #[error("decapsulation key is inconsistent (FIPS 203 hash check failed)")]
    DecapsulationKeyHashMismatch,

    /// X25519 produced the all-zero output, i.e. the peer sent a low-order point.
    #[error("X25519 shared secret is all zero (non-contributory public key)")]
    NonContributory,

    /// An AEAD tag did not verify: the message was forged, corrupted, replayed or reordered,
    /// or the two sides derived different keys.
    #[error("authenticated decryption failed")]
    Decrypt,

    /// A handshake message was shorter than its pattern requires.
    #[error("handshake message truncated: needed {needed} more bytes")]
    Truncated {
        /// Bytes missing from the message.
        needed: usize,
    },

    /// A handshake method was called out of turn (e.g. writing when it is the peer's turn).
    #[error("handshake used out of order: {0}")]
    OutOfOrder(&'static str),

    /// A required key was not configured (e.g. IK initiator without the responder's key).
    #[error("missing key: {0}")]
    MissingKey(&'static str),

    /// A handshake was configured inconsistently with its pattern.
    #[error("invalid handshake configuration: {0}")]
    InvalidConfig(&'static str),

    /// The peer presented a static key that the trust policy rejected.
    #[error("peer static key rejected by trust policy")]
    UntrustedPeer,

    /// A message exceeded the 65535-byte Noise limit.
    #[error("message too large: {len} bytes exceeds the {max}-byte limit")]
    MessageTooLarge {
        /// Size requested.
        len: usize,
        /// Maximum permitted.
        max: usize,
    },

    /// A cipher state used all 2^64-1 nonces; the session must be re-established.
    #[error("nonce space exhausted")]
    NonceExhausted,

    /// Reading or writing a framed transport stream failed.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A test-vector or key file could not be parsed.
    #[error("parse error: {0}")]
    Parse(String),
}

/// Convenience alias used throughout the crate.
pub type Result<T> = core::result::Result<T, Error>;

/// Return [`Error::InvalidLength`] unless `bytes.len() == expected`.
pub(crate) fn check_len(what: &'static str, bytes: &[u8], expected: usize) -> Result<()> {
    if bytes.len() == expected {
        Ok(())
    } else {
        Err(Error::InvalidLength {
            what,
            expected,
            actual: bytes.len(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_len_reports_both_sizes() {
        assert!(check_len("thing", &[0; 4], 4).is_ok());
        let err = check_len("thing", &[0; 3], 4).unwrap_err();
        assert_eq!(
            err.to_string(),
            "invalid thing length: expected 4 bytes, got 3"
        );
    }

    #[test]
    fn io_errors_convert() {
        let err: Error = std::io::Error::other("boom").into();
        assert!(err.to_string().contains("boom"));
    }
}
