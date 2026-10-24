//! A 32-byte shared secret that compares in constant time and wipes itself on drop.

use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The 32-byte output of every KEM in this crate.
///
/// `PartialEq` is implemented with [`ConstantTimeEq`], `Debug` never prints the bytes, and
/// the memory is zeroized when the value is dropped.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret([u8; 32]);

impl SharedSecret {
    /// Wrap raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw bytes (e.g. to feed a KDF).
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lower-case hex, for demos and test vectors. Avoid in production logs.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl ConstantTimeEq for SharedSecret {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for SharedSecret {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for SharedSecret {}

impl core::fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SharedSecret(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equality_debug_and_hex() {
        let a = SharedSecret::from_bytes([1; 32]);
        let b = SharedSecret::from_bytes([1; 32]);
        let c = SharedSecret::from_bytes([2; 32]);
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(format!("{a:?}"), "SharedSecret(<redacted>)");
        assert_eq!(a.to_hex(), "01".repeat(32));
        assert_eq!(a.as_bytes(), &[1; 32]);
    }
}
