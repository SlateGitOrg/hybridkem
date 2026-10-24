//! The symmetric primitives ML-KEM is built from (FIPS 203, Section 4.1).
//!
//! SHA-3 and SHAKE themselves (FIPS 202) come from the RustCrypto `sha3`/`shake` crates;
//! this module only fixes the input framing and output lengths the standard prescribes.

use sha3::{Digest, Sha3_256, Sha3_512};
use shake::{ExtendableOutput, Shake128, Shake128Reader, Shake256, Update, XofReader};

/// `H(s) = SHA3-256(s)`.
pub fn h(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    for p in parts {
        Digest::update(&mut hasher, p);
    }
    hasher.finalize().into()
}

/// `J(s) = SHAKE256(s, 8*32)`: the implicit-rejection key derivation.
pub fn j(parts: &[&[u8]]) -> [u8; 32] {
    let mut out = [0u8; 32];
    shake256(parts, &mut out);
    out
}

/// `G(c) = SHA3-512(c)`, split into two 32-byte halves.
pub fn g(parts: &[&[u8]]) -> ([u8; 32], [u8; 32]) {
    let mut hasher = Sha3_512::new();
    for p in parts {
        Digest::update(&mut hasher, p);
    }
    let digest = hasher.finalize();
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    a.copy_from_slice(&digest[..32]);
    b.copy_from_slice(&digest[32..]);
    (a, b)
}

/// `PRF_eta(s, b) = SHAKE256(s || b, 8*64*eta)`; fills `out` (which must be `64*eta` bytes).
pub fn prf(s: &[u8; 32], b: u8, out: &mut [u8]) {
    shake256(&[s, &[b]], out);
}

/// Absorb `parts` into SHAKE256 and squeeze `out.len()` bytes.
pub fn shake256(parts: &[&[u8]], out: &mut [u8]) {
    let mut xof = Shake256::default();
    for p in parts {
        xof.update(p);
    }
    xof.finalize_xof().read(out);
}

/// The incremental `XOF` (SHAKE128) used by `SampleNTT`.
pub struct Xof(Shake128Reader);

impl Xof {
    /// `XOF.Init` + `XOF.Absorb(rho || j || i)` + finalize, ready to squeeze.
    pub fn new(rho: &[u8; 32], j: u8, i: u8) -> Self {
        let mut xof = Shake128::default();
        xof.update(rho);
        xof.update(&[j, i]);
        Self(xof.finalize_xof())
    }

    /// `XOF.Squeeze` into `out`.
    pub fn squeeze(&mut self, out: &mut [u8]) {
        self.0.read(out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_answers_for_empty_input() {
        // FIPS 202 / NIST CAVP example values for the empty message.
        assert_eq!(
            hex::encode(h(&[])),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        );
        let (a, b) = g(&[]);
        assert_eq!(
            hex::encode([a, b].concat()),
            "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6\
             15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
        );
        assert_eq!(
            hex::encode(j(&[])),
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
        );
        let mut xof = Xof(Shake128::default().finalize_xof());
        let mut out = [0u8; 16];
        xof.squeeze(&mut out);
        assert_eq!(hex::encode(out), "7f9c2ba4e88f827d616045507605853e");
    }

    #[test]
    fn multi_part_input_is_concatenation() {
        assert_eq!(h(&[b"ab", b"c"]), h(&[b"abc"]));
        assert_eq!(j(&[b"a", b"bc"]), j(&[b"abc"]));
        assert_eq!(g(&[b"a", b"bc"]), g(&[b"abc"]));
        let mut p1 = [0u8; 128];
        let mut p2 = [0u8; 128];
        prf(&[7u8; 32], 3, &mut p1);
        shake256(&[&[7u8; 32], &[3]], &mut p2);
        assert_eq!(p1, p2);
    }
}
