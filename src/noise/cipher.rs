//! `CipherState` and `SymmetricState` from the Noise Protocol Framework (rev. 34, Sections
//! 5.1-5.2), instantiated with ChaCha20-Poly1305 and SHA-256/HKDF-SHA-256.

use crate::error::{Error, Result};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Hash output length (SHA-256).
pub const HASH_LEN: usize = 32;
/// AEAD tag length (Poly1305).
pub const TAG_LEN: usize = 16;

/// An AEAD key plus a 64-bit message counter used as the nonce.
pub struct CipherState {
    key: Option<Zeroizing<[u8; 32]>>,
    nonce: u64,
}

impl core::fmt::Debug for CipherState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CipherState")
            .field("has_key", &self.key.is_some())
            .field("nonce", &self.nonce)
            .finish()
    }
}

/// ChaCha20-Poly1305 nonce encoding from the Noise spec: 32 zero bits || little-endian `n`.
fn nonce_bytes(n: u64) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[4..].copy_from_slice(&n.to_le_bytes());
    out
}

fn aead_encrypt(key: &[u8; 32], n: u64, ad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(&(*key).into());
    cipher
        .encrypt(
            &nonce_bytes(n).into(),
            Payload {
                msg: plaintext,
                aad: ad,
            },
        )
        .expect("ChaCha20-Poly1305 encryption cannot fail for in-memory buffers")
}

impl CipherState {
    /// A cipher state with no key: encryption is the identity, as Noise specifies.
    pub fn empty() -> Self {
        Self {
            key: None,
            nonce: 0,
        }
    }

    /// `InitializeKey(k)`: set the key and reset the nonce.
    pub fn with_key(key: [u8; 32]) -> Self {
        Self {
            key: Some(Zeroizing::new(key)),
            nonce: 0,
        }
    }

    /// `HasKey()`.
    pub fn has_key(&self) -> bool {
        self.key.is_some()
    }

    /// The next nonce that will be used.
    pub fn nonce(&self) -> u64 {
        self.nonce
    }

    /// Overwrite the nonce (Noise `SetNonce`); used by tests to reach the exhaustion limit.
    pub fn set_nonce(&mut self, nonce: u64) {
        self.nonce = nonce;
    }

    /// `EncryptWithAd(ad, plaintext)`.
    pub fn encrypt_with_ad(&mut self, ad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let Some(key) = &self.key else {
            return Ok(plaintext.to_vec());
        };
        // 2^64 - 1 is reserved by the spec (it is the rekey nonce).
        if self.nonce == u64::MAX {
            return Err(Error::NonceExhausted);
        }
        let ct = aead_encrypt(key, self.nonce, ad, plaintext);
        self.nonce += 1;
        Ok(ct)
    }

    /// `DecryptWithAd(ad, ciphertext)`. On failure the nonce is *not* advanced.
    pub fn decrypt_with_ad(&mut self, ad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let Some(key) = &self.key else {
            return Ok(ciphertext.to_vec());
        };
        if self.nonce == u64::MAX {
            return Err(Error::NonceExhausted);
        }
        let cipher = ChaCha20Poly1305::new(&(**key).into());
        let pt = cipher
            .decrypt(
                &nonce_bytes(self.nonce).into(),
                Payload {
                    msg: ciphertext,
                    aad: ad,
                },
            )
            .map_err(|_| Error::Decrypt)?;
        self.nonce += 1;
        Ok(pt)
    }

    /// `Rekey()`: `k = ENCRYPT(k, 2^64-1, "", zeros(32))[..32]`. The nonce is unchanged.
    pub fn rekey(&mut self) {
        if let Some(key) = &mut self.key {
            let out = Zeroizing::new(aead_encrypt(key, u64::MAX, &[], &[0u8; 32]));
            key.copy_from_slice(&out[..32]);
        }
    }
}

/// Noise `HKDF(chaining_key, input_key_material, 2)` = RFC 5869 HKDF-SHA-256 with
/// `salt = chaining_key`, empty `info`, 64 output bytes.
pub fn hkdf2(chaining_key: &[u8; 32], ikm: &[u8]) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
    let hk = Hkdf::<Sha256>::new(Some(chaining_key), ikm);
    let mut okm = Zeroizing::new([0u8; 64]);
    hk.expand_multi_info(&[], okm.as_mut())
        .expect("64 bytes is far below the HKDF-SHA-256 output limit");
    let mut a = Zeroizing::new([0u8; 32]);
    let mut b = Zeroizing::new([0u8; 32]);
    a.copy_from_slice(&okm[..32]);
    b.copy_from_slice(&okm[32..]);
    (a, b)
}

/// The handshake-time chaining key, transcript hash and current cipher.
pub struct SymmetricState {
    ck: Zeroizing<[u8; 32]>,
    h: [u8; HASH_LEN],
    cipher: CipherState,
}

impl SymmetricState {
    /// `InitializeSymmetric(protocol_name)`.
    pub fn new(protocol_name: &str) -> Self {
        let name = protocol_name.as_bytes();
        let mut h = [0u8; HASH_LEN];
        if name.len() <= HASH_LEN {
            h[..name.len()].copy_from_slice(name);
        } else {
            h = Sha256::digest(name).into();
        }
        Self {
            ck: Zeroizing::new(h),
            h,
            cipher: CipherState::empty(),
        }
    }

    /// `MixKey(ikm)`: derive a new chaining key and cipher key.
    pub fn mix_key(&mut self, ikm: &[u8]) {
        let (ck, k) = hkdf2(&self.ck, ikm);
        self.ck = ck;
        self.cipher = CipherState::with_key(*k);
    }

    /// `MixHash(data)`: `h = SHA-256(h || data)`.
    pub fn mix_hash(&mut self, data: &[u8]) {
        let mut hasher = Sha256::new();
        hasher.update(self.h);
        hasher.update(data);
        self.h = hasher.finalize().into();
    }

    /// `EncryptAndHash(plaintext)`.
    pub fn encrypt_and_hash(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let ct = self.cipher.encrypt_with_ad(&self.h, plaintext)?;
        self.mix_hash(&ct);
        Ok(ct)
    }

    /// `DecryptAndHash(ciphertext)`.
    pub fn decrypt_and_hash(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let pt = self.cipher.decrypt_with_ad(&self.h, ciphertext)?;
        self.mix_hash(ciphertext);
        Ok(pt)
    }

    /// Length on the wire of `n` plaintext bytes after `EncryptAndHash`.
    pub fn encrypted_len(&self, n: usize) -> usize {
        if self.cipher.has_key() {
            n + TAG_LEN
        } else {
            n
        }
    }

    /// The transcript hash so far (Noise `GetHandshakeHash`).
    pub fn handshake_hash(&self) -> [u8; HASH_LEN] {
        self.h
    }

    /// `Split()`: derive the two transport cipher states (initiator→responder first).
    pub fn split(&self) -> (CipherState, CipherState) {
        let (k1, k2) = hkdf2(&self.ck, &[]);
        (CipherState::with_key(*k1), CipherState::with_key(*k2))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hkdf2_matches_rfc5869_style_expansion() {
        // RFC 5869 Test Case 3 (SHA-256, zero-length salt and info, IKM = 0x0b * 22). An
        // absent salt means HashLen zero bytes, so salt = [0; 32] is the same computation.
        let (a, b) = hkdf2(&[0u8; 32], &[0x0b; 22]);
        assert_eq!(
            hex::encode(&a[..]),
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
        );
        // The RFC's 42-byte OKM continues with these 10 bytes.
        assert_eq!(hex::encode(&b[..10]), "9d201395faa4b61a96c8");
    }

    #[test]
    fn empty_cipher_is_identity() {
        let mut c = CipherState::empty();
        assert!(!c.has_key());
        assert_eq!(c.encrypt_with_ad(b"ad", b"hello").unwrap(), b"hello");
        assert_eq!(c.decrypt_with_ad(b"ad", b"hello").unwrap(), b"hello");
        c.rekey();
        assert!(!c.has_key());
    }

    #[test]
    fn encrypt_decrypt_and_nonce_discipline() {
        let mut tx = CipherState::with_key([7; 32]);
        let mut rx = CipherState::with_key([7; 32]);
        let c0 = tx.encrypt_with_ad(b"ad", b"m0").unwrap();
        let c1 = tx.encrypt_with_ad(b"ad", b"m1").unwrap();
        assert_eq!(c0.len(), 2 + TAG_LEN);
        assert_ne!(c0[..2], c1[..2]);
        // Out-of-order delivery fails and does not advance the receiver.
        assert!(matches!(
            rx.decrypt_with_ad(b"ad", &c1),
            Err(Error::Decrypt)
        ));
        assert_eq!(rx.nonce(), 0);
        assert_eq!(rx.decrypt_with_ad(b"ad", &c0).unwrap(), b"m0");
        assert!(rx.decrypt_with_ad(b"other ad", &c1).is_err());
        assert_eq!(rx.decrypt_with_ad(b"ad", &c1).unwrap(), b"m1");
    }

    #[test]
    fn nonce_exhaustion_and_rekey() {
        let mut c = CipherState::with_key([1; 32]);
        c.set_nonce(u64::MAX);
        assert!(matches!(
            c.encrypt_with_ad(&[], b"x"),
            Err(Error::NonceExhausted)
        ));
        assert!(matches!(
            c.decrypt_with_ad(&[], b"x"),
            Err(Error::NonceExhausted)
        ));

        let mut a = CipherState::with_key([2; 32]);
        let mut b = CipherState::with_key([2; 32]);
        a.rekey();
        let ct = a.encrypt_with_ad(&[], b"after rekey").unwrap();
        assert!(b.decrypt_with_ad(&[], &ct).is_err());
        b.rekey();
        assert_eq!(b.decrypt_with_ad(&[], &ct).unwrap(), b"after rekey");
        assert!(format!("{a:?}").contains("has_key: true"));
    }

    #[test]
    fn symmetric_state_initialization() {
        let short = SymmetricState::new("Noise_NN");
        assert_eq!(&short.handshake_hash()[..8], b"Noise_NN");
        assert!(short.handshake_hash()[8..].iter().all(|&b| b == 0));
        let long_name = "x".repeat(40);
        let long = SymmetricState::new(&long_name);
        let expected: [u8; 32] = Sha256::digest(long_name.as_bytes()).into();
        assert_eq!(long.handshake_hash(), expected);
    }

    #[test]
    fn symmetric_states_stay_in_sync() {
        let mut a = SymmetricState::new("test");
        let mut b = SymmetricState::new("test");
        assert_eq!(a.encrypted_len(5), 5);
        let ct = a.encrypt_and_hash(b"plain").unwrap();
        assert_eq!(b.decrypt_and_hash(&ct).unwrap(), b"plain");
        a.mix_key(b"secret");
        b.mix_key(b"secret");
        assert_eq!(a.encrypted_len(5), 5 + TAG_LEN);
        let ct = a.encrypt_and_hash(b"hidden").unwrap();
        assert_ne!(&ct[..6], b"hidden");
        assert_eq!(b.decrypt_and_hash(&ct).unwrap(), b"hidden");
        assert_eq!(a.handshake_hash(), b.handshake_hash());
        let (mut a1, _a2) = a.split();
        let (mut b1, _b2) = b.split();
        let t = a1.encrypt_with_ad(&[], b"transport").unwrap();
        assert_eq!(b1.decrypt_with_ad(&[], &t).unwrap(), b"transport");
    }
}
