//! ML-KEM (FIPS 203) implemented from the standard.
//!
//! The layering mirrors the document:
//!
//! | FIPS 203 section | Module |
//! |---|---|
//! | 2.3 / 4.3 arithmetic, NTT (Alg. 9-12) | [`field`], [`poly`] |
//! | 4.1 hash functions `H`, `J`, `G`, `PRF`, `XOF` | `hash` |
//! | 4.2.1 `ByteEncode`/`ByteDecode`, `Compress`/`Decompress` (Alg. 5-6) | `encode` |
//! | 4.2.2 `SampleNTT`, `SamplePolyCBD` (Alg. 7-8) | `sample` |
//! | 5 K-PKE (Alg. 13-15) | `kpke` |
//! | 6-7 ML-KEM internal + checked external API (Alg. 16-21) | this module |
//!
//! ```
//! use hybridkem::mlkem::{DecapsulationKey, MlKem768};
//!
//! let mut rng = rand::rng();
//! let dk = DecapsulationKey::<MlKem768>::generate(&mut rng);
//! let (ct, k_sender) = dk.encapsulation_key().encapsulate(&mut rng);
//! let k_receiver = dk.decapsulate(ct.as_bytes()).unwrap();
//! assert_eq!(k_sender, k_receiver);
//! ```

mod encode;
pub mod field;
mod hash;
mod kpke;
mod params;
pub mod poly;
mod sample;

pub use params::{MlKem1024, MlKem512, MlKem768, ParameterSet};

use crate::error::{check_len, Error, Result};
use crate::secret::SharedSecret;
use core::marker::PhantomData;
use rand_core::CryptoRng;
use subtle::{ConditionallySelectable, ConstantTimeEq};
use zeroize::{Zeroize, Zeroizing};

/// Size of every ML-KEM seed component (`d`, `z`, `m`) and of the shared secret.
pub const SEED_LEN: usize = 32;

/// A public ML-KEM encapsulation key that has passed the FIPS 203 input checks.
#[derive(Clone)]
pub struct EncapsulationKey<P: ParameterSet> {
    bytes: Vec<u8>,
    /// `H(ek)`, cached because both encapsulation and decapsulation need it.
    h: [u8; 32],
    pke: kpke::EncryptionKey,
    _params: PhantomData<P>,
}

impl<P: ParameterSet> core::fmt::Debug for EncapsulationKey<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "EncapsulationKey<{}>(H = {})",
            P::NAME,
            hex::encode(&self.h[..8])
        )
    }
}

impl<P: ParameterSet> PartialEq for EncapsulationKey<P> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl<P: ParameterSet> Eq for EncapsulationKey<P> {}

impl<P: ParameterSet> EncapsulationKey<P> {
    /// Parse and validate an encapsulation key (FIPS 203 Section 7.2 input checks):
    /// the *type check* (exact length) and the *modulus check* (every coefficient `< q`).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        check_len("encapsulation key", bytes, P::EK_LEN)?;
        if !encode::is_canonical_12(&bytes[..P::DK_PKE_LEN]) {
            return Err(Error::EncapsulationKeyNotCanonical);
        }
        Ok(Self::from_validated_bytes(bytes.to_vec()))
    }

    fn from_validated_bytes(bytes: Vec<u8>) -> Self {
        let pke = kpke::EncryptionKey::from_bytes::<P>(&bytes);
        let h = hash::h(&[&bytes]);
        Self {
            bytes,
            h,
            pke,
            _params: PhantomData,
        }
    }

    /// The serialized key (`ByteEncode12(t-hat) || rho`).
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// `H(ek)`, the 32-byte key fingerprint ML-KEM binds into every shared secret.
    pub fn hash(&self) -> &[u8; 32] {
        &self.h
    }

    /// `ML-KEM.Encaps` (Algorithm 20): draw `m` from `rng` and encapsulate.
    pub fn encapsulate<R: CryptoRng + ?Sized>(&self, rng: &mut R) -> (Ciphertext<P>, SharedSecret) {
        let mut m = Zeroizing::new([0u8; SEED_LEN]);
        rng.fill_bytes(m.as_mut());
        self.encapsulate_deterministic(&m)
    }

    /// `ML-KEM.Encaps_internal` (Algorithm 17) with caller-provided randomness `m`.
    ///
    /// Exposed for known-answer testing. Reusing `m` is catastrophic; use
    /// [`encapsulate`](Self::encapsulate) in real code.
    pub fn encapsulate_deterministic(&self, m: &[u8; SEED_LEN]) -> (Ciphertext<P>, SharedSecret) {
        let (k, r) = hash::g(&[m, &self.h]);
        let r = Zeroizing::new(r);
        let c = self.pke.encrypt::<P>(m, &r);
        (Ciphertext::new_unchecked(c), SharedSecret::from_bytes(k))
    }
}

/// A secret ML-KEM decapsulation key. All secret material is zeroized on drop.
#[derive(Clone)]
pub struct DecapsulationKey<P: ParameterSet> {
    dk_pke: kpke::DecryptionKey,
    ek: EncapsulationKey<P>,
    /// Implicit-rejection secret.
    z: [u8; 32],
    /// `d || z` when the key was generated from a seed (the compact storage format).
    seed: Option<[u8; 64]>,
}

impl<P: ParameterSet> Drop for DecapsulationKey<P> {
    fn drop(&mut self) {
        self.z.zeroize();
        if let Some(seed) = self.seed.as_mut() {
            seed.zeroize();
        }
    }
}

impl<P: ParameterSet> core::fmt::Debug for DecapsulationKey<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "DecapsulationKey<{}>(<redacted>, ek = {:?})",
            P::NAME,
            self.ek
        )
    }
}

impl<P: ParameterSet> DecapsulationKey<P> {
    /// `ML-KEM.KeyGen` (Algorithm 19): fresh `d`, `z` from `rng`.
    pub fn generate<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        let mut seed = Zeroizing::new([0u8; 64]);
        rng.fill_bytes(seed.as_mut());
        Self::from_seed(&seed)
    }

    /// Rebuild a key from its 64-byte seed `d || z` (the format FIPS 203 recommends storing).
    pub fn from_seed(seed: &[u8; 64]) -> Self {
        let mut d = Zeroizing::new([0u8; 32]);
        let mut z = Zeroizing::new([0u8; 32]);
        d.copy_from_slice(&seed[..32]);
        z.copy_from_slice(&seed[32..]);
        let mut key = Self::generate_deterministic(&d, &z);
        key.seed = Some(*seed);
        key
    }

    /// `ML-KEM.KeyGen_internal(d, z)` (Algorithm 16).
    pub fn generate_deterministic(d: &[u8; 32], z: &[u8; 32]) -> Self {
        let (ek_pke, dk_pke) = kpke::keygen::<P>(d);
        let ek = EncapsulationKey::from_validated_bytes(ek_pke.to_bytes::<P>());
        Self {
            dk_pke,
            ek,
            z: *z,
            seed: None,
        }
    }

    /// Parse the expanded `dk = dk_PKE || ek || H(ek) || z` form, applying the FIPS 203
    /// Section 7.3 checks: type check (length) and hash check (`H(ek) == h`).
    ///
    /// The embedded `ek` is additionally required to pass the modulus check, since a key
    /// that could never have been produced by `KeyGen` is better rejected early.
    pub fn from_bytes(dk: &[u8]) -> Result<Self> {
        check_len("decapsulation key", dk, P::DK_LEN)?;
        let (dk_pke, rest) = dk.split_at(P::DK_PKE_LEN);
        let (ek_bytes, rest) = rest.split_at(P::EK_LEN);
        let (h, z) = rest.split_at(32);
        let ek = EncapsulationKey::<P>::from_bytes(ek_bytes)?;
        if !bool::from(ek.h.ct_eq(h)) {
            return Err(Error::DecapsulationKeyHashMismatch);
        }
        let mut z_arr = [0u8; 32];
        z_arr.copy_from_slice(z);
        Ok(Self {
            dk_pke: kpke::DecryptionKey::from_bytes::<P>(dk_pke),
            ek,
            z: z_arr,
            seed: None,
        })
    }

    /// Serialize to the expanded `dk_PKE || ek || H(ek) || z` form (`768k + 96` bytes).
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(P::DK_LEN));
        out.extend_from_slice(&self.dk_pke.to_bytes::<P>());
        out.extend_from_slice(&self.ek.bytes);
        out.extend_from_slice(&self.ek.h);
        out.extend_from_slice(&self.z);
        out
    }

    /// The 64-byte seed, if this key was created from one.
    pub fn seed(&self) -> Option<&[u8; 64]> {
        self.seed.as_ref()
    }

    /// The matching public key.
    pub fn encapsulation_key(&self) -> &EncapsulationKey<P> {
        &self.ek
    }

    /// `ML-KEM.Decaps` (Algorithms 18 and 21).
    ///
    /// Only the ciphertext *length* can make this fail. A ciphertext of the right length that
    /// was not produced by honest encapsulation yields the implicit-rejection key
    /// `J(z || c)`; the choice between the two keys is made with `subtle` so that the
    /// comparison result never becomes a branch.
    pub fn decapsulate(&self, ct: &[u8]) -> Result<SharedSecret> {
        check_len("ciphertext", ct, P::CT_LEN)?;
        let m_prime = self.dk_pke.decrypt::<P>(ct);
        let (k_prime, r_prime) = hash::g(&[m_prime.as_ref(), &self.ek.h]);
        let (k_prime, r_prime) = (Zeroizing::new(k_prime), Zeroizing::new(r_prime));
        let mut k = Zeroizing::new(hash::j(&[&self.z, ct]));
        let c_prime = self.ek.pke.encrypt::<P>(&m_prime, &r_prime);
        let ciphertexts_match = ct.ct_eq(&c_prime[..]);
        k.conditional_assign(&k_prime, ciphertexts_match);
        Ok(SharedSecret::from_bytes(*k))
    }
}

/// An ML-KEM ciphertext of the correct length for `P`.
#[derive(Clone, PartialEq, Eq)]
pub struct Ciphertext<P: ParameterSet> {
    bytes: Vec<u8>,
    _params: PhantomData<P>,
}

impl<P: ParameterSet> core::fmt::Debug for Ciphertext<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Ciphertext<{}>({} bytes)", P::NAME, self.bytes.len())
    }
}

impl<P: ParameterSet> Ciphertext<P> {
    fn new_unchecked(bytes: Vec<u8>) -> Self {
        debug_assert_eq!(bytes.len(), P::CT_LEN);
        Self {
            bytes,
            _params: PhantomData,
        }
    }

    /// Wrap received bytes after checking the length.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        check_len("ciphertext", bytes, P::CT_LEN)?;
        Ok(Self::new_unchecked(bytes.to_vec()))
    }

    /// The raw ciphertext.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consume into the raw bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn kem_round_trip<P: ParameterSet>() {
        let mut rng = StdRng::seed_from_u64(7);
        for _ in 0..5 {
            let dk = DecapsulationKey::<P>::generate(&mut rng);
            let (ct, k1) = dk.encapsulation_key().encapsulate(&mut rng);
            assert_eq!(ct.as_bytes().len(), P::CT_LEN);
            let k2 = dk.decapsulate(ct.as_bytes()).unwrap();
            assert_eq!(k1, k2);
        }
    }

    #[test]
    fn round_trip_all_parameter_sets() {
        kem_round_trip::<MlKem512>();
        kem_round_trip::<MlKem768>();
        kem_round_trip::<MlKem1024>();
    }

    #[test]
    fn tampered_ciphertext_gives_implicit_rejection_key() {
        let dk = DecapsulationKey::<MlKem768>::generate_deterministic(&[1; 32], &[2; 32]);
        let (ct, k) = dk.encapsulation_key().encapsulate_deterministic(&[3; 32]);
        let mut bad = ct.into_bytes();
        bad[17] ^= 0x01;
        let k_bad = dk.decapsulate(&bad).unwrap();
        assert_ne!(k, k_bad);
        assert_eq!(k_bad.as_bytes(), &hash::j(&[&[2u8; 32], &bad]));
    }

    #[test]
    fn expanded_key_round_trip_and_hash_check() {
        let dk = DecapsulationKey::<MlKem512>::generate_deterministic(&[4; 32], &[5; 32]);
        let bytes = dk.to_bytes();
        assert_eq!(bytes.len(), MlKem512::DK_LEN);
        let dk2 = DecapsulationKey::<MlKem512>::from_bytes(&bytes).unwrap();
        assert_eq!(*dk2.to_bytes(), *bytes);
        assert!(dk2.seed().is_none());

        let mut corrupt = bytes.to_vec();
        let h_pos = MlKem512::DK_PKE_LEN + MlKem512::EK_LEN;
        corrupt[h_pos] ^= 0x80;
        assert!(matches!(
            DecapsulationKey::<MlKem512>::from_bytes(&corrupt),
            Err(Error::DecapsulationKeyHashMismatch)
        ));
        assert!(matches!(
            DecapsulationKey::<MlKem512>::from_bytes(&corrupt[1..]),
            Err(Error::InvalidLength { .. })
        ));
    }

    #[test]
    fn seed_round_trip() {
        let seed = [9u8; 64];
        let dk = DecapsulationKey::<MlKem1024>::from_seed(&seed);
        assert_eq!(dk.seed(), Some(&seed));
        let again = DecapsulationKey::<MlKem1024>::from_seed(&seed);
        assert_eq!(dk.encapsulation_key(), again.encapsulation_key());
    }

    #[test]
    fn modulus_check_rejects_non_canonical_keys() {
        let dk = DecapsulationKey::<MlKem768>::generate_deterministic(&[6; 32], &[7; 32]);
        let mut ek = dk.encapsulation_key().as_bytes().to_vec();
        assert!(EncapsulationKey::<MlKem768>::from_bytes(&ek).is_ok());
        ek[0] = 0xFF;
        ek[1] |= 0x0F; // first coefficient = 4095 >= q
        assert!(matches!(
            EncapsulationKey::<MlKem768>::from_bytes(&ek),
            Err(Error::EncapsulationKeyNotCanonical)
        ));
        assert!(matches!(
            EncapsulationKey::<MlKem768>::from_bytes(&ek[..100]),
            Err(Error::InvalidLength { .. })
        ));
    }

    #[test]
    fn wrong_length_ciphertext_is_an_error() {
        let dk = DecapsulationKey::<MlKem512>::generate_deterministic(&[0; 32], &[0; 32]);
        assert!(dk.decapsulate(&[0u8; 10]).is_err());
        assert!(Ciphertext::<MlKem512>::from_bytes(&[0u8; 10]).is_err());
        assert!(Ciphertext::<MlKem512>::from_bytes(&[0u8; 768]).is_ok());
    }

    #[test]
    fn debug_output_redacts_secrets() {
        let dk = DecapsulationKey::<MlKem512>::generate_deterministic(&[0; 32], &[0; 32]);
        let s = format!("{dk:?}");
        assert!(s.contains("redacted") && s.contains("ML-KEM-512"));
        let (ct, _) = dk.encapsulation_key().encapsulate_deterministic(&[0; 32]);
        assert_eq!(format!("{ct:?}"), "Ciphertext<ML-KEM-512>(768 bytes)");
        assert_eq!(dk.encapsulation_key().hash().len(), 32);
    }
}
