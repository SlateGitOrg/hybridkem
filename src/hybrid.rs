//! X25519 + ML-KEM hybrid KEMs.
//!
//! A hybrid KEM runs a classical and a post-quantum KEM side by side and hashes both shared
//! secrets together, so the result stays secret as long as *either* component is unbroken.
//! The interesting design question is what else goes into that hash; this module offers two
//! answers as [`Combiner`] implementations:
//!
//! * [`XWingCombiner`] — X-Wing (draft-connolly-cfrg-xwing-kem-06): `SHA3-256(ss_M || ss_X ||
//!   ct_X || pk_X || label)`. It omits the ML-KEM ciphertext and key, relying on ML-KEM's
//!   ciphertext-binding (C2PRI) property proven in the X-Wing paper. Only defined for
//!   ML-KEM-768, and byte-compatible with the draft's test vectors.
//! * [`TranscriptCombiner`] — a conservative "hash everything" combiner usable with every
//!   parameter set: it also binds `H(ct_M)` and `H(ek_M)` and a label naming the parameter
//!   set, so its security argument needs nothing beyond each component being a secure KEM.
//!   Costs one extra SHA3-256 over the ML-KEM ciphertext.
//!
//! Keys use the X-Wing layout: the secret key is a 32-byte seed expanded with SHAKE256 into
//! the ML-KEM seed `d || z` and the X25519 scalar; the public key is `ek_M || pk_X` and the
//! ciphertext `ct_M || ct_X`.

use crate::error::{check_len, Error, Result};
use crate::mlkem::{
    DecapsulationKey, EncapsulationKey, MlKem1024, MlKem512, MlKem768, ParameterSet,
};
use crate::secret::SharedSecret;
use core::marker::PhantomData;
use rand_core::CryptoRng;
use sha3::{Digest, Sha3_256};
use shake::{ExtendableOutput, Shake256, Update, XofReader};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

/// Size of a hybrid secret-key seed.
pub const SEED_LEN: usize = 32;
/// Size of the encapsulation randomness (`m` for ML-KEM || ephemeral X25519 scalar).
pub const ESEED_LEN: usize = 64;
/// X25519 public key / ciphertext size.
pub const X25519_LEN: usize = 32;

/// Everything a combiner may hash.
pub struct CombinerInput<'a> {
    /// ML-KEM shared secret.
    pub ss_m: &'a [u8; 32],
    /// X25519 shared secret.
    pub ss_x: &'a [u8; 32],
    /// ML-KEM ciphertext.
    pub ct_m: &'a [u8],
    /// X25519 "ciphertext" (the ephemeral public key).
    pub ct_x: &'a [u8; 32],
    /// `H(ek_M)` (SHA3-256 of the ML-KEM encapsulation key).
    pub ek_m_hash: &'a [u8; 32],
    /// Recipient's X25519 public key.
    pub pk_x: &'a [u8; 32],
}

/// A rule for deriving the hybrid shared secret from the component outputs.
pub trait Combiner: Copy + Default + core::fmt::Debug + Send + Sync + 'static {
    /// Short name used in algorithm identifiers.
    const NAME: &'static str;
    /// Whether an all-zero X25519 output (low-order peer point) aborts the operation.
    const REJECT_NON_CONTRIBUTORY: bool;
    /// Derive the 32-byte shared secret for parameter set `P`.
    fn combine<P: ParameterSet>(input: &CombinerInput<'_>) -> [u8; 32];
}

/// The X-Wing combiner (draft-connolly-cfrg-xwing-kem-06, Section 5.3).
#[derive(Clone, Copy, Debug, Default)]
pub struct XWingCombiner;

/// `XWingLabel`: the six ASCII bytes `\.//^\`.
pub const XWING_LABEL: &[u8; 6] = b"\\.//^\\";

impl Combiner for XWingCombiner {
    const NAME: &'static str = "X-Wing";
    // Draft-06 is silent on the X25519 zero check and its reference vectors accept it; the
    // RustCrypto `x-wing` crate's default key does the same, so we match for compatibility.
    const REJECT_NON_CONTRIBUTORY: bool = false;

    fn combine<P: ParameterSet>(input: &CombinerInput<'_>) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        Digest::update(&mut hasher, input.ss_m);
        Digest::update(&mut hasher, input.ss_x);
        Digest::update(&mut hasher, input.ct_x);
        Digest::update(&mut hasher, input.pk_x);
        Digest::update(&mut hasher, XWING_LABEL);
        hasher.finalize().into()
    }
}

/// A conservative combiner that binds the full transcript (see module docs).
#[derive(Clone, Copy, Debug, Default)]
pub struct TranscriptCombiner;

impl Combiner for TranscriptCombiner {
    const NAME: &'static str = "transcript";
    const REJECT_NON_CONTRIBUTORY: bool = true;

    fn combine<P: ParameterSet>(input: &CombinerInput<'_>) -> [u8; 32] {
        let label = transcript_label::<P>();
        let ct_m_hash: [u8; 32] = Sha3_256::digest(input.ct_m).into();
        let mut hasher = Sha3_256::new();
        // Length-prefixed label, then fixed-size fields: the encoding is injective.
        Digest::update(&mut hasher, [label.len() as u8]);
        Digest::update(&mut hasher, label.as_bytes());
        Digest::update(&mut hasher, input.ss_m);
        Digest::update(&mut hasher, input.ss_x);
        Digest::update(&mut hasher, ct_m_hash);
        Digest::update(&mut hasher, input.ct_x);
        Digest::update(&mut hasher, input.ek_m_hash);
        Digest::update(&mut hasher, input.pk_x);
        hasher.finalize().into()
    }
}

fn transcript_label<P: ParameterSet>() -> String {
    format!("hybridkem/X25519+{}/v1", P::NAME)
}

/// A hybrid of X25519 and ML-KEM parameter set `P`, combined with `C`.
#[derive(Clone, Copy, Debug, Default)]
pub struct HybridKem<P: ParameterSet, C: Combiner>(PhantomData<(P, C)>);

/// X-Wing: X25519 + ML-KEM-768 with the X-Wing combiner.
pub type XWing = HybridKem<MlKem768, XWingCombiner>;
/// X25519 + ML-KEM-512 with the transcript combiner.
pub type X25519MlKem512 = HybridKem<MlKem512, TranscriptCombiner>;
/// X25519 + ML-KEM-768 with the transcript combiner.
pub type X25519MlKem768 = HybridKem<MlKem768, TranscriptCombiner>;
/// X25519 + ML-KEM-1024 with the transcript combiner.
pub type X25519MlKem1024 = HybridKem<MlKem1024, TranscriptCombiner>;

impl<P: ParameterSet, C: Combiner> HybridKem<P, C> {
    /// Public key size: `|ek_M| + 32`.
    pub const PUBLIC_KEY_LEN: usize = P::EK_LEN + X25519_LEN;
    /// Ciphertext size: `|ct_M| + 32`.
    pub const CIPHERTEXT_LEN: usize = P::CT_LEN + X25519_LEN;

    /// Algorithm name, e.g. `"X-Wing(ML-KEM-768)"`.
    pub fn name() -> String {
        format!("{}(X25519+{})", C::NAME, P::NAME)
    }
}

/// The public half of a hybrid key: `ek_M || pk_X`.
#[derive(Clone)]
pub struct HybridEncapsulationKey<P: ParameterSet, C: Combiner> {
    ek_m: EncapsulationKey<P>,
    pk_x: PublicKey,
    bytes: Vec<u8>,
    _combiner: PhantomData<C>,
}

impl<P: ParameterSet, C: Combiner> PartialEq for HybridEncapsulationKey<P, C> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl<P: ParameterSet, C: Combiner> Eq for HybridEncapsulationKey<P, C> {}

impl<P: ParameterSet, C: Combiner> core::fmt::Debug for HybridEncapsulationKey<P, C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "HybridEncapsulationKey<{}>({:?})",
            HybridKem::<P, C>::name(),
            self.ek_m
        )
    }
}

impl<P: ParameterSet, C: Combiner> HybridEncapsulationKey<P, C> {
    fn new(ek_m: EncapsulationKey<P>, pk_x: PublicKey) -> Self {
        let mut bytes = Vec::with_capacity(HybridKem::<P, C>::PUBLIC_KEY_LEN);
        bytes.extend_from_slice(ek_m.as_bytes());
        bytes.extend_from_slice(pk_x.as_bytes());
        Self {
            ek_m,
            pk_x,
            bytes,
            _combiner: PhantomData,
        }
    }

    /// Parse `ek_M || pk_X`, running the ML-KEM input checks on `ek_M`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        check_len(
            "hybrid public key",
            bytes,
            HybridKem::<P, C>::PUBLIC_KEY_LEN,
        )?;
        let (ek_bytes, pk_bytes) = bytes.split_at(P::EK_LEN);
        let ek_m = EncapsulationKey::<P>::from_bytes(ek_bytes)?;
        let mut pk = [0u8; 32];
        pk.copy_from_slice(pk_bytes);
        Ok(Self::new(ek_m, PublicKey::from(pk)))
    }

    /// The serialized public key.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Encapsulate with fresh randomness. Returns `(ct_M || ct_X, shared secret)`.
    pub fn encapsulate<R: CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
    ) -> Result<(Vec<u8>, SharedSecret)> {
        let mut eseed = Zeroizing::new([0u8; ESEED_LEN]);
        rng.fill_bytes(eseed.as_mut());
        self.encapsulate_deterministic(&eseed)
    }

    /// Encapsulate with caller-provided randomness `eseed = m || ek_X` (for test vectors).
    pub fn encapsulate_deterministic(
        &self,
        eseed: &[u8; ESEED_LEN],
    ) -> Result<(Vec<u8>, SharedSecret)> {
        let mut m = Zeroizing::new([0u8; 32]);
        m.copy_from_slice(&eseed[..32]);
        let mut ek_x_bytes = [0u8; 32];
        ek_x_bytes.copy_from_slice(&eseed[32..]);
        let ek_x = StaticSecret::from(ek_x_bytes);
        ek_x_bytes.zeroize();

        let (ct_m, ss_m) = self.ek_m.encapsulate_deterministic(&m);
        let ct_x = PublicKey::from(&ek_x);
        let ss_x = ek_x.diffie_hellman(&self.pk_x);
        if C::REJECT_NON_CONTRIBUTORY && !ss_x.was_contributory() {
            return Err(Error::NonContributory);
        }
        let ss = C::combine::<P>(&CombinerInput {
            ss_m: ss_m.as_bytes(),
            ss_x: ss_x.as_bytes(),
            ct_m: ct_m.as_bytes(),
            ct_x: ct_x.as_bytes(),
            ek_m_hash: self.ek_m.hash(),
            pk_x: self.pk_x.as_bytes(),
        });
        let mut ct = ct_m.into_bytes();
        ct.extend_from_slice(ct_x.as_bytes());
        Ok((ct, SharedSecret::from_bytes(ss)))
    }
}

/// The secret half of a hybrid key, stored as its 32-byte seed and expanded on load.
#[derive(Clone)]
pub struct HybridDecapsulationKey<P: ParameterSet, C: Combiner> {
    seed: Zeroizing<[u8; SEED_LEN]>,
    dk_m: DecapsulationKey<P>,
    sk_x: StaticSecret,
    ek: HybridEncapsulationKey<P, C>,
}

impl<P: ParameterSet, C: Combiner> core::fmt::Debug for HybridDecapsulationKey<P, C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "HybridDecapsulationKey<{}>(<redacted>)",
            HybridKem::<P, C>::name()
        )
    }
}

impl<P: ParameterSet, C: Combiner> HybridDecapsulationKey<P, C> {
    /// Generate a fresh key from `rng`.
    pub fn generate<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        let mut seed = Zeroizing::new([0u8; SEED_LEN]);
        rng.fill_bytes(seed.as_mut());
        Self::from_seed(&seed)
    }

    /// Deterministically expand a 32-byte seed: `SHAKE256(seed, 96) = d || z || sk_X`.
    pub fn from_seed(seed: &[u8; SEED_LEN]) -> Self {
        let mut xof = Shake256::default();
        xof.update(seed);
        let mut reader = xof.finalize_xof();
        let mut mlkem_seed = Zeroizing::new([0u8; 64]);
        let mut sk_x_bytes = Zeroizing::new([0u8; 32]);
        reader.read(mlkem_seed.as_mut());
        reader.read(sk_x_bytes.as_mut());
        let dk_m = DecapsulationKey::<P>::from_seed(&mlkem_seed);
        let sk_x = StaticSecret::from(*sk_x_bytes);
        let pk_x = PublicKey::from(&sk_x);
        let ek = HybridEncapsulationKey::new(dk_m.encapsulation_key().clone(), pk_x);
        Self {
            seed: Zeroizing::new(*seed),
            dk_m,
            sk_x,
            ek,
        }
    }

    /// The 32-byte seed (the serialized secret key).
    pub fn seed(&self) -> &[u8; SEED_LEN] {
        &self.seed
    }

    /// The matching public key.
    pub fn encapsulation_key(&self) -> &HybridEncapsulationKey<P, C> {
        &self.ek
    }

    /// Recover the shared secret from `ct_M || ct_X`.
    ///
    /// Fails only on a wrong length or (for combiners that reject it) a low-order `ct_X`.
    /// A forged ML-KEM half yields an unrelated key via implicit rejection.
    pub fn decapsulate(&self, ct: &[u8]) -> Result<SharedSecret> {
        check_len("hybrid ciphertext", ct, HybridKem::<P, C>::CIPHERTEXT_LEN)?;
        let (ct_m, ct_x_bytes) = ct.split_at(P::CT_LEN);
        let ss_m = self.dk_m.decapsulate(ct_m)?;
        let mut ct_x = [0u8; 32];
        ct_x.copy_from_slice(ct_x_bytes);
        let ss_x = self.sk_x.diffie_hellman(&PublicKey::from(ct_x));
        if C::REJECT_NON_CONTRIBUTORY && !ss_x.was_contributory() {
            return Err(Error::NonContributory);
        }
        let ss = C::combine::<P>(&CombinerInput {
            ss_m: ss_m.as_bytes(),
            ss_x: ss_x.as_bytes(),
            ct_m,
            ct_x: &ct_x,
            ek_m_hash: self.ek.ek_m.hash(),
            pk_x: self.ek.pk_x.as_bytes(),
        });
        Ok(SharedSecret::from_bytes(ss))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn round_trip<P: ParameterSet, C: Combiner>() {
        let mut rng = StdRng::seed_from_u64(11);
        let dk = HybridDecapsulationKey::<P, C>::generate(&mut rng);
        let ek = dk.encapsulation_key();
        assert_eq!(ek.as_bytes().len(), HybridKem::<P, C>::PUBLIC_KEY_LEN);
        let (ct, ss) = ek.encapsulate(&mut rng).unwrap();
        assert_eq!(ct.len(), HybridKem::<P, C>::CIPHERTEXT_LEN);
        assert_eq!(dk.decapsulate(&ct).unwrap(), ss);
        let parsed = HybridEncapsulationKey::<P, C>::from_bytes(ek.as_bytes()).unwrap();
        assert_eq!(&parsed, ek);
    }

    #[test]
    fn round_trips() {
        round_trip::<MlKem768, XWingCombiner>();
        round_trip::<MlKem512, TranscriptCombiner>();
        round_trip::<MlKem768, TranscriptCombiner>();
        round_trip::<MlKem1024, TranscriptCombiner>();
    }

    #[test]
    fn combiners_disagree_so_keys_are_domain_separated() {
        let seed = [3u8; 32];
        let eseed = [4u8; 64];
        let a = HybridDecapsulationKey::<MlKem768, XWingCombiner>::from_seed(&seed);
        let b = HybridDecapsulationKey::<MlKem768, TranscriptCombiner>::from_seed(&seed);
        let (ct_a, ss_a) = a
            .encapsulation_key()
            .encapsulate_deterministic(&eseed)
            .unwrap();
        let (ct_b, ss_b) = b
            .encapsulation_key()
            .encapsulate_deterministic(&eseed)
            .unwrap();
        assert_eq!(ct_a, ct_b, "same components, same ciphertext");
        assert_ne!(
            ss_a, ss_b,
            "different combiners must give different secrets"
        );
    }

    #[test]
    fn tampering_either_half_changes_the_secret() {
        let dk = X25519MlKem768::name();
        assert_eq!(dk, "transcript(X25519+ML-KEM-768)");
        let dk = HybridDecapsulationKey::<MlKem768, TranscriptCombiner>::from_seed(&[1; 32]);
        let (ct, ss) = dk
            .encapsulation_key()
            .encapsulate_deterministic(&[2; 64])
            .unwrap();
        let mut bad_m = ct.clone();
        bad_m[0] ^= 1;
        assert_ne!(dk.decapsulate(&bad_m).unwrap(), ss);
        let mut bad_x = ct.clone();
        let last = bad_x.len() - 1;
        bad_x[last] ^= 0x40;
        assert_ne!(dk.decapsulate(&bad_x).unwrap(), ss);
        assert!(dk.decapsulate(&ct[1..]).is_err());
    }

    #[test]
    fn low_order_points_are_rejected_by_transcript_combiner_only() {
        // The all-zero u-coordinate is a low-order point: X25519 with it is all-zero.
        let zero_point = [0u8; 32];
        let t = HybridDecapsulationKey::<MlKem512, TranscriptCombiner>::from_seed(&[5; 32]);
        let (mut ct, _) = t
            .encapsulation_key()
            .encapsulate_deterministic(&[6; 64])
            .unwrap();
        let n = ct.len();
        ct[n - 32..].copy_from_slice(&zero_point);
        assert!(matches!(t.decapsulate(&ct), Err(Error::NonContributory)));

        let mut pk = t.encapsulation_key().as_bytes().to_vec();
        let n = pk.len();
        pk[n - 32..].copy_from_slice(&zero_point);
        let bad_ek =
            HybridEncapsulationKey::<MlKem512, TranscriptCombiner>::from_bytes(&pk).unwrap();
        assert!(matches!(
            bad_ek.encapsulate_deterministic(&[7; 64]),
            Err(Error::NonContributory)
        ));

        let x = HybridDecapsulationKey::<MlKem768, XWingCombiner>::from_seed(&[5; 32]);
        let (mut ct, _) = x
            .encapsulation_key()
            .encapsulate_deterministic(&[6; 64])
            .unwrap();
        let n = ct.len();
        ct[n - 32..].copy_from_slice(&zero_point);
        assert!(x.decapsulate(&ct).is_ok());
    }

    #[test]
    fn seed_and_debug() {
        let dk = HybridDecapsulationKey::<MlKem768, XWingCombiner>::from_seed(&[8; 32]);
        assert_eq!(dk.seed(), &[8; 32]);
        assert!(format!("{dk:?}").contains("redacted"));
        assert!(format!("{:?}", dk.encapsulation_key()).contains("X-Wing"));
        assert!(HybridEncapsulationKey::<MlKem768, XWingCombiner>::from_bytes(&[0; 3]).is_err());
    }
}
