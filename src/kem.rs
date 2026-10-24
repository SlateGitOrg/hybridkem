//! A byte-oriented KEM abstraction shared by ML-KEM, the hybrids and a classical baseline,
//! plus [`Algorithm`] for choosing one at runtime (CLI, benchmarks, demos).

use crate::error::{check_len, Error, Result};
use crate::hybrid::{Combiner, HybridDecapsulationKey, HybridEncapsulationKey, HybridKem};
use crate::mlkem::{DecapsulationKey, EncapsulationKey, ParameterSet};
use crate::secret::SharedSecret;
use rand_core::CryptoRng;
use sha3::{Digest, Sha3_256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// A key-encapsulation mechanism with byte-string keys and ciphertexts.
///
/// This is the interface the Noise engine is generic over. Secret keys are an associated
/// type so each scheme keeps its own zeroizing representation; everything public is bytes.
pub trait Kem: Send + Sync + 'static {
    /// The secret (decapsulation) key.
    type SecretKey: Clone + Send + Sync;
    /// Encoded public-key length.
    const PUBLIC_KEY_LEN: usize;
    /// Ciphertext length.
    const CIPHERTEXT_LEN: usize;
    /// Algorithm identifier, also used inside Noise protocol names.
    fn name() -> String;
    /// Generate a key pair.
    fn generate<R: CryptoRng + ?Sized>(rng: &mut R) -> (Self::SecretKey, Vec<u8>);
    /// The public key belonging to `sk`.
    fn public_key(sk: &Self::SecretKey) -> Vec<u8>;
    /// Encapsulate to the encoded public key `pk`.
    fn encapsulate<R: CryptoRng + ?Sized>(
        pk: &[u8],
        rng: &mut R,
    ) -> Result<(Vec<u8>, SharedSecret)>;
    /// Decapsulate `ct` with `sk`.
    fn decapsulate(sk: &Self::SecretKey, ct: &[u8]) -> Result<SharedSecret>;
    /// Serialize the secret key in its compact (seed) form.
    fn secret_key_to_bytes(sk: &Self::SecretKey) -> Zeroizing<Vec<u8>>;
    /// Parse a secret key produced by [`Kem::secret_key_to_bytes`].
    fn secret_key_from_bytes(bytes: &[u8]) -> Result<Self::SecretKey>;
}

impl<P: ParameterSet> Kem for P {
    type SecretKey = DecapsulationKey<P>;
    const PUBLIC_KEY_LEN: usize = P::EK_LEN;
    const CIPHERTEXT_LEN: usize = P::CT_LEN;

    fn name() -> String {
        P::NAME.to_string()
    }

    fn generate<R: CryptoRng + ?Sized>(rng: &mut R) -> (Self::SecretKey, Vec<u8>) {
        let dk = DecapsulationKey::<P>::generate(rng);
        let pk = dk.encapsulation_key().as_bytes().to_vec();
        (dk, pk)
    }

    fn public_key(sk: &Self::SecretKey) -> Vec<u8> {
        sk.encapsulation_key().as_bytes().to_vec()
    }

    fn encapsulate<R: CryptoRng + ?Sized>(
        pk: &[u8],
        rng: &mut R,
    ) -> Result<(Vec<u8>, SharedSecret)> {
        let ek = EncapsulationKey::<P>::from_bytes(pk)?;
        let (ct, ss) = ek.encapsulate(rng);
        Ok((ct.into_bytes(), ss))
    }

    fn decapsulate(sk: &Self::SecretKey, ct: &[u8]) -> Result<SharedSecret> {
        sk.decapsulate(ct)
    }

    fn secret_key_to_bytes(sk: &Self::SecretKey) -> Zeroizing<Vec<u8>> {
        match sk.seed() {
            Some(seed) => Zeroizing::new(seed.to_vec()),
            None => sk.to_bytes(),
        }
    }

    fn secret_key_from_bytes(bytes: &[u8]) -> Result<Self::SecretKey> {
        if bytes.len() == 64 {
            let mut seed = Zeroizing::new([0u8; 64]);
            seed.copy_from_slice(bytes);
            Ok(DecapsulationKey::<P>::from_seed(&seed))
        } else {
            DecapsulationKey::<P>::from_bytes(bytes)
        }
    }
}

impl<P: ParameterSet, C: Combiner> Kem for HybridKem<P, C> {
    type SecretKey = HybridDecapsulationKey<P, C>;
    const PUBLIC_KEY_LEN: usize = HybridKem::<P, C>::PUBLIC_KEY_LEN;
    const CIPHERTEXT_LEN: usize = HybridKem::<P, C>::CIPHERTEXT_LEN;

    fn name() -> String {
        HybridKem::<P, C>::name()
    }

    fn generate<R: CryptoRng + ?Sized>(rng: &mut R) -> (Self::SecretKey, Vec<u8>) {
        let dk = HybridDecapsulationKey::<P, C>::generate(rng);
        let pk = dk.encapsulation_key().as_bytes().to_vec();
        (dk, pk)
    }

    fn public_key(sk: &Self::SecretKey) -> Vec<u8> {
        sk.encapsulation_key().as_bytes().to_vec()
    }

    fn encapsulate<R: CryptoRng + ?Sized>(
        pk: &[u8],
        rng: &mut R,
    ) -> Result<(Vec<u8>, SharedSecret)> {
        HybridEncapsulationKey::<P, C>::from_bytes(pk)?.encapsulate(rng)
    }

    fn decapsulate(sk: &Self::SecretKey, ct: &[u8]) -> Result<SharedSecret> {
        sk.decapsulate(ct)
    }

    fn secret_key_to_bytes(sk: &Self::SecretKey) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(sk.seed().to_vec())
    }

    fn secret_key_from_bytes(bytes: &[u8]) -> Result<Self::SecretKey> {
        check_len("hybrid secret key", bytes, crate::hybrid::SEED_LEN)?;
        let mut seed = Zeroizing::new([0u8; 32]);
        seed.copy_from_slice(bytes);
        Ok(HybridDecapsulationKey::<P, C>::from_seed(&seed))
    }
}

/// Classical-only baseline: X25519 used as a KEM (ephemeral-static DH, `ct` = ephemeral
/// public key, `ss = SHA3-256(label || dh || ct || pk)`). Not post-quantum; present so the
/// demo and benchmarks can show what the hybrid costs relative to today's handshakes.
#[derive(Clone, Copy, Debug, Default)]
pub struct X25519Kem;

const X25519_KEM_LABEL: &[u8] = b"hybridkem/X25519-KEM/v1";

fn x25519_kem_secret(dh: &[u8; 32], ct: &[u8; 32], pk: &[u8; 32]) -> SharedSecret {
    let mut hasher = Sha3_256::new();
    hasher.update(X25519_KEM_LABEL);
    hasher.update(dh);
    hasher.update(ct);
    hasher.update(pk);
    SharedSecret::from_bytes(hasher.finalize().into())
}

fn x25519_public(bytes: &[u8]) -> Result<PublicKey> {
    check_len("X25519 public key", bytes, 32)?;
    let mut pk = [0u8; 32];
    pk.copy_from_slice(bytes);
    Ok(PublicKey::from(pk))
}

impl Kem for X25519Kem {
    type SecretKey = StaticSecret;
    const PUBLIC_KEY_LEN: usize = 32;
    const CIPHERTEXT_LEN: usize = 32;

    fn name() -> String {
        "X25519".to_string()
    }

    fn generate<R: CryptoRng + ?Sized>(rng: &mut R) -> (Self::SecretKey, Vec<u8>) {
        let sk = StaticSecret::random_from_rng(rng);
        let pk = PublicKey::from(&sk).as_bytes().to_vec();
        (sk, pk)
    }

    fn public_key(sk: &Self::SecretKey) -> Vec<u8> {
        PublicKey::from(sk).as_bytes().to_vec()
    }

    fn encapsulate<R: CryptoRng + ?Sized>(
        pk: &[u8],
        rng: &mut R,
    ) -> Result<(Vec<u8>, SharedSecret)> {
        let pk = x25519_public(pk)?;
        let eph = StaticSecret::random_from_rng(rng);
        let ct = PublicKey::from(&eph);
        let dh = eph.diffie_hellman(&pk);
        if !dh.was_contributory() {
            return Err(Error::NonContributory);
        }
        let ss = x25519_kem_secret(dh.as_bytes(), ct.as_bytes(), pk.as_bytes());
        Ok((ct.as_bytes().to_vec(), ss))
    }

    fn decapsulate(sk: &Self::SecretKey, ct: &[u8]) -> Result<SharedSecret> {
        let ct = x25519_public(ct)?;
        let dh = sk.diffie_hellman(&ct);
        if !dh.was_contributory() {
            return Err(Error::NonContributory);
        }
        let pk = PublicKey::from(sk);
        Ok(x25519_kem_secret(
            dh.as_bytes(),
            ct.as_bytes(),
            pk.as_bytes(),
        ))
    }

    fn secret_key_to_bytes(sk: &Self::SecretKey) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(sk.to_bytes().to_vec())
    }

    fn secret_key_from_bytes(bytes: &[u8]) -> Result<Self::SecretKey> {
        check_len("X25519 secret key", bytes, 32)?;
        let mut sk = Zeroizing::new([0u8; 32]);
        sk.copy_from_slice(bytes);
        Ok(StaticSecret::from(*sk))
    }
}

/// Every KEM in the crate, selectable at runtime.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Algorithm {
    /// ML-KEM-512.
    MlKem512,
    /// ML-KEM-768.
    MlKem768,
    /// ML-KEM-1024.
    MlKem1024,
    /// Classical X25519 baseline.
    X25519,
    /// X-Wing (X25519 + ML-KEM-768, draft-06 combiner).
    XWing,
    /// X25519 + ML-KEM-512, transcript combiner.
    X25519MlKem512,
    /// X25519 + ML-KEM-768, transcript combiner.
    X25519MlKem768,
    /// X25519 + ML-KEM-1024, transcript combiner.
    X25519MlKem1024,
}

/// Expand `$body` with `$k` bound to the concrete [`Kem`] type for `$alg`.
#[macro_export]
macro_rules! with_kem {
    ($alg:expr, $k:ident => $body:expr) => {{
        use $crate::kem::Algorithm as A;
        match $alg {
            A::MlKem512 => {
                type $k = $crate::mlkem::MlKem512;
                $body
            }
            A::MlKem768 => {
                type $k = $crate::mlkem::MlKem768;
                $body
            }
            A::MlKem1024 => {
                type $k = $crate::mlkem::MlKem1024;
                $body
            }
            A::X25519 => {
                type $k = $crate::kem::X25519Kem;
                $body
            }
            A::XWing => {
                type $k = $crate::hybrid::XWing;
                $body
            }
            A::X25519MlKem512 => {
                type $k = $crate::hybrid::X25519MlKem512;
                $body
            }
            A::X25519MlKem768 => {
                type $k = $crate::hybrid::X25519MlKem768;
                $body
            }
            A::X25519MlKem1024 => {
                type $k = $crate::hybrid::X25519MlKem1024;
                $body
            }
        }
    }};
}

impl Algorithm {
    /// All algorithms, in display order.
    pub const ALL: [Algorithm; 8] = [
        Algorithm::MlKem512,
        Algorithm::MlKem768,
        Algorithm::MlKem1024,
        Algorithm::X25519,
        Algorithm::XWing,
        Algorithm::X25519MlKem512,
        Algorithm::X25519MlKem768,
        Algorithm::X25519MlKem1024,
    ];

    /// Command-line identifier, e.g. `"mlkem768"` or `"xwing"`.
    pub fn id(self) -> &'static str {
        match self {
            Algorithm::MlKem512 => "mlkem512",
            Algorithm::MlKem768 => "mlkem768",
            Algorithm::MlKem1024 => "mlkem1024",
            Algorithm::X25519 => "x25519",
            Algorithm::XWing => "xwing",
            Algorithm::X25519MlKem512 => "x25519-mlkem512",
            Algorithm::X25519MlKem768 => "x25519-mlkem768",
            Algorithm::X25519MlKem1024 => "x25519-mlkem1024",
        }
    }

    /// Descriptive name from the underlying [`Kem`].
    pub fn name(self) -> String {
        with_kem!(self, K => K::name())
    }

    /// `(public key, ciphertext)` sizes in bytes.
    pub fn sizes(self) -> (usize, usize) {
        with_kem!(self, K => (K::PUBLIC_KEY_LEN, K::CIPHERTEXT_LEN))
    }

    /// Whether the algorithm resists a quantum adversary (contains ML-KEM).
    pub fn is_post_quantum(self) -> bool {
        self != Algorithm::X25519
    }

    /// Generate a key pair, returning `(secret key bytes, public key bytes)`.
    pub fn generate<R: CryptoRng + ?Sized>(self, rng: &mut R) -> (Zeroizing<Vec<u8>>, Vec<u8>) {
        with_kem!(self, K => {
            let (sk, pk) = K::generate(rng);
            (K::secret_key_to_bytes(&sk), pk)
        })
    }

    /// Encapsulate to `pk`.
    pub fn encapsulate<R: CryptoRng + ?Sized>(
        self,
        pk: &[u8],
        rng: &mut R,
    ) -> Result<(Vec<u8>, SharedSecret)> {
        with_kem!(self, K => K::encapsulate(pk, rng))
    }

    /// Decapsulate `ct` with the serialized secret key `sk`.
    pub fn decapsulate(self, sk: &[u8], ct: &[u8]) -> Result<SharedSecret> {
        with_kem!(self, K => {
            let sk = K::secret_key_from_bytes(sk)?;
            K::decapsulate(&sk, ct)
        })
    }
}

impl core::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.id())
    }
}

impl core::str::FromStr for Algorithm {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let wanted = s.to_ascii_lowercase().replace(['_', ' '], "-");
        Algorithm::ALL
            .into_iter()
            .find(|a| a.id() == wanted || a.id().replace('-', "") == wanted.replace('-', ""))
            .ok_or_else(|| {
                let ids: Vec<&str> = Algorithm::ALL.iter().map(|a| a.id()).collect();
                Error::Parse(format!(
                    "unknown algorithm {s:?}; expected one of {}",
                    ids.join(", ")
                ))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mlkem::MlKem512;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn every_algorithm_round_trips_through_bytes() {
        let mut rng = StdRng::seed_from_u64(3);
        for alg in Algorithm::ALL {
            let (sk, pk) = alg.generate(&mut rng);
            let (pk_len, ct_len) = alg.sizes();
            assert_eq!(pk.len(), pk_len, "{alg}");
            let (ct, ss) = alg.encapsulate(&pk, &mut rng).unwrap();
            assert_eq!(ct.len(), ct_len, "{alg}");
            assert_eq!(alg.decapsulate(&sk, &ct).unwrap(), ss, "{alg}");
            assert_eq!(alg.to_string().parse::<Algorithm>().unwrap(), alg);
            assert!(!alg.name().is_empty());
            assert_eq!(alg.is_post_quantum(), alg != Algorithm::X25519);
        }
    }

    #[test]
    fn parsing_is_forgiving_but_strict_about_unknown_names() {
        assert_eq!(
            "ML-KEM-768".parse::<Algorithm>().unwrap(),
            Algorithm::MlKem768
        );
        assert_eq!(
            "x25519_mlkem1024".parse::<Algorithm>().unwrap(),
            Algorithm::X25519MlKem1024
        );
        assert_eq!("XWing".parse::<Algorithm>().unwrap(), Algorithm::XWing);
        let err = "rsa".parse::<Algorithm>().unwrap_err();
        assert!(err.to_string().contains("mlkem768"));
    }

    #[test]
    fn mlkem_secret_keys_accept_seed_or_expanded_form() {
        let dk = DecapsulationKey::<MlKem512>::generate_deterministic(&[1; 32], &[2; 32]);
        let expanded = <MlKem512 as Kem>::secret_key_to_bytes(&dk);
        assert_eq!(expanded.len(), MlKem512::DK_LEN);
        let back = <MlKem512 as Kem>::secret_key_from_bytes(&expanded).unwrap();
        assert_eq!(
            <MlKem512 as Kem>::public_key(&back),
            <MlKem512 as Kem>::public_key(&dk)
        );
        assert!(<MlKem512 as Kem>::secret_key_from_bytes(&[0; 5]).is_err());
    }

    #[test]
    fn x25519_kem_rejects_low_order_and_bad_lengths() {
        let mut rng = StdRng::seed_from_u64(4);
        assert!(matches!(
            X25519Kem::encapsulate(&[0u8; 32], &mut rng),
            Err(Error::NonContributory)
        ));
        let (sk, pk) = X25519Kem::generate(&mut rng);
        assert_eq!(X25519Kem::public_key(&sk), pk);
        assert!(matches!(
            X25519Kem::decapsulate(&sk, &[0u8; 32]),
            Err(Error::NonContributory)
        ));
        assert!(X25519Kem::decapsulate(&sk, &[1u8; 31]).is_err());
        assert!(X25519Kem::secret_key_from_bytes(&[1u8; 31]).is_err());
        assert!(<crate::hybrid::XWing as Kem>::secret_key_from_bytes(&[1u8; 31]).is_err());
    }
}
