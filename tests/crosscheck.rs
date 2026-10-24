//! Differential tests against independent implementations (dev-dependencies only):
//! the RustCrypto `ml-kem` crate for ML-KEM and the RustCrypto `x-wing` crate for X-Wing.
//!
//! Every iteration draws fresh seeds and compares byte-for-byte: encapsulation key,
//! expanded decapsulation key, ciphertext, shared secret, the implicit-rejection key for a
//! random ciphertext, and the verdict of the encapsulation-key modulus check.

#![allow(deprecated)] // ml-kem marks the expanded-key encoding deprecated; we still test it.

use hybridkem::hybrid::{HybridDecapsulationKey, HybridEncapsulationKey, XWingCombiner};
use hybridkem::mlkem::{self, ParameterSet};
use ml_kem::{Decapsulate, ExpandedKeyEncoding, KeyExport};
use rand::rngs::StdRng;
use rand::{Rng, RngExt, SeedableRng};
use x_wing::Decapsulator;

const ITERATIONS: usize = 64;

macro_rules! crosscheck_mlkem {
    ($name:ident, $ours:ty, $theirs:ty) => {
        #[test]
        fn $name() {
            let mut rng = StdRng::seed_from_u64(0x5eed_0000 + <$ours>::K as u64);
            for i in 0..ITERATIONS {
                let mut seed = [0u8; 64];
                rng.fill_bytes(&mut seed);
                let ours = mlkem::DecapsulationKey::<$ours>::from_seed(&seed);
                let theirs = ml_kem::DecapsulationKey::<$theirs>::from_seed(seed.into());

                let ek_theirs = theirs.encapsulation_key().to_bytes();
                assert_eq!(
                    ours.encapsulation_key().as_bytes(),
                    &ek_theirs[..],
                    "ek, iter {i}"
                );
                assert_eq!(
                    &ours.to_bytes()[..],
                    &theirs.to_expanded_bytes()[..],
                    "dk, iter {i}"
                );

                let mut m = [0u8; 32];
                rng.fill_bytes(&mut m);
                let (ct, k) = ours.encapsulation_key().encapsulate_deterministic(&m);
                let (ct_theirs, k_theirs) = theirs
                    .encapsulation_key()
                    .encapsulate_deterministic(&m.into());
                assert_eq!(ct.as_bytes(), &ct_theirs[..], "ct, iter {i}");
                assert_eq!(&k.as_bytes()[..], &k_theirs[..], "k, iter {i}");
                assert_eq!(
                    &ours.decapsulate(ct.as_bytes()).unwrap().as_bytes()[..],
                    &theirs.decapsulate(&ct_theirs)[..]
                );

                // Implicit rejection on a uniformly random ciphertext.
                let mut junk = vec![0u8; <$ours>::CT_LEN];
                rng.fill_bytes(&mut junk);
                let junk_theirs = ml_kem::Ciphertext::<$theirs>::try_from(&junk[..]).unwrap();
                assert_eq!(
                    &ours.decapsulate(&junk).unwrap().as_bytes()[..],
                    &theirs.decapsulate(&junk_theirs)[..],
                    "implicit rejection, iter {i}"
                );

                // Modulus check: corrupt one 12-bit coefficient to a random value in [0, 4096).
                let mut ek = ek_theirs.to_vec();
                let coeff = rng.random_range(0..256 * <$ours>::K);
                let value: u16 = rng.random_range(3000..4096);
                let byte = coeff * 3 / 2;
                if coeff % 2 == 0 {
                    ek[byte] = value as u8;
                    ek[byte + 1] = (ek[byte + 1] & 0xF0) | (value >> 8) as u8;
                } else {
                    ek[byte] = (ek[byte] & 0x0F) | ((value & 0x0F) << 4) as u8;
                    ek[byte + 1] = (value >> 4) as u8;
                }
                let ours_ok = mlkem::EncapsulationKey::<$ours>::from_bytes(&ek).is_ok();
                let key = ml_kem::kem::Key::<ml_kem::EncapsulationKey<$theirs>>::try_from(&ek[..])
                    .unwrap();
                let theirs_ok = ml_kem::EncapsulationKey::<$theirs>::new(&key).is_ok();
                assert_eq!(
                    ours_ok, theirs_ok,
                    "modulus check verdict, iter {i}, value {value}"
                );
                assert_eq!(ours_ok, value < 3329);
            }
        }
    };
}

crosscheck_mlkem!(
    mlkem512_matches_rustcrypto,
    mlkem::MlKem512,
    ml_kem::MlKem512
);
crosscheck_mlkem!(
    mlkem768_matches_rustcrypto,
    mlkem::MlKem768,
    ml_kem::MlKem768
);
crosscheck_mlkem!(
    mlkem1024_matches_rustcrypto,
    mlkem::MlKem1024,
    ml_kem::MlKem1024
);

#[test]
fn xwing_matches_rustcrypto() {
    let mut rng = StdRng::seed_from_u64(0x000a_11ce);
    for i in 0..ITERATIONS {
        let mut seed = [0u8; 32];
        let mut eseed = [0u8; 64];
        rng.fill_bytes(&mut seed);
        rng.fill_bytes(&mut eseed);

        let ours = HybridDecapsulationKey::<mlkem::MlKem768, XWingCombiner>::from_seed(&seed);
        let theirs = x_wing::DecapsulationKey::from(seed);
        let pk_theirs = theirs.encapsulation_key().to_bytes();
        assert_eq!(
            ours.encapsulation_key().as_bytes(),
            &pk_theirs[..],
            "pk, iter {i}"
        );

        let ek = HybridEncapsulationKey::<mlkem::MlKem768, XWingCombiner>::from_bytes(&pk_theirs)
            .unwrap();
        let (ct, ss) = ek.encapsulate_deterministic(&eseed).unwrap();
        let (ct_theirs, ss_theirs) = theirs
            .encapsulation_key()
            .encapsulate_deterministic(&eseed.into());
        assert_eq!(&ct[..], &ct_theirs[..], "ct, iter {i}");
        assert_eq!(&ss.as_bytes()[..], &ss_theirs[..], "ss, iter {i}");
        assert_eq!(
            &ours.decapsulate(&ct).unwrap().as_bytes()[..],
            &theirs.decapsulate(&ct_theirs)[..]
        );
    }
}
