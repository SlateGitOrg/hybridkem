//! Property tests over random seeds and inputs for the public API.

use hybridkem::hybrid::{HybridDecapsulationKey, TranscriptCombiner, XWingCombiner};
use hybridkem::kem::Algorithm;
use hybridkem::mlkem::{
    DecapsulationKey, EncapsulationKey, MlKem1024, MlKem512, MlKem768, ParameterSet,
};
use hybridkem::noise::{Builder, Pattern, StaticKeypair};
use proptest::prelude::*;
use rand::rngs::StdRng;
use rand::SeedableRng;

fn seed64() -> impl Strategy<Value = [u8; 64]> {
    proptest::collection::vec(any::<u8>(), 64).prop_map(|v| v.try_into().unwrap())
}

fn seed32() -> impl Strategy<Value = [u8; 32]> {
    proptest::array::uniform32(any::<u8>())
}

fn check_mlkem<P: ParameterSet>(
    seed: &[u8; 64],
    m: &[u8; 32],
    flip: usize,
) -> Result<(), TestCaseError> {
    let dk = DecapsulationKey::<P>::from_seed(seed);
    // Public key survives a serialize/parse round trip and passes the input checks.
    let ek = EncapsulationKey::<P>::from_bytes(dk.encapsulation_key().as_bytes()).unwrap();
    let (ct, k) = ek.encapsulate_deterministic(m);
    prop_assert_eq!(&dk.decapsulate(ct.as_bytes()).unwrap(), &k);
    // Expanded-key round trip decapsulates identically.
    let dk2 = DecapsulationKey::<P>::from_bytes(&dk.to_bytes()).unwrap();
    prop_assert_eq!(&dk2.decapsulate(ct.as_bytes()).unwrap(), &k);
    // Any single-bit change to the ciphertext yields an unrelated key (implicit rejection).
    let mut bad = ct.into_bytes();
    let bit = flip % (bad.len() * 8);
    bad[bit / 8] ^= 1 << (bit % 8);
    prop_assert_ne!(&dk.decapsulate(&bad).unwrap(), &k);
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    #[test]
    fn mlkem512_correct_and_rejects_tampering(seed in seed64(), m in seed32(), flip in any::<usize>()) {
        check_mlkem::<MlKem512>(&seed, &m, flip)?;
    }

    #[test]
    fn mlkem768_correct_and_rejects_tampering(seed in seed64(), m in seed32(), flip in any::<usize>()) {
        check_mlkem::<MlKem768>(&seed, &m, flip)?;
    }

    #[test]
    fn mlkem1024_correct_and_rejects_tampering(seed in seed64(), m in seed32(), flip in any::<usize>()) {
        check_mlkem::<MlKem1024>(&seed, &m, flip)?;
    }

    #[test]
    fn hybrids_agree_and_bind_both_halves(seed in seed32(), eseed in proptest::collection::vec(any::<u8>(), 64), flip in any::<usize>()) {
        let eseed: [u8; 64] = eseed.try_into().unwrap();
        let x = HybridDecapsulationKey::<MlKem768, XWingCombiner>::from_seed(&seed);
        let (ct, ss) = x.encapsulation_key().encapsulate_deterministic(&eseed).unwrap();
        prop_assert_eq!(&x.decapsulate(&ct).unwrap(), &ss);
        let t = HybridDecapsulationKey::<MlKem1024, TranscriptCombiner>::from_seed(&seed);
        let (ct_t, ss_t) = t.encapsulation_key().encapsulate_deterministic(&eseed).unwrap();
        prop_assert_eq!(&t.decapsulate(&ct_t).unwrap(), &ss_t);
        // Flip a bit anywhere in the transcript-combined ciphertext: secret must change or
        // the X25519 half must be rejected outright.
        let mut bad = ct_t.clone();
        let bit = flip % (bad.len() * 8);
        bad[bit / 8] ^= 1 << (bit % 8);
        if let Ok(other) = t.decapsulate(&bad) {
            prop_assert_ne!(other, ss_t);
        }
    }

    #[test]
    fn random_garbage_never_panics(alg_idx in 0usize..8, data in proptest::collection::vec(any::<u8>(), 0..2000)) {
        let alg = Algorithm::ALL[alg_idx];
        let mut rng = StdRng::seed_from_u64(alg_idx as u64);
        let (sk, pk) = alg.generate(&mut rng);
        // Arbitrary bytes as ciphertext, public key or secret key: errors are fine, panics are not.
        let _ = alg.decapsulate(&sk, &data);
        let _ = alg.encapsulate(&data, &mut rng);
        let _ = alg.decapsulate(&data, &pk);
    }

    #[test]
    fn handshake_payloads_round_trip(p1 in proptest::collection::vec(any::<u8>(), 0..300),
                                     p2 in proptest::collection::vec(any::<u8>(), 0..300),
                                     seed in any::<u64>()) {
        type K = hybridkem::hybrid::X25519MlKem512;
        let mut rng = StdRng::seed_from_u64(seed);
        let server = StaticKeypair::<K>::generate(&mut rng);
        let client = StaticKeypair::<K>::generate(&mut rng);
        let mut i = Builder::<K>::new(Pattern::IK).local_static(client.clone())
            .remote_static(&server.public).build_initiator().unwrap();
        let mut r = Builder::<K>::new(Pattern::IK).local_static(server)
            .pin_peer(&client.public).build_responder().unwrap();
        let m1 = i.write_message(&p1, &mut rng).unwrap();
        prop_assert_eq!(r.read_message(&m1).unwrap(), p1);
        let m2 = r.write_message(&p2, &mut rng).unwrap();
        prop_assert_eq!(i.read_message(&m2).unwrap(), p2);
        let mut ti = i.into_transport().unwrap();
        let mut tr = r.into_transport().unwrap();
        let c = tr.encrypt(b"ok").unwrap();
        prop_assert_eq!(ti.decrypt(&c).unwrap(), b"ok".to_vec());
    }

    #[test]
    fn handshake_rejects_arbitrary_first_messages(junk in proptest::collection::vec(any::<u8>(), 0..4000)) {
        type K = hybridkem::hybrid::XWing;
        let mut rng = StdRng::seed_from_u64(99);
        let server = StaticKeypair::<K>::generate(&mut rng);
        let mut r = Builder::<K>::new(Pattern::IK).local_static(server).build_responder().unwrap();
        prop_assert!(r.read_message(&junk).is_err());
    }
}
