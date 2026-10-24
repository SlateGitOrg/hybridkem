//! Criterion benchmarks, one group per ML-KEM parameter set, plus hybrids and handshakes.
//!
//! The RustCrypto `ml-kem` crate is benchmarked alongside as a *reference point only* (it is
//! a dev-dependency and never linked into the library).
//!
//! Run: `cargo bench --bench kem` (or `make bench`).

use criterion::{criterion_group, criterion_main, Criterion};
use hybridkem::hybrid::{HybridDecapsulationKey, TranscriptCombiner, XWingCombiner};
use hybridkem::mlkem::{self, ParameterSet};
use hybridkem::noise::{Builder, Pattern, StaticKeypair};
use ml_kem::Decapsulate;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::hint::black_box;

fn bench_param_set<P: ParameterSet>(
    c: &mut Criterion,
    reference: impl Fn(&[u8; 64], &[u8; 32]) -> Box<dyn Fn()>,
) {
    let mut rng = StdRng::seed_from_u64(1);
    let mut seed = [0u8; 64];
    let mut m = [0u8; 32];
    rng.fill_bytes(&mut seed);
    rng.fill_bytes(&mut m);
    let dk = mlkem::DecapsulationKey::<P>::from_seed(&seed);
    let ek_bytes = dk.encapsulation_key().as_bytes().to_vec();
    let (ct, _) = dk.encapsulation_key().encapsulate_deterministic(&m);

    let mut g = c.benchmark_group(P::NAME);
    g.bench_function("keygen", |b| {
        b.iter(|| mlkem::DecapsulationKey::<P>::from_seed(black_box(&seed)))
    });
    g.bench_function("encaps (incl. ek parse + checks)", |b| {
        b.iter(|| {
            let ek = mlkem::EncapsulationKey::<P>::from_bytes(black_box(&ek_bytes)).unwrap();
            ek.encapsulate_deterministic(black_box(&m))
        })
    });
    g.bench_function("encaps (pre-parsed ek)", |b| {
        b.iter(|| {
            dk.encapsulation_key()
                .encapsulate_deterministic(black_box(&m))
        })
    });
    g.bench_function("decaps", |b| {
        b.iter(|| dk.decapsulate(black_box(ct.as_bytes())).unwrap())
    });
    let reference_decaps = reference(&seed, &m);
    g.bench_function("reference ml-kem crate: decaps", |b| {
        b.iter(&reference_decaps)
    });
    g.finish();
}

macro_rules! reference_decaps {
    ($p:ty) => {
        |seed: &[u8; 64], m: &[u8; 32]| -> Box<dyn Fn()> {
            let dk = ml_kem::DecapsulationKey::<$p>::from_seed((*seed).into());
            let (ct, _) = dk
                .encapsulation_key()
                .encapsulate_deterministic(&(*m).into());
            Box::new(move || {
                black_box(dk.decapsulate(black_box(&ct)));
            })
        }
    };
}

fn mlkem_benches(c: &mut Criterion) {
    bench_param_set::<mlkem::MlKem512>(c, reference_decaps!(ml_kem::MlKem512));
    bench_param_set::<mlkem::MlKem768>(c, reference_decaps!(ml_kem::MlKem768));
    bench_param_set::<mlkem::MlKem1024>(c, reference_decaps!(ml_kem::MlKem1024));
}

fn hybrid_benches(c: &mut Criterion) {
    let mut g = c.benchmark_group("hybrid");
    let seed = [7u8; 32];
    let eseed = [9u8; 64];
    let xwing = HybridDecapsulationKey::<mlkem::MlKem768, XWingCombiner>::from_seed(&seed);
    let (ct, _) = xwing
        .encapsulation_key()
        .encapsulate_deterministic(&eseed)
        .unwrap();
    g.bench_function("X-Wing encaps", |b| {
        b.iter(|| {
            xwing
                .encapsulation_key()
                .encapsulate_deterministic(black_box(&eseed))
        })
    });
    g.bench_function("X-Wing decaps", |b| {
        b.iter(|| xwing.decapsulate(black_box(&ct)))
    });
    let t1024 = HybridDecapsulationKey::<mlkem::MlKem1024, TranscriptCombiner>::from_seed(&seed);
    let (ct, _) = t1024
        .encapsulation_key()
        .encapsulate_deterministic(&eseed)
        .unwrap();
    g.bench_function("X25519+ML-KEM-1024 (transcript) decaps", |b| {
        b.iter(|| t1024.decapsulate(black_box(&ct)))
    });
    g.finish();
}

fn handshake_benches(c: &mut Criterion) {
    type K = hybridkem::hybrid::XWing;
    let mut rng = StdRng::seed_from_u64(3);
    let server = StaticKeypair::<K>::generate(&mut rng);
    let client = StaticKeypair::<K>::generate(&mut rng);
    c.bench_function("handshake/pqIK X-Wing (both sides)", |b| {
        b.iter(|| {
            let mut i = Builder::<K>::new(Pattern::IK)
                .local_static(client.clone())
                .remote_static(&server.public)
                .build_initiator()
                .unwrap();
            let mut r = Builder::<K>::new(Pattern::IK)
                .local_static(server.clone())
                .build_responder()
                .unwrap();
            let m1 = i.write_message(&[], &mut rng).unwrap();
            r.read_message(&m1).unwrap();
            let m2 = r.write_message(&[], &mut rng).unwrap();
            i.read_message(&m2).unwrap();
            (i.into_transport().unwrap(), r.into_transport().unwrap())
        })
    });
}

criterion_group!(benches, mlkem_benches, hybrid_benches, handshake_benches);
criterion_main!(benches);
