//! A small, dependency-free timing harness for the `bench` CLI command and the README table.
//!
//! It reports the **median** of per-operation wall-clock times, which is robust to the
//! scheduler noise of a shared laptop. Criterion benchmarks (`cargo bench`) give the more
//! rigorous statistics; this exists so a single command can print a comparable table for
//! every algorithm in a few seconds.

use crate::kem::{Algorithm, Kem};
use crate::noise::{Builder, Pattern, StaticKeypair};
use crate::with_kem;
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::hint::black_box;
use std::time::Instant;

/// Median timings (microseconds) and sizes for one algorithm.
#[derive(Clone, Debug, PartialEq)]
pub struct KemTiming {
    /// The algorithm measured.
    pub algorithm: Algorithm,
    /// Public-key bytes.
    pub public_key_len: usize,
    /// Ciphertext bytes.
    pub ciphertext_len: usize,
    /// Median key generation time.
    pub keygen_us: f64,
    /// Median encapsulation time (including public-key parsing/validation).
    pub encaps_us: f64,
    /// Median decapsulation time.
    pub decaps_us: f64,
}

/// Median timing of a complete in-memory handshake plus its wire size.
#[derive(Clone, Debug, PartialEq)]
pub struct HandshakeTiming {
    /// The KEM used.
    pub algorithm: Algorithm,
    /// The pattern run.
    pub pattern: Pattern,
    /// Median time for both sides to complete, microseconds.
    pub median_us: f64,
    /// Total handshake bytes (all messages, no framing).
    pub bytes: usize,
}

/// Median of `samples` in microseconds.
pub fn median_us(samples: &mut [f64]) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    samples.sort_by(f64::total_cmp);
    samples[samples.len() / 2]
}

fn time<F: FnMut()>(iterations: usize, mut f: F) -> f64 {
    let mut samples = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let start = Instant::now();
        f();
        samples.push(start.elapsed().as_secs_f64() * 1e6);
    }
    median_us(&mut samples)
}

fn time_kem<K: Kem>(algorithm: Algorithm, iterations: usize) -> KemTiming {
    let mut rng = StdRng::seed_from_u64(0xbe4c);
    let (sk, pk) = K::generate(&mut rng);
    let (ct, _) = K::encapsulate(&pk, &mut rng).expect("fresh keys encapsulate");
    let keygen_us = time(iterations, || {
        black_box(K::generate(&mut rng));
    });
    let encaps_us = time(iterations, || {
        black_box(K::encapsulate(black_box(&pk), &mut rng).ok());
    });
    let decaps_us = time(iterations, || {
        black_box(K::decapsulate(&sk, black_box(&ct)).ok());
    });
    KemTiming {
        algorithm,
        public_key_len: K::PUBLIC_KEY_LEN,
        ciphertext_len: K::CIPHERTEXT_LEN,
        keygen_us,
        encaps_us,
        decaps_us,
    }
}

/// Time key generation, encapsulation and decapsulation for `algorithm`.
pub fn time_algorithm(algorithm: Algorithm, iterations: usize) -> KemTiming {
    with_kem!(algorithm, K => time_kem::<K>(algorithm, iterations))
}

fn time_handshake_kem<K: Kem>(
    algorithm: Algorithm,
    pattern: Pattern,
    iterations: usize,
) -> HandshakeTiming {
    let mut rng = StdRng::seed_from_u64(0x4a5d);
    let server = StaticKeypair::<K>::generate(&mut rng);
    let client = StaticKeypair::<K>::generate(&mut rng);
    let mut bytes = 0;
    let median_us = time(iterations, || {
        let mut ib = Builder::<K>::new(pattern);
        if pattern.needs_local_static(crate::noise::Role::Initiator) {
            ib = ib.local_static(client.clone());
        }
        if pattern.responder_static_premessage() {
            ib = ib.remote_static(&server.public);
        }
        let mut i = ib.build_initiator().expect("valid config");
        let mut r = Builder::<K>::new(pattern)
            .local_static(server.clone())
            .build_responder()
            .expect("valid config");
        bytes = 0;
        while !i.is_finished() {
            let (w, rd) = if i.is_my_turn() {
                (&mut i, &mut r)
            } else {
                (&mut r, &mut i)
            };
            let msg = w.write_message(&[], &mut rng).expect("honest write");
            bytes += msg.len();
            rd.read_message(&msg).expect("honest read");
        }
        black_box((i.into_transport().ok(), r.into_transport().ok()));
    });
    HandshakeTiming {
        algorithm,
        pattern,
        median_us,
        bytes,
    }
}

/// Time a complete handshake (both sides, in memory) for `algorithm` and `pattern`.
pub fn time_handshake(
    algorithm: Algorithm,
    pattern: Pattern,
    iterations: usize,
) -> HandshakeTiming {
    with_kem!(algorithm, K => time_handshake_kem::<K>(algorithm, pattern, iterations))
}

/// Render KEM timings as a Markdown table.
pub fn kem_table(rows: &[KemTiming]) -> String {
    let mut out = String::from(
        "| algorithm | pk bytes | ct bytes | keygen µs | encaps µs | decaps µs |\n|---|---:|---:|---:|---:|---:|\n",
    );
    for r in rows {
        out.push_str(&format!(
            "| {} | {} | {} | {:.1} | {:.1} | {:.1} |\n",
            r.algorithm.name(),
            r.public_key_len,
            r.ciphertext_len,
            r.keygen_us,
            r.encaps_us,
            r.decaps_us
        ));
    }
    out
}

/// Render handshake timings as a Markdown table.
pub fn handshake_table(rows: &[HandshakeTiming]) -> String {
    let mut out = String::from(
        "| KEM | pattern | handshake bytes | full handshake µs |\n|---|---|---:|---:|\n",
    );
    for r in rows {
        out.push_str(&format!(
            "| {} | {} | {} | {:.1} |\n",
            r.algorithm.name(),
            r.pattern,
            r.bytes,
            r.median_us
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn median_handles_even_odd_and_empty() {
        assert_eq!(median_us(&mut []), 0.0);
        assert_eq!(median_us(&mut [3.0, 1.0, 2.0]), 2.0);
        assert_eq!(median_us(&mut [4.0, 1.0, 3.0, 2.0]), 3.0);
    }

    #[test]
    fn timings_and_tables_are_well_formed() {
        let row = time_algorithm(Algorithm::MlKem512, 3);
        assert_eq!((row.public_key_len, row.ciphertext_len), (800, 768));
        assert!(row.keygen_us > 0.0 && row.encaps_us > 0.0 && row.decaps_us > 0.0);
        let table = kem_table(&[row]);
        assert!(table.contains("| ML-KEM-512 | 800 | 768 |"));

        let hs = time_handshake(Algorithm::X25519, Pattern::XX, 2);
        // XX with X25519 KEM: e(32) | ekem(32)+s(32+16)+tag | skem(32+16)+s(32+16)+tag | skem(32+16)+tag
        assert_eq!(hs.bytes, 32 + (32 + 48 + 16) + (48 + 48 + 16) + (48 + 16));
        assert!(handshake_table(&[hs]).contains("pqXX"));
    }
}
