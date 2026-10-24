//! A dudect-style timing-leak detector (Reparaz, Balasch, Verbauwhede, "Dude, is my code
//! constant time?", DATE 2017).
//!
//! Method: run an operation on inputs from two classes chosen so that a constant-time
//! implementation should take the same time for both, interleave the classes randomly,
//! time every call, and apply Welch's t-test to the two timing distributions. Because
//! timing noise is heavy-tailed, the test is repeated on versions of the data cropped at a
//! ladder of upper percentiles, and the largest |t| is reported.
//!
//! Interpretation (dudect's thresholds): |t| < 4.5 means *no leak detected at this sample
//! size* — not a proof of constant time; |t| > 10 is strong evidence of a leak. A deliberately
//! leaky target ([`Target::NaiveCompare`]) is included as a positive control so a reader can
//! see the harness is capable of detecting a leak on the machine at hand.

use crate::hybrid::{HybridDecapsulationKey, XWingCombiner};
use crate::mlkem::{DecapsulationKey, MlKem768, ParameterSet};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::hint::black_box;
use std::time::Instant;
use subtle::ConstantTimeEq;

/// Online mean/variance accumulator (Welford's algorithm).
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct RunningStats {
    n: f64,
    mean: f64,
    m2: f64,
}

impl RunningStats {
    /// Add one observation.
    pub fn push(&mut self, x: f64) {
        self.n += 1.0;
        let delta = x - self.mean;
        self.mean += delta / self.n;
        self.m2 += delta * (x - self.mean);
    }

    /// Number of observations.
    pub fn count(&self) -> usize {
        self.n as usize
    }

    /// Sample mean.
    pub fn mean(&self) -> f64 {
        self.mean
    }

    /// Unbiased sample variance (0 for fewer than two observations).
    pub fn variance(&self) -> f64 {
        if self.n < 2.0 {
            0.0
        } else {
            self.m2 / (self.n - 1.0)
        }
    }
}

/// Welch's t statistic for two independent samples (0 when undefined).
pub fn welch_t(a: &RunningStats, b: &RunningStats) -> f64 {
    let se = (a.variance() / a.n + b.variance() / b.n).sqrt();
    if !se.is_finite() || se == 0.0 {
        return 0.0;
    }
    (a.mean - b.mean) / se
}

/// dudect's crop ladder: `1 - 0.5^(10 (i+1) / count)` for `i in 0..count`.
pub fn crop_percentiles(count: usize) -> Vec<f64> {
    (0..count)
        .map(|i| 1.0 - 0.5f64.powf(10.0 * (i as f64 + 1.0) / count as f64))
        .collect()
}

/// Value at quantile `p` of `sorted` (nearest-rank).
fn quantile(sorted: &[u64], p: f64) -> u64 {
    let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

/// Raw timings for both classes.
#[derive(Clone, Debug, Default)]
pub struct Measurements {
    /// Nanoseconds per measurement, class 0.
    pub class0: Vec<u64>,
    /// Nanoseconds per measurement, class 1.
    pub class1: Vec<u64>,
}

/// Welch's t on the raw data and on each percentile-cropped copy; returns the max |t|.
pub fn max_abs_t(m: &Measurements) -> f64 {
    let mut all: Vec<u64> = m.class0.iter().chain(m.class1.iter()).copied().collect();
    if all.is_empty() {
        return 0.0;
    }
    all.sort_unstable();
    let mut thresholds = vec![u64::MAX];
    thresholds.extend(crop_percentiles(20).into_iter().map(|p| quantile(&all, p)));
    thresholds
        .into_iter()
        .map(|cut| {
            let mut a = RunningStats::default();
            let mut b = RunningStats::default();
            m.class0
                .iter()
                .filter(|&&x| x <= cut)
                .for_each(|&x| a.push(x as f64));
            m.class1
                .iter()
                .filter(|&&x| x <= cut)
                .for_each(|&x| b.push(x as f64));
            welch_t(&a, &b).abs()
        })
        .fold(0.0, f64::max)
}

/// Time `op(class, index)` for `samples` randomly interleaved calls, each repeated `reps`
/// times inside one timing window (to rise above the clock resolution for fast operations).
pub fn measure<F: FnMut(usize, usize)>(
    samples: usize,
    reps: usize,
    seed: u64,
    mut op: F,
) -> Measurements {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut m = Measurements::default();
    // Warm caches and branch predictors before recording anything.
    for i in 0..samples.min(64) {
        op(i % 2, i);
    }
    for i in 0..samples {
        let class = (rng.next_u32() & 1) as usize;
        let start = Instant::now();
        for _ in 0..reps {
            op(class, i);
        }
        let elapsed = start.elapsed().as_nanos() as u64;
        if class == 0 {
            m.class0.push(elapsed);
        } else {
            m.class1.push(elapsed);
        }
    }
    m
}

/// How to read a t value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// |t| < 4.5.
    NoLeakDetected,
    /// 4.5 <= |t| < 10: rerun with more samples on a quieter machine.
    Inconclusive,
    /// |t| >= 10.
    Leak,
}

impl Verdict {
    /// Classify a |t| value with dudect's thresholds.
    pub fn from_t(t: f64) -> Self {
        if t < 4.5 {
            Verdict::NoLeakDetected
        } else if t < 10.0 {
            Verdict::Inconclusive
        } else {
            Verdict::Leak
        }
    }

    /// Short label.
    pub fn label(self) -> &'static str {
        match self {
            Verdict::NoLeakDetected => "no leak detected",
            Verdict::Inconclusive => "inconclusive",
            Verdict::Leak => "LEAK",
        }
    }
}

/// The outcome of one timing test.
#[derive(Clone, Debug)]
pub struct Report {
    /// Which target was measured.
    pub target: Target,
    /// Measurements per class.
    pub samples: (usize, usize),
    /// Median nanoseconds per measurement, per class.
    pub median_ns: (u64, u64),
    /// Largest |t| over the crop ladder.
    pub max_t: f64,
    /// Interpretation of `max_t`.
    pub verdict: Verdict,
}

/// The built-in timing targets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    /// ML-KEM-768 decapsulation: honest ciphertexts vs uniformly random ones. The second
    /// class takes the implicit-rejection path, so any timing difference would reveal to an
    /// attacker whether a forged ciphertext was "accepted" (the basis of KyberSlash-style
    /// and plaintext-checking attacks).
    DecapsValidVsInvalid,
    /// ML-KEM-768 decapsulation of honest ciphertexts encrypting the all-zero message vs
    /// random messages: checks that decryption/re-encryption timing is message-independent.
    DecapsMessageZeroVsRandom,
    /// X-Wing decapsulation, honest vs random ciphertexts.
    XWingDecapsValidVsInvalid,
    /// `subtle::ConstantTimeEq` on 1088-byte buffers: equal vs differing in the first byte.
    SubtleCompare,
    /// Positive control: `==` on 1088-byte buffers (early-exit `memcmp`). Expected to leak.
    NaiveCompare,
}

impl Target {
    /// Every target, positive control last.
    pub const ALL: [Target; 5] = [
        Target::DecapsValidVsInvalid,
        Target::DecapsMessageZeroVsRandom,
        Target::XWingDecapsValidVsInvalid,
        Target::SubtleCompare,
        Target::NaiveCompare,
    ];

    /// Stable identifier.
    pub fn id(self) -> &'static str {
        match self {
            Target::DecapsValidVsInvalid => "mlkem768-decaps-valid-vs-invalid",
            Target::DecapsMessageZeroVsRandom => "mlkem768-decaps-msg-zero-vs-random",
            Target::XWingDecapsValidVsInvalid => "xwing-decaps-valid-vs-invalid",
            Target::SubtleCompare => "subtle-ct-eq-1088B",
            Target::NaiveCompare => "naive-eq-1088B (positive control)",
        }
    }

    /// Whether a leak is the expected result (only for the positive control).
    pub fn expect_leak(self) -> bool {
        self == Target::NaiveCompare
    }

    /// Operations timed together per measurement.
    fn reps(self) -> usize {
        match self {
            Target::SubtleCompare | Target::NaiveCompare => 64,
            _ => 1,
        }
    }

    /// Run the test with `samples` measurements in total.
    pub fn run(self, samples: usize, seed: u64) -> Report {
        let mut rng = StdRng::seed_from_u64(seed ^ 0x6475_6465_6374);
        let pool = 64usize; // distinct inputs per class, cycled through
        let m = match self {
            Target::DecapsValidVsInvalid | Target::DecapsMessageZeroVsRandom => {
                let mut seed64 = [0u8; 64];
                rng.fill_bytes(&mut seed64);
                let dk = DecapsulationKey::<MlKem768>::from_seed(&seed64);
                let ek = dk.encapsulation_key();
                let mut classes: [Vec<Vec<u8>>; 2] = [Vec::new(), Vec::new()];
                for _ in 0..pool {
                    let mut m = [0u8; 32];
                    rng.fill_bytes(&mut m);
                    if self == Target::DecapsValidVsInvalid {
                        classes[0].push(ek.encapsulate_deterministic(&m).0.into_bytes());
                        let mut junk = vec![0u8; MlKem768::CT_LEN];
                        rng.fill_bytes(&mut junk);
                        classes[1].push(junk);
                    } else {
                        classes[0].push(ek.encapsulate_deterministic(&[0u8; 32]).0.into_bytes());
                        classes[1].push(ek.encapsulate_deterministic(&m).0.into_bytes());
                    }
                }
                measure(samples, self.reps(), seed, |c, i| {
                    black_box(dk.decapsulate(black_box(&classes[c][i % pool])).ok());
                })
            }
            Target::XWingDecapsValidVsInvalid => {
                let mut s = [0u8; 32];
                rng.fill_bytes(&mut s);
                let dk = HybridDecapsulationKey::<MlKem768, XWingCombiner>::from_seed(&s);
                let mut classes: [Vec<Vec<u8>>; 2] = [Vec::new(), Vec::new()];
                for _ in 0..pool {
                    let mut eseed = [0u8; 64];
                    rng.fill_bytes(&mut eseed);
                    let (ct, _) = dk
                        .encapsulation_key()
                        .encapsulate_deterministic(&eseed)
                        .expect("X-Wing never rejects");
                    let mut junk = ct.clone();
                    rng.fill_bytes(&mut junk[..MlKem768::CT_LEN]);
                    classes[0].push(ct);
                    classes[1].push(junk);
                }
                measure(samples, self.reps(), seed, |c, i| {
                    black_box(dk.decapsulate(black_box(&classes[c][i % pool])).ok());
                })
            }
            Target::SubtleCompare | Target::NaiveCompare => {
                let mut base = vec![0u8; MlKem768::CT_LEN];
                rng.fill_bytes(&mut base);
                let equal = base.clone();
                let mut differ = base.clone();
                differ[0] ^= 0xFF;
                let others = [equal, differ];
                let subtle = self == Target::SubtleCompare;
                measure(samples, self.reps(), seed, |c, _| {
                    let a = black_box(&base[..]);
                    let b = black_box(&others[c][..]);
                    if subtle {
                        black_box(bool::from(a.ct_eq(b)));
                    } else {
                        black_box(a == b);
                    }
                })
            }
        };
        report(self, &m)
    }
}

fn median(v: &[u64]) -> u64 {
    if v.is_empty() {
        return 0;
    }
    let mut s = v.to_vec();
    s.sort_unstable();
    s[s.len() / 2]
}

fn report(target: Target, m: &Measurements) -> Report {
    let max_t = max_abs_t(m);
    Report {
        target,
        samples: (m.class0.len(), m.class1.len()),
        median_ns: (median(&m.class0), median(&m.class1)),
        max_t,
        verdict: Verdict::from_t(max_t),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn welford_matches_two_pass_formulas() {
        let data = [2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0];
        let mut s = RunningStats::default();
        data.iter().for_each(|&x| s.push(x));
        assert_eq!(s.count(), 8);
        assert!((s.mean() - 5.0).abs() < 1e-12);
        assert!((s.variance() - 32.0 / 7.0).abs() < 1e-12);
        assert_eq!(RunningStats::default().variance(), 0.0);
    }

    #[test]
    fn welch_t_known_value() {
        // a = {1,2,3,4,5}: mean 3, var 2.5; b = {3,4,5,6,7}: mean 5, var 2.5.
        // t = (3-5)/sqrt(2.5/5 + 2.5/5) = -2.
        let mut a = RunningStats::default();
        let mut b = RunningStats::default();
        (1..=5).for_each(|x| a.push(f64::from(x)));
        (3..=7).for_each(|x| b.push(f64::from(x)));
        assert!((welch_t(&a, &b) + 2.0).abs() < 1e-12);
        assert_eq!(welch_t(&a, &a), 0.0);
        assert_eq!(
            welch_t(&RunningStats::default(), &RunningStats::default()),
            0.0
        );
    }

    #[test]
    fn crop_ladder_is_increasing_and_below_one() {
        let p = crop_percentiles(20);
        assert_eq!(p.len(), 20);
        assert!(p.windows(2).all(|w| w[0] < w[1]));
        assert!(p[0] > 0.0 && *p.last().unwrap() < 1.0);
    }

    #[test]
    fn max_abs_t_on_synthetic_data() {
        // Identical distributions: |t| = 0. Shifted: large.
        let same = Measurements {
            class0: (0..1000).map(|i| 100 + (i % 7)).collect(),
            class1: (0..1000).map(|i| 100 + (i % 7)).collect(),
        };
        assert!(max_abs_t(&same) < 1e-9);
        let shifted = Measurements {
            class0: (0..1000).map(|i| 100 + (i % 7)).collect(),
            class1: (0..1000).map(|i| 110 + (i % 7)).collect(),
        };
        assert!(max_abs_t(&shifted) > 10.0);
        assert_eq!(max_abs_t(&Measurements::default()), 0.0);
    }

    #[test]
    fn verdict_thresholds() {
        assert_eq!(Verdict::from_t(1.0), Verdict::NoLeakDetected);
        assert_eq!(Verdict::from_t(5.0), Verdict::Inconclusive);
        assert_eq!(Verdict::from_t(50.0), Verdict::Leak);
        assert_eq!(Verdict::Leak.label(), "LEAK");
    }

    #[test]
    fn measure_splits_classes_and_records_everything() {
        let mut calls = [0usize; 2];
        let m = measure(200, 3, 1, |c, _| calls[c] += 1);
        assert_eq!(m.class0.len() + m.class1.len(), 200);
        assert!(m.class0.len() > 50 && m.class1.len() > 50);
        // 64 warm-up calls + 200 samples * 3 reps.
        assert_eq!(calls[0] + calls[1], 64 + 600);
        assert_eq!(median(&[]), 0);
    }

    #[test]
    fn every_target_runs_and_reports() {
        // Tiny sample counts: this checks plumbing only, not timing behaviour.
        for t in Target::ALL {
            let r = t.run(40, 5);
            assert_eq!(r.samples.0 + r.samples.1, 40, "{}", t.id());
            assert!(r.max_t.is_finite());
            assert_eq!(t.expect_leak(), t == Target::NaiveCompare);
        }
    }
}
