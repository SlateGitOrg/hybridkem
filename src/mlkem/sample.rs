//! Sampling algorithms (FIPS 203, Section 4.2.2, Algorithms 7 and 8).

use super::field::{self, Q};
use super::hash::Xof;
use super::poly::{Poly, N};

/// Bytes squeezed from the XOF per refill in [`sample_ntt`]: one SHAKE128 block (168 bytes,
/// a multiple of 3), so most polynomials need exactly 3-4 refills.
const XOF_BLOCK: usize = 168;

/// `SampleNTT(rho || j || i)` (Algorithm 7): rejection-sample a uniformly random NTT-domain
/// polynomial from SHAKE128.
///
/// The number of XOF bytes consumed varies, but the input is the *public* seed `rho`, so the
/// data-dependent loop leaks nothing secret. Squeezing a whole block at a time instead of 3
/// bytes is an implementation detail that yields the identical byte stream.
pub fn sample_ntt(rho: &[u8; 32], j: u8, i: u8) -> Poly {
    let mut xof = Xof::new(rho, j, i);
    let mut out = [0u16; N];
    let mut buf = [0u8; XOF_BLOCK];
    let mut filled = 0;
    while filled < N {
        xof.squeeze(&mut buf);
        for c in buf.chunks_exact(3) {
            let d1 = u16::from(c[0]) | (u16::from(c[1] & 0x0F) << 8);
            let d2 = u16::from(c[1] >> 4) | (u16::from(c[2]) << 4);
            if d1 < Q {
                out[filled] = d1;
                filled += 1;
            }
            if d2 < Q && filled < N {
                out[filled] = d2;
                filled += 1;
            }
            if filled == N {
                break;
            }
        }
    }
    Poly(out)
}

/// `SamplePolyCBD_eta(B)` (Algorithm 8) for `eta` in {2, 3}: each coefficient is the
/// difference of two sums of `eta` uniformly random bits, giving a centered binomial
/// distribution on `[-eta, eta]` mod q.
///
/// Runs in constant time: fixed loop bounds, bit extraction by shifts and masks only.
pub fn sample_poly_cbd(bytes: &[u8], eta: usize) -> Poly {
    debug_assert!(eta == 2 || eta == 3);
    debug_assert_eq!(bytes.len(), 64 * eta);
    let mut out = [0u16; N];
    let bit = |pos: usize| -> u16 { u16::from((bytes[pos >> 3] >> (pos & 7)) & 1) };
    for (i, o) in out.iter_mut().enumerate() {
        let base = 2 * i * eta;
        let mut x = 0u16;
        let mut y = 0u16;
        for k in 0..eta {
            x += bit(base + k);
            y += bit(base + eta + k);
        }
        // x, y <= 3 so x + q - y is in (0, 2q) and csubq maps it into [0, q).
        *o = field::csubq(u32::from(x) + u32::from(Q) - u32::from(y)) as u16;
    }
    Poly(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn centered(c: u16) -> i32 {
        let c = i32::from(c);
        if c > i32::from(Q) / 2 {
            c - i32::from(Q)
        } else {
            c
        }
    }

    #[test]
    fn sample_ntt_outputs_are_canonical_and_deterministic() {
        let rho = [42u8; 32];
        let a = sample_ntt(&rho, 0, 1);
        assert!(a.0.iter().all(|&c| c < Q));
        assert_eq!(a, sample_ntt(&rho, 0, 1));
        assert_ne!(a, sample_ntt(&rho, 1, 0), "index order must matter");
    }

    #[test]
    fn sample_ntt_is_roughly_uniform() {
        // Across 64 polynomials (16384 coefficients) the mean should be close to (q-1)/2.
        let mut sum = 0u64;
        let mut count = 0u64;
        for i in 0..8u8 {
            for j in 0..8u8 {
                let p = sample_ntt(&[i ^ 0x5A; 32], j, i);
                sum += p.0.iter().map(|&c| u64::from(c)).sum::<u64>();
                count += N as u64;
            }
        }
        let mean = sum as f64 / count as f64;
        assert!((mean - 1664.0).abs() < 30.0, "mean {mean}");
    }

    #[test]
    fn cbd_all_zero_and_all_one_inputs() {
        for eta in [2usize, 3] {
            let zeros = vec![0u8; 64 * eta];
            assert_eq!(sample_poly_cbd(&zeros, eta), Poly::default());
            let ones = vec![0xFFu8; 64 * eta];
            // Every x = y = eta, so every coefficient is 0.
            assert_eq!(sample_poly_cbd(&ones, eta), Poly::default());
        }
    }

    #[test]
    fn cbd_extremes_and_distribution() {
        // eta = 2: bits [1,1,0,0] -> x=2, y=0 -> +2; bits [0,0,1,1] -> -2.
        let mut bytes = vec![0u8; 128];
        bytes[0] = 0b1100_0011; // coeff0 = +2, coeff1 = -2
        let p = sample_poly_cbd(&bytes, 2);
        assert_eq!(centered(p.0[0]), 2);
        assert_eq!(centered(p.0[1]), -2);

        // Pseudo-random input: values stay in [-eta, eta] and the empirical variance is
        // near eta/2 (variance of CBD_eta).
        for eta in [2usize, 3] {
            let mut bytes = vec![0u8; 64 * eta];
            super::super::hash::shake256(&[b"cbd-test", &[eta as u8]], &mut bytes);
            let p = sample_poly_cbd(&bytes, eta);
            let vals: Vec<i32> = p.0.iter().map(|&c| centered(c)).collect();
            assert!(vals.iter().all(|v| v.unsigned_abs() as usize <= eta));
            let var = vals.iter().map(|v| f64::from(v * v)).sum::<f64>() / N as f64;
            assert!((var - eta as f64 / 2.0).abs() < 0.35, "eta {eta} var {var}");
        }
    }
}
