//! Polynomials in `R_q = Z_q[X]/(X^256 + 1)` and the number-theoretic transform
//! (FIPS 203, Section 4.3, Algorithms 9-12).
//!
//! The NTT here is the textbook layered Cooley-Tukey / Gentleman-Sande pair from the
//! standard. Because `X^256 + 1` only splits into 128 quadratic factors modulo 3329, the
//! "NTT domain" is 128 degree-one polynomials and multiplication there is
//! [`base_case_multiply`] on coefficient pairs. All loops have fixed trip counts, so the
//! transform's control flow never depends on coefficient values.

use super::field::{self, bit_rev7, pow_mod};
use zeroize::Zeroize;

/// Number of coefficients in a polynomial.
pub const N: usize = 256;

/// `zeta^BitRev7(i) mod q` for `i in 0..128`, with `zeta = 17` (FIPS 203, Appendix A).
pub const ZETAS: [u16; 128] = build_zetas();

/// `zeta^(2*BitRev7(i) + 1) mod q` for `i in 0..128`: the roots of the 128 quadratic factors.
pub const GAMMAS: [u16; 128] = build_gammas();

/// `128^-1 mod q`, applied at the end of the inverse NTT.
const NINV: u16 = 3303;

const fn build_zetas() -> [u16; 128] {
    let mut table = [0u16; 128];
    let mut i = 0;
    while i < 128 {
        table[i] = pow_mod(17, bit_rev7(i as u8) as u32) as u16;
        i += 1;
    }
    table
}

const fn build_gammas() -> [u16; 128] {
    let mut table = [0u16; 128];
    let mut i = 0;
    while i < 128 {
        table[i] = pow_mod(17, 2 * bit_rev7(i as u8) as u32 + 1) as u16;
        i += 1;
    }
    table
}

/// A polynomial with canonical coefficients in `[0, q)`.
///
/// The same type holds both the normal and the NTT representation; which one a value is in
/// is tracked by the calling code, exactly as the spec does with its `^` notation.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Poly(pub [u16; N]);

impl Default for Poly {
    fn default() -> Self {
        Self([0; N])
    }
}

impl core::fmt::Debug for Poly {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Coefficients may be secret; print only a short public-safe summary.
        f.write_str("Poly([..256 coefficients..])")
    }
}

impl Zeroize for Poly {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Poly {
    /// Coefficient-wise `self + other`.
    pub fn add(&self, other: &Self) -> Self {
        let mut out = [0u16; N];
        for (o, (a, b)) in out.iter_mut().zip(self.0.iter().zip(other.0.iter())) {
            *o = field::add(*a, *b);
        }
        Self(out)
    }

    /// Coefficient-wise `self - other`.
    pub fn sub(&self, other: &Self) -> Self {
        let mut out = [0u16; N];
        for (o, (a, b)) in out.iter_mut().zip(self.0.iter().zip(other.0.iter())) {
            *o = field::sub(*a, *b);
        }
        Self(out)
    }

    /// In-place coefficient-wise addition.
    pub fn add_assign(&mut self, other: &Self) {
        for (a, b) in self.0.iter_mut().zip(other.0.iter()) {
            *a = field::add(*a, *b);
        }
    }

    /// Forward NTT (Algorithm 9). Output is in bit-reversed order, as the spec requires.
    pub fn ntt(&self) -> Self {
        let mut f = self.0;
        let mut i = 1;
        let mut len = 128;
        while len >= 2 {
            let mut start = 0;
            while start < N {
                let zeta = ZETAS[i];
                i += 1;
                for j in start..start + len {
                    let t = field::mul(zeta, f[j + len]);
                    f[j + len] = field::sub(f[j], t);
                    f[j] = field::add(f[j], t);
                }
                start += 2 * len;
            }
            len /= 2;
        }
        Self(f)
    }

    /// Inverse NTT (Algorithm 10), including the final multiplication by `128^-1`.
    pub fn inv_ntt(&self) -> Self {
        let mut f = self.0;
        let mut i = 127;
        let mut len = 2;
        while len <= 128 {
            let mut start = 0;
            while start < N {
                let zeta = ZETAS[i];
                i -= 1;
                for j in start..start + len {
                    let t = f[j];
                    f[j] = field::add(t, f[j + len]);
                    f[j + len] = field::mul(zeta, field::sub(f[j + len], t));
                }
                start += 2 * len;
            }
            len *= 2;
        }
        for c in f.iter_mut() {
            *c = field::mul(*c, NINV);
        }
        Self(f)
    }

    /// Product of two NTT-domain polynomials (Algorithm 11, `MultiplyNTTs`).
    pub fn multiply_ntt(&self, other: &Self) -> Self {
        let mut out = [0u16; N];
        for i in 0..N / 2 {
            let (c0, c1) = base_case_multiply(
                self.0[2 * i],
                self.0[2 * i + 1],
                other.0[2 * i],
                other.0[2 * i + 1],
                GAMMAS[i],
            );
            out[2 * i] = c0;
            out[2 * i + 1] = c1;
        }
        Self(out)
    }

    /// `self += a * b` with all three in the NTT domain; the inner step of matrix products.
    pub fn multiply_ntt_accumulate(&mut self, a: &Self, b: &Self) {
        let product = a.multiply_ntt(b);
        self.add_assign(&product);
    }
}

/// Multiply `(a0 + a1 X)(b0 + b1 X)` modulo `X^2 - gamma` (Algorithm 12).
#[inline(always)]
pub fn base_case_multiply(a0: u16, a1: u16, b0: u16, b1: u16, gamma: u16) -> (u16, u16) {
    let c0 = field::add(field::mul(a0, b0), field::mul(field::mul(a1, b1), gamma));
    let c1 = field::add(field::mul(a0, b1), field::mul(a1, b0));
    (c0, c1)
}

/// Schoolbook multiplication in `Z_q[X]/(X^256 + 1)`; the reference the NTT is tested against.
#[cfg(test)]
pub fn schoolbook_multiply(a: &Poly, b: &Poly) -> Poly {
    let mut acc = [0i64; N];
    for i in 0..N {
        for j in 0..N {
            let prod = i64::from(a.0[i]) * i64::from(b.0[j]);
            if i + j < N {
                acc[i + j] += prod;
            } else {
                acc[i + j - N] -= prod; // X^256 = -1
            }
        }
    }
    let q = i64::from(super::field::Q);
    let mut out = [0u16; N];
    for (o, v) in out.iter_mut().zip(acc.iter()) {
        *o = v.rem_euclid(q) as u16;
    }
    Poly(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mlkem::field::Q;
    use proptest::prelude::*;

    fn arb_poly() -> impl Strategy<Value = Poly> {
        proptest::collection::vec(0..Q, N).prop_map(|v| {
            let mut p = [0u16; N];
            p.copy_from_slice(&v);
            Poly(p)
        })
    }

    #[test]
    fn zeta_table_matches_fips203_appendix_a_prefix() {
        // First entries of the table printed in FIPS 203 Appendix A.
        assert_eq!(&ZETAS[..8], &[1, 1729, 2580, 3289, 2642, 630, 1897, 848]);
        // First entries of the gamma table (Appendix A, second table).
        assert_eq!(&GAMMAS[..4], &[17, 3312, 2761, 568]);
    }

    #[test]
    fn ntt_of_constant_one_is_all_ones_pairs() {
        let mut one = Poly::default();
        one.0[0] = 1;
        let hat = one.ntt();
        for i in 0..N / 2 {
            assert_eq!(hat.0[2 * i], 1);
            assert_eq!(hat.0[2 * i + 1], 0);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn ntt_round_trips(p in arb_poly()) {
            prop_assert_eq!(p.ntt().inv_ntt(), p);
        }

        #[test]
        fn ntt_multiplication_matches_schoolbook(a in arb_poly(), b in arb_poly()) {
            let fast = a.ntt().multiply_ntt(&b.ntt()).inv_ntt();
            prop_assert_eq!(fast, schoolbook_multiply(&a, &b));
        }

        #[test]
        fn ntt_is_linear(a in arb_poly(), b in arb_poly()) {
            prop_assert_eq!(a.add(&b).ntt(), a.ntt().add(&b.ntt()));
            prop_assert_eq!(a.sub(&b).ntt(), a.ntt().sub(&b.ntt()));
        }
    }

    #[test]
    fn accumulate_adds_product() {
        let mut a = Poly::default();
        let mut b = Poly::default();
        for i in 0..N {
            a.0[i] = (i as u16 * 7) % Q;
            b.0[i] = (i as u16 * 13 + 5) % Q;
        }
        let mut acc = a;
        acc.multiply_ntt_accumulate(&a, &b);
        assert_eq!(acc, a.add(&a.multiply_ntt(&b)));
    }

    #[test]
    fn debug_does_not_print_coefficients() {
        let mut p = Poly::default();
        p.0[0] = 1234;
        assert!(!format!("{p:?}").contains("1234"));
        p.zeroize();
        assert_eq!(p, Poly::default());
    }
}
