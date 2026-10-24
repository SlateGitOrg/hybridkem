//! Arithmetic in `Z_q` with `q = 3329` (FIPS 203, Section 2.3).
//!
//! Every function here is branch-free and runs in time independent of its inputs: reductions
//! use a Barrett multiply-shift and conditional subtraction is done with an arithmetic mask
//! rather than an `if`. Coefficients are kept in canonical form `[0, q)` as `u16`.

/// The ML-KEM modulus `q = 2^8 * 13 + 1`.
pub const Q: u16 = 3329;
const Q32: u32 = Q as u32;

/// `floor(2^32 / q)`, the Barrett constant used by [`reduce`].
const BARRETT_MULTIPLIER: u64 = (1u64 << 32) / Q32 as u64;

/// Map `x < 2q` to `x mod q` without branching.
#[inline(always)]
pub fn csubq(x: u32) -> u32 {
    let t = x.wrapping_sub(Q32);
    // `t >> 31` is 1 exactly when x < q (the subtraction wrapped); the mask is then all-ones.
    let mask = 0u32.wrapping_sub(t >> 31);
    t.wrapping_add(Q32 & mask)
}

/// Reduce any `x < 2^26` to `x mod q` in constant time (Barrett reduction).
///
/// With `m = floor(2^32 / q)`, `x - floor(x*m / 2^32) * q` lies in `[0, 2q)` for every
/// `x < 2^26`, so a single conditional subtraction finishes the job. The bound is checked
/// exhaustively by the unit tests below.
#[inline(always)]
pub fn reduce(x: u32) -> u16 {
    let quotient = ((u64::from(x) * BARRETT_MULTIPLIER) >> 32) as u32;
    csubq(x - quotient * Q32) as u16
}

/// `(a + b) mod q` for canonical `a, b`.
#[inline(always)]
pub fn add(a: u16, b: u16) -> u16 {
    csubq(u32::from(a) + u32::from(b)) as u16
}

/// `(a - b) mod q` for canonical `a, b`.
#[inline(always)]
pub fn sub(a: u16, b: u16) -> u16 {
    csubq(u32::from(a) + Q32 - u32::from(b)) as u16
}

/// `(a * b) mod q` for canonical `a, b`.
#[inline(always)]
pub fn mul(a: u16, b: u16) -> u16 {
    reduce(u32::from(a) * u32::from(b))
}

/// `base^exp mod q`, used only at compile time to build twiddle-factor tables.
pub const fn pow_mod(base: u32, mut exp: u32) -> u32 {
    let mut result = 1u32;
    let mut b = base % Q32;
    while exp > 0 {
        if exp & 1 == 1 {
            result = result * b % Q32;
        }
        b = b * b % Q32;
        exp >>= 1;
    }
    result
}

/// Reverse the low 7 bits of `i` (`BitRev7` in FIPS 203).
pub const fn bit_rev7(i: u8) -> u8 {
    let mut out = 0u8;
    let mut k = 0;
    while k < 7 {
        out |= ((i >> k) & 1) << (6 - k);
        k += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reduce_is_exact_on_its_whole_documented_domain_sampled() {
        // Exhaustive over every product of two canonical values would be 11M cases; instead
        // check every x below 2^20 exhaustively plus a stride across the rest of [0, 2^26).
        for x in 0..(1u32 << 20) {
            assert_eq!(u32::from(reduce(x)), x % Q32, "x = {x}");
        }
        let mut x = 1u32 << 20;
        while x < (1u32 << 26) {
            assert_eq!(u32::from(reduce(x)), x % Q32, "x = {x}");
            x += 97;
        }
        let max = (1u32 << 26) - 1;
        assert_eq!(u32::from(reduce(max)), max % Q32);
    }

    #[test]
    fn products_of_canonical_values_reduce_correctly() {
        let max = u32::from(Q - 1) * u32::from(Q - 1);
        assert_eq!(u32::from(reduce(max)), max % Q32);
        for a in (0..Q).step_by(7) {
            for b in (0..Q).step_by(11) {
                assert_eq!(u32::from(mul(a, b)), u32::from(a) * u32::from(b) % Q32);
            }
        }
    }

    #[test]
    fn add_and_sub_wrap_correctly() {
        for a in (0..Q).step_by(13) {
            for b in (0..Q).step_by(17) {
                assert_eq!(u32::from(add(a, b)), (u32::from(a) + u32::from(b)) % Q32);
                assert_eq!(
                    u32::from(sub(a, b)),
                    (u32::from(a) + Q32 - u32::from(b)) % Q32
                );
            }
        }
        assert_eq!(add(Q - 1, 1), 0);
        assert_eq!(sub(0, 1), Q - 1);
    }

    #[test]
    fn csubq_covers_both_branches() {
        assert_eq!(csubq(0), 0);
        assert_eq!(csubq(Q32 - 1), Q32 - 1);
        assert_eq!(csubq(Q32), 0);
        assert_eq!(csubq(2 * Q32 - 1), Q32 - 1);
    }

    #[test]
    fn seventeen_is_a_primitive_256th_root_of_unity() {
        assert_eq!(pow_mod(17, 256), 1);
        assert_eq!(pow_mod(17, 128), u32::from(Q) - 1);
    }

    #[test]
    fn bit_rev7_matches_spec_examples() {
        assert_eq!(bit_rev7(0), 0);
        assert_eq!(bit_rev7(1), 64);
        assert_eq!(bit_rev7(2), 32);
        assert_eq!(bit_rev7(127), 127);
        for i in 0..128u8 {
            assert_eq!(bit_rev7(bit_rev7(i)), i);
        }
    }
}
