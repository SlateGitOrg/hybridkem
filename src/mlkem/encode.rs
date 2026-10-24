//! Byte encoding and compression (FIPS 203, Section 4.2.1, Algorithms 3-6 and Eq. 4.7/4.8).
//!
//! `ByteEncode_d`/`ByteDecode_d` pack 256 `d`-bit integers into `32*d` bytes, least
//! significant bit first. `Compress_d` rounds `x * 2^d / q`; the division by `q` is done
//! with a precomputed reciprocal so no hardware divide (whose latency can depend on the
//! operand on some CPUs) ever touches secret data.

use super::field::Q;
use super::poly::{Poly, N};

/// `ceil(2^35 / q)`: multiplying by this and shifting right by 35 divides any
/// numerator below `2^23` by `q` exactly (checked exhaustively in the tests).
const RECIP_Q: u64 = (1u64 << 35).div_ceil(Q as u64);

/// Number of bytes `ByteEncode_d` produces for one polynomial.
pub const fn encoded_len(d: usize) -> usize {
    32 * d
}

/// `ByteEncode_d(F)` for `1 <= d <= 12`; coefficients must already fit in `d` bits
/// (for `d = 12`, be canonical mod q). Appends `32*d` bytes to `out`.
pub fn byte_encode(poly: &Poly, d: usize, out: &mut Vec<u8>) {
    debug_assert!((1..=12).contains(&d));
    let mask = (1u32 << d) - 1;
    let mut acc: u32 = 0;
    let mut acc_bits = 0;
    for &c in poly.0.iter() {
        acc |= (u32::from(c) & mask) << acc_bits;
        acc_bits += d;
        while acc_bits >= 8 {
            out.push(acc as u8);
            acc >>= 8;
            acc_bits -= 8;
        }
    }
    debug_assert_eq!(acc_bits, 0);
}

/// Unpack 256 raw `d`-bit values from exactly `32*d` bytes (no modular reduction).
pub fn byte_decode_raw(bytes: &[u8], d: usize) -> Poly {
    debug_assert!((1..=12).contains(&d));
    debug_assert_eq!(bytes.len(), encoded_len(d));
    let mask = (1u32 << d) - 1;
    let mut out = [0u16; N];
    let mut acc: u32 = 0;
    let mut acc_bits = 0;
    let mut idx = 0;
    for &b in bytes {
        acc |= u32::from(b) << acc_bits;
        acc_bits += 8;
        while acc_bits >= d {
            out[idx] = (acc & mask) as u16;
            idx += 1;
            acc >>= d;
            acc_bits -= d;
        }
    }
    Poly(out)
}

/// `ByteDecode_d(B)` as specified: for `d = 12` the values are reduced mod q.
pub fn byte_decode(bytes: &[u8], d: usize) -> Poly {
    let mut p = byte_decode_raw(bytes, d);
    if d == 12 {
        // Raw 12-bit values are < 4096 < 2q, so one conditional subtraction reduces them.
        for c in p.0.iter_mut() {
            *c = super::field::csubq(u32::from(*c)) as u16;
        }
    }
    p
}

/// True iff every 12-bit value in `bytes` is already `< q`: the FIPS 203 *modulus check*
/// `ByteEncode12(ByteDecode12(ek)) == ek` (Section 7.2). Operates on public data only.
pub fn is_canonical_12(bytes: &[u8]) -> bool {
    debug_assert_eq!(bytes.len() % encoded_len(12), 0);
    bytes
        .chunks_exact(encoded_len(12))
        .all(|chunk| byte_decode_raw(chunk, 12).0.iter().all(|&c| c < Q))
}

/// `Compress_d(x) = round(2^d * x / q) mod 2^d` for canonical `x`, `1 <= d <= 11`.
#[inline(always)]
pub fn compress(x: u16, d: usize) -> u16 {
    // round(a / q) == floor((a + (q-1)/2) / q) for odd q, where a = x * 2^d.
    let numerator = (u64::from(x) << d) + u64::from(Q / 2);
    let quotient = (numerator * RECIP_Q) >> 35;
    (quotient as u16) & ((1u16 << d) - 1)
}

/// `Decompress_d(y) = round(q * y / 2^d)` for `y < 2^d`.
#[inline(always)]
pub fn decompress(y: u16, d: usize) -> u16 {
    ((u32::from(y) * u32::from(Q) + (1u32 << (d - 1))) >> d) as u16
}

/// Apply [`compress`] to every coefficient.
pub fn compress_poly(p: &Poly, d: usize) -> Poly {
    let mut out = [0u16; N];
    for (o, &c) in out.iter_mut().zip(p.0.iter()) {
        *o = compress(c, d);
    }
    Poly(out)
}

/// Apply [`decompress`] to every coefficient.
pub fn decompress_poly(p: &Poly, d: usize) -> Poly {
    let mut out = [0u16; N];
    for (o, &c) in out.iter_mut().zip(p.0.iter()) {
        *o = decompress(c, d);
    }
    Poly(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Straightforward rational-arithmetic reference for Compress_d.
    fn compress_reference(x: u16, d: usize) -> u16 {
        let num = (u64::from(x) << d) * 2 + u64::from(Q); // 2 * (x 2^d / q + 1/2) * q
        ((num / (2 * u64::from(Q))) % (1u64 << d)) as u16
    }

    fn decompress_reference(y: u16, d: usize) -> u16 {
        let num = u64::from(y) * u64::from(Q) * 2 + (1u64 << d);
        (num / (1u64 << (d + 1))) as u16
    }

    #[test]
    fn compress_matches_reference_exhaustively() {
        for d in 1..=11 {
            for x in 0..Q {
                assert_eq!(compress(x, d), compress_reference(x, d), "x={x} d={d}");
            }
        }
    }

    #[test]
    fn decompress_matches_reference_exhaustively() {
        for d in 1..=11 {
            for y in 0..(1u16 << d) {
                assert_eq!(decompress(y, d), decompress_reference(y, d), "y={y} d={d}");
            }
        }
    }

    #[test]
    fn compress_then_decompress_error_is_bounded() {
        // FIPS 203 Eq. 4.9-style bound: |x' - x| mod± q <= round(q / 2^(d+1)).
        for d in 1..=11usize {
            let bound = (u32::from(Q) + (1 << (d + 1)) - 1) >> (d + 1);
            for x in 0..Q {
                let back = decompress(compress(x, d), d);
                let diff = (i32::from(back) - i32::from(x)).rem_euclid(i32::from(Q));
                let dist = diff.min(i32::from(Q) - diff) as u32;
                assert!(dist <= bound, "x={x} d={d} back={back}");
            }
        }
    }

    #[test]
    fn message_bit_rounding() {
        // Compress_1 maps values near q/2 to 1 and values near 0 to 0.
        assert_eq!(compress(0, 1), 0);
        assert_eq!(compress(832, 1), 0);
        assert_eq!(compress(833, 1), 1);
        assert_eq!(compress(1665, 1), 1);
        assert_eq!(compress(2496, 1), 1);
        assert_eq!(compress(2497, 1), 0);
        assert_eq!(decompress(1, 1), 1665);
    }

    #[test]
    fn decode12_reduces_and_canonical_check_detects_large_values() {
        let mut bytes = vec![0u8; encoded_len(12)];
        // First coefficient = 4095 (0xFFF).
        bytes[0] = 0xFF;
        bytes[1] = 0x0F;
        assert!(!is_canonical_12(&bytes));
        assert_eq!(byte_decode(&bytes, 12).0[0], 4095 - Q);
        assert_eq!(byte_decode_raw(&bytes, 12).0[0], 4095);
        bytes[0] = 0x00;
        bytes[1] = 0x0D; // 0xD00 = 3328 = q - 1
        assert!(is_canonical_12(&bytes));
        bytes[0] = 0x01; // 3329 = q
        assert!(!is_canonical_12(&bytes));
    }

    proptest! {
        #[test]
        fn encode_decode_round_trip(d in 1usize..=12, seed in proptest::collection::vec(any::<u16>(), N)) {
            let modulus = if d == 12 { u32::from(Q) } else { 1u32 << d };
            let mut p = [0u16; N];
            for (o, s) in p.iter_mut().zip(seed.iter()) {
                *o = (u32::from(*s) % modulus) as u16;
            }
            let poly = Poly(p);
            let mut out = Vec::new();
            byte_encode(&poly, d, &mut out);
            prop_assert_eq!(out.len(), encoded_len(d));
            prop_assert_eq!(byte_decode(&out, d), poly);
        }

        #[test]
        fn decode_encode_round_trip_bytes(d in 1usize..=11, bytes in proptest::collection::vec(any::<u8>(), 32 * 11)) {
            // For d < 12 every byte string is a valid encoding, so decode∘encode is the identity.
            let input = &bytes[..encoded_len(d)];
            let mut out = Vec::new();
            byte_encode(&byte_decode(input, d), d, &mut out);
            prop_assert_eq!(&out[..], input);
        }
    }

    #[test]
    fn poly_level_helpers_apply_coefficientwise() {
        let mut p = Poly::default();
        for (i, c) in p.0.iter_mut().enumerate() {
            *c = (i as u16 * 13) % Q;
        }
        let c = compress_poly(&p, 10);
        let back = decompress_poly(&c, 10);
        for i in 0..N {
            assert_eq!(c.0[i], compress(p.0[i], 10));
            assert_eq!(back.0[i], decompress(c.0[i], 10));
        }
    }
}
