//! K-PKE, the IND-CPA public-key encryption scheme underneath ML-KEM
//! (FIPS 203, Section 5, Algorithms 13-15).
//!
//! Vectors of polynomials are `Vec<Poly>` of length `k`; the matrix `A-hat` is a row-major
//! `Vec<Poly>` of length `k*k` where entry `(i, j)` is `SampleNTT(rho || j || i)`.

use super::encode::{byte_decode, byte_encode, compress_poly, decompress_poly, encoded_len};
use super::hash::{g, prf};
use super::params::ParameterSet;
use super::poly::Poly;
use super::sample::{sample_ntt, sample_poly_cbd};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// The public K-PKE encryption key with its expanded matrix cached.
#[derive(Clone)]
pub struct EncryptionKey {
    /// `t-hat`, in the NTT domain.
    t_hat: Vec<Poly>,
    /// Public seed for the matrix.
    rho: [u8; 32],
    /// `A-hat` (row-major, `k*k`), expanded once from `rho` so encapsulation does not redo it.
    a_hat: Vec<Poly>,
}

/// The secret K-PKE decryption key `s-hat`. Wiped on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DecryptionKey {
    s_hat: Vec<Poly>,
}

/// Expand `A-hat` from `rho`: `A[i][j] = SampleNTT(rho || j || i)` (Alg. 13 lines 3-7).
fn expand_a(rho: &[u8; 32], k: usize) -> Vec<Poly> {
    let mut a = Vec::with_capacity(k * k);
    for i in 0..k {
        for j in 0..k {
            a.push(sample_ntt(rho, j as u8, i as u8));
        }
    }
    a
}

/// Sample `k` CBD polynomials with consecutive PRF counters starting at `*nonce`.
fn sample_vector(seed: &[u8; 32], nonce: &mut u8, k: usize, eta: usize) -> Zeroizing<Vec<Poly>> {
    let mut buf = Zeroizing::new(vec![0u8; 64 * eta]);
    let mut out = Zeroizing::new(Vec::with_capacity(k));
    for _ in 0..k {
        prf(seed, *nonce, &mut buf);
        *nonce += 1;
        out.push(sample_poly_cbd(&buf, eta));
    }
    out
}

impl EncryptionKey {
    /// Build from already-validated `ByteEncode12(t-hat) || rho` bytes.
    ///
    /// The caller is responsible for the FIPS 203 modulus check; this function reduces any
    /// out-of-range coefficient mod q exactly as `ByteDecode12` specifies.
    pub fn from_bytes<P: ParameterSet>(bytes: &[u8]) -> Self {
        debug_assert_eq!(bytes.len(), P::EK_LEN);
        let (t_bytes, rho_bytes) = bytes.split_at(P::DK_PKE_LEN);
        let t_hat = t_bytes
            .chunks_exact(encoded_len(12))
            .map(|chunk| byte_decode(chunk, 12))
            .collect();
        let mut rho = [0u8; 32];
        rho.copy_from_slice(rho_bytes);
        let a_hat = expand_a(&rho, P::K);
        Self { t_hat, rho, a_hat }
    }

    /// `ByteEncode12(t-hat) || rho`.
    pub fn to_bytes<P: ParameterSet>(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(P::EK_LEN);
        for p in &self.t_hat {
            byte_encode(p, 12, &mut out);
        }
        out.extend_from_slice(&self.rho);
        out
    }

    /// `K-PKE.Encrypt(ek, m, r)` (Algorithm 14). Returns `c = c1 || c2`.
    pub fn encrypt<P: ParameterSet>(&self, m: &[u8; 32], r: &[u8; 32]) -> Vec<u8> {
        let k = P::K;
        let mut nonce = 0u8;
        let y = sample_vector(r, &mut nonce, k, P::ETA1);
        let e1 = sample_vector(r, &mut nonce, k, P::ETA2);
        let mut e2_buf = Zeroizing::new(vec![0u8; 64 * P::ETA2]);
        prf(r, nonce, &mut e2_buf);
        let e2 = Zeroizing::new(sample_poly_cbd(&e2_buf, P::ETA2));

        let y_hat: Zeroizing<Vec<Poly>> = Zeroizing::new(y.iter().map(Poly::ntt).collect());

        // u = NTT^-1(A-hat^T o y-hat) + e1, i.e. u[i] = sum_j A[j][i] * y[j].
        let mut out = Vec::with_capacity(P::CT_LEN);
        for i in 0..k {
            let mut acc = Zeroizing::new(Poly::default());
            for (j, yj) in y_hat.iter().enumerate() {
                acc.multiply_ntt_accumulate(&self.a_hat[j * k + i], yj);
            }
            let u_i = Zeroizing::new(acc.inv_ntt().add(&e1[i]));
            byte_encode(&compress_poly(&u_i, P::DU), P::DU, &mut out);
        }

        // v = NTT^-1(t-hat^T o y-hat) + e2 + Decompress_1(ByteDecode_1(m)).
        let mut acc = Zeroizing::new(Poly::default());
        for (t, yj) in self.t_hat.iter().zip(y_hat.iter()) {
            acc.multiply_ntt_accumulate(t, yj);
        }
        let mu = Zeroizing::new(decompress_poly(&byte_decode(m, 1), 1));
        let v = Zeroizing::new(acc.inv_ntt().add(&e2).add(&mu));
        byte_encode(&compress_poly(&v, P::DV), P::DV, &mut out);
        out
    }
}

impl DecryptionKey {
    /// Parse `ByteEncode12(s-hat)` (reducing mod q per `ByteDecode12`).
    pub fn from_bytes<P: ParameterSet>(bytes: &[u8]) -> Self {
        debug_assert_eq!(bytes.len(), P::DK_PKE_LEN);
        let s_hat = bytes
            .chunks_exact(encoded_len(12))
            .map(|chunk| byte_decode(chunk, 12))
            .collect();
        Self { s_hat }
    }

    /// `ByteEncode12(s-hat)`.
    pub fn to_bytes<P: ParameterSet>(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(P::DK_PKE_LEN));
        for p in &self.s_hat {
            byte_encode(p, 12, &mut out);
        }
        out
    }

    /// `K-PKE.Decrypt(dk, c)` (Algorithm 15). `c` must be exactly `P::CT_LEN` bytes.
    pub fn decrypt<P: ParameterSet>(&self, c: &[u8]) -> Zeroizing<[u8; 32]> {
        debug_assert_eq!(c.len(), P::CT_LEN);
        let (c1, c2) = c.split_at(encoded_len(P::DU) * P::K);
        let mut acc = Zeroizing::new(Poly::default());
        for (chunk, s) in c1.chunks_exact(encoded_len(P::DU)).zip(self.s_hat.iter()) {
            let u_prime = decompress_poly(&byte_decode(chunk, P::DU), P::DU);
            acc.multiply_ntt_accumulate(s, &u_prime.ntt());
        }
        let v_prime = decompress_poly(&byte_decode(c2, P::DV), P::DV);
        let w = Zeroizing::new(v_prime.sub(&acc.inv_ntt()));
        let mut m = Zeroizing::new(Vec::with_capacity(32));
        byte_encode(&compress_poly(&w, 1), 1, &mut m);
        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(&m);
        out
    }
}

/// `K-PKE.KeyGen(d)` (Algorithm 13), including the FIPS 203 final domain separator `k`
/// appended to `d` before hashing.
pub fn keygen<P: ParameterSet>(d: &[u8; 32]) -> (EncryptionKey, DecryptionKey) {
    let k = P::K;
    let (rho, sigma) = g(&[d, &[k as u8]]);
    let sigma = Zeroizing::new(sigma);
    let a_hat = expand_a(&rho, k);
    let mut nonce = 0u8;
    let s = sample_vector(&sigma, &mut nonce, k, P::ETA1);
    let e = sample_vector(&sigma, &mut nonce, k, P::ETA1);
    let s_hat: Vec<Poly> = s.iter().map(Poly::ntt).collect();
    let e_hat: Zeroizing<Vec<Poly>> = Zeroizing::new(e.iter().map(Poly::ntt).collect());

    // t-hat = A-hat o s-hat + e-hat, i.e. t[i] = sum_j A[i][j] * s[j] + e[i].
    let mut t_hat = Vec::with_capacity(k);
    for i in 0..k {
        let mut acc = e_hat[i];
        for (j, sj) in s_hat.iter().enumerate() {
            acc.multiply_ntt_accumulate(&a_hat[i * k + j], sj);
        }
        t_hat.push(acc);
    }
    (EncryptionKey { t_hat, rho, a_hat }, DecryptionKey { s_hat })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mlkem::params::{MlKem1024, MlKem512, MlKem768};

    fn round_trip<P: ParameterSet>() {
        for seed in 0..8u8 {
            let (ek, dk) = keygen::<P>(&[seed; 32]);
            let m = [seed.wrapping_mul(31) ^ 0xA5; 32];
            let c = ek.encrypt::<P>(&m, &[seed.wrapping_add(1); 32]);
            assert_eq!(c.len(), P::CT_LEN);
            assert_eq!(*dk.decrypt::<P>(&c), m);
        }
    }

    #[test]
    fn encrypt_decrypt_round_trip_all_parameter_sets() {
        round_trip::<MlKem512>();
        round_trip::<MlKem768>();
        round_trip::<MlKem1024>();
    }

    #[test]
    fn key_serialization_round_trips() {
        let (ek, dk) = keygen::<MlKem768>(&[9; 32]);
        let ek_bytes = ek.to_bytes::<MlKem768>();
        assert_eq!(ek_bytes.len(), MlKem768::EK_LEN);
        let ek2 = EncryptionKey::from_bytes::<MlKem768>(&ek_bytes);
        assert_eq!(ek2.to_bytes::<MlKem768>(), ek_bytes);
        let dk_bytes = dk.to_bytes::<MlKem768>();
        let dk2 = DecryptionKey::from_bytes::<MlKem768>(&dk_bytes);
        assert_eq!(*dk2.to_bytes::<MlKem768>(), *dk_bytes);
    }

    #[test]
    fn encryption_is_deterministic_in_r_and_randomized_across_r() {
        let (ek, _) = keygen::<MlKem512>(&[1; 32]);
        let m = [0x11; 32];
        assert_eq!(
            ek.encrypt::<MlKem512>(&m, &[2; 32]),
            ek.encrypt::<MlKem512>(&m, &[2; 32])
        );
        assert_ne!(
            ek.encrypt::<MlKem512>(&m, &[2; 32]),
            ek.encrypt::<MlKem512>(&m, &[3; 32])
        );
    }
}
