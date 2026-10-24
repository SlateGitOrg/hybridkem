//! The three FIPS 203 parameter sets (Section 8, Table 2) and the sizes derived from them
//! (Table 3).

/// Compile-time description of an ML-KEM parameter set.
///
/// Implemented only by the three marker types [`MlKem512`], [`MlKem768`] and [`MlKem1024`];
/// the trait is sealed so downstream code cannot invent non-standard parameter sets.
pub trait ParameterSet:
    sealed::Sealed + Copy + Default + core::fmt::Debug + Send + Sync + 'static
{
    /// Human-readable name, e.g. `"ML-KEM-768"`.
    const NAME: &'static str;
    /// Module rank `k`.
    const K: usize;
    /// CBD parameter for the secret and key-generation noise.
    const ETA1: usize;
    /// CBD parameter for the encryption noise `e1`, `e2`.
    const ETA2: usize;
    /// Compression bits for the `u` component of the ciphertext.
    const DU: usize;
    /// Compression bits for the `v` component of the ciphertext.
    const DV: usize;

    /// Encapsulation key size in bytes: `384k + 32`.
    const EK_LEN: usize = 384 * Self::K + 32;
    /// (Expanded) decapsulation key size in bytes: `768k + 96`.
    const DK_LEN: usize = 768 * Self::K + 96;
    /// Ciphertext size in bytes: `32(du*k + dv)`.
    const CT_LEN: usize = 32 * (Self::DU * Self::K + Self::DV);
    /// Size of the K-PKE decryption key `dk_PKE`: `384k`.
    const DK_PKE_LEN: usize = 384 * Self::K;
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::MlKem512 {}
    impl Sealed for super::MlKem768 {}
    impl Sealed for super::MlKem1024 {}
}

/// ML-KEM-512: NIST security category 1.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MlKem512;

/// ML-KEM-768: NIST security category 3 (the recommended default).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MlKem768;

/// ML-KEM-1024: NIST security category 5.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MlKem1024;

impl ParameterSet for MlKem512 {
    const NAME: &'static str = "ML-KEM-512";
    const K: usize = 2;
    const ETA1: usize = 3;
    const ETA2: usize = 2;
    const DU: usize = 10;
    const DV: usize = 4;
}

impl ParameterSet for MlKem768 {
    const NAME: &'static str = "ML-KEM-768";
    const K: usize = 3;
    const ETA1: usize = 2;
    const ETA2: usize = 2;
    const DU: usize = 10;
    const DV: usize = 4;
}

impl ParameterSet for MlKem1024 {
    const NAME: &'static str = "ML-KEM-1024";
    const K: usize = 4;
    const ETA1: usize = 2;
    const ETA2: usize = 2;
    const DU: usize = 11;
    const DV: usize = 5;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_match_fips203_table_3() {
        assert_eq!(
            (MlKem512::EK_LEN, MlKem512::DK_LEN, MlKem512::CT_LEN),
            (800, 1632, 768)
        );
        assert_eq!(
            (MlKem768::EK_LEN, MlKem768::DK_LEN, MlKem768::CT_LEN),
            (1184, 2400, 1088)
        );
        assert_eq!(
            (MlKem1024::EK_LEN, MlKem1024::DK_LEN, MlKem1024::CT_LEN),
            (1568, 3168, 1568)
        );
        assert_eq!(MlKem768::DK_PKE_LEN, 1152);
    }
}
