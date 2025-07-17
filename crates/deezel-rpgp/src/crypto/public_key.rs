extern crate alloc;
use num_enum::{FromPrimitive, IntoPrimitive};

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use proptest::prelude::*;
    use proptest::strategy::{BoxedStrategy, Strategy};

    prop_compose! {
        pub fn arbitrary_pk_alg()(
            num in prop_oneof![
                Just(1u8), Just(2), Just(3), Just(16), Just(17), Just(18), Just(19),
                Just(20), Just(21), Just(22), Just(25), Just(26), Just(27), Just(28),
                Just(30), Just(31), Just(32), Just(33), Just(34), Just(35), Just(36),
                Just(100), Just(101), Just(102), Just(103), Just(104), Just(105),
                Just(106), Just(107), Just(108), Just(109), Just(110),
            ]
        ) -> PublicKeyAlgorithm {
            PublicKeyAlgorithm::from(num)
        }
    }

    proptest! {
        #[test]
        fn arbitrary(alg in arbitrary_pk_alg()) {
            let num: u8 = alg.into();
            assert_eq!(alg, PublicKeyAlgorithm::from(num));
        }
    }

    impl Arbitrary for PublicKeyAlgorithm {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
            arbitrary_pk_alg().boxed()
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, FromPrimitive, IntoPrimitive)]
#[repr(u8)]
#[non_exhaustive]
pub enum PublicKeyAlgorithm {
    /// RSA (Encrypt and Sign)
    RSA = 1,
    /// DEPRECATED: RSA (Encrypt-Only)
    RSAEncrypt = 2,
    /// DEPRECATED: RSA (Sign-Only)
    RSASign = 3,
    /// Elgamal (Encrypt-Only)
    ElgamalEncrypt = 16,
    /// DSA (Digital Signature Algorithm)
    DSA = 17,
    /// Elliptic Curve: RFC 9580 [formerly in RFC 6637]
    ECDH = 18,
    /// ECDSA: RFC 9580 [formerly in RFC 6637]
    ECDSA = 19,
    /// DEPRECATED: Elgamal (Encrypt and Sign)
    Elgamal = 20,
    /// Reserved for Diffie-Hellman (X9.42, as defined for IETF-S/MIME)
    DiffieHellman = 21,
    /// EdDSA legacy format [deprecated in RFC 9580, superseded by Ed25519 (27)]
    EdDSALegacy = 22,
    /// X25519 [RFC 9580]
    X25519 = 25,
    /// X448 [RFC 9580]
    X448 = 26,
    /// Ed25519 [RFC 9580]
    Ed25519 = 27,
    /// Ed448 [RFC 9580]
    Ed448 = 28,

    /// ML-DSA-65+Ed25519
    #[cfg(feature = "draft-pqc")]
    MlDsa65Ed25519 = 30,
    /// ML-DSA-87+Ed448
    #[cfg(feature = "draft-pqc")]
    MlDsa87Ed448 = 31,

    /// SLH-DSA-SHAKE-128s
    #[cfg(feature = "draft-pqc")]
    SlhDsaShake128s = 32,
    /// SLH-DSA-SHAKE-128f
    #[cfg(feature = "draft-pqc")]
    SlhDsaShake128f = 33,
    /// SLH-DSA-SHAKE-256s
    #[cfg(feature = "draft-pqc")]
    SlhDsaShake256s = 34,

    /// ML-KEM-768+X25519
    #[cfg(feature = "draft-pqc")]
    MlKem768X25519 = 35,
    /// ML-KEM-1024+X448
    #[cfg(feature = "draft-pqc")]
    MlKem1024X448 = 36,

    /// Private experimental range (from OpenPGP)
    Private100 = 100,
    Private101 = 101,
    Private102 = 102,
    Private103 = 103,
    Private104 = 104,
    Private105 = 105,
    Private106 = 106,
    Private107 = 107,
    Private108 = 108,
    Private109 = 109,
    Private110 = 110,

    #[num_enum(catch_all)]
    Unknown(u8),
}

impl Default for PublicKeyAlgorithm {
    fn default() -> Self {
        Self::RSA
    }
}

impl PublicKeyAlgorithm {
    /// true if the algorithm uses a post-quantum cryptographic scheme
    /// (and can thus provide post-quantum security)
    pub fn is_pqc(&self) -> bool {
        match self {
            #[cfg(feature = "draft-pqc")]
            Self::MlDsa65Ed25519
            | Self::MlDsa87Ed448
            | Self::SlhDsaShake128s
            | Self::SlhDsaShake128f
            | Self::SlhDsaShake256s
            | Self::MlKem768X25519
            | Self::MlKem1024X448 => true,

            _ => false,
        }
    }
}
