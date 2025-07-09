use chrono::{Duration, SubsecRound};
use derive_builder::Builder;
use rand::{CryptoRng, Rng};
use smallvec::SmallVec;
use alloc::{
    string::{String, ToString},
    vec,
    vec::Vec,
};

#[cfg(feature = "draft-pqc")]
use crate::crypto::{
    ml_dsa65_ed25519, ml_dsa87_ed448, ml_kem1024_x448, ml_kem768_x25519, slh_dsa_shake128f,
    slh_dsa_shake128s, slh_dsa_shake256s,
};
use crate::{
    composed::{KeyDetails, SecretKey, SecretSubkey},
    crypto::{
        aead::AeadAlgorithm, dsa, ecc_curve::ECCCurve, ecdh, ecdsa, ed25519, ed448,
        hash::HashAlgorithm, public_key::PublicKeyAlgorithm, rsa, sym::SymmetricKeyAlgorithm,
        x25519, x448,
    },
    errors::Result,
    packet::{self, KeyFlags, PubKeyInner, UserAttribute, UserId},
    types::{self, CompressionAlgorithm, PlainSecretParams, PublicParams, S2kParams},
};

#[derive(Debug, PartialEq, Eq, Builder)]
#[builder(build_fn(validate = "Self::validate"))]
pub struct SecretKeyParams {
    /// OpenPGP key version of primary
    #[builder(default)]
    version: types::KeyVersion,

    /// Asymmetric algorithm for the primary
    key_type: KeyType,

    // -- Keyflags for primary
    #[builder(default)]
    can_sign: bool,
    #[builder(default)]
    can_certify: bool,
    #[builder(default)]
    can_encrypt: bool,
    #[builder(default)]
    can_authenticate: bool,

    // -- Metadata for the primary key
    #[builder(default = "chrono::Utc::now().trunc_subsecs(0)")]
    created_at: chrono::DateTime<chrono::Utc>,
    #[builder(default)]
    expiration: Option<Duration>,
    #[builder(default = "true")]
    feature_seipd_v1: bool,
    #[builder(default)]
    feature_seipd_v2: bool,

    // -- Public-facing preferences on the certificate
    /// List of symmetric algorithms that indicate which algorithms the key holder prefers to use.
    #[builder(default)]
    preferred_symmetric_algorithms: SmallVec<[SymmetricKeyAlgorithm; 8]>,
    /// List of hash algorithms that indicate which algorithms the key holder prefers to use.
    #[builder(default)]
    preferred_hash_algorithms: SmallVec<[HashAlgorithm; 8]>,
    /// List of compression algorithms that indicate which algorithms the key holder prefers to use.
    #[builder(default)]
    preferred_compression_algorithms: SmallVec<[CompressionAlgorithm; 8]>,
    /// List of AEAD algorithms that indicate which algorithms the key holder prefers to use.
    #[builder(default)]
    preferred_aead_algorithms: SmallVec<[(SymmetricKeyAlgorithm, AeadAlgorithm); 4]>,

    // -- Password-locking of the primary
    #[builder(default)]
    passphrase: Option<String>,
    #[builder(default)]
    s2k: Option<S2kParams>,

    // -- Packet framing for the primary key
    #[builder(default)]
    packet_version: types::PacketHeaderVersion,

    // -- Associated components
    /// Primary User ID, required for v4 keys, but not required for v6 keys
    #[builder(default, setter(custom))]
    primary_user_id: Option<String>,
    #[builder(default)]
    user_ids: Vec<String>,
    #[builder(default)]
    user_attributes: Vec<UserAttribute>,
    #[builder(default)]
    subkeys: Vec<SubkeyParams>,
}

#[derive(Debug, Clone, PartialEq, Eq, Builder)]
pub struct SubkeyParams {
    // -- OpenPGP key version of this subkey
    #[builder(default)]
    version: types::KeyVersion,

    // -- Asymmetric algorithm of this subkey
    key_type: KeyType,

    // -- Keyflags for this subkey
    #[builder(default)]
    can_sign: bool,
    #[builder(default)]
    can_encrypt: bool,
    #[builder(default)]
    can_authenticate: bool,

    // -- Metadata for the primary key
    #[builder(default = "chrono::Utc::now().trunc_subsecs(0)")]
    created_at: chrono::DateTime<chrono::Utc>,
    #[builder(default)]
    expiration: Option<Duration>,

    // -- Password-locking of this subkey
    #[builder(default)]
    passphrase: Option<String>,
    #[builder(default)]
    s2k: Option<S2kParams>,

    // -- Packet framing for this subkey
    #[builder(default)]
    packet_version: types::PacketHeaderVersion,
}

impl SecretKeyParamsBuilder {
    fn validate_keytype(
        key_type: Option<&KeyType>,
        can_sign: Option<bool>,
        can_encrypt: Option<bool>,
        can_authenticate: Option<bool>,
    ) -> core::result::Result<(), String> {
        if let Some(key_type) = &key_type {
            if can_sign == Some(true) && !key_type.can_sign() {
                return Err(format!(
                    "KeyType {:?} can not be used for signing keys",
                    key_type
                ));
            }
            if can_encrypt == Some(true) && !key_type.can_encrypt() {
                return Err(format!(
                    "KeyType {:?} can not be used for encryption keys",
                    key_type
                ));
            }
            if can_authenticate == Some(true) && !key_type.can_sign() {
                return Err(format!(
                    "KeyType {:?} can not be used for authentication keys",
                    key_type
                ));
            }

            match key_type {
                KeyType::Rsa(size) => {
                    if *size < 2048 {
                        return Err("Keys with less than 2048bits are considered insecure".into());
                    }
                }
                KeyType::ECDSA(curve) => match curve {
                    ECCCurve::P256 | ECCCurve::P384 | ECCCurve::P521 | ECCCurve::Secp256k1 => {}
                    _ => return Err(format!("Curve {} is not supported for ECDSA", curve.name())),
                },
                _ => {}
            }
        }

        Ok(())
    }

    fn validate(&self) -> core::result::Result<(), String> {
        // Don't allow mixing of v4/v6 primary and subkeys
        match self.version {
            // V6 primary
            Some(types::KeyVersion::V6) => {
                // all subkeys must be v6
                for sub in self.subkeys.iter().flatten() {
                    if sub.version != types::KeyVersion::V6 {
                        return Err(format!(
                            "V6 primary key may not be combined with {:?} subkey",
                            sub.version
                        ));
                    }
                }
            }
            // non-V6 primary
            _ => {
                // subkeys may not be v6
                // (but v2/3/4 have been mixed historically, so we will let those slide)
                for sub in self.subkeys.iter().flatten() {
                    if sub.version == types::KeyVersion::V6 {
                        return Err(format!(
                            "{:?} primary key may not be combined with V6 subkey",
                            self.version
                        ));
                    }
                }
            }
        };

        Self::validate_keytype(
            self.key_type.as_ref(),
            self.can_sign,
            self.can_encrypt,
            self.can_authenticate,
        )?;

        if let Some(subkeys) = &self.subkeys {
            for subkey in subkeys {
                Self::validate_keytype(
                    Some(&subkey.key_type),
                    Some(subkey.can_sign),
                    Some(subkey.can_encrypt),
                    Some(subkey.can_authenticate),
                )?;
            }
        }

        if self.version == Some(types::KeyVersion::V4) && self.primary_user_id.is_none() {
            return Err("V4 keys must have a primary User ID".into());
        }

        Ok(())
    }

    pub fn user_id<VALUE: Into<String>>(&mut self, value: VALUE) -> &mut Self {
        if let Some(ref mut user_ids) = self.user_ids {
            user_ids.push(value.into());
        } else {
            self.user_ids = Some(vec![value.into()]);
        }
        self
    }

    pub fn subkey<VALUE: Into<SubkeyParams>>(&mut self, value: VALUE) -> &mut Self {
        if let Some(ref mut subkeys) = self.subkeys {
            subkeys.push(value.into());
        } else {
            self.subkeys = Some(vec![value.into()]);
        }
        self
    }

    pub fn primary_user_id(&mut self, value: String) -> &mut Self {
        self.primary_user_id = Some(Some(value));
        self
    }
}

impl SecretKeyParams {
    pub fn generate<R: Rng + CryptoRng>(self, mut rng: R) -> Result<SecretKey> {
        let passphrase = self.passphrase;
        let s2k = self
            .s2k
            .unwrap_or_else(|| S2kParams::new_default(&mut rng, self.version));
        let (public_params, secret_params) = self.key_type.generate(&mut rng)?;
        let pub_key = PubKeyInner::new(
            self.version,
            self.key_type.to_alg(),
            self.created_at,
            self.expiration.map(|v| v.num_seconds() as u16),
            public_params,
        )?;
        let primary_pub_key = crate::packet::PublicKey::from_inner(pub_key)?;
        let mut primary_key = packet::SecretKey::new(primary_pub_key.clone(), secret_params)?;
        if let Some(passphrase) = passphrase {
            primary_key.set_password_with_s2k(&passphrase.into(), s2k)?;
        }

        let mut keyflags = KeyFlags::default();
        keyflags.set_certify(self.can_certify);
        keyflags.set_encrypt_comms(self.can_encrypt);
        keyflags.set_encrypt_storage(self.can_encrypt);
        keyflags.set_sign(self.can_sign);
        keyflags.set_authentication(self.can_authenticate);

        let primary_user_id = match self.primary_user_id {
            None => None,
            Some(id) => Some(UserId::from_str(Default::default(), id)?),
        };

        let mut features = packet::Features::default();
        if self.feature_seipd_v1 {
            features.set_seipd_v1(true);
        }
        if self.feature_seipd_v2 {
            features.set_seipd_v2(true);
        };

        Ok(SecretKey::new(
            primary_key,
            KeyDetails::new(
                primary_user_id,
                self.user_ids
                    .iter()
                    .map(|m| UserId::from_str(Default::default(), m))
                    .collect::<Result<Vec<_>, _>>()?,
                self.user_attributes,
                keyflags,
                features,
                self.preferred_symmetric_algorithms,
                self.preferred_hash_algorithms,
                self.preferred_compression_algorithms,
                self.preferred_aead_algorithms,
            ),
            Default::default(),
            self.subkeys
                .into_iter()
                .map(|subkey| {
                    let passphrase = subkey.passphrase;
                    let s2k = subkey
                        .s2k
                        .unwrap_or_else(|| S2kParams::new_default(&mut rng, subkey.version));
                    let (public_params, secret_params) = subkey.key_type.generate(&mut rng)?;
                    let mut keyflags = KeyFlags::default();
                    keyflags.set_encrypt_comms(subkey.can_encrypt);
                    keyflags.set_encrypt_storage(subkey.can_encrypt);
                    keyflags.set_sign(subkey.can_sign);
                    keyflags.set_authentication(subkey.can_authenticate);

                    let pub_key = PubKeyInner::new(
                        subkey.version,
                        subkey.key_type.to_alg(),
                        subkey.created_at,
                        subkey.expiration.map(|v| v.num_seconds() as u16),
                        public_params,
                    )?;
                    let pub_key = packet::PublicSubkey::from_inner(pub_key)?;
                    let mut sub = packet::SecretSubkey::new(pub_key, secret_params)?;

                    // Produce embedded back signature for signing-capable subkeys
                    let embedded = if subkey.can_sign {
                        let backsig =
                            sub.sign_primary_key_binding(&mut rng, &primary_pub_key, &"".into())?;

                        Some(backsig)
                    } else {
                        None
                    };

                    if let Some(passphrase) = passphrase {
                        sub.set_password_with_s2k(&passphrase.as_str().into(), s2k)?;
                    }

                    Ok(SecretSubkey::new(sub, keyflags, embedded))
                })
                .collect::<Result<Vec<_>>>()?,
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyType {
    /// Encryption & Signing with RSA and the given bitsize.
    Rsa(u32),
    /// Encrypting with ECDH
    ECDH(ECCCurve),
    /// Signing with Curve25519, legacy format (deprecated in RFC 9580)
    Ed25519Legacy,
    /// Signing with ECDSA
    ECDSA(ECCCurve),
    /// Signing with DSA for the given bitsize.
    Dsa(DsaKeySize),
    /// Signing with Ed25519
    Ed25519,
    /// Signing with Ed448
    Ed448,
    /// Encrypting with X25519
    X25519,
    /// Encrypting with X448
    X448,
    /// Encrypting using MlKem768-X25519
    #[cfg(feature = "draft-pqc")]
    MlKem768X25519,
    /// Encrypting using MlKem1024-X25519
    #[cfg(feature = "draft-pqc")]
    MlKem1024X448,
    /// Signing using ML DSA 65 ED25519
    #[cfg(feature = "draft-pqc")]
    MlDsa65Ed25519,
    /// Signing using ML DSA 87 ED448
    #[cfg(feature = "draft-pqc")]
    MlDsa87Ed448,
    /// Signing with SLH DSA Shake 128s
    #[cfg(feature = "draft-pqc")]
    SlhDsaShake128s,
    /// Signing with SLH DSA Shake 128f
    #[cfg(feature = "draft-pqc")]
    SlhDsaShake128f,
    /// Signing with SLH DSA Shake 256s
    #[cfg(feature = "draft-pqc")]
    SlhDsaShake256s,
}

#[derive(Clone, Debug, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum DsaKeySize {
    /// DSA parameter size constant: L = 1024, N = 160
    B1024 = 1024,
    /// DSA parameter size constant: L = 2048, N = 256
    B2048 = 2048,
    /// DSA parameter size constant: L = 3072, N = 256
    B3072 = 3072,
}

impl From<DsaKeySize> for dsa::KeySize {
    fn from(value: DsaKeySize) -> Self {
        match value {
            #[allow(deprecated)]
            DsaKeySize::B1024 => dsa::KeySize::DSA_1024_160,
            DsaKeySize::B2048 => dsa::KeySize::DSA_2048_256,
            DsaKeySize::B3072 => dsa::KeySize::DSA_3072_256,
        }
    }
}

impl KeyType {
    pub fn to_alg(&self) -> PublicKeyAlgorithm {
        match self {
            KeyType::Rsa(_) => PublicKeyAlgorithm::RSA,
            KeyType::ECDH(_) => PublicKeyAlgorithm::ECDH,
            KeyType::Ed25519Legacy => PublicKeyAlgorithm::EdDSALegacy,
            KeyType::ECDSA(_) => PublicKeyAlgorithm::ECDSA,
            KeyType::Dsa(_) => PublicKeyAlgorithm::DSA,
            KeyType::Ed25519 => PublicKeyAlgorithm::Ed25519,
            KeyType::Ed448 => PublicKeyAlgorithm::Ed448,
            KeyType::X25519 => PublicKeyAlgorithm::X25519,
            KeyType::X448 => PublicKeyAlgorithm::X448,
            #[cfg(feature = "draft-pqc")]
            KeyType::MlKem768X25519 => PublicKeyAlgorithm::MlKem768X25519,
            #[cfg(feature = "draft-pqc")]
            KeyType::MlKem1024X448 => PublicKeyAlgorithm::MlKem1024X448,
            #[cfg(feature = "draft-pqc")]
            KeyType::MlDsa65Ed25519 => PublicKeyAlgorithm::MlDsa65Ed25519,
            #[cfg(feature = "draft-pqc")]
            KeyType::MlDsa87Ed448 => PublicKeyAlgorithm::MlDsa87Ed448,
            #[cfg(feature = "draft-pqc")]
            KeyType::SlhDsaShake128s => PublicKeyAlgorithm::SlhDsaShake128s,
            #[cfg(feature = "draft-pqc")]
            KeyType::SlhDsaShake128f => PublicKeyAlgorithm::SlhDsaShake128f,
            #[cfg(feature = "draft-pqc")]
            KeyType::SlhDsaShake256s => PublicKeyAlgorithm::SlhDsaShake256s,
        }
    }

    /// Does this asymmetric algorithm support the cryptographic primitive of encryption?
    /// (Note that this is a subtly different meaning from OpenPGP's key flags.)
    pub fn can_sign(&self) -> bool {
        match self {
            KeyType::Rsa(_) => true,

            KeyType::Dsa(_)
            | KeyType::ECDSA(_)
            | KeyType::Ed25519Legacy
            | KeyType::Ed25519
            | KeyType::Ed448 => true,
            KeyType::ECDH(_) | KeyType::X25519 | KeyType::X448 => false,
            #[cfg(feature = "draft-pqc")]
            KeyType::MlKem768X25519 | KeyType::MlKem1024X448 => false,
            #[cfg(feature = "draft-pqc")]
            KeyType::MlDsa65Ed25519
            | KeyType::MlDsa87Ed448
            | KeyType::SlhDsaShake128s
            | KeyType::SlhDsaShake128f
            | KeyType::SlhDsaShake256s => true,
        }
    }

    /// Does this asymmetric algorithm support the cryptographic primitive of encryption?
    /// (Note that this is a subtly different meaning from OpenPGP's key flags.)
    pub fn can_encrypt(&self) -> bool {
        match self {
            KeyType::Rsa(_) => true,

            KeyType::Dsa(_)
            | KeyType::ECDSA(_)
            | KeyType::Ed25519Legacy
            | KeyType::Ed25519
            | KeyType::Ed448 => false,
            KeyType::ECDH(_) | KeyType::X25519 | KeyType::X448 => true,
            #[cfg(feature = "draft-pqc")]
            KeyType::MlKem768X25519 | KeyType::MlKem1024X448 => true,
            #[cfg(feature = "draft-pqc")]
            KeyType::MlDsa65Ed25519
            | KeyType::MlDsa87Ed448
            | KeyType::SlhDsaShake128s
            | KeyType::SlhDsaShake128f
            | KeyType::SlhDsaShake256s => false,
        }
    }

    pub fn generate<R: Rng + CryptoRng>(
        &self,
        rng: R,
    ) -> Result<(PublicParams, types::SecretParams)> {
        let (pub_params, plain) = match self {
            KeyType::Rsa(bit_size) => {
                let secret = rsa::SecretKey::generate(rng, *bit_size as usize)?;
                let public_params = PublicParams::RSA((&secret).into());
                let secret_params = PlainSecretParams::RSA(secret);
                (public_params, secret_params)
            }
            KeyType::ECDH(curve) => {
                let secret = ecdh::SecretKey::generate(rng, curve)?;
                let public_params = PublicParams::ECDH((&secret).into());
                let secret_params = PlainSecretParams::ECDH(secret);
                (public_params, secret_params)
            }
            KeyType::Ed25519Legacy => {
                let secret = ed25519::SecretKey::generate(rng, ed25519::Mode::EdDSALegacy);
                let public_params = PublicParams::EdDSALegacy((&secret).into());
                let secret_params = PlainSecretParams::Ed25519Legacy(secret);
                (public_params, secret_params)
            }
            KeyType::ECDSA(curve) => {
                let secret = ecdsa::SecretKey::generate(rng, curve)?;
                let public_params = PublicParams::ECDSA(
                    (&secret).try_into().expect("must not generate unuspported"),
                );
                let secret_params = PlainSecretParams::ECDSA(secret);
                (public_params, secret_params)
            }
            KeyType::Dsa(key_size) => {
                let secret = dsa::SecretKey::generate(rng, (*key_size).into());
                let public_params = PublicParams::DSA((&secret).into());
                let secret_params = PlainSecretParams::DSA(secret);
                (public_params, secret_params)
            }
            KeyType::Ed25519 => {
                let secret = ed25519::SecretKey::generate(rng, ed25519::Mode::Ed25519);
                let public_params = PublicParams::Ed25519((&secret).into());
                let secret_params = PlainSecretParams::Ed25519(secret);
                (public_params, secret_params)
            }
            KeyType::Ed448 => {
                let secret = ed448::SecretKey::generate(rng);
                let public_params = PublicParams::Ed448((&secret).into());
                let secret_params = PlainSecretParams::Ed448(secret);
                (public_params, secret_params)
            }
            KeyType::X25519 => {
                let secret = x25519::SecretKey::generate(rng);
                let public_params = PublicParams::X25519((&secret).into());
                let secret_params = PlainSecretParams::X25519(secret);
                (public_params, secret_params)
            }
            KeyType::X448 => {
                let secret = x448::SecretKey::generate(rng);
                let public_params = PublicParams::X448((&secret).into());
                let secret_params = PlainSecretParams::X448(secret);
                (public_params, secret_params)
            }
            #[cfg(feature = "draft-pqc")]
            KeyType::MlKem768X25519 => {
                let secret = ml_kem768_x25519::SecretKey::generate(rng);
                let public_params = PublicParams::MlKem768X25519((&secret).into());
                let secret_params = PlainSecretParams::MlKem768X25519(secret);
                (public_params, secret_params)
            }
            #[cfg(feature = "draft-pqc")]
            KeyType::MlKem1024X448 => {
                let secret = ml_kem1024_x448::SecretKey::generate(rng);
                let public_params = PublicParams::MlKem1024X448((&secret).into());
                let secret_params = PlainSecretParams::MlKem1024X448(secret);
                (public_params, secret_params)
            }
            #[cfg(feature = "draft-pqc")]
            KeyType::MlDsa65Ed25519 => {
                let secret = ml_dsa65_ed25519::SecretKey::generate(rng);
                let public_params = PublicParams::MlDsa65Ed25519((&secret).into());
                let secret_params = PlainSecretParams::MlDsa65Ed25519(secret);
                (public_params, secret_params)
            }
            #[cfg(feature = "draft-pqc")]
            KeyType::MlDsa87Ed448 => {
                let secret = ml_dsa87_ed448::SecretKey::generate(rng);
                let public_params = PublicParams::MlDsa87Ed448((&secret).into());
                let secret_params = PlainSecretParams::MlDsa87Ed448(secret);
                (public_params, secret_params)
            }
            #[cfg(feature = "draft-pqc")]
            KeyType::SlhDsaShake128s => {
                let secret = slh_dsa_shake128s::SecretKey::generate(rng);
                let public_params = PublicParams::SlhDsaShake128s((&secret).into());
                let secret_params = PlainSecretParams::SlhDsaShake128s(secret);
                (public_params, secret_params)
            }
            #[cfg(feature = "draft-pqc")]
            KeyType::SlhDsaShake128f => {
                let secret = slh_dsa_shake128f::SecretKey::generate(rng);
                let public_params = PublicParams::SlhDsaShake128f((&secret).into());
                let secret_params = PlainSecretParams::SlhDsaShake128f(secret);
                (public_params, secret_params)
            }
            #[cfg(feature = "draft-pqc")]
            KeyType::SlhDsaShake256s => {
                let secret = slh_dsa_shake256s::SecretKey::generate(rng);
                let public_params = PublicParams::SlhDsaShake256s((&secret).into());
                let secret_params = PlainSecretParams::SlhDsaShake256s(secret);
                (public_params, secret_params)
            }
        };

        Ok((pub_params, types::SecretParams::Plain(plain)))
    }
}
