use alloc::{
    collections::VecDeque,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use chrono::SubsecRound;
use crc24::Crc24Hasher;
use generic_array::typenum::U64;
use log::debug;
use rand::{CryptoRng, Rng};
use zeroize::Zeroizing;

use super::ArmorOptions;
use crate::{
    armor,
    composed::Esk,
    crypto::{
        aead::{AeadAlgorithm, ChunkSize},
        hash::HashAlgorithm,
        sym::SymmetricKeyAlgorithm,
    },
    errors::{bail, ensure, ensure_eq, Result},
    line_writer::{LineBreak, LineWriter},
    normalize_lines::NormalizedReader,
    packet::{
        CompressedDataGenerator, DataMode, LiteralDataGenerator, LiteralDataHeader,
        MaybeNormalizedReader, OnePassSignature, PacketHeader, PacketTrait,
        PublicKeyEncryptedSessionKey, SignatureHasher, SignatureType, SignatureVersionSpecific,
        Subpacket, SubpacketData, SymEncryptedProtectedData, SymEncryptedProtectedDataConfig,
        SymKeyEncryptedSessionKey,
    },
    ser::Serialize,
    types::{
        CompressionAlgorithm, Fingerprint, KeyId, KeyVersion, PacketHeaderVersion, PacketLength,
        Password, SecretKeyTrait, StringToKey, Tag,
    },
    util::{fill_buffer, TeeWriter},
};

use crate::io::{Read, Write};


pub type DummyReader = &'static [u8];

/// Constructs message from a given data source.
///
/// All data is processed in a streaming fashion, with minimal memory allocations.
///
/// If the file size is known upfront (fixed buffer, or file source), the resulting packets
/// will be fixed size lengths (unless compression is involved).
///
/// If the file size is not known upfront, partial packets will be generated, at each level
/// (encryption, compression, literal data).
///
/// If the total data fits into a single chunk, a single fixed packet is generated.
pub struct Builder<'a, R = DummyReader, E = NoEncryption> {
    source: Source<R>,
    compression: Option<CompressionAlgorithm>,
    signing: Vec<SigningConfig<'a>>,
    encryption: E,
    /// The chunk size when generating partial packets
    partial_chunk_size: u32,
    // XXX: text-mode literals (including Utf8) are not currently supported by this builder:
    // Normalizing line endings in them may change their length, and we don't currently handle this.
    // However, the usefulness of text-mode literal data packets is questionable.
    data_mode: DataMode,
    /// Only Binary or Text are allowed
    sign_typ: SignatureType,
}

#[derive(Clone)]
enum Source<R = DummyReader> {
    Bytes { name: Bytes, bytes: Bytes },
    Reader { file_name: Bytes, reader: R },
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub struct NoEncryption;

#[derive(Debug, PartialEq, Clone)]
pub struct EncryptionSeipdV1 {
    session_key: Zeroizing<Vec<u8>>,
    sym_esks: Vec<SymKeyEncryptedSessionKey>,
    pub_esks: Vec<PublicKeyEncryptedSessionKey>,
    sym_alg: SymmetricKeyAlgorithm,
}

#[derive(derive_more::Debug, PartialEq, Clone)]
pub struct EncryptionSeipdV2 {
    session_key: Zeroizing<Vec<u8>>,
    sym_esks: Vec<SymKeyEncryptedSessionKey>,
    pub_esks: Vec<PublicKeyEncryptedSessionKey>,
    sym_alg: SymmetricKeyAlgorithm,
    aead: AeadAlgorithm,
    chunk_size: ChunkSize,
    #[debug("{}", hex::encode(salt))]
    salt: [u8; 32],
}

pub trait Encryption: PartialEq {
    fn encrypt<R, READ, W>(
        self,
        rng: R,
        generator: READ,
        partial_chunk_size: u32,
        len: Option<u32>,
        out: W,
    ) -> Result<()>
    where
        R: Rng + CryptoRng,
        READ: Read,
        W: Write;

    fn is_plaintext(&self) -> bool;
}

/// Configures a signing key and how to use it.
#[derive(Debug)]
struct SigningConfig<'a> {
    /// The key to sign with
    key: &'a dyn SecretKeyTrait,
    /// A password to unlock it
    key_pw: Password,
    /// The hash algorithm to be used when signing.
    hash_algorithm: HashAlgorithm,
}

impl<'a> SigningConfig<'a> {
    /// Create a new signing configuration.
    fn new(key: &'a dyn SecretKeyTrait, key_pw: Password, hash: HashAlgorithm) -> Self {
        Self {
            key,
            key_pw,
            hash_algorithm: hash,
        }
    }
}

/// The default chunk size for partial packets.
pub const DEFAULT_PARTIAL_CHUNK_SIZE: u32 = 1024 * 512;

impl Builder<'_, DummyReader> {
    /// Source the data from the given byte buffer.
    pub fn from_bytes(name: impl Into<Bytes>, bytes: impl Into<Bytes>) -> Self {
        Self {
            source: Source::Bytes {
                name: name.into(),
                bytes: bytes.into(),
            },
            compression: None,
            encryption: NoEncryption,
            partial_chunk_size: DEFAULT_PARTIAL_CHUNK_SIZE,
            data_mode: DataMode::Binary,
            sign_typ: SignatureType::Binary,
            signing: Vec::new(),
        }
    }
}

fn prepare<R>(
    mut rng: R,
    typ: SignatureType,
    keys: &[SigningConfig<'_>],
) -> Result<Vec<(crate::packet::SignatureConfig, OnePassSignature)>>
where
    R: Rng + CryptoRng,
{
    let mut out = Vec::new();

    let keys_len = keys.len();
    for (i, config) in keys.iter().enumerate() {
        let is_last = i == keys_len - 1;

        // Signature setup
        let key_id = config.key.key_id();
        let algorithm = config.key.algorithm();
        let hash_alg = config.hash_algorithm;

        let hashed_subpackets = vec![
            Subpacket::regular(SubpacketData::IssuerFingerprint(config.key.fingerprint()))?,
            Subpacket::regular(SubpacketData::SignatureCreationTime(
                chrono::Utc::now().trunc_subsecs(0),
            ))?,
        ];

        // prepare signing
        let mut sig_config = match config.key.version() {
            KeyVersion::V4 => crate::packet::SignatureConfig::v4(typ, algorithm, hash_alg),
            KeyVersion::V6 => {
                crate::packet::SignatureConfig::v6(&mut rng, typ, algorithm, hash_alg)?
            }
            v => bail!("unsupported key version {:?}", v),
        };
        sig_config.hashed_subpackets = hashed_subpackets;
        if config.key.version() <= KeyVersion::V4 {
            sig_config.unhashed_subpackets =
                vec![Subpacket::regular(SubpacketData::Issuer(key_id))?];
        }

        let mut ops = match config.key.version() {
            KeyVersion::V4 => OnePassSignature::v3(typ, hash_alg, algorithm, key_id),
            KeyVersion::V6 => {
                let SignatureVersionSpecific::V6 { ref salt } = sig_config.version_specific else {
                    // This should never happen
                    bail!("Inconsistent Signature and OnePassSignature version")
                };

                let Fingerprint::V6(fp) = config.key.fingerprint() else {
                    bail!("Inconsistent Signature and Fingerprint version")
                };

                OnePassSignature::v6(typ, hash_alg, algorithm, salt.clone(), fp)
            }
            v => bail!("Unsupported key version {:?}", v),
        };

        if !is_last {
            ops.set_is_nested();
        }

        out.push((sig_config, ops));
    }

    Ok(out)
}

impl<'a, R: Read> Builder<'a, R, NoEncryption> {
    /// Encrypt this message using Seipd V1.
    pub fn seipd_v1<RAND>(
        self,
        mut rng: RAND,
        sym_alg: SymmetricKeyAlgorithm,
    ) -> Builder<'a, R, EncryptionSeipdV1>
    where
        RAND: CryptoRng + Rng,
    {
        let session_key = sym_alg.new_session_key(&mut rng);
        Builder {
            source: self.source,
            compression: self.compression,
            partial_chunk_size: self.partial_chunk_size,
            data_mode: self.data_mode,
            sign_typ: self.sign_typ,
            encryption: EncryptionSeipdV1 {
                sym_alg,
                session_key,
                sym_esks: Vec::new(),
                pub_esks: Vec::new(),
            },
            signing: self.signing,
        }
    }
}

impl<'a, R: Read> Builder<'a, R, NoEncryption> {
    /// Encrypt this message using Seipd V2.
    pub fn seipd_v2<RAND>(
        self,
        mut rng: RAND,
        sym_alg: SymmetricKeyAlgorithm,
        aead: AeadAlgorithm,
        chunk_size: ChunkSize,
    ) -> Builder<'a, R, EncryptionSeipdV2>
    where
        RAND: CryptoRng + Rng,
    {
        let session_key = sym_alg.new_session_key(&mut rng);

        let mut salt = [0u8; 32];
        rng.fill_bytes(&mut salt);

        Builder {
            source: self.source,
            compression: self.compression,
            partial_chunk_size: self.partial_chunk_size,
            data_mode: self.data_mode,
            sign_typ: self.sign_typ,
            encryption: EncryptionSeipdV2 {
                sym_alg,
                session_key,
                chunk_size,
                aead,
                salt,
                sym_esks: Vec::new(),
                pub_esks: Vec::new(),
            },
            signing: self.signing,
        }
    }
}

impl<R: Read> Builder<'_, R, EncryptionSeipdV1> {
    /// Encrypt to a public key
    pub fn encrypt_to_key<RAND, K>(&mut self, mut rng: RAND, pkey: &K) -> Result<&mut Self>
    where
        RAND: CryptoRng + Rng,
        K: crate::types::PublicKeyTrait,
    {
        // Encrypt (sym) the session key using the provided password.
        let pkes = PublicKeyEncryptedSessionKey::from_session_key_v3(
            &mut rng,
            &self.encryption.session_key,
            self.encryption.sym_alg,
            pkey,
        )?;
        self.encryption.pub_esks.push(pkes);
        Ok(self)
    }

    /// Encrypt to a public key, but leave the recipient field unset
    pub fn encrypt_to_key_anonymous<RAND, K>(
        &mut self,
        mut rng: RAND,
        pkey: &K,
    ) -> Result<&mut Self>
    where
        RAND: CryptoRng + Rng,
        K: crate::types::PublicKeyTrait,
    {
        // Encrypt (sym) the session key using the provided password.
        let mut pkes = PublicKeyEncryptedSessionKey::from_session_key_v3(
            &mut rng,
            &self.encryption.session_key,
            self.encryption.sym_alg,
            pkey,
        )?;
        // Blank out the recipient id
        if let PublicKeyEncryptedSessionKey::V3 { id, .. } = &mut pkes {
            *id = KeyId::WILDCARD;
        }

        self.encryption.pub_esks.push(pkes);
        Ok(self)
    }

    /// Encrypt to a password.
    pub fn encrypt_with_password(
        &mut self,
        s2k: StringToKey,
        msg_pw: &Password,
    ) -> Result<&mut Self> {
        let esk = SymKeyEncryptedSessionKey::encrypt_v4(
            msg_pw,
            &self.encryption.session_key,
            s2k,
            self.encryption.sym_alg,
        )?;
        self.encryption.sym_esks.push(esk);
        Ok(self)
    }

    /// Returns the currently used session key.
    ///
    /// WARNING: this is sensitive material, and leaking it can lead to
    /// a compromise of the data.
    pub fn session_key(&self) -> &Zeroizing<Vec<u8>> {
        &self.encryption.session_key
    }
}

impl<R: Read> Builder<'_, R, EncryptionSeipdV2> {
    /// Encrypt to a public key
    pub fn encrypt_to_key<RAND, K>(&mut self, mut rng: RAND, pkey: &K) -> Result<&mut Self>
    where
        RAND: CryptoRng + Rng,
        K: crate::types::PublicKeyTrait,
    {
        // Encrypt (sym) the session key using the provided password.
        let pkes = PublicKeyEncryptedSessionKey::from_session_key_v6(
            &mut rng,
            &self.encryption.session_key,
            pkey,
        )?;
        self.encryption.pub_esks.push(pkes);
        Ok(self)
    }

    /// Encrypt to a public key, but leave the recipient field unset
    pub fn encrypt_to_key_anonymous<RAND, K>(
        &mut self,
        mut rng: RAND,
        pkey: &K,
    ) -> Result<&mut Self>
    where
        RAND: CryptoRng + Rng,
        K: crate::types::PublicKeyTrait,
    {
        // Encrypt (sym) the session key using the provided password.
        let mut pkes = PublicKeyEncryptedSessionKey::from_session_key_v6(
            &mut rng,
            &self.encryption.session_key,
            pkey,
        )?;
        // Blank out the recipient id
        if let PublicKeyEncryptedSessionKey::V6 { fingerprint, .. } = &mut pkes {
            *fingerprint = None;
        }

        self.encryption.pub_esks.push(pkes);
        Ok(self)
    }

    /// Encrypt to a password.
    pub fn encrypt_with_password<RAND>(
        &mut self,
        mut rng: RAND,
        s2k: StringToKey,
        msg_pw: &Password,
    ) -> Result<&mut Self>
    where
        RAND: Rng + CryptoRng,
    {
        // Encrypt (sym) the session key using the provided password.
        let esk = SymKeyEncryptedSessionKey::encrypt_v6(
            &mut rng,
            msg_pw,
            &self.encryption.session_key,
            s2k,
            self.encryption.sym_alg,
            self.encryption.aead,
        )?;
        self.encryption.sym_esks.push(esk);
        Ok(self)
    }

    /// Returns the currently used session key.
    ///
    /// WARNING: this is sensitive material, and leaking it can lead to
    /// a compromise of the data.
    pub fn session_key(&self) -> &Zeroizing<Vec<u8>> {
        &self.encryption.session_key
    }
}

impl<R: Read> Builder<'_, R, NoEncryption> {
    /// Source the data from a reader.
    pub fn from_reader(file_name: impl Into<Bytes>, reader: R) -> Self {
        Self {
            source: Source::Reader {
                file_name: file_name.into(),
                reader,
            },
            compression: None,
            encryption: NoEncryption,
            partial_chunk_size: DEFAULT_PARTIAL_CHUNK_SIZE,
            data_mode: DataMode::Binary,
            sign_typ: SignatureType::Binary,
            signing: Vec::new(),
        }
    }
}

impl<'a, R: Read, E: Encryption> Builder<'a, R, E> {
    // XXX: we don't currently allow setting the literal data mode, it *must* be binary!

    // /// Configure the [`DataMode`] for the literal data portion.
    // ///
    // /// Defaults to `DataMode::Binary`
    // ///
    // /// If the mode is set to `DataMode::Utf8` (or `DataMode::Text`), the [SignatureType] will be `Text`, and line endings will be hashed in normalized form.
    // pub fn data_mode(mut self, mode: DataMode) -> Self {
    //     assert_eq!(mode, DataMode::Binary); // FIXME
    //
    //     self.data_mode = mode;
    //     self
    // }

    /// Configure the data signatures to use `SignatureType::Binary`.
    ///
    /// This is the default.
    pub fn sign_binary(&mut self) -> &mut Self {
        self.sign_typ = SignatureType::Binary;
        self
    }

    /// Configure the data signatures to use `SignatureType::Text`.
    pub fn sign_text(&mut self) -> &mut Self {
        self.sign_typ = SignatureType::Text;
        self
    }

    /// Set the chunk size, which controls how large partial packets
    /// will be.
    ///
    /// Due to the restrictions on partial packet lengths, this size
    /// - must be larger than `512`,
    /// - must be a power of 2.
    ///
    /// Defaults to [`DEFAULT_PARTIAL_CHUNK_SIZE`].
    pub fn partial_chunk_size(&mut self, size: u32) -> Result<&mut Self> {
        ensure!(size >= 512, "partial chunk size must be at least 512");
        ensure!(
            size.is_power_of_two(),
            "partial chunk size must be a power of two"
        );
        self.partial_chunk_size = size;
        Ok(self)
    }

    /// Configure compression.
    ///
    /// Defaults to no compression.
    pub fn compression(&mut self, compression: CompressionAlgorithm) -> &mut Self {
        self.compression.replace(compression);
        self
    }

    pub fn sign(
        &mut self,
        key: &'a dyn SecretKeyTrait,
        key_pw: Password,
        hash_algorithm: HashAlgorithm,
    ) -> &mut Self {
        self.signing
            .push(SigningConfig::new(key, key_pw, hash_algorithm));
        self
    }

    /// Write the data out to a writer.
    pub fn to_writer<RAND, W>(self, rng: RAND, out: W) -> Result<()>
    where
        RAND: Rng + CryptoRng,
        W: Write,
    {
        let sign_typ = self.sign_typ;

        match self.source {
            Source::Bytes { name, bytes } => {
                debug!("sourcing bytes {:?}: {} bytes", name, bytes.len());
                // If the size is larger than u32::MAX switch to None, as
                // fixed packets can only be at most u32::MAX size large
                let len = bytes.len().try_into().ok();
                let source = bytes.reader();
                to_writer_inner(
                    rng,
                    name,
                    source,
                    len,
                    sign_typ,
                    self.signing,
                    self.data_mode,
                    self.partial_chunk_size,
                    self.compression,
                    self.encryption,
                    out,
                )?;
            }
            Source::Reader { file_name, reader } => {
                to_writer_inner(
                    rng,
                    file_name,
                    reader,
                    None,
                    sign_typ,
                    self.signing,
                    self.data_mode,
                    self.partial_chunk_size,
                    self.compression,
                    self.encryption,
                    out,
                )?;
            }
        }
        Ok(())
    }

    /// Write the data not as binary, but ascii armor encoded.
    pub fn to_armored_writer<RAND, W>(
        self,
        rng: RAND,
        opts: ArmorOptions<'_>,
        mut out: W,
    ) -> Result<()>
    where
        RAND: Rng + CryptoRng,
        W: Write,
    {
        let typ = armor::BlockType::Message;

        // write header
        armor::write_header(&mut out, typ, opts.headers)?;

        // write body
        let mut crc_hasher = opts.include_checksum.then(Crc24Hasher::new);
        {
            let crc_hasher = crc_hasher.as_mut();
            let mut line_wrapper = LineWriter::<_, U64>::new(out.by_ref(), LineBreak::Lf);
            let mut enc = armor::Base64Encoder::new(&mut line_wrapper);

            if let Some(crc_hasher) = crc_hasher {
                let mut tee = TeeWriter::new(crc_hasher, &mut enc);
                self.to_writer(rng, &mut tee)?;
            } else {
                self.to_writer(rng, &mut enc)?;
            }
        }

        // write footer
        armor::write_footer(&mut out, typ, crc_hasher)?;
        out.flush()?;

        Ok(())
    }

    /// Write the data out directly to a `Vec<u8>`.
    pub fn to_vec<RAND>(self, rng: RAND) -> Result<Vec<u8>>
    where
        RAND: Rng + CryptoRng,
    {
        let mut out = Vec::new();
        self.to_writer(rng, &mut out)?;
        Ok(out)
    }

    /// Write the data as ascii armored data, directly to a `String`.
    pub fn to_armored_string<RAND>(self, rng: RAND, opts: ArmorOptions<'_>) -> Result<String>
    where
        RAND: Rng + CryptoRng,
    {
        let mut out = Vec::new();
        self.to_armored_writer(rng, opts, &mut out)?;
        let out = String::from_utf8(out).expect("ascii armor is utf8");
        Ok(out)
    }
}

#[allow(clippy::too_many_arguments)]
fn to_writer_inner<RAND, R, W, E>(
    mut rng: RAND,
    _name: Bytes,
    source: R,
    source_len: Option<u32>,
    sign_typ: SignatureType,
    signers: Vec<SigningConfig<'_>>,
    data_mode: DataMode,
    partial_chunk_size: u32,
    compression: Option<CompressionAlgorithm>,
    encryption: E,
    out: W,
) -> Result<()>
where
    RAND: Rng + CryptoRng,
    R: Read,
    W: Write,
    E: Encryption,
{
    // Construct Literal Data Packet (inner)
    let literal_data_header = LiteralDataHeader::new(data_mode);

    let sign_generator = SignGenerator::new(
        &mut rng,
        sign_typ,
        literal_data_header,
        partial_chunk_size,
        source,
        signers,
        source_len,
    )?;

    match compression {
        Some(compression) => {
            let len = sign_generator.len();
            let generator =
                CompressedDataGenerator::new(compression, sign_generator, len, partial_chunk_size)?;

            encryption.encrypt(&mut rng, generator, partial_chunk_size, None, out)?;
        }
        None => {
            let len = sign_generator.len();
            encryption.encrypt(&mut rng, sign_generator, partial_chunk_size, len, out)?;
        }
    }
    Ok(())
}

impl Encryption for NoEncryption {
    fn encrypt<R, READ, W>(
        self,
        _rng: R,
        mut generator: READ,
        _partial_chunk_size: u32,
        _len: Option<u32>,
        mut out: W,
    ) -> Result<()>
    where
        R: Rng + CryptoRng,
        READ: Read,
        W: Write,
    {
        let mut buf = [0u8; 4096];
        loop {
            let read = generator.read(&mut buf)?;
            if read == 0 {
                break;
            }
            out.write_all(&buf[..read])?;
        }
        Ok(())
    }

    fn is_plaintext(&self) -> bool {
        true
    }
}

impl Encryption for EncryptionSeipdV1 {
    fn encrypt<R, READ, W>(
        self,
        rng: R,
        generator: READ,
        partial_chunk_size: u32,
        len: Option<u32>,
        mut out: W,
    ) -> Result<()>
    where
        R: Rng + CryptoRng,
        READ: Read,
        W: Write,
    {
        let EncryptionSeipdV1 {
            session_key,
            sym_esks,
            pub_esks,
            sym_alg,
        } = self;
        // Write out symmetric esks
        for sym_esk in sym_esks {
            let esk = Esk::SymKeyEncryptedSessionKey(sym_esk);
            esk.to_writer(&mut out)?;
        }
        // Write out public esks
        for pub_esk in pub_esks {
            let esk = Esk::PublicKeyEncryptedSessionKey(pub_esk);
            esk.to_writer(&mut out)?;
        }

        let config = SymEncryptedProtectedDataConfig::V1;
        let encrypted = sym_alg.stream_encryptor(rng, &session_key, generator)?;

        encrypt_write(
            Tag::SymEncryptedProtectedData,
            partial_chunk_size,
            sym_alg,
            config,
            len,
            encrypted,
            out,
        )
    }

    fn is_plaintext(&self) -> bool {
        false
    }
}

impl Encryption for EncryptionSeipdV2 {
    fn encrypt<R, READ, W>(
        self,
        _rng: R,
        generator: READ,
        partial_chunk_size: u32,
        len: Option<u32>,
        mut out: W,
    ) -> Result<()>
    where
        R: Rng + CryptoRng,
        READ: Read,
        W: Write,
    {
        let EncryptionSeipdV2 {
            session_key,
            sym_esks,
            pub_esks,
            sym_alg,
            aead,
            chunk_size,
            salt,
        } = self;
        ensure_eq!(
            session_key.len(),
            sym_alg.key_size(),
            "Unexpected session key length for {:?}",
            sym_alg
        );

        // Write out symmetric esks
        for sym_esk in sym_esks {
            let esk = Esk::SymKeyEncryptedSessionKey(sym_esk);
            esk.to_writer(&mut out)?;
        }
        // Write out public esks
        for pub_esk in pub_esks {
            let esk = Esk::PublicKeyEncryptedSessionKey(pub_esk);
            esk.to_writer(&mut out)?;
        }
        let config = SymEncryptedProtectedDataConfig::V2 {
            sym_alg,
            aead,
            chunk_size,
            salt,
        };

        let encrypted = SymEncryptedProtectedData::encrypt_seipdv2_stream(
            sym_alg,
            aead,
            chunk_size,
            &session_key,
            salt,
            generator,
        )?;

        encrypt_write(
            Tag::SymEncryptedProtectedData,
            partial_chunk_size,
            sym_alg,
            config,
            len,
            encrypted,
            out,
        )
    }

    fn is_plaintext(&self) -> bool {
        false
    }
}

fn encrypt_write<R: Read, W: Write>(
    tag: Tag,
    partial_chunk_size: u32,
    sym_alg: SymmetricKeyAlgorithm,
    config: SymEncryptedProtectedDataConfig,
    len: Option<u32>,
    mut encrypted: R,
    mut out: W,
) -> Result<()> {
    debug!(
        "encrypt {:?}: at {} chunks, total len: {:?}",
        tag, partial_chunk_size, len
    );
    match len {
        None => {
            let mut buf = [0u8; 4096];
            loop {
                let read = encrypted.read(&mut buf)?;
                if read == 0 {
                    break;
                }

                let len = PacketLength::Partial(read.try_into()?);
                let packet_header =
                    PacketHeader::from_parts(PacketHeaderVersion::New, tag, len)?;
                packet_header.to_writer(&mut out)?;
                out.write_all(&buf[..read])?;
            }

            // write empty packet to signal end
            let packet_header =
                PacketHeader::from_parts(PacketHeaderVersion::New, tag, PacketLength::Partial(0))?;
            packet_header.to_writer(&mut out)?;
        }
        Some(in_size) => {
            // calculate expected encrypted file size
            let enc_file_size = sym_alg.encrypted_protected_len(in_size.try_into()?);
            let packet_len = config.write_len() + enc_file_size;

            let packet_header = PacketHeader::from_parts(
                PacketHeaderVersion::New,
                tag,
                PacketLength::Fixed(packet_len.try_into()?),
            )?;
            packet_header.to_writer(&mut out)?;
            config.to_writer(&mut out)?;

            let mut buf = [0u8; 4096];
            loop {
                let read = encrypted.read(&mut buf)?;
                if read == 0 {
                    break;
                }
                out.write_all(&buf[..read])?;
            }
        }
    }

    Ok(())
}

struct SignGenerator<'a, R: Read> {
    total_len: Option<u32>,
    state: State<'a, R>,
}

enum State<'a, R: Read> {
    /// Buffer a single OPS
    Ops {
        /// We pop off one OPS at a time, until this is empty
        ops: VecDeque<OnePassSignature>,
        buffer: BytesMut,
        configs: VecDeque<SigningConfig<'a>>,
        source: LiteralDataGenerator<SignatureHashers<MaybeNormalizedReader<R>>>,
    },
    /// Pass through the source,
    /// sending the data to the hashers as well
    Body {
        configs: VecDeque<SigningConfig<'a>>,
        source: LiteralDataGenerator<SignatureHashers<MaybeNormalizedReader<R>>>,
    },
    /// Buffer a single Signature
    Signatures {
        buffer: BytesMut,
        configs: VecDeque<SigningConfig<'a>>,
        hashers: VecDeque<SignatureHasher>,
    },
    Error,
    Done,
}

struct SignatureHashers<R> {
    hashers: VecDeque<SignatureHasher>,
    source: R,
}

impl<R> SignatureHashers<R> {
    fn update_hashers(&mut self, buf: &[u8]) {
        for hasher in &mut self.hashers {
            hasher.update(buf);
        }
    }
}

impl<R: Read> Read for SignatureHashers<R> {
    fn read(&mut self, buf: &mut [u8]) -> crate::io::Result<usize> {
        let read = self.source.read(buf)?;
        self.update_hashers(&buf[..read]);
        Ok(read)
    }
}

impl<'a, R: Read> SignGenerator<'a, R> {
    fn new<RAND>(
        mut rng: RAND,
        typ: SignatureType,
        literal_data_header: LiteralDataHeader,
        chunk_size: u32,
        source: R,
        signers: Vec<SigningConfig<'a>>,
        source_len: Option<u32>,
    ) -> Result<Self>
    where
        RAND: CryptoRng + Rng,
    {
        let prep = prepare(&mut rng, typ, &signers)?;
        let mut configs = VecDeque::with_capacity(prep.len());
        let mut sign_hashers = VecDeque::with_capacity(prep.len());
        let mut ops = VecDeque::with_capacity(prep.len());
        for ((config, op), signer) in prep.into_iter().zip(signers.into_iter()) {
            ops.push_back(op);
            sign_hashers.push_back(config.into_hasher()?);
            configs.push_back(signer);
        }

        let normalized_source = if literal_data_header.mode() == DataMode::Utf8 {
            MaybeNormalizedReader::Normalized(NormalizedReader::new(source, LineBreak::Crlf))
        } else {
            MaybeNormalizedReader::Raw(source)
        };

        let hashed_source = SignatureHashers {
            hashers: sign_hashers,
            source: normalized_source,
        };

        let source =
            LiteralDataGenerator::new(literal_data_header, hashed_source, source_len, chunk_size)?;
        let _len = source.len();

        let total_len = None;
        // len.map(|source_len| {
        // calculate final length
        //  let ops_len = ops.iter().map(|o| o.write_len_with_header()).sum();
        // let sigs_len = sign_hashers
        //     .iter()
        //     .map(|(signer, hasher)| hasher.write_len_with_header())
        //     .sum();
        // TODO:
        // ops_len + source_len + sigs_len
        // });

        let state = if ops.is_empty() {
            State::Body { configs, source }
        } else {
            State::Ops {
                ops,
                buffer: BytesMut::new(),
                configs,
                source,
            }
        };

        Ok(Self { total_len, state })
    }

    /// Returns the expected write length if known upfront.
    fn len(&self) -> Option<u32> {
        self.total_len
    }
}

impl<R: Read> Read for SignGenerator<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> crate::io::Result<usize> {
        use core::mem;

        loop {
            let next_state = match &mut self.state {
                State::Ops {
                    ops,
                    buffer,
                    configs,
                    source,
                } => {
                    if buffer.has_remaining() {
                        let written = buffer.remaining().min(buf.len());
                        buf[..written].copy_from_slice(&buffer[..written]);
                        buffer.advance(written);
                        return Ok(written);
                    }

                    match ops.pop_front() {
                        Some(op) => {
                            op.to_writer_with_header(buffer)?;
                            continue;
                        }
                        None => State::Body {
                            configs: mem::take(configs),
                            source: mem::replace(
                                source,
                                // dummy
                                LiteralDataGenerator::new(
                                    LiteralDataHeader::new(DataMode::Binary),
                                    SignatureHashers {
                                        hashers: Default::default(),
                                        source: MaybeNormalizedReader::Raw(&[]),
                                    },
                                    None,
                                    0,
                                )
                                .unwrap(),
                            ),
                        },
                    }
                }
                State::Body { configs, source } => {
                    let read = source.read(buf)?;
                    if read == 0 {
                        // done reading the body, create signatures
                        let hashers = source.inner_mut().hashers.drain(..).collect();
                        State::Signatures {
                            buffer: BytesMut::new(),
                            configs: mem::take(configs),
                            hashers,
                        }
                    } else {
                        return Ok(read);
                    }
                }
                State::Signatures {
                    buffer,
                    configs,
                    hashers,
                } => {
                    if buffer.has_remaining() {
                        let written = buffer.remaining().min(buf.len());
                        buf[..written].copy_from_slice(&buffer[..written]);
                        buffer.advance(written);
                        return Ok(written);
                    }

                    match configs.pop_front() {
                        Some(config) => {
                            let mut hasher = hashers.pop_front().expect("equal length");
                            hasher.finalize(&config.key, &config.key_pw)?.to_writer(buffer)?;
                            continue;
                        }
                        None => State::Done,
                    }
                }
                State::Done => return Ok(0),
                State::Error => panic!("error state"),
            };

            self.state = next_state;
        }
    }
}
