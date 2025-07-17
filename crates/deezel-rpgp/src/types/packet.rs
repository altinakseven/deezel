extern crate alloc;
use crate::io::BufRead;

use crate::io::{Write, WriteBytesExt};
use byteorder::BigEndian;
use log::debug;
use num_enum::{FromPrimitive, IntoPrimitive, TryFromPrimitive};

use crate::{errors::Result, parsing_reader::BufReadParsing};

/// Represents the packet length.
#[derive(derive_more::Debug, PartialEq, Eq, Clone, Copy)]
pub enum PacketLength {
    Fixed(u32),
    Indeterminate,
    Partial(u32),
}

impl PacketLength {
    /// Returns how many bytes encoding the given length as fixed encoding would need.
    pub fn fixed_encoding_len(len: u32) -> usize {
        if len < 192 {
            1
        } else if len < 8384 {
            2
        } else {
            1 + 4
        }
    }

    pub fn try_from_reader<R: BufRead>(mut r: R) -> crate::io::Result<Self> {
        let olen = r.read_u8()?;
        let len = match olen {
            // One-Octet Lengths
            0..=191 => PacketLength::Fixed(olen.into()),
            // Two-Octet Lengths
            192..=223 => {
                let a = r.read_u8()?;
                let l = ((olen as u32 - 192) << 8) + 192 + a as u32;
                PacketLength::Fixed(l)
            }
            // Partial Body Lengths
            224..=254 => PacketLength::Partial(1 << (olen as usize & 0x1F)),
            // Five-Octet Lengths
            255 => {
                let len = r.read_be_u32()?;
                PacketLength::Fixed(len)
            }
        };
        Ok(len)
    }

    /// Returns the length in bytes, if it is specified.
    pub fn maybe_len(&self) -> Option<u32> {
        match self {
            Self::Fixed(len) => Some(*len),
            Self::Indeterminate => None,
            Self::Partial(len) => Some(*len),
        }
    }

    pub fn to_writer_new<W: Write>(&self, writer: &mut W) -> Result<()> {
        match self {
            PacketLength::Fixed(len) => {
                if *len < 192 {
                    writer.write_u8(*len as u8)?;
                } else if *len < 8384 {
                    writer.write_u8((((len - 192) >> 8) + 192) as u8)?;
                    writer.write_u8(((len - 192) & 0xFF) as u8)?;
                } else {
                    writer.write_u8(255)?;
                    writer.write_u32::<BigEndian>(*len)?;
                }
            }
            PacketLength::Indeterminate => {
                unreachable!("invalid state: indeterminate lengths for new style packet header");
            }
            PacketLength::Partial(len) => {
                debug_assert_eq!(len.count_ones(), 1); // must be a power of two

                // y & 0x1F
                let n = len.trailing_zeros();
                let n = (224 + n) as u8;
                writer.write_u8(n)?;
            }
        }
        Ok(())
    }
}

/// Packet Type ID, see <https://www.rfc-editor.org/rfc/rfc9580.html#packet-types>
///
/// The "Packet Type ID" was called "Packet tag" in RFC 4880 (Section 4.3 "Packet Tags").
/// Ref <https://www.rfc-editor.org/rfc/rfc9580.html#appendix-B.1-3.7.1>
///
/// However, rPGP will continue to use the term "(Packet) Tag" for the time being.
#[derive(Debug, PartialEq, Eq, Clone, Copy, FromPrimitive, IntoPrimitive)]
#[repr(u8)]
#[non_exhaustive]
pub enum Tag {
    /// Public-Key Encrypted Session Key Packet
    PublicKeyEncryptedSessionKey = 1,
    /// Signature Packet
    Signature = 2,
    /// Symmetric-Key Encrypted Session Key Packet
    SymKeyEncryptedSessionKey = 3,
    /// One-Pass Signature Packet
    OnePassSignature = 4,
    /// Secret-Key Packet
    SecretKey = 5,
    /// Public-Key Packet
    PublicKey = 6,
    /// Secret-Subkey Packet
    SecretSubkey = 7,
    /// Compressed Data Packet
    CompressedData = 8,
    /// Symmetrically Encrypted Data Packet
    SymEncryptedData = 9,
    /// Marker Packet
    Marker = 10,
    /// Literal Data Packet
    LiteralData = 11,
    /// Trust Packet
    Trust = 12,
    /// User ID Packet
    UserId = 13,
    /// Public-Subkey Packet
    PublicSubkey = 14,
    /// User Attribute Packet
    UserAttribute = 17,
    /// Sym. Encrypted and Integrity Protected Data Packet
    SymEncryptedProtectedData = 18,
    /// Modification Detection Code Packet
    ModDetectionCode = 19,
    /// Padding Packet
    Padding = 21,

    #[num_enum(catch_all)]
    Other(u8),
}

impl Tag {
    /// Packet Type ID encoded in OpenPGP format
    /// (bits 7 and 6 set, bits 5-0 carry the packet type ID)
    pub const fn encode(self) -> u8 {
        let t = match self {
            Self::PublicKeyEncryptedSessionKey => 1,
            Self::Signature => 2,
            Self::SymKeyEncryptedSessionKey => 3,
            Self::OnePassSignature => 4,
            Self::SecretKey => 5,
            Self::PublicKey => 6,
            Self::SecretSubkey => 7,
            Self::CompressedData => 8,
            Self::SymEncryptedData => 9,
            Self::Marker => 10,
            Self::LiteralData => 11,
            Self::Trust => 12,
            Self::UserId => 13,
            Self::PublicSubkey => 14,
            Self::UserAttribute => 17,
            Self::SymEncryptedProtectedData => 18,
            Self::ModDetectionCode => 19,
            Self::Padding => 21,
            Self::Other(i) => i,
        };
        0b1100_0000 | t
    }

    pub const fn from_bits(bits: u8) -> Self {
        match bits {
            1 => Self::PublicKeyEncryptedSessionKey,
            2 => Self::Signature,
            3 => Self::SymKeyEncryptedSessionKey,
            4 => Self::OnePassSignature,
            5 => Self::SecretKey,
            6 => Self::PublicKey,
            7 => Self::SecretSubkey,
            8 => Self::CompressedData,
            9 => Self::SymEncryptedData,
            10 => Self::Marker,
            11 => Self::LiteralData,
            12 => Self::Trust,
            13 => Self::UserId,
            14 => Self::PublicSubkey,
            17 => Self::UserAttribute,
            18 => Self::SymEncryptedProtectedData,
            19 => Self::ModDetectionCode,
            21 => Self::Padding,
            i => Self::Other(i),
        }
    }
}

/// The version of the packet format.
///
/// There are two packet formats
/// (see <https://www.rfc-editor.org/rfc/rfc9580.html#name-packet-headers>):
///
/// 1) the (current) OpenPGP packet format specified by this document and its
///    predecessors RFC 4880 and RFC 2440 and
///
/// 2) the Legacy packet format as used by implementations predating any IETF specification of OpenPGP.
#[derive(Debug, PartialEq, Eq, Clone, Copy, TryFromPrimitive)]
#[repr(u8)]
#[derive(Default)]
pub enum PacketHeaderVersion {
    /// Old Packet Format ("Legacy packet format")
    Old = 0,
    /// New Packet Format ("OpenPGP packet format")
    #[default]
    New = 1,
}

impl PacketHeaderVersion {
    pub fn write_header(self, writer: &mut impl Write, tag: Tag, len: usize) -> Result<()> {
        debug!("write_header {:?} {:?} {}", self, tag, len);
        let tag: u8 = tag.into();
        match self {
            PacketHeaderVersion::Old => {
                if len < 256 {
                    // one octet
                    writer.write_u8(0b1000_0000 | (tag << 2))?;
                    writer.write_u8(len.try_into()?)?;
                } else if len < 65536 {
                    // two octets
                    writer.write_u8(0b1000_0001 | (tag << 2))?;
                    writer.write_all(&(len as u16).to_be_bytes())?;
                } else {
                    // four octets
                    writer.write_u8(0b1000_0010 | (tag << 2))?;
                    writer.write_u32::<BigEndian>(len as u32)?;
                }
            }
            PacketHeaderVersion::New => {
                writer.write_u8(0b1100_0000 | tag)?;
                if len < 192 {
                    writer.write_u8(len.try_into()?)?;
                } else if len < 8384 {
                    writer.write_u8((((len - 192) >> 8) + 192) as u8)?;
                    writer.write_u8(((len - 192) & 0xFF) as u8)?;
                } else {
                    writer.write_u8(255)?;
                    writer.write_u32::<BigEndian>(len as u32)?;
                }
            }
        }

        Ok(())
    }

    /// Length of the header, in bytes.
    pub fn header_len(self, len: usize) -> usize {
        match self {
            PacketHeaderVersion::Old => {
                if len < 256 {
                    // one octet
                    2
                } else if len < 65536 {
                    // two octets
                    3
                } else {
                    // four octets
                    5
                }
            }
            PacketHeaderVersion::New => {
                if len < 192 {
                    2
                } else if len < 8384 {
                    3
                } else {
                    6
                }
            }
        }
    }
}

// TODO: find a better place for this
#[derive(Debug, PartialEq, Eq, Clone, Copy, PartialOrd, FromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum KeyVersion {
    V2 = 2,
    V3 = 3,
    V4 = 4,
    V5 = 5,
    V6 = 6,

    #[num_enum(catch_all)]
    Other(u8),
}

impl KeyVersion {
    /// Size of OpenPGP fingerprint in bytes
    /// (returns `None` for unknown versions)
    pub const fn fingerprint_len(&self) -> Option<usize> {
        match self {
            KeyVersion::V2 | KeyVersion::V3 => Some(16), // MD5
            KeyVersion::V4 => Some(20),                  // SHA1
            KeyVersion::V5 | KeyVersion::V6 => Some(32), // SHA256
            KeyVersion::Other(_) => None,
        }
    }
}

impl Default for KeyVersion {
    fn default() -> Self {
        Self::V4
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, FromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum PkeskVersion {
    V3 = 3,
    V6 = 6,

    #[num_enum(catch_all)]
    Other(u8),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, FromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum SkeskVersion {
    V4 = 4,
    V6 = 6,

    #[num_enum(catch_all)]
    Other(u8),
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use proptest::prelude::*;
    use proptest::strategy::{BoxedStrategy, Strategy};

    use super::*;

    impl Arbitrary for PacketHeaderVersion {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
            prop_oneof![
                Just(PacketHeaderVersion::Old),
                Just(PacketHeaderVersion::New),
            ]
            .boxed()
        }
    }

    impl Arbitrary for Tag {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
            prop_oneof![
                Just(Tag::PublicKeyEncryptedSessionKey),
                Just(Tag::Signature),
                Just(Tag::SymKeyEncryptedSessionKey),
                Just(Tag::OnePassSignature),
                Just(Tag::SecretKey),
                Just(Tag::PublicKey),
                Just(Tag::SecretSubkey),
                Just(Tag::CompressedData),
                Just(Tag::SymEncryptedData),
                Just(Tag::Marker),
                Just(Tag::LiteralData),
                Just(Tag::Trust),
                Just(Tag::UserId),
                Just(Tag::PublicSubkey),
                Just(Tag::UserAttribute),
                Just(Tag::SymEncryptedProtectedData),
                Just(Tag::ModDetectionCode),
                Just(Tag::Padding),
            ]
            .boxed()
        }
    }

    impl Arbitrary for PacketLength {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            prop_oneof![
                (1..=u32::MAX).prop_map(PacketLength::Fixed),
                Just(PacketLength::Indeterminate),
                (1u32..=30).prop_map(|l: u32| PacketLength::Partial(2u32.pow(l))),
            ]
            .boxed()
        }
    }

    proptest! {
        #[test]
        fn header_len(version: PacketHeaderVersion, len: usize) {
            let mut buf = Vec::new();
            version.write_header(&mut buf, Tag::Signature, len).unwrap();
            assert_eq!(buf.len(), version.header_len(len));
        }
    }

    impl Arbitrary for KeyVersion {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
            prop_oneof![
                Just(KeyVersion::V2),
                Just(KeyVersion::V3),
                Just(KeyVersion::V4),
                Just(KeyVersion::V5),
                Just(KeyVersion::V6),
            ]
            .boxed()
        }
    }
}
