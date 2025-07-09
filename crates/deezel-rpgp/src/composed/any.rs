use crate::{
    armor::{self, BlockType},
    composed::{
        cleartext::CleartextSignedMessage, Deserializable, Message, SignedPublicKey,
        SignedSecretKey, StandaloneSignature,
    },
    errors::{ensure, unimplemented_err, Result},
};

use crate::io::{BufRead, Read};
use core::fmt::Debug;


/// A flexible representation of what can be represented in an armor file.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum Any<'a> {
    Cleartext(CleartextSignedMessage),
    PublicKey(SignedPublicKey),
    SecretKey(SignedSecretKey),
    Message(Message<'a>),
    Signature(StandaloneSignature),
}

impl<'a> Any<'a> {
    /// Parse armored ascii data.
    pub fn from_armor(
        bytes: &'a [u8],
    ) -> Result<(Self, armor::Headers)> {
        Self::from_armor_buf(bytes)
    }

    /// Parse a single armor encoded composition.
    pub fn from_string(input: &'a str) -> Result<(Self, armor::Headers)> {
        Self::from_armor_buf(input.as_bytes())
    }

    // TODO: re-enable this
    // /// Parse armored ascii data.
    // pub fn from_armor_buf(
    //     input: &'a [u8],
    // ) -> Result<(Self, armor::Headers)> {
    //     let (typ, headers, decoded) = armor::parse(input)?;
    //     match typ {
    //         // Standard PGP types
    //         BlockType::PublicKey => {
    //             let key = SignedPublicKey::from_bytes(&decoded)?;
    //             Ok((Self::PublicKey(key), headers))
    //         }
    //         BlockType::PrivateKey => {
    //             let key = SignedSecretKey::from_bytes(&decoded)?;
    //             Ok((Self::SecretKey(key), headers))
    //         }
    //         BlockType::Message => {
    //             let msg = Message::from_bytes(&decoded)?;
    //             Ok((Self::Message(msg), headers))
    //         }
    //         BlockType::Signature => {
    //             let sig = StandaloneSignature::from_bytes(&decoded)?;
    //             Ok((Self::Signature(sig), headers))
    //         }
    //         BlockType::CleartextMessage => {
    //             let (sig, headers) =
    //                 CleartextSignedMessage::from_armor_after_header(&decoded, headers, 0)?;
    //             Ok((Self::Cleartext(sig), headers))
    //         }
    //         _ => unimplemented_err!("unsupported block type: {}", typ),
    //     }
    // }
}
