use alloc::boxed::Box;
use crate::{
    armor_new::{self, BlockType},
    composed::{
        cleartext::CleartextSignedMessage, Deserializable, Message, SignedPublicKey,
        SignedSecretKey, StandaloneSignature,
    },
    errors::{format_err, Result},
    io::Cursor,
};
use alloc::string::ToString;

use core::fmt::Debug;


/// A flexible representation of what can be represented in an armor_new file.
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
    /// Parse armor_newed ascii data.
    pub fn from_armor_new(bytes: &'a [u8]) -> Result<(Self, armor_new::Headers)> {
        let (typ, headers, decoded) = armor_new::decode(bytes)?;
        
        log::debug!("Decoded armor_new data length: {}", decoded.len());
        log::debug!("First 32 bytes: {:?}", &decoded[..decoded.len().min(32)]);
        
        let packets = crate::packet::PacketParser::new(Cursor::new(&decoded));

        let first = match typ {
            BlockType::PublicKey => {
                log::debug!("Parsing public key");
                let mut parser = SignedPublicKey::from_packets(packets.peekable());
                let key_result = parser.next();
                log::debug!("Parser result: {:?}", key_result.is_some());
                
                let key = key_result
                    .ok_or_else(|| format_err!("no matching packet found"))??;
                Self::PublicKey(key)
            }
            BlockType::PrivateKey => {
                let key = SignedSecretKey::from_packets(packets.peekable())
                    .next()
                    .ok_or_else(|| format_err!("unable to parse secret key"))??;
                Self::SecretKey(key)
            }
            BlockType::Message => {
                let static_slice: &'static [u8] = Box::leak(decoded.into_boxed_slice());
                let msg = Message::from_bytes(static_slice)?;
                Self::Message(msg)
            }
            BlockType::Signature => {
                let sig = StandaloneSignature::from_packets(packets.peekable())
                    .next()
                    .ok_or_else(|| format_err!("unable to parse signature"))??;
                Self::Signature(sig)
            }
            BlockType::CleartextMessage => {
                let (sig, _headers) =
                    CleartextSignedMessage::from_armor_new_after_header(&decoded, headers.clone(), 0)?;
                Self::Cleartext(sig)
            }
            _ => unimplemented!("unsupported block type: {}", typ),
        };

        Ok((first, headers))
    }

    /// Parse a single armor_new encoded composition.
    pub fn from_string(input: &'a str) -> Result<(Self, armor_new::Headers)> {
        Self::from_armor_new(input.as_bytes())
    }

}
