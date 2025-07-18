use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::vec;
use core::str::FromStr;
use alloc::vec::Vec;
use alloc::format;
extern crate alloc;
use crate::{
    armor::BlockType,
    composed::{
        message::Message, shared::is_binary, CompressedDataReader, Edata, Esk, LiteralDataReader,
        SignatureBodyReader, SignatureOnePassReader,
    },
    errors::{bail, Result},
    parsing_reader::BufReadParsing,
    types::{PkeskVersion, SkeskVersion, Tag},
};


/// Parses a single message level
pub(super) fn next(
    mut packets: crate::packet::PacketParser<super::MessageReader<'_>>,
    is_nested: bool,
) -> Result<Option<Message<'_>>> {
    loop {
        let Some(packet) = packets.next_owned() else {
            return Ok(None);
        };
        let mut packet = packet?;

        // Handle 1 OpenPGP Message per loop iteration
        let tag = packet.packet_header().tag();

        match tag {
            Tag::SymKeyEncryptedSessionKey | Tag::PublicKeyEncryptedSessionKey => {
                // (a) Encrypted Message:
                //   - ESK Seq
                //   - Encrypted Data -> OpenPGP Message

                let mut esks = Vec::new();
                let esk = Esk::try_from_reader(&mut packet)?;
                esks.push(esk);

                packets = crate::packet::PacketParser::new(packet.into_inner());
                // Read ESKs unit we find the Encrypted Data
                loop {
                    let Some(packet) = packets.next_owned() else {
                        bail!("missing encrypted data packet");
                    };

                    let mut packet = packet?;
                    let tag = packet.packet_header().tag();
                    match tag {
                        Tag::SymKeyEncryptedSessionKey | Tag::PublicKeyEncryptedSessionKey => {
                            let esk = Esk::try_from_reader(&mut packet)?;
                            esks.push(esk);
                            packets = crate::packet::PacketParser::new(packet.into_inner());
                        }
                        Tag::SymEncryptedData | Tag::SymEncryptedProtectedData => {
                            let edata = Edata::try_from_reader(packet)?;
                            let esk = match edata {
                                Edata::SymEncryptedData { .. } => {
                                    esk_filter(esks, PkeskVersion::V3, SkeskVersion::V4)
                                }
                                Edata::SymEncryptedProtectedData { ref reader } => {
                                    match reader.config() {
                                        crate::packet::SymEncryptedProtectedDataConfig::V1 => {
                                            esk_filter(esks, PkeskVersion::V3, SkeskVersion::V4)
                                        }
                                        crate::packet::SymEncryptedProtectedDataConfig::V2 {
                                            ..
                                        } => esk_filter(esks, PkeskVersion::V6, SkeskVersion::V6),
                                    }
                                }
                            };

                            return Ok(Some(Message::Encrypted {
                                esk,
                                edata,
                                is_nested,
                            }));
                        }
                        Tag::Padding => {
                            // drain reader
                            packet.drain()?;
                            packets = crate::packet::PacketParser::new(packet.into_inner());
                        }
                        Tag::Marker => {
                            // drain reader
                            packet.drain()?;
                            packets = crate::packet::PacketParser::new(packet.into_inner());
                        }
                        _ => {
                            bail!("unexpected tag in an encrypted message: {:?}", tag);
                        }
                    }
                }
            }
            Tag::Signature => {
                // (b) Signed Message
                //   (1) Signature Packet, OpenPGP Message
                //      - Signature Packet
                //      - OpenPGP Message
                let signature =
                    crate::packet::Signature::try_from_reader(packet.packet_header(), &mut packet)?;
                packets = crate::packet::PacketParser::new(packet.into_inner());
                let Some(inner_message) = next(packets, true)? else {
                    bail!("missing next packet");
                };
                let reader = SignatureBodyReader::new(signature, Box::new(inner_message))?;
                let message = Message::Signed { reader, is_nested };
                return Ok(Some(message));
            }
            Tag::OnePassSignature => {
                //   (2) One-Pass Signed Message.
                //      - OPS
                //      - OpenPgp Message
                //      - Signature Packet
                let one_pass_signature = crate::packet::OnePassSignature::try_from_reader(
                    packet.packet_header(),
                    &mut packet,
                )?;
                packets = crate::packet::PacketParser::new(packet.into_inner());
                let Some(inner_message) = next(packets, true)? else {
                    bail!("missing next packet");
                };

                let reader =
                    SignatureOnePassReader::new(&one_pass_signature, Box::new(inner_message))?;
                let message = Message::SignedOnePass {
                    one_pass_signature,
                    reader,
                    is_nested,
                };
                return Ok(Some(message));
            }
            Tag::CompressedData => {
                // (c) Compressed Message
                //   - Compressed Packet
                let reader = CompressedDataReader::new(packet, false)?;
                let message = Message::Compressed { reader, is_nested };
                return Ok(Some(message));
            }
            Tag::LiteralData => {
                // (d) Literal Message
                //   - Literal Packet
                let reader = LiteralDataReader::new(packet)?;
                let message = Message::Literal { reader, is_nested };
                return Ok(Some(message));
            }
            Tag::Padding => {
                // drain reader
                packet.drain()?;
                packets = crate::packet::PacketParser::new(packet.into_inner());
            }
            Tag::Marker => {
                // drain reader
                packet.drain()?;
                packets = crate::packet::PacketParser::new(packet.into_inner());
            }
            _ => {
                bail!("unexpected packet type: {:?}", tag);
            }
        }
    }
}

/// Drop PKESK and SKESK with versions that are not aligned with the encryption container
///
/// An implementation processing an Encrypted Message MUST discard any
/// preceding ESK packet with a version that does not align with the
/// version of the payload.
/// See <https://www.rfc-editor.org/rfc/rfc9580.html#section-10.3.2.1-7>
fn esk_filter(esk: Vec<Esk>, pkesk_allowed: PkeskVersion, skesk_allowed: SkeskVersion) -> Vec<Esk> {
    esk.into_iter()
        .filter(|esk| match esk {
            Esk::PublicKeyEncryptedSessionKey(pkesk) => pkesk.version() == pkesk_allowed,
            Esk::SymKeyEncryptedSessionKey(skesk) => skesk.version() == skesk_allowed,
        })
        .collect()
}

impl<'a> Message<'a> {
    /// Parse a composed message.
    /// Ref: <https://www.rfc-editor.org/rfc/rfc9580.html#name-openpgp-messages>
    fn from_packets(packets: crate::packet::PacketParser<super::MessageReader<'a>>) -> Result<Self> {
        match next(packets, false)? {
            Some(message) => Ok(message),
            None => {
                bail!("no valid OpenPGP message found");
            }
        }
    }

    /// Parses a message from the given bytes.
    pub fn from_bytes(source: &'a [u8]) -> Result<Self> {
        let message_reader = super::MessageReader::Reader(Box::new(source));
        let parser = crate::packet::PacketParser::new(message_reader);
        Self::from_packets(parser)
    }

    // TODO: re-enable this
    // /// Construct a message from the decrypted edata.
    // ///
    // /// `is_nested` must be passed through from the source `Message`.
    // pub(super) fn from_edata(edata: Edata<'a>, is_nested: bool) -> Result<Self> {
    //     let source = MessageReader::Edata(Box::new(edata));
    //     Message::internal_from_bytes(source, is_nested)
    // }

    // /// Construct a message from a compressed data reader.
    // ///
    // /// `is_nested` must be passed through from the source `Message`.
    // pub(super) fn from_compressed(
    //     reader: CompressedDataReader,
    //     is_nested: bool,
    // ) -> Result<Self> {
    //     let source = MessageReader::Compressed(Box::new(reader));
    //     Message::internal_from_bytes(source, is_nested)
    // }

    // fn internal_from_bytes(source: MessageReader<'a>, is_nested: bool) -> Result<Self> {
    //     let packets = crate::packet::PacketParser::new(source);
    //     match next(packets, is_nested)? {
    //         Some(message) => Ok(message),
    //         None => {
    //             bail!("no valid OpenPGP message found");
    //         }
    //     }
    // }

    /// From armored string
    pub fn from_string(data: &'a str) -> Result<(Self, crate::armor::Headers)> {
        Self::from_armor(data.as_bytes())
    }

    /// Armored ascii data.
    pub fn from_armor(
        input: &'a [u8],
    ) -> Result<(Self, crate::armor::Headers)> {
        let armored = crate::armor::Armored::decode(input)?;
        let (typ, headers, decoded) = (armored.message_type, armored.headers, armored.data);

        let block_type = BlockType::from_str(typ.as_str())?;
        if !Self::matches_block_type(block_type) {
            bail!("unexpected block type: {}", typ);
        }

        let static_slice: &'static [u8] = Box::leak(decoded.into_boxed_slice());
        let headers = headers.into_iter().map(|(k, v)| (k, vec![v])).collect();
        Ok((Self::from_bytes(static_slice)?, headers))
    }

    /// Parse from a reader which might contain ASCII armored data or binary data.
    pub fn from_reader(
        mut source: &'a [u8],
    ) -> Result<(Self, Option<crate::armor::Headers>)> {
        if is_binary(&mut source)? {
            let msg = Self::from_bytes(source)?;
            Ok((msg, None))
        } else {
            let (msg, headers) = Self::from_armor(source)?;
            Ok((msg, Some(headers)))
        }
    }

    fn matches_block_type(typ: BlockType) -> bool {
        matches!(
            typ,
            BlockType::Message
                | BlockType::PgpMessage
                | BlockType::MultiPartMessage(_, _)
                | BlockType::File
        )
    }
}
