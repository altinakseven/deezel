use alloc::boxed::Box;
use alloc::vec::Vec;
use alloc::format;
extern crate alloc;
use core::iter;

use crate::{
    armor::{self, BlockType},
    composed::signed_key::{
        PublicOrSecret, SignedPublicKey, SignedPublicKeyParser, SignedSecretKey,
        SignedSecretKeyParser,
    },
    errors::{bail, unimplemented_err, Result},
    packet::{Packet, PacketParser, PacketTrait},
    types::Tag,
};

impl PublicOrSecret {
    /// Parses a list of secret and public keys, from either ASCII-armored or binary OpenPGP data.
    ///
    /// Returns an iterator of public or secret keys and a BTreeMap containing armor headers
    /// (None, if the data was unarmored)
    #[allow(clippy::type_complexity)]
    pub fn from_reader_many<'a>(
        input: &'a [u8],
    ) -> Result<(
        Box<dyn Iterator<Item = Result<PublicOrSecret>> + 'a>,
        Option<armor::Headers>,
    )> {
        Self::from_reader_many_buf(input)
    }

    #[allow(clippy::type_complexity)]
    pub fn from_reader_many_buf<'a>(
        mut input: &'a [u8],
    ) -> Result<(
        Box<dyn Iterator<Item = Result<PublicOrSecret>> + 'a>,
        Option<armor::Headers>,
    )> {
        if !crate::composed::shared::is_binary(&mut input)? {
            let (keys, headers) = Self::from_armor_many(input)?;
            Ok((keys, Some(headers)))
        } else {
            Ok((Self::from_bytes_many(input)?, None))
        }
    }

    /// Parses a list of secret and public keys from ascii armored text.
    #[allow(clippy::type_complexity)]
    pub fn from_armor_many<'a>(
        input: &'a [u8],
    ) -> Result<(
        Box<dyn Iterator<Item = Result<PublicOrSecret>> + 'a>,
        armor::Headers,
    )> {
        let (typ, headers, decoded) = armor::decode(input)?;

        // TODO: add typ information to the key possibly?
        match typ {
            // Standard PGP types
            BlockType::PublicKey | BlockType::PrivateKey | BlockType::File => {
                // TODO: check that the result is what it actually said.
                // We need to own the decoded data to avoid lifetime issues
                let owned_decoded = decoded.into_boxed_slice();
                // We need to collect packets to avoid lifetime issues with the decoded buffer
                let packets: Vec<_> = PacketParser::new(&*owned_decoded)
                    .filter_map(crate::composed::shared::filter_parsed_packet_results)
                    .collect::<Result<Vec<_>>>()?;

              Ok((Box::new(PubPrivIterator {
                  inner: Some(packets.into_iter().map(Ok).peekable()),
              }), headers))
            }
            BlockType::Message
            | BlockType::MultiPartMessage(_, _)
            | BlockType::Signature
            | BlockType::CleartextMessage => {
                bail!("unexpected block type: {}", typ)
            }
            BlockType::PublicKeyPKCS1(_)
            | BlockType::PublicKeyPKCS8
            | BlockType::PublicKeyOpenssh
            | BlockType::PrivateKeyPKCS1(_)
            | BlockType::PrivateKeyPKCS8
            | BlockType::PrivateKeyOpenssh => {
                unimplemented_err!("key format {}", typ);
            }
        }
    }

    // TODO: re-enable this
    // /// Parses a list of secret and public keys from ascii armored text.
    // #[allow(clippy::type_complexity)]
    // pub fn from_armor_many_buf<'a>(
    //     input: &'a [u8],
    // ) -> Result<(
    //     Box<dyn Iterator<Item = Result<PublicOrSecret>> + 'a>,
    //     armor::Headers,
    // )> {
    //     let (typ, headers, decoded) = armor::parse(input)?;

    //     // TODO: add typ information to the key possibly?
    //     match typ {
    //         // Standard PGP types
    //         BlockType::PublicKey | BlockType::PrivateKey | BlockType::File => {
    //             // TODO: check that the result is what it actually said.
    //             Ok((Self::from_bytes_many(&decoded)?, headers))
    //         }
    //         BlockType::Message
    //         | BlockType::MultiPartMessage(_, _)
    //         | BlockType::Signature
    //         | BlockType::CleartextMessage => {
    //             bail!("unexpected block type: {}", typ)
    //         }
    //         BlockType::PublicKeyPKCS1(_)
    //         | BlockType::PublicKeyPKCS8
    //         | BlockType::PublicKeyOpenssh
    //         | BlockType::PrivateKeyPKCS1(_)
    //         | BlockType::PrivateKeyPKCS8
    //         | BlockType::PrivateKeyOpenssh => {
    //             unimplemented_err!("key format {}", typ);
    //         }
    //     }
    // }

    /// Parses a list of secret and public keys from raw bytes.
    pub fn from_bytes_many<'a>(
        bytes: &'a [u8],
    ) -> Result<Box<dyn Iterator<Item = Result<PublicOrSecret>> + 'a>> {
        let packets = PacketParser::new(bytes)
            .filter_map(crate::composed::shared::filter_parsed_packet_results)
            .peekable();

        Ok(Box::new(PubPrivIterator {
            inner: Some(packets),
        }))
    }
}

pub struct PubPrivIterator<I: Sized + Iterator<Item = Result<Packet>>> {
    inner: Option<iter::Peekable<I>>,
}

impl<I: Sized + Iterator<Item = Result<Packet>>> Iterator for PubPrivIterator<I> {
    type Item = Result<PublicOrSecret>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.inner.take() {
            None => None,
            Some(mut packets) => match packets.peek() {
                Some(Ok(peeked_packet)) => {
                    let (res, packets) = match peeked_packet.tag() {
                        Tag::SecretKey => {
                            let mut parser = SignedSecretKeyParser::from_packets(packets);
                            let p: Option<Result<SignedSecretKey>> = parser.next();
                            (
                                p.map(|key| key.map(PublicOrSecret::Secret)),
                                parser.into_inner(),
                            )
                        }
                        Tag::PublicKey => {
                            let mut parser = SignedPublicKeyParser::from_packets(packets);
                            let p: Option<Result<SignedPublicKey>> = parser.next();
                            (
                                p.map(|key| key.map(PublicOrSecret::Public)),
                                parser.into_inner(),
                            )
                        }
                        _ => (None, packets),
                    };

                    self.inner = Some(packets);

                    res
                }
                Some(Err(_)) => Some(Err(packets.next().expect("checked").expect_err("checked"))),
                None => None,
            },
        }
    }
}
