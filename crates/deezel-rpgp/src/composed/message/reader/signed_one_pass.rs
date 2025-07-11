use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::format;
extern crate alloc;
use bytes::{Buf, BytesMut};
use log::debug;

use super::PacketBodyReader;
use crate::{
    composed::{Message, MessageReader, RingResult, TheRing},
    errors::{bail, ensure_eq, Result},
    packet::{OnePassSignature, OpsVersionSpecific, Packet, Signature, SignatureType},
    util::{fill_buffer, NormalizingHasher},
};

use crate::io::{BufRead, Error, Read};


#[derive(derive_more::Debug)]
pub enum SignatureOnePassReader<'a> {
    Init {
        /// Running hasher
        norm_hasher: Option<NormalizingHasher>,
        /// Data source
        source: Box<Message<'a>>,
    },
    Body {
        /// Running hasher
        norm_hasher: Option<NormalizingHasher>,
        /// Data source
        source: Box<Message<'a>>,
        #[debug("{}", hex::encode(buffer))]
        buffer: BytesMut,
    },
    Done {
        /// Finalized hash
        #[debug("{:?}", hash.as_ref().map(hex::encode))]
        hash: Option<Box<[u8]>>,
        /// Data source
        source: Box<Message<'a>>,
        /// Final signature,
        signature: Signature,
    },
    Error,
}

impl<'a> SignatureOnePassReader<'a> {
    pub(crate) fn new(ops: &OnePassSignature, source: Box<Message<'a>>) -> Result<Self> {
        let mut hasher = ops.hash_algorithm().new_hasher().ok();
        if let Some(ref mut hasher) = hasher {
            if let OpsVersionSpecific::V6 { salt, .. } = ops.version_specific() {
                // Salt size must match the expected length for the hash algorithm that is used
                //
                // See: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.3-2.10.2.1.1
                ensure_eq!(
                    ops.hash_algorithm().salt_len(),
                    Some(salt.len()),
                    "Illegal salt length {} for a V6 Signature using {:?}",
                    salt.len(),
                    ops.hash_algorithm(),
                );

                hasher.update(salt.as_ref());
            }
        }
        let text_mode = ops.typ() == SignatureType::Text;
        let norm_hasher = hasher.map(|hasher| NormalizingHasher::new(hasher, text_mode));

        Ok(Self::Init {
            norm_hasher,
            source,
        })
    }

    pub fn hash(&self) -> Option<&[u8]> {
        match self {
            Self::Init { .. } => None,
            Self::Body { .. } => None,
            Self::Done { hash, .. } => hash.as_deref(),
            Self::Error => panic!("SignatureOnePassReader errored"),
        }
    }

    pub fn signature(&self) -> Option<&Signature> {
        match self {
            Self::Init { .. } => None,
            Self::Body { .. } => None,
            Self::Done { signature, .. } => Some(signature),
            Self::Error => panic!("SignatureOnePassReader errored"),
        }
    }

    pub fn get_ref(&self) -> &Message<'a> {
        match self {
            Self::Init { source, .. } => source,
            Self::Body { source, .. } => source,
            Self::Done { source, .. } => source,
            Self::Error => panic!("SignatureOnePassReader errored"),
        }
    }

    pub fn get_mut(&mut self) -> &mut Message<'a> {
        match self {
            Self::Init { source, .. } => source,
            Self::Body { source, .. } => source,
            Self::Done { source, .. } => source,
            Self::Error => panic!("SignatureOnePassReader errored"),
        }
    }

    pub fn into_inner(self) -> PacketBodyReader<MessageReader<'a>> {
        match self {
            Self::Init { source, .. } => source.into_inner(),
            Self::Body { source, .. } => source.into_inner(),
            Self::Done { source, .. } => source.into_inner(),
            Self::Error => panic!("SignatureOnePassReader errored"),
        }
    }

    fn fill_inner(&mut self) -> Result<(), Error> {
        if matches!(self, Self::Done { .. }) {
            return Ok(());
        }

        loop {
            match core::mem::replace(self, Self::Error) {
                Self::Init {
                    mut norm_hasher,
                    mut source,
                } => {
                    debug!("SignatureOnePassReader init");
                    let mut buffer = BytesMut::zeroed(1024);
                    let read = fill_buffer(&mut source, &mut buffer, None)?;
                    buffer.truncate(read);

                    if read == 0 {
                        debug!("SignatureOnePassReader: source returned 0 bytes on init, checking if source has more data");
                        
                        // Before giving up, check if the source has any data available
                        // This handles reconstructed messages where the first read might return 0
                        loop {
                            match source.fill_buf() {
                                Ok(buf) if buf.is_empty() => {
                                    debug!("SignatureOnePassReader: source is truly empty on init");
                                    return Err(crate::io::Error::new(crate::io::ErrorKind::UnexpectedEof, "unexpected end of file"));
                                }
                                Ok(buf) => {
                                    debug!("SignatureOnePassReader: source has {} bytes available after 0-byte read", buf.len());
                                    let len = buf.len().min(1024);
                                    buffer.clear();
                                    buffer.extend_from_slice(&buf[..len]);
                                    
                                    if let Some(ref mut hasher) = norm_hasher {
                                        hasher.hash_buf(&buffer[..len]);
                                    }
                                    
                                    source.consume(len);
                                    
                                    *self = Self::Body {
                                        norm_hasher,
                                        source,
                                        buffer,
                                    };
                                    return Ok(());
                                }
                                Err(e) => {
                                    debug!("SignatureOnePassReader: error reading from source on init: {:?}", e);
                                    return Err(e);
                                }
                            }
                        }
                    }

                    if let Some(ref mut hasher) = norm_hasher {
                        hasher.hash_buf(&buffer[..read]);
                    }

                    *self = Self::Body {
                        norm_hasher,
                        source,
                        buffer,
                    };
                }
                Self::Body {
                    mut norm_hasher,
                    mut source,
                    mut buffer,
                } => {
                    debug!("SignatureOnePassReader body");

                    if buffer.has_remaining() {
                        *self = Self::Body {
                            norm_hasher,
                            source,
                            buffer,
                        };
                        return Ok(());
                    }

                    buffer.resize(1024, 0);
                    let read = fill_buffer(&mut source, &mut buffer, None)?;
                    buffer.truncate(read);

                    if let Some(ref mut hasher) = norm_hasher {
                        hasher.hash_buf(&buffer[..read]);
                    }

                    if read == 0 {
                        debug!("SignatureOnePassReader finish");

                        // Before processing signature, ensure all data from source is consumed
                        // This is critical for reconstructed messages where the PacketBodyReader may still have data
                        loop {
                            match source.fill_buf() {
                                Ok(buf) if buf.is_empty() => {
                                    debug!("SignatureOnePassReader: source is truly empty, proceeding with signature processing");
                                    break;
                                }
                                Ok(buf) => {
                                    debug!("SignatureOnePassReader: source still has {} bytes, consuming them", buf.len());
                                    let len = buf.len();
                                    if let Some(ref mut hasher) = norm_hasher {
                                        hasher.hash_buf(buf);
                                    }
                                    source.consume(len);
                                }
                                Err(e) => {
                                    debug!("SignatureOnePassReader: error reading from source: {:?}", e);
                                    return Err(e);
                                }
                            }
                        }

                        let hasher = norm_hasher.map(|h| h.done());

                        let (reader, parts) = source.into_parts();

                        // read the signature
                        let mut packets = crate::packet::PacketParser::new(reader);
                        let Some(packet) = packets.next() else {
                            return Err(crate::io::Error::new(crate::io::ErrorKind::Other, "missing signature packet"));
                        };
                        let packet =
                            packet.map_err(|_| crate::io::Error::new(crate::io::ErrorKind::Other, "failed to parse packet"))?;

                        let Packet::Signature(signature) = packet else {
                            return Err(crate::io::Error::new(crate::io::ErrorKind::Other, "expected signature packet"));
                        };

                        // calculate final hash
                        let hash = if let Some(mut hasher) = hasher {
                            debug!("calculating final hash");
                            if let Some(config) = signature.config() {
                                let len = config
                                    .hash_signature_data(&mut hasher)
                                    .map_err(|_| crate::io::Error::new(crate::io::ErrorKind::Other, "failed to hash signature data"))?;
                                hasher.update(
                                    &config.trailer(len).map_err(|_| crate::io::Error::new(crate::io::ErrorKind::Other, "failed to create trailer"))?,
                                );
                                Some(hasher.finalize())
                            } else {
                                None
                            }
                        } else {
                            None
                        };

                        // reconstruct message source
                        let reader = packets.into_inner();
                        let source = parts.into_message_readable(reader);

                        *self = Self::Done {
                            signature,
                            hash,
                            source: Box::new(source),
                        };
                    } else {
                        *self = Self::Body {
                            norm_hasher,
                            source,
                            buffer,
                        }
                    };

                    return Ok(());
                }
                Self::Done {
                    hash,
                    source,
                    signature,
                } => {
                    *self = Self::Done {
                        hash,
                        source,
                        signature,
                    };
                    return Ok(());
                }
                Self::Error => return Err(crate::io::Error::new(crate::io::ErrorKind::Other, "signed one pass reader error")),
            }
        }
    }

    pub fn is_done(&self) -> bool {
        matches!(self, Self::Done { .. })
    }

    pub(crate) fn decompress(self) -> Result<Self> {
        match self {
            Self::Init {
                norm_hasher,
                source,
            } => {
                let source = source.decompress()?;
                Ok(Self::Init {
                    norm_hasher,
                    source: Box::new(source),
                })
            }
            _ => {
                bail!("cannot decompress message that has already been read from");
            }
        }
    }

    pub(crate) fn decrypt_the_ring(
        self,
        ring: TheRing<'_>,
        abort_early: bool,
    ) -> Result<(Self, RingResult)> {
        match self {
            Self::Init {
                norm_hasher,
                source,
            } => {
                let (source, fps) = source.decrypt_the_ring(ring, abort_early)?;
                Ok((
                    Self::Init {
                        norm_hasher,
                        source: Box::new(source),
                    },
                    fps,
                ))
            }
            _ => {
                bail!("cannot decrypt message that has already been read from");
            }
        }
    }
}

impl BufRead for SignatureOnePassReader<'_> {
    fn fill_buf(&mut self) -> Result<&[u8], Error> {
        self.fill_inner()?;
        match self {
            Self::Init { .. } => unreachable!("invalid state"),
            Self::Body { buffer, .. } => Ok(&buffer[..]),
            Self::Done { source, .. } => {
                // For Done state, try to read from the source message directly
                // This handles the case where we have a reconstructed message from decrypted data
                source.fill_buf()
            },
            Self::Error => Err(crate::io::Error::new(crate::io::ErrorKind::Other, "signed one pass reader error")),
        }
    }

    fn consume(&mut self, amt: usize) {
        match self {
            Self::Init { .. } => panic!("must not be called before fill_buf"),
            Self::Body { buffer, .. } => {
                buffer.advance(amt);
            }
            Self::Done { source, .. } => {
                // For Done state, consume from the source message directly
                source.consume(amt);
            }
            Self::Error => panic!("SignatureOnePassReader errored"),
        }
    }
}

impl Read for SignatureOnePassReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        let internal_buf = self.fill_buf()?;
        let len = internal_buf.len().min(buf.len());
        buf[..len].copy_from_slice(&internal_buf[..len]);
        self.consume(len);
        Ok(len)
    }
}
