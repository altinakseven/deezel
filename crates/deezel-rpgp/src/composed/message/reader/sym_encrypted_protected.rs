use alloc::string::ToString;
use alloc::format;
extern crate alloc;
use super::PacketBodyReader;
use crate::{
    composed::{DebugBufRead, PlainSessionKey},
    errors::{bail, ensure_eq, unsupported_err, Result},
    packet::{PacketHeader, StreamDecryptor, SymEncryptedProtectedDataConfig},
    types::Tag,
};

use crate::io::{BufRead, Error, Read};


#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum SymEncryptedProtectedDataReader<R: DebugBufRead> {
    Init {
        source: PacketBodyReader<R>,
        config: SymEncryptedProtectedDataConfig,
    },
    Body {
        config: SymEncryptedProtectedDataConfig,
        decryptor: MaybeDecryptor<PacketBodyReader<R>>,
    },
    Done {
        source: PacketBodyReader<R>,
        config: SymEncryptedProtectedDataConfig,
    },
    Error,
}

#[derive(derive_more::Debug)]
#[allow(clippy::large_enum_variant)]
pub enum MaybeDecryptor<R: DebugBufRead> {
    Raw(#[debug("R")] R),
    Decryptor(StreamDecryptor<R>),
}

impl<R: DebugBufRead> MaybeDecryptor<R> {
    pub fn into_inner(self) -> R {
        match self {
            Self::Raw(r) => r,
            Self::Decryptor(r) => r.into_inner(),
        }
    }

    pub fn get_ref(&self) -> &R {
        match self {
            Self::Raw(r) => r,
            Self::Decryptor(r) => r.get_ref(),
        }
    }

    pub fn get_mut(&mut self) -> &mut R {
        match self {
            Self::Raw(r) => r,
            Self::Decryptor(r) => r.get_mut(),
        }
    }
}

impl<R: DebugBufRead> BufRead for MaybeDecryptor<R> {
    fn fill_buf(&mut self) -> Result<&[u8], Error> {
        match self {
            Self::Raw(r) => r.fill_buf(),
            Self::Decryptor(r) => r.fill_buf(),
        }
    }

    fn consume(&mut self, amt: usize) {
        match self {
            Self::Raw(r) => r.consume(amt),
            Self::Decryptor(r) => r.consume(amt),
        }
    }
}

impl<R: DebugBufRead> Read for MaybeDecryptor<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        let internal_buf = self.fill_buf()?;
        let len = internal_buf.len().min(buf.len());
        buf[..len].copy_from_slice(&internal_buf[..len]);
        self.consume(len);
        Ok(len)
    }
}

impl<R: DebugBufRead> SymEncryptedProtectedDataReader<R> {
    pub fn new(mut source: PacketBodyReader<R>) -> Result<Self> {
        debug_assert_eq!(source.packet_header().tag(), Tag::SymEncryptedProtectedData);
        let config = SymEncryptedProtectedDataConfig::try_from_reader(&mut source)?;

        Ok(Self::Init { source, config })
    }

    pub fn decrypt(&mut self, session_key: &PlainSessionKey) -> Result<()> {
        match core::mem::replace(self, Self::Error) {
            Self::Init { source, config } => {
                let decryptor = match config {
                    SymEncryptedProtectedDataConfig::V1 => {
                        let (sym_alg, session_key) = match session_key {
                            PlainSessionKey::V3_4 { sym_alg, key } => (sym_alg, key),
                            PlainSessionKey::V5 { .. } => {
                                unsupported_err!("v5 is not supported");
                            }
                            PlainSessionKey::V6 { .. } => {
                                bail!("mismatch between session key and edata config");
                            }
                            PlainSessionKey::Unknown { sym_alg, key } => (sym_alg, key),
                        };

                        StreamDecryptor::v1(*sym_alg, session_key, source)?
                    }
                    SymEncryptedProtectedDataConfig::V2 {
                        sym_alg,
                        aead,
                        chunk_size,
                        salt,
                    } => {
                        let (sym_alg_session_key, session_key) = match session_key {
                            PlainSessionKey::V3_4 { .. } => {
                                bail!("mismatch between session key and edata config");
                            }
                            PlainSessionKey::V5 { .. } => {
                                unsupported_err!("v5 is not supported");
                            }
                            PlainSessionKey::V6 { key } => (None, key),
                            PlainSessionKey::Unknown { sym_alg, key } => (Some(sym_alg), key),
                        };
                        if let Some(sym_alg_session_key) = sym_alg_session_key {
                            ensure_eq!(
                                sym_alg,
                                *sym_alg_session_key,
                                "mismatching symmetric key algorithm"
                            );
                        }

                        ensure_eq!(
                            session_key.len(),
                            sym_alg.key_size(),
                            "Unexpected session key length for {:?}",
                            sym_alg
                        );
                        StreamDecryptor::v2(sym_alg, aead, chunk_size, &salt, session_key, source)?
                    }
                };

                *self = Self::Body {
                    config,
                    decryptor: MaybeDecryptor::Decryptor(decryptor),
                };
                Ok(())
            }
            Self::Body { config, decryptor } => {
                *self = Self::Body { config, decryptor };
                bail!("cannot decrypt after starting to read")
            }
            Self::Done { source, config } => {
                *self = Self::Done { source, config };
                bail!("cannot decrypt after finishing to read")
            }
            Self::Error => bail!("SymEncryptedProtectedDataReader errored"),
        }
    }

    pub(crate) fn new_done(
        config: SymEncryptedProtectedDataConfig,
        source: PacketBodyReader<R>,
    ) -> Self {
        Self::Done { source, config }
    }

    pub fn config(&self) -> &SymEncryptedProtectedDataConfig {
        match self {
            Self::Init { config, .. } => config,
            Self::Body { config, .. } => config,
            Self::Done { config, .. } => config,
            Self::Error => {
                panic!("SymEncryptedProtectedDataReader errored")
            }
        }
    }

    pub fn is_done(&self) -> bool {
        matches!(self, Self::Done { .. })
    }

    pub fn into_inner(self) -> PacketBodyReader<R> {
        match self {
            Self::Init { source, .. } => source,
            Self::Body { decryptor, .. } => decryptor.into_inner(),
            Self::Done { source, .. } => source,
            Self::Error => {
                panic!("SymEncryptedProtectedDataReader errored")
            }
        }
    }

    pub fn get_mut(&mut self) -> &mut PacketBodyReader<R> {
        match self {
            Self::Init { source, .. } => source,
            Self::Body { decryptor, .. } => decryptor.get_mut(),
            Self::Done { source, .. } => source,
            Self::Error => {
                panic!("SymEncryptedProtectedDataReader errored")
            }
        }
    }

    pub fn packet_header(&self) -> PacketHeader {
        match self {
            Self::Init { source, .. } => source.packet_header(),
            Self::Body { decryptor, .. } => decryptor.get_ref().packet_header(),
            Self::Done { source, .. } => source.packet_header(),
            Self::Error => {
                panic!("SymEncryptedProtectedDataReader errored")
            }
        }
    }

    fn fill_inner(&mut self) -> Result<(), Error> {
        if matches!(self, Self::Done { .. }) {
            return Ok(());
        }

        loop {
            match core::mem::replace(self, Self::Error) {
                Self::Init { source, config } => {
                    *self = Self::Body {
                        config,
                        decryptor: MaybeDecryptor::Raw(source),
                    }
                }
                Self::Body {
                    config,
                    mut decryptor,
                } => {
                    let buf = decryptor.fill_buf()?;
                    if buf.is_empty() {
                        let source = decryptor.into_inner();

                        *self = Self::Done { source, config };
                    } else {
                        *self = Self::Body { config, decryptor };
                    }
                    return Ok(());
                }
                Self::Done { source, config } => {
                    *self = Self::Done { source, config };
                    return Ok(());
                }
                Self::Error => {
                    return Err(crate::io::Error::new(crate::io::ErrorKind::Other, "sym encrypted protected reader error"));
                }
            }
        }
    }
}

impl<R: DebugBufRead> BufRead for SymEncryptedProtectedDataReader<R> {
    fn fill_buf(&mut self) -> Result<&[u8], Error> {
        self.fill_inner()?;
        match self {
            Self::Init { .. } => unreachable!("invalid state"),
            Self::Body { decryptor, .. } => decryptor.fill_buf(),

            Self::Done { .. } => Ok(&[][..]),
            Self::Error => Err(crate::io::Error::new(crate::io::ErrorKind::Other, "sym encrypted protected reader error")),
        }
    }

    fn consume(&mut self, amt: usize) {
        match self {
            Self::Init { .. } => unreachable!("invalid state"),
            Self::Body { decryptor, .. } => decryptor.consume(amt),
            Self::Done { .. } => {}
            Self::Error => {
                panic!("SymEncryptedProtectedDataReader errored")
            }
        }
    }
}

impl<R: DebugBufRead> Read for SymEncryptedProtectedDataReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        let internal_buf = self.fill_buf()?;
        let len = internal_buf.len().min(buf.len());
        buf[..len].copy_from_slice(&internal_buf[..len]);
        self.consume(len);
        Ok(len)
    }
}
