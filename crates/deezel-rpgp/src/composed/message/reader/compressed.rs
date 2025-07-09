use bytes::{Buf, BytesMut};

use super::{fill_buffer, PacketBodyReader};
use crate::{
    composed::DebugBufRead,
    packet::{Decompressor, PacketHeader},
    types::Tag,
};

use crate::io::{BufRead, Error, Read};


#[derive(Debug)]
pub enum CompressedDataReader<R: DebugBufRead> {
    Body {
        source: MaybeDecompress<PacketBodyReader<R>>,
        buffer: BytesMut,
    },
    Done {
        source: PacketBodyReader<R>,
    },
    Error,
}

impl<R: DebugBufRead> CompressedDataReader<R> {
    pub fn new(source: PacketBodyReader<R>, decompress: bool) -> Result<Self, Error> {
        debug_assert_eq!(source.packet_header().tag(), Tag::CompressedData);

        let source = if decompress {
            let dec = Decompressor::from_reader(source)?;
            MaybeDecompress::Decompress(dec)
        } else {
            MaybeDecompress::Raw(source)
        };

        Ok(Self::Body {
            source,
            buffer: BytesMut::with_capacity(1024),
        })
    }

    pub fn new_done(source: PacketBodyReader<R>) -> Self {
        Self::Done { source }
    }

    pub fn is_done(&self) -> bool {
        matches!(self, Self::Done { .. })
    }

    pub fn into_inner(self) -> PacketBodyReader<R> {
        match self {
            Self::Body { source, .. } => source.into_inner(),
            Self::Done { source, .. } => source,
            Self::Error => {
                panic!("CompressedDataReader errored")
            }
        }
    }

    pub fn get_mut(&mut self) -> &mut PacketBodyReader<R> {
        match self {
            Self::Body { source, .. } => source.get_mut(),
            Self::Done { source, .. } => source,
            Self::Error => {
                panic!("CompressedDataReader errored")
            }
        }
    }

    pub fn packet_header(&self) -> PacketHeader {
        match self {
            Self::Body { ref source, .. } => match source {
                MaybeDecompress::Raw(r) => r.packet_header(),
                MaybeDecompress::Decompress(r) => r.get_ref().packet_header(),
            },
            Self::Done { ref source, .. } => source.packet_header(),
            Self::Error => {
                panic!("CompressedDataReader errored")
            }
        }
    }

    /// Enables decompression
    pub fn decompress(self) -> Result<Self, Error> {
        match self {
            Self::Body { source, buffer } => Ok(Self::Body {
                source: source.decompress()?,
                buffer,
            }),
            Self::Done { .. } => Err(Error::Other),
            Self::Error => Err(Error::Other),
        }
    }
}

impl<R: DebugBufRead> BufRead for CompressedDataReader<R> {
    fn fill_buf(&mut self) -> Result<&[u8], Error> {
        self.fill_inner()?;
        match self {
            Self::Body { ref mut buffer, .. } => Ok(&buffer[..]),
            Self::Done { .. } => Ok(&[][..]),
            Self::Error => Err(Error::Other),
        }
    }

    fn consume(&mut self, amt: usize) {
        match self {
            Self::Body { ref mut buffer, .. } => {
                buffer.advance(amt);
            }
            Self::Done { .. } => {}
            Self::Error => {
                panic!("CompressedDataReader errored");
            }
        }
    }
}

impl<R: DebugBufRead> Read for CompressedDataReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        let internal_buf = self.fill_buf()?;
        let len = internal_buf.len().min(buf.len());
        buf[..len].copy_from_slice(&internal_buf[..len]);
        self.consume(len);
        Ok(len)
    }
}

impl<R: DebugBufRead> CompressedDataReader<R> {
    fn fill_inner(&mut self) -> Result<(), Error> {
        if matches!(self, Self::Done { .. }) {
            return Ok(());
        }

        match core::mem::replace(self, Self::Error) {
            Self::Body {
                mut source,
                mut buffer,
            } => {
                if buffer.has_remaining() {
                    *self = Self::Body { source, buffer };
                    return Ok(());
                }

                buffer.resize(1024, 0);
                let read = fill_buffer(&mut source, &mut buffer, None)?;
                buffer.truncate(read);

                if read == 0 {
                    let source = source.into_inner();

                    *self = Self::Done { source };
                } else {
                    *self = Self::Body { source, buffer };
                }
                Ok(())
            }
            Self::Done { source } => {
                *self = Self::Done { source };
                Ok(())
            }
            Self::Error => Err(Error::Other),
        }
    }
}

#[derive(Debug)]
pub enum MaybeDecompress<R: DebugBufRead> {
    Raw(R),
    Decompress(Decompressor<R>),
}

impl<R: DebugBufRead> MaybeDecompress<R> {
    fn decompress(self) -> Result<Self, Error> {
        match self {
            Self::Raw(r) => Ok(Self::Decompress(Decompressor::from_reader(r)?)),
            Self::Decompress(_) => {
                // already decompressing
                Ok(self)
            }
        }
    }
}

impl<R: DebugBufRead> MaybeDecompress<R> {
    fn into_inner(self) -> R {
        match self {
            Self::Raw(r) => r,
            Self::Decompress(r) => r.into_inner(),
        }
    }
    fn get_mut(&mut self) -> &mut R {
        match self {
            Self::Raw(r) => r,
            Self::Decompress(r) => r.get_mut(),
        }
    }
}

impl<R: DebugBufRead> BufRead for MaybeDecompress<R> {
    fn fill_buf(&mut self) -> Result<&[u8], Error> {
        match self {
            Self::Raw(ref mut r) => r.fill_buf(),
            Self::Decompress(ref mut r) => r.fill_buf(),
        }
    }
    fn consume(&mut self, amt: usize) {
        match self {
            Self::Raw(ref mut r) => r.consume(amt),
            Self::Decompress(ref mut r) => r.consume(amt),
        }
    }
}

impl<R: DebugBufRead> Read for MaybeDecompress<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        let internal_buf = self.fill_buf()?;
        let len = internal_buf.len().min(buf.len());
        buf[..len].copy_from_slice(&internal_buf[..len]);
        self.consume(len);
        Ok(len)
    }
}
