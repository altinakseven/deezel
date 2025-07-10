extern crate alloc;
use crate::io::{self, BufRead, Write};
use bytes::Bytes;
#[cfg(feature = "bzip2")]
use bzip2::{self, Action, Compression as BzCompression, Status as BzStatus};
use flate2::{Compression, FlushCompress, Status};
use log::debug;

use crate::{
    errors::Result,
    packet::{PacketHeader, PacketTrait},
    parsing_reader::BufReadParsing,
    ser::Serialize,
    types::CompressionAlgorithm,
};

/// Packet for compressed data.
///
/// Ref <https://www.rfc-editor.org/rfc/rfc9580.html#name-compressed-data-packet-type>
#[derive(Clone, PartialEq, Eq, derive_more::Debug)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct CompressedData {
    packet_header: PacketHeader,
    compression_algorithm: CompressionAlgorithm,
    #[debug("{}", hex::encode(compressed_data))]
    #[cfg_attr(test, proptest(strategy = "tests::compressed_data_gen()"))]
    compressed_data: Bytes,
}

/// Structure to decompress a given reader.
pub enum Decompressor {
    Uncompressed,
    Zip(flate2::Decompress),
    Zlib(flate2::Decompress),
    #[cfg(feature = "bzip2")]
    Bzip2(bzip2::Decompress),
}

impl core::fmt::Debug for Decompressor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Uncompressed => write!(f, "Uncompressed"),
            Self::Zip(_) => write!(f, "Zip"),
            Self::Zlib(_) => write!(f, "Zlib"),
            #[cfg(feature = "bzip2")]
            Self::Bzip2(_) => write!(f, "Bzip2"),
        }
    }
}

impl Decompressor {
    pub fn new(alg: CompressionAlgorithm) -> Self {
        debug!("creating decompressor for {:?}", alg);
        match alg {
            CompressionAlgorithm::Uncompressed => Self::Uncompressed,
            CompressionAlgorithm::ZIP => Self::Zip(flate2::Decompress::new(false)),
            CompressionAlgorithm::ZLIB => Self::Zlib(flate2::Decompress::new(true)),
            #[cfg(feature = "bzip2")]
            CompressionAlgorithm::BZip2 => Self::Bzip2(bzip2::Decompress::new(false)),
            _ => unimplemented!(),
        }
    }

    pub fn decompress(
        &mut self,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(usize, usize), DecompressError> {
        match self {
            Decompressor::Uncompressed => {
                let len = input.len().min(output.len());
                output[..len].copy_from_slice(&input[..len]);
                Ok((len, len))
            }
            Decompressor::Zip(d) | Decompressor::Zlib(d) => {
                let before_in = d.total_in();
                let before_out = d.total_out();
                d.decompress(input, output, flate2::FlushDecompress::None)?;
                Ok((
                    (d.total_in() - before_in) as usize,
                    (d.total_out() - before_out) as usize,
                ))
            }
            #[cfg(feature = "bzip2")]
            Decompressor::Bzip2(d) => {
                let before_in = d.total_in();
                let before_out = d.total_out();
                d.decompress(input, output).map_err(DecompressError::Bzip2)?;
                Ok((
                    (d.total_in() - before_in) as usize,
                    (d.total_out() - before_out) as usize,
                ))
            }
        }
    }
}

#[derive(Debug)]
pub enum DecompressError {
    Flate2(flate2::DecompressError),
    #[cfg(feature = "bzip2")]
    Bzip2(bzip2::Error),
}

impl From<flate2::DecompressError> for DecompressError {
    fn from(err: flate2::DecompressError) -> Self {
        Self::Flate2(err)
    }
}

pub enum Compressor {
    Uncompressed,
    Zip(flate2::Compress),
    Zlib(flate2::Compress),
    #[cfg(feature = "bzip2")]
    Bzip2(bzip2::Compress),
}

impl Compressor {
    pub fn new(alg: CompressionAlgorithm) -> Self {
        debug!("creating compressor for {:?}", alg);
        match alg {
            CompressionAlgorithm::Uncompressed => Self::Uncompressed,
            CompressionAlgorithm::ZIP => {
                Self::Zip(flate2::Compress::new(Compression::default(), false))
            }
            CompressionAlgorithm::ZLIB => {
                Self::Zlib(flate2::Compress::new(Compression::default(), true))
            }
            #[cfg(feature = "bzip2")]
            CompressionAlgorithm::BZip2 => {
                Self::Bzip2(bzip2::Compress::new(BzCompression::default(), 0))
            }
            _ => unimplemented!(),
        }
    }

    pub fn compress(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        flush: FlushCompress,
    ) -> Result<(usize, usize, Status), ()> {
        match self {
            Compressor::Uncompressed => {
                let len = input.len().min(output.len());
                output[..len].copy_from_slice(&input[..len]);
                let status = if len < input.len() {
                    Status::Ok
                } else {
                    Status::StreamEnd
                };
                Ok((len, len, status))
            }
            Compressor::Zip(c) | Compressor::Zlib(c) => {
                let before_in = c.total_in();
                let before_out = c.total_out();
                let status = c.compress(input, output, flush).unwrap();
                Ok((
                    (c.total_in() - before_in) as usize,
                    (c.total_out() - before_out) as usize,
                    status,
                ))
            }
            #[cfg(feature = "bzip2")]
            Compressor::Bzip2(d) => {
                let before_in = d.total_in();
                let before_out = d.total_out();
                let bz_action = match flush {
                    FlushCompress::None => Action::Run,
                    FlushCompress::Sync => Action::Flush,
                    FlushCompress::Full => Action::Flush,
                    FlushCompress::Finish => Action::Finish,
                    _ => return Err(()), // New variants are not supported
                };
                let status = match d.compress(input, output, bz_action) {
                    Ok(s) => s,
                    Err(_) => return Err(()),
                };
                Ok((
                    (d.total_in() - before_in) as usize,
                    (d.total_out() - before_out) as usize,
                    match status {
                        BzStatus::Ok => Status::Ok,
                        BzStatus::FlushOk => Status::Ok,
                        BzStatus::RunOk => Status::Ok,
                        BzStatus::FinishOk => Status::Ok,
                        BzStatus::StreamEnd => Status::StreamEnd,
                        _ => return Err(()), // Unknown status
                    },
                ))
            }
        }
    }
}

impl CompressedData {
    /// Parses a `CompressedData` packet from the given `Buf`.
    pub fn try_from_reader<B: BufRead>(packet_header: PacketHeader, mut input: B) -> Result<Self> {
        let alg = input.read_u8().map(CompressionAlgorithm::from)?;

        Ok(CompressedData {
            packet_header,
            compression_algorithm: alg,
            compressed_data: input.rest()?.freeze(),
        })
    }

    /// Create the structure from the raw compressed data.
    #[cfg(test)]
    fn from_compressed(alg: CompressionAlgorithm, data: impl Into<Bytes>) -> Result<Self> {
        let compressed_data = data.into();
        let len = 1 + compressed_data.len();
        let packet_header = PacketHeader::new_fixed(Tag::CompressedData, len.try_into()?);

        Ok(CompressedData {
            packet_header,
            compression_algorithm: alg,
            compressed_data,
        })
    }

    /// Creates a decompressor.
    pub fn decompress(&self, mut sink: impl Write) -> Result<()> {
        let mut decompressor = Decompressor::new(self.compression_algorithm);
        let mut compressed_data = &self.compressed_data[..];
        let mut decompressed_buf = [0u8; 4096];

        loop {
            let (consumed, written) =
                decompressor
                    .decompress(compressed_data, &mut decompressed_buf)
                    .map_err(|_e| io::Error::new(io::ErrorKind::Other, "decompression failed"))?;
            compressed_data = &compressed_data[consumed..];
            sink.write_all(&decompressed_buf[..written])?;

            if consumed == 0 && written == 0 {
                break;
            }
        }

        Ok(())
    }

    /// Returns a reference to raw compressed data.
    pub fn compressed_data(&self) -> &[u8] {
        &self.compressed_data
    }
}

impl Serialize for CompressedData {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_u8(self.compression_algorithm.into())?;
        writer.write_all(&self.compressed_data)?;

        Ok(())
    }

    fn write_len(&self) -> usize {
        1 + self.compressed_data.len()
    }
}

impl PacketTrait for CompressedData {
    fn packet_header(&self) -> &PacketHeader {
        &self.packet_header
    }
}



#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    use super::*;
    use crate::packet::Packet;

    proptest::prop_compose! {
        pub fn compressed_data_gen()(source: Vec<u8>) -> Bytes {
            // TODO: actually compress
            source.into()
        }
    }

    proptest! {
        #[test]
        fn write_len(packet: CompressedData) {
            let mut buf = Vec::new();
            packet.to_writer(&mut buf).unwrap();
            assert_eq!(buf.len(), packet.write_len());
        }


        #[test]
        fn packet_roundtrip(packet: CompressedData) {
            let mut buf = Vec::new();
            packet.to_writer(&mut buf).unwrap();
            let new_packet = CompressedData::try_from_reader(*packet.packet_header(), &mut &buf[..]).unwrap();
            assert_eq!(packet, new_packet);
        }
    }
}
