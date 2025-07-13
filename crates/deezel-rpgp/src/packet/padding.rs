use alloc::vec;
extern crate alloc;
use crate::io::{BufRead, Write};

use bytes::Bytes;
use rand::{CryptoRng, RngCore};

use crate::{
    errors::Result,
    packet::{PacketHeader, PacketTrait},
    parsing_reader::BufReadParsing,
    ser::Serialize,
    types::{PacketHeaderVersion, PacketLength, Tag},
};

/// Padding Packet
///
/// <https://www.rfc-editor.org/rfc/rfc9580.html#name-padding-packet-type-id-21>
#[derive(derive_more::Debug, Clone, PartialEq, Eq)]
pub struct Padding {
    packet_header: PacketHeader,
    /// Random data.
    #[debug("{}", hex::encode(data))]
    data: Bytes,
}

impl Padding {
    /// Parses a `Padding` packet from the given slice.
    pub fn try_from_reader<B: BufRead>(packet_header: PacketHeader, mut input: B) -> Result<Self> {
        let data = input.rest()?.freeze();

        Ok(Padding {
            packet_header,
            data,
        })
    }

    /// Create a new padding packet of `size` in bytes.
    pub fn new<R: CryptoRng + RngCore>(
        mut rng: R,
        packet_version: PacketHeaderVersion,
        size: usize,
    ) -> Result<Self> {
        let mut data = vec![0u8; size];
        rng.fill_bytes(&mut data);

        let len = PacketLength::Fixed(data.len().try_into()?);
        let packet_header = PacketHeader::from_parts(packet_version, Tag::Padding, len)?;

        Ok(Padding {
            packet_header,
            data: data.into(),
        })
    }
}

impl Serialize for Padding {
    fn to_writer<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&self.data)?;

        Ok(())
    }

    fn write_len(&self) -> usize {
        self.data.len()
    }
}

impl PacketTrait for Padding {
    fn packet_header(&self) -> &PacketHeader {
        &self.packet_header
    }
}

