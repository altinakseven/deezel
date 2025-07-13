use alloc::format;
extern crate alloc;
use crate::io::{self, BufRead};

use crate::{
    errors::{ensure_eq, Result},
    packet::{PacketHeader, PacketTrait},
    parsing_reader::BufReadParsing,
    ser::Serialize,
};

/// PGP as UTF-8 octets.
const PGP: [u8; 3] = [0x50, 0x47, 0x50];

/// Marker Packet
/// <https://www.rfc-editor.org/rfc/rfc9580.html#name-marker-packet-type-id-10>
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Marker {
    packet_header: PacketHeader,
}

impl Marker {
    /// Parses a `Marker` packet from the given slice.
    pub fn try_from_reader<B: BufRead>(packet_header: PacketHeader, mut input: B) -> Result<Self> {
        let marker = input.read_array::<3>()?;
        ensure_eq!(marker, PGP, "invalid input");

        Ok(Marker { packet_header })
    }
}

impl Serialize for Marker {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&PGP[..])?;
        Ok(())
    }

    fn write_len(&self) -> usize {
        PGP.len()
    }
}

impl PacketTrait for Marker {
    fn packet_header(&self) -> &PacketHeader {
        &self.packet_header
    }
}

