// Copyright 2022-2024, The Deezel Developers.
// Deezel is a part of the Deezel project.
// Deezel is a free software, licensed under the MIT license.

use crate::armor::writer::ArmorWriter;
use crate::base64::decoder::Base64Decoder;
use crate::io::{BufRead, Cursor, Read};
use crate::normalize_lines::NormalizeLines;
use crate::packet::Packet;
use crate::{Error, Result};
use std::io::Write;

/// A reader that de-armors PGP data.
pub struct Dearmor<R: BufRead> {
    /// The underlying reader.
    inner: R,
    /// The decoded, but not yet parsed, data.
    buffer: Cursor<Vec<u8>>,
    /// Whether we are done reading.
    done: bool,
}

impl<R: BufRead> Dearmor<R> {
    /// Creates a new de-armoring reader.
    pub fn new(reader: R) -> Self {
        Self {
            inner: reader,
            buffer: Cursor::new(Vec::new()),
            done: false,
        }
    }

    /// Returns the next packet from the stream.
    pub fn next_packet(&mut self) -> Result<Option<Packet>> {
        loop {
            if self.done {
                return Ok(None);
            }

            match Packet::from_reader(&mut self.buffer) {
                Ok(packet) => return Ok(Some(packet)),
                Err(e) => {
                    if e.is_incomplete() {
                        // We need more data.
                        if self.read_into_buffer()? == 0 {
                            // No more data, but we have a partial packet.
                            return Err(Error::IncompletePacket);
                        }
                    } else {
                        return Err(e);
                    }
                }
            }
        }
    }

    // Reads from the underlying reader and de-armors the data into the buffer.
    fn read_into_buffer(&mut self) -> Result<usize> {
        // Find the next armor header.
        let mut line = Vec::new();
        loop {
            if self.inner.read_until(b'\n', &mut line)? == 0 {
                // We are done.
                self.done = true;
                return Ok(0);
            }

            if line.ends_with(b"-----\n") && line.starts_with(b"-----BEGIN ") {
                break;
            }

            line.clear();
        }

        // We found an armor header, now find the footer.
        let mut armored = Vec::new();
        let mut line = Vec::new();
        loop {
            if self.inner.read_until(b'\n', &mut line)? == 0 {
                // We are done.
                self.done = true;
                return Ok(0);
            }

            if line.starts_with(b"-----END ") {
                break;
            }

            armored.write_all(&line).unwrap();
            line.clear();
        }

        // Decode the armored data.
        let mut decoder = Base64Decoder::new(Cursor::new(armored));
        let mut decoded = Vec::new();
        decoder.read_to_end(&mut decoded)?;

        // Write the decoded data to the buffer.
        let pos = self.buffer.position();
        self.buffer.get_mut().splice(pos as usize.., decoded);
        self.buffer.set_position(pos);

        Ok(self.buffer.get_ref().len())
    }
}

impl<R: BufRead> Read for Dearmor<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        // Try to read from the buffer first.
        let read = self.buffer.read(buf)?;
        if read > 0 {
            return Ok(read);
        }

        // If the buffer is empty, read from the underlying reader.
        if self.read_into_buffer()? == 0 {
            // We are done.
            return Ok(0);
        }

        // Try to read from the buffer again.
        self.buffer.read(buf)
    }
}

impl<R: BufRead> BufRead for Dearmor<R> {
    fn fill_buf(&mut self) -> Result<&[u8]> {
        if self.buffer.position() == self.buffer.get_ref().len() {
            self.read_into_buffer()?;
        }
        self.buffer.fill_buf()
    }

    fn consume(&mut self, amt: usize) {
        self.buffer.consume(amt);
    }
}

/// A struct that holds the decoded parts of a PGP message.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct Armored<'a> {
    /// The message type.
    pub message_type: &'a str,
    /// The headers.
    pub headers: Vec<(&'a str, &'a str)>,
    /// The decoded data.
    pub data: Vec<u8>,
}

impl<'a> Armored<'a> {
    /// Decodes an armored PGP message.
    pub fndecode(input: &'a [u8]) -> Result<Self> {
        let mut lines = NormalizeLines::new(input);

        // Find the armor header.
        let header = loop {
            if let Some(line) = lines.next() {
                if line.ends_with(b"-----\n") && line.starts_with(b"-----BEGIN ") {
                    break line;
                }
            } else {
                return Err(Error::InvalidArmor);
            }
        };

        let message_type = &header[11..header.len() - 6];
        let message_type = std::str::from_utf8(message_type).unwrap();

        // Read the headers.
        let mut headers = Vec::new();
        let mut armored = Vec::new();
        loop {
            if let Some(line) = lines.next() {
                if line == b"\n" {
                    break;
                }

                let mut parts = line.splitn(2, |c| *c == b':');
                if let (Some(key), Some(value)) = (parts.next(), parts.next()) {
                    let key = std::str::from_utf8(key).unwrap();
                    let value = std::str::from_utf8(value).unwrap().trim();
                    headers.push((key, value));
                }
            } else {
                return Err(Error::InvalidArmor);
            }
        }

        // Read the armored data.
        loop {
            if let Some(line) = lines.next() {
                if line.starts_with(b"-----END ") {
                    break;
                }
                armored.write_all(&line).unwrap();
            } else {
                return Err(Error::InvalidArmor);
            }
        }

        // Decode the armored data.
        let mut decoder = Base64Decoder::new(Cursor::new(armored));
        let mut data = Vec::new();
        decoder.read_to_end(&mut data)?;

        Ok(Self {
            message_type,
            headers,
            data,
        })
    }

    /// Encodes the message into an armored PGP message.
    pub fn to_writer<W: Write>(&self, writer: &mut W) -> Result<()> {
        let mut armor_writer = ArmorWriter::new(writer, self.message_type, self.headers.clone())?;
        armor_writer.write_all(&self.data)?;
        armor_writer.finish()?;
        Ok(())
    }
}
