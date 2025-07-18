// Copyright 2022-2024, The Deezel Developers.
// Deezel is a part of the Deezel project.
// Deezel is a free software, licensed under the MIT license.

use alloc::{string::{String, ToString}, vec::Vec};
use core::str;

use crate::armor::writer::ArmorWriter;
use crate::base64::decoder::Base64Decoder;
use crate::io::{self as io, BufRead, Cursor, Read, Write};
use crate::normalize_lines::NormalizedReader;
use crate::packet::{Packet, PacketHeader};
use crate::errors::{Error, Result};
use crate::line_writer::LineBreak;
use crate::buf_reader::BufReader;

/// A reader that de-armors PGP data.
pub struct Dearmor<R: Read> {
    /// The underlying reader.
    inner: BufReader<R>,
    /// The decoded, but not yet parsed, data.
    buffer: Cursor<Vec<u8>>,
    /// Whether we are done reading.
    done: bool,
}

impl<R: Read> Dearmor<R> {
    /// Creates a new de-armoring reader.
    pub fn new(reader: R) -> Self {
        Self {
            inner: BufReader::new(reader),
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

            let packet_header = match PacketHeader::try_from_reader(&mut self.buffer) {
                Ok(packet_header) => packet_header,
                Err(e) => {
                    let e: Error = e.try_into().unwrap();
                    if self.read_into_buffer().is_err() {
                        return Err(e);
                    }
                    // try again
                    continue;
                }
            };

            match Packet::from_reader(packet_header, &mut self.buffer) {
                Ok(packet) => return Ok(Some(packet)),
                Err(Error::PacketIncomplete { source, .. }) => {
                    // We need more data.
                    if self.read_into_buffer()? == 0 {
                        // No more data, but we have a partial packet.
                        return Err(Error::PacketIncomplete {
                            source,
                            #[cfg(feature = "std")]
                            backtrace: snafu::GenerateImplicitData::generate(),
                        });
                    }
                }
                Err(e) => return Err(e),
            }
        }
    }

    // Reads from the underlying reader and de-armors the data into the buffer.
    fn read_into_buffer(&mut self) -> Result<usize> {
        // Find the next armor header.
        let mut line = Vec::new();
        loop {
            let read = read_line(&mut self.inner, &mut line)?;
            if read == 0 {
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
        line.clear();
        loop {
            let read = read_line(&mut self.inner, &mut line)?;
            if read == 0 {
                // We are done.
                self.done = true;
                return Ok(0);
            }

            if line.starts_with(b"=") || line.starts_with(b"-----END ") {
                break;
            }

            if line.ends_with(b"\n") {
                line.pop();
                if line.ends_with(b"\r") {
                    line.pop();
                }
            }
            armored.extend_from_slice(&line);
            line.clear();
        }

        // Decode the armored data.
        let mut cursor = Cursor::new(armored);
        let mut decoder = Base64Decoder::new(&mut cursor);
        let mut decoded = Vec::new();
        // Implement read_to_end manually
        let mut buf = [0u8; 1024];
        loop {
            let n = decoder.read(&mut buf)?;
            if n == 0 {
                break;
            }
            decoded.extend_from_slice(&buf[..n]);
        }


        // Write the decoded data to the buffer.
        let pos = self.buffer.position();
        self.buffer.get_mut().splice(pos as usize.., decoded);
        self.buffer.set_position(pos);

        Ok(self.buffer.get_ref().len())
    }
}

fn read_line<R: Read>(reader: &mut BufReader<R>, buf: &mut Vec<u8>) -> io::Result<usize> {
    let mut read = 0;
    loop {
        let available = match reader.fill_buf() {
            Ok(n) => n,
            Err(e) => return Err(e),
        };

        if available.is_empty() {
            break;
        }

        let (done, used) = {
            if let Some(i) = available.iter().position(|&b| b == b'\n') {
                buf.extend_from_slice(&available[..=i]);
                (true, i + 1)
            } else {
                buf.extend_from_slice(available);
                (false, available.len())
            }
        };

        reader.consume(used);
        read += used;

        if done {
            break;
        }
    }
    Ok(read)
}


impl<R: Read> Read for Dearmor<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // Try to read from the buffer first.
        let read = self.buffer.read(buf)?;
        if read > 0 {
            return Ok(read);
        }

        // If the buffer is empty, read from the underlying reader.
        if self
            .read_into_buffer()
            .map_err(|_e| io::Error::new(io::ErrorKind::Other, "read_into_buffer failed"))?
            == 0
        {
            // We are done.
            return Ok(0);
        }

        // Try to read from the buffer again.
        self.buffer.read(buf)
    }
}

impl<R: Read> BufRead for Dearmor<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if self.buffer.position() as usize == self.buffer.get_ref().len() {
            self.read_into_buffer()
                .map_err(|_e| io::Error::new(io::ErrorKind::Other, "read_into_buffer failed"))?;
        }
        self.buffer.fill_buf()
    }

    fn consume(&mut self, amt: usize) {
        self.buffer.consume(amt);
    }
}

/// A struct that holds the decoded parts of a PGP message.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct Armored {
    /// The message type.
    pub message_type: String,
    /// The headers.
    pub headers: Vec<(String, String)>,
    /// The decoded data.
    pub data: Vec<u8>,
}

impl Armored {
    /// Decodes an armored PGP message.
    pub fn decode(input: &[u8]) -> Result<Self> {
        let mut lines = BufReader::new(NormalizedReader::new(input, LineBreak::Lf));

        // Find the armor header.
        let mut header = Vec::new();
        read_line(&mut lines, &mut header)?;
        if !header.ends_with(b"-----\n") || !header.starts_with(b"-----BEGIN ") {
            return Err(Error::InvalidInput {
                #[cfg(feature = "std")]
                backtrace: snafu::GenerateImplicitData::generate(),
            });
        }

        let message_type = str::from_utf8(&header[11..header.len() - 6]).unwrap().to_string();

        // Read the headers.
        let mut headers = Vec::new();
        let mut armored = Vec::new();
        loop {
            let mut line = Vec::new();
            read_line(&mut lines, &mut line)?;
            if line.is_empty() || line == b"\n" {
                break;
            }

            let mut parts = line.splitn(2, |c| *c == b':');
            if let (Some(key), Some(value)) = (parts.next(), parts.next()) {
                let key = str::from_utf8(key).unwrap().to_string();
                let value = str::from_utf8(value).unwrap().trim().to_string();
                headers.push((key, value));
            }
        }

        // Read the armored data.
        loop {
            let mut line = Vec::new();
            read_line(&mut lines, &mut line)?;
            if line.is_empty() || line.starts_with(b"=") || line.starts_with(b"-----END ") {
                break;
            }
            if line.ends_with(b"\n") {
                line.pop();
                if line.ends_with(b"\r") {
                    line.pop();
                }
            }
            armored.extend_from_slice(&line);
        }

        // Decode the armored data.
        let mut cursor = Cursor::new(armored);
        let mut decoder = Base64Decoder::new(&mut cursor);
        let mut data = Vec::new();
        // Implement read_to_end manually
        let mut buf = [0u8; 1024];
        loop {
            let n = decoder.read(&mut buf)?;
            if n == 0 {
                break;
            }
            data.extend_from_slice(&buf[..n]);
        }

        Ok(Self {
            message_type,
            headers,
            data,
        })
    }

    /// Encodes the message into an armored PGP message.
    pub fn to_writer<W: Write>(&self, writer: &mut W) -> Result<()> {
        let mut armor_writer = ArmorWriter::new(writer, &self.message_type, self.headers.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect())?;
        armor_writer.write_all(&self.data)?;
        armor_writer.finish()?;
        Ok(())
    }
}
