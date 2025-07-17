// Copyright 2022-2024, The Deezel Developers.
// Deezel is a part of the Deezel project.
// Deezel is a free software, licensed under the MIT license.

use crate::io::Write;
use crate::{Result, Sha1};

const LINE_LENGTH: usize = 64;

/// A writer that armors PGP data.
pub struct ArmorWriter<W: Write> {
    /// The underlying writer.
    inner: W,
    /// The message type.
    message_type: String,
    /// The headers.
    headers: Vec<(String, String)>,
    /// The buffer for the data to be armored.
    buffer: Vec<u8>,
    /// The checksum.
    checksum: Sha1,
    /// Whether the header has been written.
    header_written: bool,
    /// Whether the footer has been written.
    footer_written: bool,
}

impl<W: Write> ArmorWriter<W> {
    /// Creates a new armoring writer.
    pub fn new(
        writer: W,
        message_type: &str,
        headers: Vec<(&str, &str)>,
    ) -> Result<Self> {
        Ok(Self {
            inner: writer,
            message_type: message_type.to_string(),
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            buffer: Vec::new(),
            checksum: Sha1::new(),
            header_written: false,
            footer_written: false,
        })
    }

    /// Finishes writing the armored data.
    pub fn finish(&mut self) -> Result<()> {
        if self.footer_written {
            return Ok(());
        }

        self.flush()?;

        let checksum = self.checksum.digest();
        let checksum = crc24(&checksum);
        let checksum = base64::encode(checksum);

        self.inner.write_all(b"=")?;
        self.inner.write_all(checksum.as_bytes())?;
        self.inner.write_all(b"\n")?;

        self.inner.write_all(b"-----END ")?;
        self.inner.write_all(self.message_type.as_bytes())?;
        self.inner.write_all(b"-----\n")?;

        self.footer_written = true;

        Ok(())
    }
}

impl<W: Write> Write for ArmorWriter<W> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        if !self.header_written {
            self.inner.write_all(b"-----BEGIN ")?;
            self.inner.write_all(self.message_type.as_bytes())?;
            self.inner.write_all(b"-----\n")?;

            for (key, value) in &self.headers {
                self.inner.write_all(key.as_bytes())?;
                self.inner.write_all(b": ")?;
                self.inner.write_all(value.as_bytes())?;
                self.inner.write_all(b"\n")?;
            }

            self.inner.write_all(b"\n")?;

            self.header_written = true;
        }

        self.buffer.extend_from_slice(buf);
        self.checksum.update(buf);

        while self.buffer.len() >= LINE_LENGTH {
            let line = self.buffer.drain(..LINE_LENGTH).collect::<Vec<u8>>();
            let line = base64::encode(&line);
            self.inner.write_all(line.as_bytes())?;
            self.inner.write_all(b"\n")?;
        }

        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<()> {
        if !self.buffer.is_empty() {
            let line = base64::encode(&self.buffer);
            self.inner.write_all(line.as_bytes())?;
            self.inner.write_all(b"\n")?;
            self.buffer.clear();
        }

        self.inner.flush()
    }
}

impl<W: Write> Drop for ArmorWriter<W> {
    fn drop(&mut self) {
        self.finish().unwrap();
    }
}

fn crc24(data: &[u8]) -> [u8; 3] {
    let mut crc = 0x00B7_04CE;
    for byte in data {
        crc ^= (*byte as u32) << 16;
        for _ in 0..8 {
            crc <<= 1;
            if crc & 0x0100_0000 != 0 {
                crc ^= 0x0186_4CFB;
            }
        }
    }
    (crc & 0x00FF_FFFF).to_be_bytes()[1..].try_into().unwrap()
}
