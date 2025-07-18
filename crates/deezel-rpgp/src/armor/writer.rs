// Copyright 2022-2024, The Deezel Developers.
// Deezel is a part of the Deezel project.
// Deezel is a free software, licensed under the MIT license.

use crate::io::{self, Write};
use crate::errors::Result;
use sha1_checked::Sha1;
use digest::Digest;
use base64ct::{Base64, Encoding};
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;
use core::str::FromStr;

/// A writer that armors PGP data.
pub struct ArmorWriter<W: Write> {
    /// The underlying writer.
    pub inner: W,
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
    pub fn new<'a>(
        writer: &'a mut W,
        message_type: &'a str,
        headers: Vec<(&'a str, &'a str)>,
    ) -> Result<ArmorWriter<&'a mut W>> {
        Ok(ArmorWriter {
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

        let checksum = self.checksum.clone().finalize();
        let checksum = crc24(&checksum);
        let mut enc_buf = [0u8; 4];
        let checksum = Base64::encode(&checksum, &mut enc_buf).unwrap();

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
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
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

        while self.buffer.len() >= 48 {
            let line = self.buffer.drain(..48).collect::<Vec<u8>>();
            let mut enc_buf = [0u8; 64];
            let encoded = Base64::encode(&line, &mut enc_buf).unwrap();
            self.inner.write_all(encoded.as_bytes())?;
            self.inner.write_all(b"\n")?;
        }

        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if !self.buffer.is_empty() {
            let mut enc_buf = [0u8; 64];
            let encoded = Base64::encode(&self.buffer, &mut enc_buf).unwrap();
            self.inner.write_all(encoded.as_bytes())?;
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

/// The type of the armored message.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum BlockType {
    PublicKey,
    PrivateKey,
    Message,
    PgpMessage,
    MultiPartMessage(usize, usize),
    Signature,
    CleartextMessage,
    File,
    PublicKeyPKCS1(&'static str),
    PublicKeyPKCS8,
    PublicKeyOpenssh,
    PrivateKeyPKCS1(&'static str),
    PrivateKeyPKCS8,
    PrivateKeyOpenssh,
}

impl BlockType {
    pub fn to_str(&self) -> &str {
        match self {
            BlockType::PublicKey => "PUBLIC KEY",
            BlockType::PrivateKey => "PRIVATE KEY",
            BlockType::Message => "MESSAGE",
            BlockType::PgpMessage => "PGP MESSAGE",
            BlockType::MultiPartMessage(_, _) => "MESSAGE",
            BlockType::Signature => "SIGNATURE",
            BlockType::CleartextMessage => "SIGNED MESSAGE",
            BlockType::File => "FILE",
            BlockType::PublicKeyPKCS1(_) => "PUBLIC KEY",
            BlockType::PublicKeyPKCS8 => "PUBLIC KEY",
            BlockType::PublicKeyOpenssh => "OPENSSH PUBLIC KEY",
            BlockType::PrivateKeyPKCS1(_) => "PRIVATE KEY",
            BlockType::PrivateKeyPKCS8 => "PRIVATE KEY",
            BlockType::PrivateKeyOpenssh => "OPENSSH PRIVATE KEY",
        }
    }
}

impl fmt::Display for BlockType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

impl FromStr for BlockType {
    type Err = crate::errors::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "PUBLIC KEY" => Ok(BlockType::PublicKey),
            "PRIVATE KEY" => Ok(BlockType::PrivateKey),
            "MESSAGE" => Ok(BlockType::Message),
            "PGP MESSAGE" => Ok(BlockType::PgpMessage),
            "SIGNATURE" => Ok(BlockType::Signature),
            "SIGNED MESSAGE" => Ok(BlockType::CleartextMessage),
            "FILE" => Ok(BlockType::File),
            _ => Err(crate::errors::Error::InvalidInput {
                #[cfg(feature = "std")]
                backtrace: snafu::GenerateImplicitData::generate(),
            }),
        }
    }
}

/// A list of headers.
pub type Headers = BTreeMap<String, Vec<String>>;
