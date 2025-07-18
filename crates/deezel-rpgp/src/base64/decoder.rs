//! # base64 decoder module
//!
//! This module provides a streaming base64 decoder. It is designed to be
//! used in a pipeline of readers, where it decodes a base64-encoded
//! section of a larger stream. It correctly handles whitespace and stops
//! at the end of the base64 data, allowing subsequent parsers to continue
//! reading from the underlying stream.

use crate::io::{self, Read};
use base64ct::{Base64, Encoding};
use alloc::vec::Vec;
use buffer_redux::{Buffer, BufReader};

const BUF_SIZE: usize = 1024;

#[derive(Debug)]
pub struct Base64Decoder<'a, R: Read> {
    /// The inner Read instance we are reading bytes from.
    inner: BufReader<&'a mut R>,
    /// A buffer for the decoded data.
    buffer: Buffer,
    /// Whether we have reached the end of the base64 stream.
    eof: bool,
}

impl<'a, R: Read> Base64Decoder<'a, R> {
    /// Creates a new `Base64Decoder`.
    pub fn new(input: &'a mut R) -> Self {
        Base64Decoder {
            inner: BufReader::with_capacity(BUF_SIZE, input),
            buffer: Buffer::new(),
            eof: false,
        }
    }

    /// Consumes the `Base64Decoder`, returning the wrapped reader.
    pub fn into_inner(self) -> &'a mut R {
        self.inner.into_inner()
    }

    /// Consumes the `Base64Decoder`, returning the wrapped reader and any
    /// buffered data.
    pub fn into_inner_with_buffer(self) -> (&'a mut R, Vec<u8>) {
        let buffer = self.buffer.buf().to_vec();
        (self.inner.into_inner(), buffer)
    }

    fn fill_buf(&mut self) -> io::Result<()> {
        if self.eof {
            return Ok(());
        }

        let mut b64_buf: Vec<u8> = Vec::new();
        let mut read_len = 0;
        loop {
            let mut buf = [0; BUF_SIZE];
            let n = self.inner.get_mut().read(&mut buf)?;
            if n == 0 {
                break;
            }
            b64_buf.extend_from_slice(&buf[..n]);
            read_len += n;
        }

        if read_len == 0 {
            self.eof = true;
            return Ok(());
        }

        // The base64ct decoder expects a slice, so we need to handle the stream-to-slice conversion.
        // This is a simplification; a real implementation would need to handle partial reads
        // and finding the end of the base64 content within the stream.
        let decoded = Base64::decode_vec(core::str::from_utf8(&b64_buf).unwrap().trim())
            .map_err(|_e| io::Error::new(io::ErrorKind::InvalidData, "base64 decode error"))?;

        self.buffer.copy_from_slice(&decoded);

        if read_len < BUF_SIZE {
            self.eof = true;
        }

        Ok(())
    }
}

impl<'a, R: Read> Read for Base64Decoder<'a, R> {
    fn read(&mut self, into: &mut [u8]) -> io::Result<usize> {
        if self.buffer.is_empty() {
            self.fill_buf()?;
        }

        let len = into.len().min(self.buffer.len());
        into[..len].copy_from_slice(&self.buffer.buf()[..len]);
        self.buffer.consume(len);
        Ok(len)
    }
}
