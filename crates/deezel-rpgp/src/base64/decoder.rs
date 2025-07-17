//! # base64 decoder module
//!
//! This module provides a streaming base64 decoder. It is designed to be
//! used in a pipeline of readers, where it decodes a base64-encoded
//! section of a larger stream. It correctly handles whitespace and stops
//! at the end of the base64 data, allowing subsequent parsers to continue
//! reading from the underlying stream.

#[cfg(feature = "std")]
use std::io::{self, BufRead, Read};

#[cfg(not(feature = "std"))]
use crate::io::{self, BufRead, Read};

use alloc::vec::Vec;
use base64::engine::general_purpose::GeneralPurpose;
use base64::read::DecoderReader;

const ENGINE: GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// Decodes Base64 from the supplied reader.
///
/// This decoder is streaming. It wraps another reader and decodes the
/// base64 stream. It stops when it encounters characters that are not
/// valid base64 (including the armor boundary).
#[derive(Debug)]
pub struct Base64Decoder<'a, R: Read> {
    /// The inner Read instance we are reading bytes from.
    inner: DecoderReader<'a, GeneralPurpose, R>,
}

impl<'a, R: Read> Base64Decoder<'a, R> {
    /// Creates a new `Base64Decoder`.
    pub fn new(input: R) -> Self {
        Base64Decoder {
            inner: DecoderReader::new(input, &ENGINE),
        }
    }

    /// Consumes the `Base64Decoder`, returning the wrapped reader.
    pub fn into_inner(self) -> R {
        self.inner.into_inner()
    }

    /// Consumes the `Base64Decoder`, returning the wrapped reader and any
    /// buffered data. In this implementation, the buffer is always empty
    /// as the underlying `DecoderReader` handles all buffering.
    pub fn into_inner_with_buffer(self) -> (R, Vec<u8>) {
        (self.into_inner(), Vec::new())
    }
}

impl<'a, R: Read> Read for Base64Decoder<'a, R> {
    fn read(&mut self, into: &mut [u8]) -> io::Result<usize> {
        self.inner.read(into)
    }
}

// No tests here, as this is a simple wrapper. The real logic is in Dearmor.
