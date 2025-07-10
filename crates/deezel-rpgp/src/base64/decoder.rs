//! # base64 decoder module
extern crate alloc;

use buffer_redux::{BufReader, Buffer};

const BUF_SIZE: usize = 1024;
// This will be replaced with a no_std compatible trait
pub trait Read {}
impl Read for &[u8] {}


/// Decodes Base64 from the supplied reader.
#[derive(Debug)]
pub struct Base64Decoder<R> {
    /// The inner Read instance we are reading bytes from.
    inner: BufReader<R>,
}

impl<R: Read> Base64Decoder<R> {
    /// Creates a new `Base64Decoder`.
    pub fn new(input: R) -> Self {
        Base64Decoder {
            inner: BufReader::with_capacity(BUF_SIZE, input),
        }
    }

    pub fn into_inner_with_buffer(self) -> (R, Buffer) {
        self.inner.into_inner_with_buffer()
    }
}

impl<R: Read> Read for Base64Decoder<R> {
    // This function needs to be refactored to not use crate::io
}
