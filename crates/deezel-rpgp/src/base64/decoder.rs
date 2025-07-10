//! # base64 decoder module
extern crate alloc;

use base64::engine::{general_purpose::GeneralPurpose, Engine};
use buffer_redux::{BufReader, Buffer};

const BUF_SIZE: usize = 1024;
const BUF_CAPACITY: usize = BUF_SIZE / 4 * 3;
const ENGINE: GeneralPurpose = base64::engine::general_purpose::STANDARD;

// This will be replaced with a no_std compatible trait
pub trait Read {}
impl Read for &[u8] {}
pub trait BufRead: Read {}
impl BufRead for &[u8] {}
pub trait Error {}
impl Error for () {}


/// Decodes Base64 from the supplied reader.
#[derive(Debug)]
pub struct Base64Decoder<R> {
    /// The inner Read instance we are reading bytes from.
    inner: BufReader<R>,
    /// leftover decoded output
    out: Buffer,
    out_buffer: [u8; BUF_CAPACITY],
    /// Memorize if we had an error, so we can return it on calls to read again.
    err: Option<()>,
}

impl<R: Read> Base64Decoder<R> {
    /// Creates a new `Base64Decoder`.
    pub fn new(input: R) -> Self {
        Base64Decoder {
            inner: BufReader::with_capacity(BUF_SIZE, input),
            out: Buffer::with_capacity(BUF_CAPACITY),
            out_buffer: [0u8; BUF_CAPACITY],
            err: None,
        }
    }

    pub fn into_inner_with_buffer(self) -> (R, Buffer) {
        self.inner.into_inner_with_buffer()
    }
}

impl<R: Read> Read for Base64Decoder<R> {
    // This function needs to be refactored to not use crate::io
}

/// Tries to decode as much of the given slice as possible.
/// Returns the amount written and consumed.
fn try_decode_engine_slice<T: ?Sized + AsRef<[u8]>>(
    input: &T,
    output: &mut [u8],
) -> (usize, usize) {
    let input_bytes = input.as_ref();
    let mut n = input_bytes.len();
    while n > 0 {
        match ENGINE.decode_slice(&input_bytes[..n], output) {
            Ok(size) => {
                return (n, size);
            }
            Err(_) => {
                if n % 4 != 0 {
                    n -= n % 4
                } else {
                    n -= 4
                }
            }
        }
    }

    (0, 0)
}
