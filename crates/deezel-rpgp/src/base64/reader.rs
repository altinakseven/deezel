//! # base64 reader module

// This will be replaced with a no_std compatible trait
pub trait Read {}
impl Read for &[u8] {}
pub trait BufRead: Read {
    fn fill_buf(&mut self) -> Result<&[u8], ()>;
    fn consume(&mut self, amt: usize);
}
impl BufRead for &[u8] {
    fn fill_buf(&mut self) -> Result<&[u8], ()> {
        Ok(self)
    }
    fn consume(&mut self, amt: usize) {
        *self = &self[amt..];
    }
}


/// Reads base64 values from a given byte input, stops once it detects the first non base64 char.
#[derive(Debug)]
pub struct Base64Reader<R: BufRead> {
    inner: R,
}

impl<R: BufRead> Base64Reader<R> {
    /// Creates a new `Base64Reader`.
    pub fn new(input: R) -> Self {
        Base64Reader { inner: input }
    }

    /// Consume `self` and return the inner reader.
    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: BufRead> Read for Base64Reader<R> {
    // This function needs to be refactored to not use std::io
}

#[inline]
fn is_base64_token(c: u8) -> bool {
    ((0x41..=0x5A).contains(&c) || (0x61..=0x7A).contains(&c))
        // alphabetic
        || (0x30..=0x39).contains(&c) //  digit
        || c == b'/'
        || c == b'+'
        || c == b'='
        || c == b'\n'
        || c == b'\r'
}
