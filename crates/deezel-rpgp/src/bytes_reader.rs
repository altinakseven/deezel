use bytes::{Buf, Bytes};
use crate::io::{self, BufRead, Read};

pub struct BytesReader {
    inner: Bytes,
}

impl BytesReader {
    pub fn new(inner: Bytes) -> Self {
        Self { inner }
    }
}

impl Read for BytesReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let amt = core::cmp::min(buf.len(), self.inner.len());
        buf[..amt].copy_from_slice(&self.inner[..amt]);
        self.inner.advance(amt);
        Ok(amt)
    }
}

impl BufRead for BytesReader {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        Ok(&self.inner)
    }

    fn consume(&mut self, amt: usize) {
        self.inner.advance(amt);
    }
}