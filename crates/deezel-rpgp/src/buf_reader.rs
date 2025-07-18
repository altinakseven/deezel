#![allow(unsafe_code)]
// A simple BufReader implementation for no_std environments.

use crate::io::{self, Read, BufRead};
use alloc::vec::Vec;

const DEFAULT_BUF_SIZE: usize = 8 * 1024;

pub struct BufReader<R> {
    inner: R,
    buf: Vec<u8>,
    pos: usize,
    cap: usize,
}

impl<R: Read> BufReader<R> {
    pub fn new(inner: R) -> Self {
        Self::with_capacity(DEFAULT_BUF_SIZE, inner)
    }

    pub fn with_capacity(capacity: usize, inner: R) -> Self {
        let mut buf = Vec::with_capacity(capacity);
        // SAFETY: We are creating a Vec with uninitialized memory, but we will
        // only ever read from the initialized part of the buffer.
        unsafe { buf.set_len(capacity) };
        Self {
            inner,
            buf,
            pos: 0,
            cap: 0,
        }
    }
}

impl<R: Read> BufRead for BufReader<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if self.pos >= self.cap {
            self.cap = self.inner.read(&mut self.buf)?;
            self.pos = 0;
        }
        Ok(&self.buf[self.pos..self.cap])
    }

    fn consume(&mut self, amt: usize) {
        self.pos = core::cmp::min(self.pos + amt, self.cap);
    }
}

impl<R: Read> Read for BufReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = {
            let mut rem = self.fill_buf()?;
            rem.read(buf)?
        };
        self.consume(n);
        Ok(n)
    }
}