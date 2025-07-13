//! A `no_std` compatible version of `std::io`.
//!
//! This module provides `Read`, `Write`, and `BufRead` traits that are
//! compatible with `std::io` but also work in `no_std` environments.

#![allow(clippy::module_inception)]

#[cfg(feature = "std")]

#[cfg(not(feature = "std"))]
pub use self::no_std_io::*;

#[cfg(not(feature = "std"))]
mod no_std_io {
    pub fn copy<R: ?Sized, W: ?Sized>(reader: &mut R, writer: &mut W) -> Result<u64>
    where
        R: Read,
        W: Write,
    {
        let mut buf = [0; 8 * 1024];
        let mut written = 0;
        loop {
            let len = match reader.read(&mut buf) {
                Ok(0) => return Ok(written),
                Ok(len) => len,
                Err(e) => return Err(e),
            };
            writer.write_all(&buf[..len])?;
            written += len as u64;
        }
    }
    use alloc::vec::Vec;
    use core::result;
    use bytes::{BufMut, BytesMut};

    /// A `no_std` compatible `io::Error`.
    #[derive(Debug)]
    pub struct Error {
        kind: ErrorKind,
        msg: &'static str,
    }

    impl Error {
        pub fn new(kind: ErrorKind, msg: &'static str) -> Self {
            Self { kind, msg }
        }

        pub fn kind(&self) -> ErrorKind {
            self.kind
        }
    }

    impl core::fmt::Display for Error {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(f, "{:?}: {}", self.kind, self.msg)
        }
    }

    impl snafu::Error for Error {}

    /// A `no_std` compatible `io::ErrorKind`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum ErrorKind {
        UnexpectedEof,
        InvalidInput,
        InvalidData,
        Interrupted,
        Other,
    }

    impl From<ErrorKind> for Error {
        fn from(kind: ErrorKind) -> Self {
            Self::new(kind, "")
        }
    }

    pub type Result<T> = result::Result<T, Error>;

    /// A `no_std` compatible `io::Read` trait.
    pub trait Read {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize>;

        fn read_exact(&mut self, mut buf: &mut [u8]) -> Result<()> {
            while !buf.is_empty() {
                match self.read(buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        let tmp = buf;
                        buf = &mut tmp[n..];
                    }
                    Err(e) => return Err(e),
                }
            }
            if !buf.is_empty() {
                Err(Error::new(
                    ErrorKind::UnexpectedEof,
                    "failed to fill whole buffer",
                ))
            } else {
                Ok(())
            }
        }

        fn read_to_end(&mut self, buf: &mut Vec<u8>) -> Result<usize> {
            let mut buffer = [0; 8 * 1024];
            let mut read = 0;
            loop {
                let len = match self.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(len) => len,
                    Err(e) => return Err(e),
                };
                buf.extend_from_slice(&buffer[..len]);
                read += len;
            }
            Ok(read)
        }

        fn read_to_string(&mut self, buf: &mut alloc::string::String) -> Result<usize> {
            let mut bytes = alloc::vec::Vec::new();
            let len = self.read_to_end(&mut bytes)?;
            match alloc::string::String::from_utf8(bytes) {
                Ok(s) => {
                    *buf = s;
                    Ok(len)
                }
                Err(_) => Err(Error::new(ErrorKind::InvalidData, "invalid UTF-8")),
            }
        }
    }

    impl<'a> Read for &'a [u8] {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
            let amt = core::cmp::min(buf.len(), self.len());
            let (a, b) = self.split_at(amt);
            buf[..amt].copy_from_slice(a);
            *self = b;
            Ok(amt)
        }
    }

    /// A `no_std` compatible `io::Write` trait.
    pub trait Write {
        fn write(&mut self, buf: &[u8]) -> Result<usize>;
        fn write_all(&mut self, mut buf: &[u8]) -> Result<()> {
            while !buf.is_empty() {
                match self.write(buf) {
                    Ok(0) => {
                        return Err(Error::new(
                            ErrorKind::Other,
                            "failed to write whole buffer",
                        ));
                    }
                    Ok(n) => buf = &buf[n..],
                    Err(e) => return Err(e),
                }
            }
            Ok(())
        }
        fn flush(&mut self) -> Result<()>;

        fn write_u8(&mut self, n: u8) -> Result<()> {
            self.write_all(&[n])
        }

        fn write_be_u16(&mut self, n: u16) -> Result<()> {
            self.write_all(&n.to_be_bytes())
        }

        fn write_be_u32(&mut self, n: u32) -> Result<()> {
            self.write_all(&n.to_be_bytes())
        }

        fn write_le_u16(&mut self, n: u16) -> Result<()> {
            self.write_all(&n.to_le_bytes())
        }
    }

    impl<'a, R: ?Sized + Read> Read for &'a mut R {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
            (**self).read(buf)
        }
    }

    impl<'a, R: ?Sized + BufRead> BufRead for &'a mut R {
        fn fill_buf(&mut self) -> Result<&[u8]> {
            (**self).fill_buf()
        }

        fn consume(&mut self, amt: usize) {
            (**self).consume(amt)
        }
    }
 
     impl<'a, W: Write + ?Sized> Write for &'a mut W {
         fn write(&mut self, buf: &[u8]) -> Result<usize> {
            (*self).write(buf)
        }

        fn write_all(&mut self, buf: &[u8]) -> Result<()> {
            (*self).write_all(buf)
        }

        fn flush(&mut self) -> Result<()> {
            (*self).flush()
        }
    }

    impl Write for Vec<u8> {
        fn write(&mut self, buf: &[u8]) -> Result<usize> {
            self.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> Result<()> {
            Ok(())
        }
    }

    impl<'a> Write for &'a mut [u8] {
        fn write(&mut self, buf: &[u8]) -> Result<usize> {
            let amt = core::cmp::min(buf.len(), self.len());
            let (a, b) = core::mem::take(self).split_at_mut(amt);
            a.copy_from_slice(&buf[..amt]);
            *self = b;
            Ok(amt)
        }

        fn flush(&mut self) -> Result<()> {
            Ok(())
        }
    }

    impl Write for bytes::buf::Writer<BytesMut> {
        fn write(&mut self, buf: &[u8]) -> Result<usize> {
            self.get_mut().put_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> Result<()> {
            Ok(())
        }
    }

    /// A `no_std` compatible `io::Cursor`.
    #[derive(Debug, Clone, Default)]
    pub struct Cursor<T> {
        inner: T,
        pos: u64,
    }

    impl<T> Cursor<T> {
        pub fn new(inner: T) -> Self {
            Cursor { inner, pos: 0 }
        }

        pub fn position(&self) -> u64 {
            self.pos
        }

        pub fn set_position(&mut self, pos: u64) {
            self.pos = pos;
        }
    }

    impl<T: AsRef<[u8]>> Read for Cursor<T> {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
            let inner_buf = self.inner.as_ref();
            let pos = self.pos as usize;
            if pos >= inner_buf.len() {
                return Ok(0);
            }

            let remaining = &inner_buf[pos..];
            let amt = core::cmp::min(buf.len(), remaining.len());
            buf[..amt].copy_from_slice(&remaining[..amt]);
            self.pos += amt as u64;
            Ok(amt)
        }
    }

   impl<T: bytes::Buf> Read for bytes::buf::Reader<T> {
       fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
           let amt = core::cmp::min(buf.len(), self.get_ref().chunk().len());
           buf[..amt].copy_from_slice(&self.get_ref().chunk()[..amt]);
           self.get_mut().advance(amt);
           Ok(amt)
       }
   }

    /// A `no_std` compatible `io::BufRead` trait.
    pub trait BufRead: Read {
        fn fill_buf(&mut self) -> Result<&[u8]>;
        fn consume(&mut self, amt: usize);
        
        /// Create a Take adapter that limits reads to the specified number of bytes
        fn take(self, limit: u64) -> Take<Self>
        where
            Self: Sized,
        {
            Take::new(self, limit)
        }
    }
    
    /// A Take adapter that limits reads to a specified number of bytes
    #[derive(Debug)]
    pub struct Take<R> {
        inner: R,
        limit: u64,
    }

    impl<R> Take<R> {
        pub fn new(inner: R, limit: u64) -> Self {
            Self { inner, limit }
        }
        
        pub fn into_inner(self) -> R {
            self.inner
        }
        
        pub fn get_mut(&mut self) -> &mut R {
            &mut self.inner
        }
        
        pub fn limit(&self) -> u64 {
            self.limit
        }
    }

    impl<R: Read> Read for Take<R> {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
            if self.limit == 0 {
                return Ok(0);
            }
            let max = (buf.len() as u64).min(self.limit) as usize;
            let n = self.inner.read(&mut buf[..max])?;
            self.limit -= n as u64;
            Ok(n)
        }
    }

    impl<R: BufRead> BufRead for Take<R> {
        fn fill_buf(&mut self) -> Result<&[u8]> {
            if self.limit == 0 {
                return Ok(&[]);
            }
            let buf = self.inner.fill_buf()?;
            let len = (buf.len() as u64).min(self.limit) as usize;
            Ok(&buf[..len])
        }
        
        fn consume(&mut self, amt: usize) {
            let amt = (amt as u64).min(self.limit) as usize;
            self.inner.consume(amt);
            self.limit -= amt as u64;
        }
    }

    impl<'a> BufRead for &'a [u8] {
        fn fill_buf(&mut self) -> Result<&[u8]> {
            Ok(*self)
        }

        fn consume(&mut self, amt: usize) {
            *self = &self[amt..];
        }
    }

    impl<'a, T: AsRef<[u8]>> BufRead for Cursor<T> {
        fn fill_buf(&mut self) -> Result<&[u8]> {
            let len = self.inner.as_ref().len() as u64;
            let start = core::cmp::min(self.pos, len) as usize;
            Ok(&self.inner.as_ref()[start..])
        }

        fn consume(&mut self, amt: usize) {
            self.pos += amt as u64;
        }
    }

    impl<T: bytes::Buf> BufRead for bytes::buf::Reader<T> {
        fn fill_buf(&mut self) -> Result<&[u8]> {
            Ok(self.get_ref().chunk())
        }

        fn consume(&mut self, amt: usize) {
            self.get_mut().advance(amt);
        }
    }
 
     pub struct BufReader<R> {
         inner: R,
        buf: Vec<u8>,
        pos: usize,
        cap: usize,
    }

    impl<R: Read> BufReader<R> {
        pub fn new(inner: R) -> Self {
            Self::with_capacity(8 * 1024, inner)
        }

        pub fn with_capacity(cap: usize, inner: R) -> Self {
            let mut buf = Vec::new();
            buf.resize(cap, 0);
            Self {
                inner,
                buf,
                pos: 0,
                cap: 0,
            }
        }
    }

    impl<R: Read> Read for BufReader<R> {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
            if self.pos == self.cap && buf.len() >= self.buf.len() {
                return self.inner.read(buf);
            }

            let nread = {
                let mut rem = self.fill_buf()?;
                rem.read(buf)?
            };
            self.consume(nread);
            Ok(nread)
        }
    }

    impl<R: Read> BufRead for BufReader<R> {
        fn fill_buf(&mut self) -> Result<&[u8]> {
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

    // Additional BufRead implementations for Box types
    impl<T: BufRead> BufRead for alloc::boxed::Box<T> {
        fn fill_buf(&mut self) -> Result<&[u8]> {
            (**self).fill_buf()
        }

        fn consume(&mut self, amt: usize) {
            (**self).consume(amt)
        }
    }

    impl<T: Read> Read for alloc::boxed::Box<T> {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
            (**self).read(buf)
        }
    }
}
