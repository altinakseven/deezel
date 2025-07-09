// crates/deezel-rpgp/src/io.rs

//! A `no_std` compatible `io` module.
//!
//! It exports items from `std::io` when the `std` feature is enabled,
//! otherwise it provides `no_std`-friendly alternatives.
#![allow(clippy::module_inception)]
extern crate alloc;
use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::format;

#[cfg(feature = "std")]
pub mod imp {
    pub use std::io::{self, BufRead, Error, ErrorKind, Read, Result, Write};
}

#[cfg(not(feature = "std"))]
pub mod imp {
    extern crate alloc;
    use snafu::Snafu;

    #[derive(Debug, Snafu)]
    pub enum Error {
        #[snafu(display("other error: {message}"))]
        Other { message: String },
        #[snafu(display("write zero"))]
        WriteZero,
        #[snafu(display("unexpected eof"))]
        UnexpectedEof,
        #[snafu(display("invalid input: {message}"))]
        InvalidInput { message: String },
    }

    impl From<snafu::NoneError> for Error {
        fn from(_: snafu::NoneError) -> Self {
            Error::Other {
                message: "NoneError".to_string(),
            }
        }
    }

    pub type Result<T> = core::result::Result<T, Error>;

    pub struct Cursor<T> {
        inner: T,
        pos: usize,
    }

    impl<T> Cursor<T> {
        pub fn new(inner: T) -> Self {
            Cursor { inner, pos: 0 }
        }
    }

    #[derive(Debug, PartialEq, Eq, Copy, Clone)]
    pub enum ErrorKind {
        WriteZero,
        UnexpectedEof,
        Other,
        InvalidInput,
    }

    impl Error {
        pub fn new(kind: ErrorKind, msg: String) -> Self {
            match kind {
                ErrorKind::WriteZero => Error::WriteZero,
                ErrorKind::UnexpectedEof => Error::UnexpectedEof,
                ErrorKind::InvalidInput => Error::InvalidInput { message: msg },
                _ => Error::Other { message: msg },
            }
        }

        pub fn kind(&self) -> ErrorKind {
            match self {
                Error::WriteZero => ErrorKind::WriteZero,
                Error::UnexpectedEof => ErrorKind::UnexpectedEof,
                Error::Other { .. } => ErrorKind::Other,
                Error::InvalidInput { .. } => ErrorKind::InvalidInput,
            }
        }
    }

    /// A trait for objects that can be read from.
    pub trait Read {
        /// Read from the stream.
        fn read(&mut self, buf: &mut [u8]) -> Result<usize>;

        /// Reads all bytes until EOF in this source, placing them into `buf`.
        fn read_to_end(&mut self, buf: &mut alloc::vec::Vec<u8>) -> Result<usize> {
            let start_len = buf.len();
            // A buffer on the stack.
            let mut local_buf = [0u8; 2048];

            loop {
                match self.read(&mut local_buf) {
                    Ok(0) => return Ok(buf.len() - start_len),
                    Ok(n) => {
                        buf.extend_from_slice(&local_buf[..n]);
                    }
                    Err(e) => return Err(e),
                }
            }
        }

        /// Read the exact number of bytes required to fill `buf`.
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
                Err(Error::UnexpectedEof)
            } else {
                Ok(())
            }
        }
    }

    impl<R: Read + ?Sized> Read for &mut R {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
            (**self).read(buf)
        }
    }

    impl Read for &[u8] {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
            let amt = core::cmp::min(buf.len(), self.len());
            let (a, b) = self.split_at(amt);
            buf[..amt].copy_from_slice(a);
            *self = b;
            Ok(amt)
        }
    }

    impl<T: AsRef<[u8]>> Read for Cursor<T> {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
            let remaining = &self.inner.as_ref()[self.pos..];
            let amt = core::cmp::min(buf.len(), remaining.len());
            if amt > 0 {
                buf[..amt].copy_from_slice(&remaining[..amt]);
                self.pos += amt;
            }
            Ok(amt)
        }
    }

    /// A trait for objects that can be written to.
    pub trait Write {
        /// Write a buffer into this writer, returning how many bytes were written.
        fn write(&mut self, buf: &[u8]) -> Result<usize>;

        /// Flush this output stream, ensuring that all intermediately buffered contents reach their destination.
        fn flush(&mut self) -> Result<()>;

        /// Attempts to write an entire buffer into this writer.
        fn write_all(&mut self, mut buf: &[u8]) -> Result<()> {
            while !buf.is_empty() {
                match self.write(buf) {
                    Ok(0) => {
                        return Err(Error::WriteZero);
                    }
                    Ok(n) => buf = &buf[n..],
                    Err(e) => return Err(e),
                }
            }
            Ok(())
        }
    }

    impl<W: Write + ?Sized> Write for &mut W {
        fn write(&mut self, buf: &[u8]) -> Result<usize> {
            (**self).write(buf)
        }

        fn flush(&mut self) -> Result<()> {
            (**self).flush()
        }
    }
    
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
                Err(e) => return Err(e.into()),
            };
            writer.write_all(&buf[..len])?;
            written += len as u64;
        }
    }

    impl Write for alloc::vec::Vec<u8> {
        fn write(&mut self, buf: &[u8]) -> Result<usize> {
            self.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> Result<()> {
            Ok(())
        }
    }

    /// A no-std BufRead trait. This is a simplified version.
    pub trait BufRead: Read {
        fn fill_buf(&mut self) -> Result<&[u8]>;
        fn consume(&mut self, amt: usize);
    }

    impl<T: AsRef<[u8]>> BufRead for Cursor<T> {
        fn fill_buf(&mut self) -> Result<&[u8]> {
            Ok(&self.inner.as_ref()[self.pos..])
        }

        fn consume(&mut self, amt: usize) {
            self.pos = core::cmp::min(self.pos + amt, self.inner.as_ref().len());
        }
    }

    impl<'a, R: BufRead + ?Sized> BufRead for &'a mut R {
        fn fill_buf(&mut self) -> Result<&[u8]> {
            (**self).fill_buf()
        }
        fn consume(&mut self, amt: usize) {
            (**self).consume(amt)
        }
    }
}

pub use self::imp::{BufRead, Cursor, Error, ErrorKind, Read, Result, Write};