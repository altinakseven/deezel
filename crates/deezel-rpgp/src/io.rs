// crates/deezel-rpgp/src/io.rs

//! A `no_std` compatible `io` module.
//!
//! It exports items from `std::io` when the `std` feature is enabled,
//! otherwise it provides `no_std`-friendly alternatives.

#![allow(clippy::module_inception)]

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
        #[snafu(display("other error"))]
        Other,
        #[snafu(display("write zero"))]
        WriteZero,
        #[snafu(display("unexpected eof"))]
        UnexpectedEof,
    }

    impl From<snafu::NoneError> for Error {
        fn from(_: snafu::NoneError) -> Self {
            Error::Other
        }
    }

    pub type Result<T> = core::result::Result<T, Error>;

    #[derive(Debug, PartialEq, Eq, Copy, Clone)]
    pub enum ErrorKind {
        WriteZero,
        UnexpectedEof,
        Other,
        InvalidInput,
    }

    impl Error {
        pub fn new(kind: ErrorKind, _msg: &'static str) -> Self {
            // In no_std, we can't easily store the message, so we just use the kind.
            // This is a simplification.
            match kind {
                ErrorKind::WriteZero => Error::WriteZero,
                ErrorKind::UnexpectedEof => Error::UnexpectedEof,
                _ => Error::Other,
            }
        }

        pub fn kind(&self) -> ErrorKind {
            match self {
                Error::WriteZero => ErrorKind::WriteZero,
                Error::UnexpectedEof => ErrorKind::UnexpectedEof,
                Error::Other => ErrorKind::Other,
            }
        }
    }

    /// A trait for objects that can be read from.
    pub trait Read {
        /// Read from the stream.
        fn read(&mut self, buf: &mut [u8]) -> Result<usize>;

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

    impl<'a, R: BufRead + ?Sized> BufRead for &'a mut R {
        fn fill_buf(&mut self) -> Result<&[u8]> {
            (**self).fill_buf()
        }
        fn consume(&mut self, amt: usize) {
            (**self).consume(amt)
        }
    }
}

pub use self::imp::{BufRead, Error, ErrorKind, Read, Result, Write};