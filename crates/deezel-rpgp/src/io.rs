//! A `no_std` compatible version of `std::io`.
//!
//! This module provides `Read`, `Write`, and `BufRead` traits that are
//! compatible with `std::io` but also work in `no_std` environments.

#![allow(clippy::module_inception)]

#[cfg(feature = "std")]
mod std_io {
    pub use std::io::{self, copy, BufRead, BufReader, Cursor, Error, ErrorKind, Read, Result, Write};
    pub use byteorder::{ReadBytesExt, WriteBytesExt};
}

#[cfg(feature = "std")]
pub use self::std_io::*;

#[cfg(not(feature = "std"))]
mod no_std_io_imports {
    pub use byteorder::{ReadBytesExt, WriteBytesExt};
    pub use no_std_io::io::{self, BufRead, Cursor, Error, ErrorKind, Read, Result, Write};

    // copy from https://github.com/Rust-for-Linux/linux/blob/6b5453589998a88d01c18746163351b49c54344c/rust/kernel/lib.rs#L373
    pub fn copy<R: Read, W: Write>(reader: &mut R, writer: &mut W) -> Result<u64> {
        let mut count = 0;
        // TODO: use a larger buffer.
        let mut buf = [0; 512];
        loop {
            let len = match reader.read(&mut buf) {
                Ok(0) => return Ok(count),
                Ok(len) => len,
                Err(e) => return Err(e),
            };
            writer.write_all(&buf[..len])?;
            count += len as u64;
        }
    }
}

#[cfg(not(feature = "std"))]
pub use self::no_std_io_imports::*;