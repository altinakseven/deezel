//! # Utilities

extern crate alloc;
use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::format;

use core::hash;
use digest::DynDigest;
use nom::Input;

use crate::io::{BufRead, Read, Write};

pub(crate) fn fill_buffer<R: Read>(
    source: &mut R,
    buffer: &mut [u8],
    chunk_size: Option<usize>,
) -> Result<usize, crate::io::Error> {
    let mut read = 0;
    let mut chunk_size = chunk_size.unwrap_or(buffer.len());

    while read < chunk_size {
        match source.read(&mut buffer[read..]) {
            Ok(0) => break,
            Ok(n) => {
                read += n;
                chunk_size -= n;
            }
            Err(e) => return Err(e),
        }
    }

    Ok(read)
}

macro_rules! impl_try_from_into {
    ($enum_name:ident, $( $name:ident => $variant_type:ty ),*) => {
       $(
           impl core::convert::TryFrom<$enum_name> for $variant_type {
               // TODO: Proper error
               type Error = $crate::errors::Error;

               fn try_from(other: $enum_name) -> ::core::result::Result<$variant_type, Self::Error> {
                   if let $enum_name::$name(value) = other {
                       Ok(value)
                   } else {
                       Err($crate::errors::format_err!("invalid packet type: {:?}", other))
                   }
               }
           }

           impl From<$variant_type> for $enum_name {
               fn from(other: $variant_type) -> $enum_name {
                   $enum_name::$name(other)
               }
           }
       )*
    }
}

pub(crate) use impl_try_from_into;

pub struct TeeWriter<'a, A, B> {
    a: &'a mut A,
    b: &'a mut B,
}

impl<'a, A, B> TeeWriter<'a, A, B> {
    pub fn new(a: &'a mut A, b: &'a mut B) -> Self {
        TeeWriter { a, b }
    }
}

impl<A: hash::Hasher, B: Write> Write for TeeWriter<'_, A, B> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, crate::io::Error> {
        self.a.write(buf);
        self.b.write(buf)
    }

    fn flush(&mut self) -> Result<(), crate::io::Error> {
        self.b.flush()
    }
}

#[derive(derive_more::Debug)]
pub struct NormalizingHasher {
    #[debug("hasher")]
    hasher: Box<dyn DynDigest + Send>,
    text_mode: bool,
    last_was_cr: bool,
}

impl NormalizingHasher {
    pub(crate) fn new(hasher: Box<dyn DynDigest + Send>, text_mode: bool) -> Self {
        Self {
            hasher,
            text_mode,
            last_was_cr: false,
        }
    }

    pub(crate) fn done(mut self) -> Box<dyn DynDigest + Send> {
        if self.text_mode && self.last_was_cr {
            self.hasher.update(b"\n")
        }

        self.hasher
    }

    pub(crate) fn hash_buf(&mut self, buffer: &[u8]) {
        if buffer.is_empty() {
            return;
        }

        if !self.text_mode {
            self.hasher.update(buffer);
        } else {
            let mut buf = buffer;

            if self.last_was_cr {
                self.hasher.update(b"\n");

                if buf[0] == b'\n' {
                    buf = &buf[1..];
                }

                self.last_was_cr = false;
            }

            while !buf.is_empty() {
                match buf.position(|c| c == b'\r' || c == b'\n') {
                    None => {
                        // no line endings in sight, just hash the data
                        self.hasher.update(buf);
                        buf = &[]
                    }

                    Some(pos) => {
                        // consume all bytes before line-break-related position

                        self.hasher.update(&buf[..pos]);
                        buf = &buf[pos..];

                        // handle this line-break related context
                        let only_one = buf.len() == 1;
                        match (buf[0], only_one) {
                            (b'\n', _) => {
                                self.hasher.update(b"\r\n");
                                buf = &buf[1..];
                            }
                            (b'\r', false) => {
                                self.hasher.update(b"\r\n");

                                // we are guaranteed to have at least two bytes
                                if buf[1] == b'\n' {
                                    // there was a '\n' in the stream, we consume it as well
                                    buf = &buf[2..];
                                } else {
                                    // this was a lone '\r', we have normalized it
                                    buf = &buf[1..];
                                }
                            }
                            (b'\r', true) => {
                                // this one '\r' was the last thing in the buffer
                                self.hasher.update(b"\r");
                                buf = &[];

                                self.last_was_cr = true;
                            }
                            _ => unreachable!("buf.position gave us either a '\n or a '\r'"),
                        }
                    }
                }
            }
        }
    }
}
