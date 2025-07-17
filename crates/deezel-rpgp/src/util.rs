//! # Utilities

extern crate alloc;
use alloc::boxed::Box;

use core::hash;
use digest::DynDigest;
use nom::Input;
use dyn_clone::DynClone;

use crate::io::{Read, Write};

pub(crate) fn fill_buffer<R: Read>(
    source: &mut R,
    buffer: &mut [u8],
    chunk_size: Option<usize>,
) -> Result<usize, crate::io::Error> {
    let target_size = chunk_size.unwrap_or(buffer.len());
    let mut total_read = 0;

    while total_read < target_size {
        let remaining_target = target_size - total_read;
        let buffer_slice = &mut buffer[total_read..];

        // Determine the slice to read into for this iteration.
        // It's the smaller of the remaining buffer or the remaining target.
        let len = buffer_slice.len();
        let read_buf = &mut buffer_slice[..remaining_target.min(len)];

        if read_buf.is_empty() {
            // This can happen if target_size > buffer.len() and we've filled the buffer.
            break;
        }

        match source.read(read_buf) {
            Ok(0) => {
                break; // EOF
            }
            Ok(n) => {
                total_read += n;
            }
            Err(e) => {
                if e.kind() != crate::io::ErrorKind::Interrupted {
                    return Err(e);
                }
            }
        }
    }

    Ok(total_read)
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


#[cfg(feature = "std")]
impl<A: hash::Hasher, B: Write> std::io::Write for TeeWriter<'_, A, B> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.a.write(buf);
        self.b.write(buf).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, "tee write failed"))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.b.flush().map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, "tee flush failed"))
    }
}

/// A `DynDigest` that is also `Clone` and `Send`.
pub trait CloneableDigest: DynDigest + DynClone + Send {}

dyn_clone::clone_trait_object!(CloneableDigest);

// Every type that implements `DynDigest`, `DynClone` and `Send` also implements `CloneableDigest`.
impl<T: DynDigest + DynClone + Send + 'static> CloneableDigest for T {}

#[derive(derive_more::Debug)]
pub struct NormalizingHasher {
    #[debug("hasher")]
    hasher: Box<dyn CloneableDigest>,
    text_mode: bool,
    last_was_cr: bool,
}

impl Clone for NormalizingHasher {
    fn clone(&self) -> Self {
        Self {
            hasher: self.hasher.clone(),
            text_mode: self.text_mode,
            last_was_cr: self.last_was_cr,
        }
    }
}

impl NormalizingHasher {
    pub(crate) fn new(hasher: Box<dyn CloneableDigest>, text_mode: bool) -> Self {
        Self {
            hasher,
            text_mode,
            last_was_cr: false,
        }
    }

    pub(crate) fn done(mut self) -> Box<dyn CloneableDigest> {
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
#[cfg(test)]
pub mod test {
    use crate::io::{self, Read};
    use alloc::string::String;
    use alloc::vec::Vec;
    use rand::{Rng, RngCore};

    #[derive(Debug, Clone)]
    pub struct ChaosReader<R: Rng> {
        rng: R,
        data: Vec<u8>,
        pos: usize,
    }

    impl<R: Rng> ChaosReader<R> {
        pub fn new(rng: R, data: Vec<u8>) -> Self {
            Self { rng, data, pos: 0 }
        }
    }

    impl<R: RngCore> Read for ChaosReader<R> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.pos >= self.data.len() {
                return Ok(0);
            }

            let remaining = self.data.len() - self.pos;
            let max_read = self.rng.gen_range(1..=buf.len().min(remaining));
            let end = self.pos + max_read;
            buf[..max_read].copy_from_slice(&self.data[self.pos..end]);
            self.pos = end;

            Ok(max_read)
        }
    }

    pub fn random_string<R: Rng>(rng: &mut R, len: usize) -> String {
        let mut s = String::with_capacity(len);
        for _ in 0..len {
            s.push(rng.gen_range('a'..='z') as char);
        }
        s
    }

    pub fn check_strings(a: &str, b: &str) {
        assert_eq!(a, b);
    }
}
#[cfg(feature = "test-utils")]
pub(crate) fn random_string(max_len: usize) -> String {
    use rand::{distributions::Alphanumeric, Rng};

    let mut rng = rand::thread_rng();
    let len = rng.gen_range(0..max_len);

    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}

#[cfg(feature = "test-utils")]
pub(crate) fn check_strings(a: &str, b: &str) {
    if a != b {
        let mut a_chars = a.chars();
        let mut b_chars = b.chars();
        let mut i = 0;
        loop {
            let a_c = a_chars.next();
            let b_c = b_chars.next();
            if a_c != b_c {
                panic!(
                    "string differ at index {}, a: {:?}, b: {:?}",
                    i,
                    a_c,
                    b_c.clone()
                );
            }
            if a_c.is_none() {
                break;
            }
            i += 1;
        }
    }
}
