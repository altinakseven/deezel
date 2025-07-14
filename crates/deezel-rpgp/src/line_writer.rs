//! # Line writer module
extern crate alloc;

use crate::io;

use generic_array::{
    typenum::{Sum, Unsigned, U2},
    ArrayLength, GenericArray,
};

const CRLF: [u8; 2] = [b'\r', b'\n'];
const CR: [u8; 1] = [b'\r'];
const LF: [u8; 1] = [b'\n'];

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LineBreak {
    Crlf,
    Lf,
    Cr,
}

impl AsRef<[u8]> for LineBreak {
    fn as_ref(&self) -> &[u8] {
        match self {
            LineBreak::Crlf => &CRLF[..],
            LineBreak::Lf => &LF[..],
            LineBreak::Cr => &CR[..],
        }
    }
}

/// A `Write` implementation that splits any written bytes into the given length lines.
///
///
/// # Panics
///
/// Calling `write()` after `finish()` is invalid and will panic.
pub struct LineWriter<'a, W, N>
where
    W: io::Write,
    N: Unsigned + ArrayLength<u8>,
    N: core::ops::Add<U2>,
    Sum<N, U2>: ArrayLength<u8>,
{
    /// Which kind of line break to insert.
    line_break: LineBreak,
    /// Where encoded data is written to.
    w: &'a mut W,
    /// Holds a partial chunk, if any, after the last `write()`, so that we may then fill the chunk
    /// with the next `write()`, write it, then proceed with the rest of the input normally.
    extra: GenericArray<u8, N>,
    /// How much of `extra` is occupied, in `[0, N]`.
    extra_len: usize,
    buffer: GenericArray<u8, Sum<N, U2>>,
    /// True iff partial last chunk has been written.
    finished: bool,
    /// panic safety: don't write again in destructor if writer panicked while we were writing to it
    panicked: bool,
}

impl<'a, W, N> LineWriter<'a, W, N>
where
    W: 'a + io::Write,
    N: Unsigned + ArrayLength<u8>,
    N: core::ops::Add<U2>,
    Sum<N, U2>: ArrayLength<u8>,
{
    /// Creates a new encoder around an existing writer.
    pub fn new(w: &'a mut W, line_break: LineBreak) -> Self {
        LineWriter {
            line_break,
            w,
            extra: Default::default(),
            buffer: Default::default(),
            extra_len: 0,
            finished: false,
            panicked: false,
        }
    }

    /// Write all remaining buffered data.
    ///
    /// Once this succeeds, no further writes can be performed.
    ///
    /// # Errors
    ///
    /// Assuming the wrapped writer obeys the `Write` contract, if this returns `Err`, no data was
    /// written, and `finish()` may be retried if appropriate for the type of error, etc.
    pub fn finish(&mut self) -> io::Result<()> {
        if self.finished {
            return Ok(());
        };

        if self.extra_len > 0 {
            self.panicked = true;
            self.w.write_all(&self.extra[..self.extra_len])?;
            self.w.write_all(self.line_break.as_ref())?;
            self.panicked = false;
            // write succeeded, do not write the encoding of extra again if finish() is retried
            self.extra_len = 0;
        }

        self.finished = true;
        Ok(())
    }
}

impl<'a, W, N> io::Write for LineWriter<'a, W, N>
where
    W: 'a + io::Write,
    N: Unsigned + ArrayLength<u8>,
    N: core::ops::Add<U2>,
    Sum<N, U2>: ArrayLength<u8>,
{
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if self.finished {
            panic!("Cannot write more after calling finish()");
        }

        if input.is_empty() {
            return Ok(0);
        }

        // The contract of `Write::write` places some constraints on this implementation:
        // - a call to `write()` represents at most one call to a wrapped `Write`, so we can't
        // iterate over the input and encode multiple chunks.
        // - Errors mean that "no bytes were written to this writer", so we need to reset the
        // internal state to what it was before the error occurred

        let sl = N::to_usize();
        let line_break = self.line_break.as_ref();

        let orig_extra_len = self.extra_len;

        // process leftover stuff from last write
        if self.extra_len + input.len() < sl {
            // still not enough
            self.extra_len += input.len();
            self.extra[orig_extra_len..self.extra_len].copy_from_slice(input);
            Ok(input.len())
        } else {
            let mut buffer_pos = 0;
            let mut input_pos = 0;

            if self.extra_len > 0 {
                let copied = core::cmp::min(orig_extra_len, self.buffer.len());
                self.buffer[buffer_pos..buffer_pos + copied].copy_from_slice(&self.extra[..copied]);
                self.extra_len -= copied;
                buffer_pos += copied;
            }

            if buffer_pos < sl {
                let missing = core::cmp::min(sl - buffer_pos, input.len() - input_pos);

                self.buffer[buffer_pos..buffer_pos + missing]
                    .copy_from_slice(&input[input_pos..input_pos + missing]);

                buffer_pos += missing;
                input_pos += missing;
            }

            // still not enough
            if buffer_pos < sl {
                return Ok(input_pos);
            }

            // insert line break
            self.buffer[buffer_pos..buffer_pos + line_break.len()].copy_from_slice(line_break);
            buffer_pos += line_break.len();

            self.panicked = true;
            let r = self.w.write_all(&self.buffer[..buffer_pos]);
            self.panicked = false;

            match r {
                Ok(_) => Ok(input_pos),
                Err(err) => {
                    // in case we filled and encoded `extra`, reset extra_len
                    self.extra_len = orig_extra_len;
                    Err(err)
                }
            }
        }
    }

    /// Because this is usually treated as OK to call multiple times, it will *not* flush any
    /// incomplete chunks of input or write padding.
    fn flush(&mut self) -> io::Result<()> {
        self.w.flush()
    }
}

impl<'a, W, N> Drop for LineWriter<'a, W, N>
where
    W: 'a + io::Write,
    N: Unsigned + ArrayLength<u8>,
    N: core::ops::Add<U2>,
    Sum<N, U2>: ArrayLength<u8>,
{
    fn drop(&mut self) {
        if !self.panicked {
            // like `BufWriter`, ignore errors during drop
            let _ = self.finish();
        }
    }
}
