//! # Line ending normalization module
extern crate alloc;
use alloc::string::String;

use alloc::borrow::Cow;
use bytes::{Buf, BytesMut};
use spin::Once;

use crate::util::fill_buffer;
pub use crate::line_writer::LineBreak;

static RE: Once<regex::bytes::Regex> = Once::new();

fn get_re() -> &'static regex::bytes::Regex {
    RE.call_once(|| regex::bytes::Regex::new(r"(\r\n?|\n)").expect("valid regex"))
}

use crate::io::{Error, Read};

/// This struct wraps a reader and normalize line endings.
#[derive(Clone)]
pub struct NormalizedReader<R>
where
    R: Read,
{
    line_break: LineBreak,
    source: R,
    in_buffer: [u8; BUF_SIZE / 2],
    replaced: BytesMut,
    is_done: bool,
}

const BUF_SIZE: usize = 1024;
impl<R: Read> NormalizedReader<R> {
    pub fn new(source: R, line_break: LineBreak) -> Self {
        Self {
            source,
            line_break,
            in_buffer: [0u8; BUF_SIZE / 2],
            replaced: BytesMut::with_capacity(BUF_SIZE),
            is_done: false,
        }
    }

    /// Fills the buffer, and then normalizes it
    fn fill_buffer(&mut self) -> Result<(), Error> {
        if self.replaced.has_remaining() || self.is_done {
            return Ok(());
        }

        let mut have_split_crlf = false;
        if !self.in_buffer.is_empty() {
            let last = self.in_buffer.last().copied();
            if last == Some(b'\r') {
                have_split_crlf = true;
            }
        }

        let read = fill_buffer(&mut self.source, &mut self.in_buffer, None)?;

        if read == 0 {
            self.is_done = true;
        }

        self.cleanup_buffer(read, have_split_crlf);

        Ok(())
    }

    /// Normalizes the line endings in the current buffer
    fn cleanup_buffer(&mut self, read: usize, have_split_crlf: bool) {
        let in_buffer = if have_split_crlf && read > 0 {
            // skip the first byte of the buffer, which is a `\n` as it was already handled before
            &self.in_buffer[1..read]
        } else {
            &self.in_buffer[..read]
        };

        let res = get_re().replace_all(in_buffer, self.line_break.as_ref());
        self.replaced.clear();
        self.replaced.extend_from_slice(&res);
    }


    pub(crate) fn inner_mut(&mut self) -> &mut R {
        &mut self.source
    }
}


impl<R: Read> Read for NormalizedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        self.fill_buffer()?;

        let len = self.replaced.len().min(buf.len());
        self.replaced.copy_to_slice(&mut buf[..len]);

        Ok(len)
    }
}

pub(crate) fn normalize_lines(s: &str, line_break: LineBreak) -> Cow<'_, str> {
    let bytes = get_re().replace_all(s.as_bytes(), line_break.as_ref());
    match bytes {
        Cow::Borrowed(bytes) => {
            Cow::Borrowed(core::str::from_utf8(bytes).expect("valid bytes in"))
        }
        Cow::Owned(bytes) => {
            Cow::Owned(alloc::string::String::from_utf8(bytes).expect("valid bytes in"))
        }
    }
}
