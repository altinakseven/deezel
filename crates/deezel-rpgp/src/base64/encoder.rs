//! no_std compatible base64 encoder
use crate::io::Write;
use base64ct::{Base64, Encoding};

pub struct EncoderWriter<W: Write> {
    writer: W,
    buffer: [u8; 3],
    buf_len: usize,
}

impl<W: Write> EncoderWriter<W> {
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            buffer: [0; 3],
            buf_len: 0,
        }
    }

    pub fn flush(&mut self) -> Result<(), crate::io::Error> {
        if self.buf_len > 0 {
            let mut enc_buf = [0u8; 4];
            let encoded = Base64::encode(&self.buffer[..self.buf_len], &mut enc_buf).unwrap();
            self.writer.write_all(encoded.as_bytes())?;
            self.buf_len = 0;
        }
        self.writer.flush()
    }
}

impl<W: Write> Write for EncoderWriter<W> {
    fn write(&mut self, mut buf: &[u8]) -> Result<usize, crate::io::Error> {
        let original_len = buf.len();
        if self.buf_len > 0 {
            let take = (3 - self.buf_len).min(buf.len());
            self.buffer[self.buf_len..self.buf_len + take].copy_from_slice(&buf[..take]);
            self.buf_len += take;
            buf = &buf[take..];

            if self.buf_len == 3 {
                let mut enc_buf = [0u8; 4];
                let encoded = Base64::encode(&self.buffer, &mut enc_buf).unwrap();
                self.writer.write_all(encoded.as_bytes())?;
                self.buf_len = 0;
            }
        }

        while buf.len() >= 3 {
            let mut enc_buf = [0u8; 4];
            let encoded = Base64::encode(&buf[..3], &mut enc_buf).unwrap();
            self.writer.write_all(encoded.as_bytes())?;
            buf = &buf[3..];
        }

        if !buf.is_empty() {
            self.buffer[..buf.len()].copy_from_slice(buf);
            self.buf_len = buf.len();
        }

        Ok(original_len)
    }

    fn flush(&mut self) -> Result<(), crate::io::Error> {
        self.flush()
    }
}

impl<W: Write> Drop for EncoderWriter<W> {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}