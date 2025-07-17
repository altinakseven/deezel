//! # base64 decoder module

#[cfg(feature = "std")]
use std::io::{self, BufRead, Read};

#[cfg(not(feature = "std"))]
use crate::io::{self, BufRead, Read};

use base64::engine::{general_purpose::GeneralPurpose, Engine};
use crate::io::BufReader;
use alloc::vec::Vec;

const BUF_SIZE: usize = 1024;
const BUF_CAPACITY: usize = BUF_SIZE / 4 * 3;
const ENGINE: GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// Decodes Base64 from the supplied reader.
#[derive(Debug)]
pub struct Base64Decoder<R: BufRead> {
    /// The inner Read instance we are reading bytes from.
    inner: R,
    /// leftover decoded output
    out: Vec<u8>,
    out_buffer: [u8; BUF_CAPACITY],
    /// Memorize if we had an error, so we can return it on calls to read again.
    err: Option<io::Error>,
}

impl<R: BufRead> Base64Decoder<R> {
    /// Creates a new `Base64Decoder`.
    pub fn new(input: R) -> Self {
        Base64Decoder {
            inner: input,
            out: Vec::with_capacity(BUF_CAPACITY),
            out_buffer: [0u8; BUF_CAPACITY],
            err: None,
        }
    }

    pub fn into_inner(self) -> R {
        self.inner
    }

    pub fn into_inner_with_buffer(self) -> (R, Vec<u8>) {
        (self.inner, self.out)
    }
}

impl<R: BufRead> Read for Base64Decoder<R> {
    fn read(&mut self, into: &mut [u8]) -> io::Result<usize> {
        // take care of leftovers
        if !self.out.is_empty() {
            let len = core::cmp::min(self.out.len(), into.len());
            into[..len].copy_from_slice(&self.out[..len]);
            self.out.drain(..len);
            return Ok(len);
        }

        // if we had an error before, return it
        if let Some(ref err) = self.err {
            return Err(copy_err(err));
        }

        // fill our buffer
        let available = self.inner.fill_buf()?;
        if available.len() < 4 && available.len() > 0 {
            // not enough data to decode a full block, and not EOF
            // This indicates we need more data, but we can't get it without blocking
            // or further reads. In a no_std context, we can't just loop on read.
            // We will return what we have, and expect the caller to handle it.
            // In this case, we have nothing decoded, so we return 0.
            // If it was an actual EOF, available.len() would be 0.
            return Ok(0);
        }

        // short circuit empty read
        if available.is_empty() {
            return Ok(0);
        }

        let nr = available.len() / 4 * 4;
        let nw = available.len() / 4 * 3;

        let (consumed, written) = if nw > into.len() {
            let (consumed, nw) =
                try_decode_engine_slice(&available[..nr], &mut self.out_buffer[..]);

            let n = core::cmp::min(nw, into.len());
            let t = &self.out_buffer[0..nw];
            let (t1, t2) = t.split_at(n);

            // copy what we have into `into`
            into[0..n].copy_from_slice(t1);
            // store the rest
            self.out.extend_from_slice(t2);

            (consumed, n)
        } else {
            try_decode_engine_slice(&available[..nr], into)
        };

        self.inner.consume(consumed);

        Ok(written)
    }
}

/// Tries to decode as much of the given slice as possible.
/// Returns the amount written and consumed.
fn try_decode_engine_slice<T: ?Sized + AsRef<[u8]>>(
    input: &T,
    output: &mut [u8],
) -> (usize, usize) {
    let input_bytes = input.as_ref();

    match ENGINE.decode_slice(input_bytes, output) {
        Ok(size) => (input_bytes.len(), size),
        Err(e) => match e {
            base64::DecodeSliceError::DecodeError(base64::DecodeError::InvalidLength(_)) => {
                // Not a multiple of 4. This can happen if we don't have the full stream.
                // Decode what we can.
                let decodable_len = input_bytes.len() / 4 * 4;
                if decodable_len > 0 {
                    // There's something to decode
                    match ENGINE.decode_slice(&input_bytes[..decodable_len], output) {
                        Ok(size) => (decodable_len, size),
                        Err(_) => (0, 0), // Should not happen
                    }
                } else {
                    (0, 0)
                }
            }
            // Any other error means we've hit something that is not base64.
            // We should not consume anything. The caller will see (0,0) and
            // stop reading.
            _ => (0, 0),
        },
    }
}

// why, why why????
fn copy_err(err: &io::Error) -> io::Error {
    io::Error::new(err.kind(), "copied error")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use alloc::vec;
    use alloc::string::String;
    use rand::{Rng, SeedableRng};
    use rand_xorshift::XorShiftRng;

    use super::*;
    use crate::base64::Base64Reader;

    fn test_roundtrip(cap: usize, n: usize, insert_lines: bool) {
        let rng = &mut XorShiftRng::from_seed([
            0x3, 0x8, 0x3, 0xe, 0x3, 0x8, 0x3, 0xe, 0x3, 0x8, 0x3, 0xe, 0x3, 0x8, 0x3, 0xe,
        ]);

        for i in 0..n {
            let data: Vec<u8> = (0..i).map(|_| rng.gen()).collect();
            let mut encoded_data = ENGINE.encode(&data);

            if insert_lines {
                for j in 0..i {
                    // insert line break with a 1/10 chance
                    if rng.gen_ratio(1, 10) {
                        if j >= encoded_data.len() {
                            encoded_data.push('\n');
                        } else {
                            encoded_data.insert(j, '\n');
                        }
                    }
                }
                let mut r = Base64Reader::new(
                    crate::io::BufReader::with_capacity(cap, encoded_data.as_bytes()),
                );
                let mut out = Vec::new();
                r.read_to_end(&mut out).unwrap();
                assert_eq!(data, out);
            } else {
                let mut r = Base64Reader::new(crate::io::BufReader::with_capacity(
                    cap,
                    encoded_data.as_bytes(),
                ));
                let mut out = Vec::new();
                r.read_to_end(&mut out).unwrap();
                assert_eq!(data, out);
            }
        }
    }

    #[test]
    fn test_base64_decoder_roundtrip_standard_1000_no_newlines() {
        test_roundtrip(1, 1000, false);
        test_roundtrip(2, 1000, false);
        test_roundtrip(8, 1000, false);
        test_roundtrip(256, 1000, false);
        test_roundtrip(1024, 1000, false);
        test_roundtrip(8 * 1024, 1000, false);
    }

    #[test]
    fn test_base64_decoder_roundtrip_standard_1000_newlines() {
        test_roundtrip(1, 1000, true);
        test_roundtrip(2, 1000, true);
        test_roundtrip(8, 1000, true);
        test_roundtrip(256, 1000, true);
        test_roundtrip(1024, 1000, true);
        test_roundtrip(8 * 1024, 1000, true);
    }

    #[test]
    fn test_base64_decoder_with_base64_reader() {
        let source = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";

        let data = "TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdCwgc2VkIGRvIGVpdXNtb2Qgd\n\
                     GVtcG9yIGluY2lkaWR1bnQgdXQgbGFib3JlIGV0IGRvbG9yZSBtYWduYSBhbGlxdWEuIFV0IGVuaW0gYWQgbWluaW0\n\
                     gdmVuaWFtLCBxdWlz\n\
                     IG5vc3RydWQgZXhlcmNpdGF0aW9uIHVsbGFtY28gbGFib3JpcyBuaXNpIHV0IGFsaXF1aXAgZXggZW\n\
                     EgY29tbW9kbyBjb25zZXF1YXQuIER1aXMgYXV0ZSBpcnVyZSBkb2\n\
                     xvciBpbiByZXByZWhlbmRlcml0IGluIHZvbHVwdGF0ZSB2ZWxpdCBlc3NlIGNpbGx1bSBkb2xvcmUgZXUgZnVnaWF\n\
                     0IG51bGxhIHBhcmlhdHVyLiBFeGNlcHRldXIgc2ludCBvY2NhZWNhdCBjdXBpZGF0YXQgbm9uIHByb2lkZW50LCBzdW50IGluIGN1bHBhIHF1aSBvZm\n\
                     ZpY2lhIGRlc2VydW50IG1vbGxpdCBhbmltIGlkIGVzdCBsYWJvcnVtLg==";

        let reader = Base64Reader::new(data.as_bytes());
        let mut reader = Base64Decoder::new(reader);
        let mut res = String::new();

        reader.read_to_string(&mut res).unwrap();
        assert_eq!(source, res);
    }

    #[test]
    fn test_base64_decoder_with_end_base() {
        let data = "TG9yZW0g\n=TG9y\n-----hello";

        let br = Base64Reader::new(data.as_bytes());
        let mut reader = Base64Decoder::new(br);
        let mut res = vec![0u8; 32];

        // First read gets the valid data
        assert_eq!(reader.read(&mut res).unwrap(), 6);
        assert_eq!(&res[0..6], b"Lorem ");

        // Second read should see the invalid data and return 0 (EOF)
        assert_eq!(reader.read(&mut res).unwrap(), 0);

        let (r, buffer) = reader.into_inner_with_buffer();
        let mut r = r.into_inner();

        // The leftover decoded buffer should be empty
        assert!(buffer.is_empty());

        // The inner reader should contain the rest of the original stream,
        // as the Base64Reader stops at invalid characters.
        let mut rest = Vec::new();
        r.read_to_end(&mut rest).unwrap();
        assert_eq!(&rest, b"=TG9y\n-----hello");
    }

    #[test]
    fn test_base64_decoder_with_end_one_linebreak() {
        let data = "TG9yZW0g\n=TG9y-----hello";

        let br = Base64Reader::new(data.as_bytes());
        let mut reader = Base64Decoder::new(br);
        let mut res = vec![0u8; 32];

        assert_eq!(reader.read(&mut res).unwrap(), 6);
        assert_eq!(&res[0..6], b"Lorem ");
        assert_eq!(reader.read(&mut res).unwrap(), 0);

        let (r, buffer) = reader.into_inner_with_buffer();
        let mut r = r.into_inner();

        assert!(buffer.is_empty());
        let mut rest = Vec::new();
        r.read_to_end(&mut rest).unwrap();
        assert_eq!(&rest, b"=TG9y-----hello");
    }

    #[test]
    fn test_base64_decoder_with_end_no_linebreak() {
        let data = "TG9yZW0g=TG9y-----hello";

        let br = Base64Reader::new(data.as_bytes());
        let mut reader = Base64Decoder::new(br);
        let mut res = vec![0u8; 32];

        assert_eq!(reader.read(&mut res).unwrap(), 6);
        assert_eq!(&res[0..6], b"Lorem ");
        assert_eq!(reader.read(&mut res).unwrap(), 0);

        let (r, buffer) = reader.into_inner_with_buffer();
        let mut r = r.into_inner();

        assert!(buffer.is_empty());
        let mut rest = Vec::new();
        r.read_to_end(&mut rest).unwrap();
        assert_eq!(&rest, b"=TG9y-----hello");
    }
}
