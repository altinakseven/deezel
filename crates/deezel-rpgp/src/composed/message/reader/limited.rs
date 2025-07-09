use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::format;
extern crate alloc;
use crate::io::{BufRead, Error, Read};

#[derive(Debug)]
pub enum LimitedReader<R: BufRead> {
    Fixed { reader: R },
    Indeterminate(R),
    Partial(R),
}

impl<R: BufRead> BufRead for LimitedReader<R> {
    fn fill_buf(&mut self) -> Result<&[u8], Error> {
        match self {
            Self::Fixed { ref mut reader, .. } => reader.fill_buf(),
            Self::Indeterminate(ref mut r) => r.fill_buf(),
            Self::Partial(ref mut r) => r.fill_buf(),
        }
    }

    fn consume(&mut self, amt: usize) {
        match self {
            Self::Fixed { reader } => {
                reader.consume(amt);
            }
            Self::Indeterminate(ref mut r) => r.consume(amt),
            Self::Partial(ref mut r) => r.consume(amt),
        }
    }
}

impl<R: BufRead> Read for LimitedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        let internal_buf = self.fill_buf()?;
        let len = internal_buf.len().min(buf.len());
        buf[..len].copy_from_slice(&internal_buf[..len]);
        self.consume(len);
        Ok(len)
    }
}

// TODO: no_std Take
// impl<R: BufRead + Take<R>> LimitedReader<R> {
//     pub fn fixed(limit: u64, reader: R) -> Self {
//         let reader = reader.take(limit);
//         Self::Fixed { reader }
//     }

//     pub fn into_inner(self) -> R {
//         match self {
//             Self::Fixed { reader, .. } => reader.into_inner(),
//             Self::Indeterminate(source) => source,
//             Self::Partial(source) => source.into_inner(),
//         }
//     }
//     pub fn get_mut(&mut self) -> &mut R {
//         match self {
//             Self::Fixed { reader, .. } => reader.get_mut(),
//             Self::Indeterminate(source) => source,
//             Self::Partial(source) => source.get_mut(),
//         }
//     }
// }
