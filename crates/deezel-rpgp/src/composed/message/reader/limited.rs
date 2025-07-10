extern crate alloc;
use crate::io::{BufRead, Error, Read};

/// A simple Take-like wrapper for limiting reads
#[derive(Debug)]
pub struct Take<R> {
    inner: R,
    limit: u64,
}

impl<R> Take<R> {
    pub fn new(inner: R, limit: u64) -> Self {
        Self { inner, limit }
    }
    
    pub fn into_inner(self) -> R {
        self.inner
    }
    
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }
    
    pub fn limit(&self) -> u64 {
        self.limit
    }
}

impl<R: BufRead> BufRead for Take<R> {
    fn fill_buf(&mut self) -> Result<&[u8], Error> {
        if self.limit == 0 {
            return Ok(&[]);
        }
        let buf = self.inner.fill_buf()?;
        let len = (buf.len() as u64).min(self.limit) as usize;
        Ok(&buf[..len])
    }
    
    fn consume(&mut self, amt: usize) {
        let amt = (amt as u64).min(self.limit) as usize;
        self.inner.consume(amt);
        self.limit -= amt as u64;
    }
}

impl<R: Read> Read for Take<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        if self.limit == 0 {
            return Ok(0);
        }
        let max = (buf.len() as u64).min(self.limit) as usize;
        let n = self.inner.read(&mut buf[..max])?;
        self.limit -= n as u64;
        Ok(n)
    }
}

#[derive(Debug)]
pub enum LimitedReader<R: BufRead> {
    Fixed { reader: Take<R> },
    Indeterminate(R),
    Partial(Take<R>),
}

impl<R: BufRead> BufRead for LimitedReader<R> {
    fn fill_buf(&mut self) -> Result<&[u8], Error> {
        match self {
            Self::Fixed { ref mut reader } => reader.fill_buf(),
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

impl<R: BufRead> LimitedReader<R> {
    pub fn fixed(limit: u64, reader: R) -> Self {
        let reader = Take::new(reader, limit);
        Self::Fixed { reader }
    }

    pub fn into_inner(self) -> R {
        match self {
            Self::Fixed { reader } => reader.into_inner(),
            Self::Indeterminate(source) => source,
            Self::Partial(source) => source.into_inner(),
        }
    }
    
    pub fn get_mut(&mut self) -> &mut R {
        match self {
            Self::Fixed { reader } => reader.get_mut(),
            Self::Indeterminate(source) => source,
            Self::Partial(source) => source.get_mut(),
        }
    }
    
    pub fn limit(&self) -> u64 {
        match self {
            Self::Fixed { reader } => reader.limit(),
            Self::Indeterminate(_) => u64::MAX,
            Self::Partial(reader) => reader.limit(),
        }
    }
}
