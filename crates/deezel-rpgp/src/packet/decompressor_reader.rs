use alloc::vec::Vec;
use bytes::{Buf, BytesMut};
use core::fmt::Debug;

use crate::{
    composed::DebugBufRead,
    io::{self, BufRead, Read},
    packet::compressed_data::Decompressor as BufferDecompressor,
    types::CompressionAlgorithm,
};

/// A decompressor that wraps a reader and provides streaming decompression
#[derive(Debug)]
pub struct Decompressor<R: DebugBufRead> {
    reader: R,
    decompressor: BufferDecompressor,
    buffer: BytesMut,
    input_buffer: Vec<u8>,
    eof: bool,
}

impl<R: DebugBufRead> Decompressor<R> {
    pub fn from_reader(mut reader: R) -> Result<Self, io::Error> {
        // Read the compression algorithm from the first byte
        let alg_byte = {
            let buf = reader.fill_buf()?;
            if buf.is_empty() {
                return Err(io::Error::new(io::ErrorKind::Other, "empty compressed data"));
            }
            buf[0]
        };
        reader.consume(1);
        
        let alg = CompressionAlgorithm::from(alg_byte);
        let decompressor = BufferDecompressor::new(alg);
        
        Ok(Self {
            reader,
            decompressor,
            buffer: BytesMut::with_capacity(4096),
            input_buffer: Vec::with_capacity(4096),
            eof: false,
        })
    }
    
    pub fn into_inner(self) -> R {
        self.reader
    }
    
    pub fn get_ref(&self) -> &R {
        &self.reader
    }
    
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.reader
    }
    
    fn fill_output_buffer(&mut self) -> Result<(), io::Error> {
        if self.eof || self.buffer.has_remaining() {
            return Ok(());
        }
        
        // Read more input data if needed
        if self.input_buffer.is_empty() {
            self.input_buffer.resize(4096, 0);
            let n = self.reader.read(&mut self.input_buffer)?;
            self.input_buffer.truncate(n);
            if n == 0 {
                self.eof = true;
                return Ok(());
            }
        }
        
        // Decompress data
        self.buffer.resize(4096, 0);
        let (consumed, written) = self.decompressor
            .decompress(&self.input_buffer, &mut self.buffer)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "decompression failed"))?;
            
        // Remove consumed input
        self.input_buffer.drain(..consumed);
        self.buffer.truncate(written);
        
        Ok(())
    }
}

impl<R: DebugBufRead> BufRead for Decompressor<R> {
    fn fill_buf(&mut self) -> Result<&[u8], io::Error> {
        self.fill_output_buffer()?;
        Ok(&self.buffer[..])
    }
    
    fn consume(&mut self, amt: usize) {
        self.buffer.advance(amt);
    }
}

impl<R: DebugBufRead> Read for Decompressor<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        let internal_buf = self.fill_buf()?;
        let len = internal_buf.len().min(buf.len());
        buf[..len].copy_from_slice(&internal_buf[..len]);
        self.consume(len);
        Ok(len)
    }
}