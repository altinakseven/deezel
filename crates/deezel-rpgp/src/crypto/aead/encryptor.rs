use alloc::vec::Vec;
use bytes::{Buf, BytesMut};
use zeroize::Zeroizing;

use super::{ChunkSize, InvalidSessionKeySnafu};
use crate::{
    crypto::{
        aead::{aead_setup, AeadAlgorithm, Error},
        sym::SymmetricKeyAlgorithm,
    },
    util::fill_buffer,
};

// This will be replaced with a no_std compatible trait
pub trait Read {}
impl Read for &[u8] {}

pub struct StreamEncryptor<R> {
    source: R,
    /// Indicates if we are done reading from the `source`.
    is_source_done: bool,
    /// Total number of bytes read from the source.
    bytes_read: u64,
    chunk_index: u64,
    buffer: BytesMut,
    info: [u8; 5],
    message_key: Zeroizing<Vec<u8>>,
    nonce: Vec<u8>,
    chunk_size_expanded: usize,
    aead: AeadAlgorithm,
    sym_alg: SymmetricKeyAlgorithm,
}

impl<R: Read> StreamEncryptor<R> {
    /// Encrypts the data using the given symmetric key.
    pub(crate) fn new(
        sym_alg: SymmetricKeyAlgorithm,
        aead: AeadAlgorithm,
        chunk_size: ChunkSize,
        session_key: &[u8],
        salt: &[u8; 32],
        source: R,
    ) -> Result<Self, Error> {
        if session_key.len() != sym_alg.key_size() {
            return Err(InvalidSessionKeySnafu {
                alg: sym_alg,
                session_key_size: session_key.len(),
            }
            .build());
        }

        let (info, message_key, nonce) =
            aead_setup(sym_alg, aead, chunk_size, &salt[..], session_key);
        let chunk_size_expanded: usize = chunk_size
            .as_byte_size()
            .try_into()
            .expect("invalid chunk size");

        let buffer = BytesMut::with_capacity(chunk_size_expanded);

        Ok(StreamEncryptor {
            source,
            is_source_done: false,
            bytes_read: 0,
            chunk_index: 0,
            info,
            message_key,
            nonce,
            chunk_size_expanded,
            aead,
            sym_alg,
            buffer,
        })
    }

    /// Constructs the final auth tag
    fn create_final_auth_tag(&mut self) -> Result<(), Error> {
        // Associated data is extended with number of plaintext octets.
        let mut final_info = self.info.to_vec();
        // length: 8 octets as big endian
        final_info.extend_from_slice(&self.bytes_read.to_be_bytes());

        // encrypts empty string
        self.buffer.clear();
        self.aead
            .encrypt_in_place(
                &self.sym_alg,
                &self.message_key,
                &self.nonce,
                &final_info,
                &mut self.buffer,
            )?;

        Ok(())
    }

    fn fill_buffer(&mut self) -> Result<(), Error> {
        // This function needs to be refactored to not use std::io
        Ok(())
    }
}

impl<R: Read> Read for StreamEncryptor<R> {
    // This function needs to be refactored to not use std::io
}
