//! Keystore data structures for deezel
//!
//! This module defines the structures used for storing and managing
//! wallet keystores, including encrypted seeds and public metadata.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Represents the entire JSON keystore.
/// This structure is designed to be stored in a file, with the seed
/// encrypted using PGP.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Keystore {
    /// PGP ASCII armored encrypted seed data.
    pub encrypted_seed: String,
    /// Master public key for address derivation (hex encoded).
    pub master_public_key: String,
    /// Master fingerprint for identification.
    pub master_fingerprint: String,
    /// Creation timestamp (Unix epoch).
    pub created_at: u64,
    /// Version of the keystore format.
    pub version: String,
    /// PBKDF2 parameters for key derivation from passphrase.
    pub pbkdf2_params: PbkdfParams,
    /// A map of network type to a list of pre-derived addresses.
    /// This is kept for potential compatibility but new logic should
    /// prefer dynamic derivation.
    #[serde(default)]
    pub addresses: HashMap<String, Vec<AddressInfo>>,
}

/// Parameters for the PBKDF2/S2K key derivation function.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PbkdfParams {
    /// The salt used in the S2K derivation (hex encoded).
    pub salt: String,
    /// The number of iterations for the S2K function.
    pub iterations: u32,
    /// The symmetric key algorithm used.
    #[serde(default)]
    pub algorithm: Option<String>,
}

/// Information about a derived address.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AddressInfo {
    /// The derivation path for the address.
    pub path: String,
    /// The address string.
    pub address: String,
    /// The type of address (e.g., "p2wpkh", "p2tr").
    pub address_type: String,
}