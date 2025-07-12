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
    /// Account-level extended public key (xpub) for deriving addresses without the private key.
    #[serde(default)]
    pub account_xpub: String,
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

use crate::{DeezelError, Result};
use bip39::{Mnemonic, Seed};
use deezel_rpgp::composed::Message;
use deezel_rpgp::types::Password;
use std::path::Path;

impl Keystore {
    /// Load keystore from a file path.
    pub fn from_file(path: &Path) -> Result<Self> {
        let data = std::fs::read_to_string(path)
            .map_err(|e| DeezelError::Wallet(format!("Failed to read keystore file: {}", e)))?;
        serde_json::from_str(&data)
            .map_err(|e| DeezelError::Wallet(format!("Failed to parse keystore: {}", e)))
    }

    /// Decrypts the seed from a keystore using the provided passphrase.
    pub fn decrypt_seed(&self, passphrase: &str) -> Result<String> {
        let (message, _headers) = Message::from_armor(self.encrypted_seed.as_bytes())
            .map_err(|e| DeezelError::Crypto(format!("Failed to parse armored message: {}", e)))?;

        let mut decryptor = message.decrypt_with_password(&Password::from(passphrase))
            .map_err(|e| DeezelError::Crypto(format!("Failed to create decryptor: {}", e)))?;

        let decrypted_bytes = decryptor.as_data_vec()
            .map_err(|e| DeezelError::Crypto(format!("Failed to get decrypted data: {}", e)))?;
        
        // The encrypted data is the mnemonic phrase itself, so we convert it to a string.
        let mnemonic_str = String::from_utf8(decrypted_bytes)
            .map_err(|e| DeezelError::Wallet(format!("Failed to convert decrypted data to mnemonic string: {}", e)))?;

        // Validate that it's a valid mnemonic, but we return the string.
        Mnemonic::from_phrase(&mnemonic_str, bip39::Language::English)
            .map_err(|e| DeezelError::Wallet(format!("Invalid mnemonic phrase: {}", e)))?;

        Ok(mnemonic_str)
    }
}

use bitcoin::{
    network::Network,
    bip32::{DerivationPath, Xpriv, Xpub},
    secp256k1::{Secp256k1, All},
    Address,
};
use std::str::FromStr;


/// Derives a Bitcoin address from a mnemonic and a derivation path.
pub fn derive_address(mnemonic_str: &str, path: &DerivationPath, network: Network) -> Result<Address> {
    let mnemonic = Mnemonic::from_phrase(mnemonic_str, bip39::Language::English)
        .map_err(|e| DeezelError::Wallet(format!("Invalid mnemonic: {}", e)))?;
    let seed = Seed::new(&mnemonic, "");
    let secp = Secp256k1::<All>::new();
    let root = Xpriv::new_master(network, seed.as_bytes())
        .map_err(|e| DeezelError::Wallet(format!("Failed to create master key: {}", e)))?;
    let derived_xpriv = root.derive_priv(&secp, path)
        .map_err(|e| DeezelError::Wallet(format!("Failed to derive private key: {}", e)))?;
    let keypair = derived_xpriv.to_keypair(&secp);
    let (internal_key, _parity) = keypair.public_key().x_only_public_key();
    
    // Assuming Taproot (P2TR) addresses as that seems to be the standard in this project
    Ok(Address::p2tr(&secp, internal_key, None, network))
}

/// Derives a Bitcoin address from a master public key and a derivation path.
pub fn derive_address_from_public_key(master_public_key: &str, path: &DerivationPath, network: Network) -> Result<Address> {
    let secp = Secp256k1::<All>::new();
    let root = Xpub::from_str(master_public_key)
        .map_err(|e| DeezelError::Wallet(format!("Invalid master public key: {}", e)))?;

    // We can only derive non-hardened keys from a public key.
    // The path provided should be relative to the master public key and contain only non-hardened components.
    let derived_xpub = root.derive_pub(&secp, path)
        .map_err(|e| DeezelError::Wallet(format!("Failed to derive public key: {}. Note: Hardened derivation from a public key is not possible.", e)))?;
    
    let (internal_key, _parity) = derived_xpub.public_key.x_only_public_key();
    
    Ok(Address::p2tr(&secp, internal_key, None, network))
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