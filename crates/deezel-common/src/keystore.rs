//! Keystore data structures for deezel
//!
//! This module defines the structures used for storing and managing
//! wallet keystores, including encrypted seeds and public metadata.

use serde::{Deserialize, Serialize};
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

/// Represents the entire JSON keystore.
/// This structure is designed to be stored in a file, with the seed
/// encrypted using PGP.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Keystore {
    /// PGP ASCII armored encrypted seed data.
    pub encrypted_seed: String,
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
    pub addresses: BTreeMap<String, Vec<AddressInfo>>,
}

/// Parameters for the PBKDF2/S2K key derivation function.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
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
#[cfg(not(target_arch = "wasm32"))]
use std::path::Path;

impl Keystore {
    // TODO: This is a temporary, insecure implementation. The seed is not encrypted.
    pub fn new(mnemonic: &Mnemonic, network: Network) -> Result<Self> {
        let seed = Seed::new(mnemonic, "");
        let secp = Secp256k1::new();
        let root = Xpriv::new_master(network, seed.as_bytes())?;
        let path = DerivationPath::from_str("m/86'/0'/0'")?;
        let xpub = Xpub::from_priv(&secp, &root.derive_priv(&secp, &path)?);

        let mut armored_seed = Vec::new();
        deezel_asc::armor::writer::write(
            mnemonic.phrase().as_bytes(),
            deezel_asc::armor::reader::BlockType::PrivateKey,
            &mut armored_seed,
            None,
            true,
        )?;

        Ok(Self {
            encrypted_seed: String::from_utf8(armored_seed)?,
            master_fingerprint: root.fingerprint(&secp).to_string(),
            created_at: 0, // TODO
            version: "1.0".to_string(),
            pbkdf2_params: PbkdfParams {
                salt: "".to_string(),
                iterations: 0,
                algorithm: None,
            },
            account_xpub: xpub.to_string(),
            addresses: BTreeMap::new(),
        })
    }

    /// Load keystore from a file path.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn from_file(path: &Path) -> Result<Self> {
        let data = std::fs::read_to_string(path)
            .map_err(|e| DeezelError::Wallet(format!("Failed to read keystore file: {}", e)))?;
        serde_json::from_str(&data)
            .map_err(|e| DeezelError::Wallet(format!("Failed to parse keystore: {}", e)))
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn save_to_file(&self, path: &Path) -> Result<()> {
        let data = serde_json::to_string_pretty(self)?;
        std::fs::write(path, data)?;
        Ok(())
    }

    /// Decodes the armored seed from the keystore.
    /// Note: This does not perform any decryption.
    pub fn get_seed_from_armor(&self) -> Result<String> {
        let (_, _, data) = deezel_asc::armor::reader::decode(self.encrypted_seed.as_bytes())
            .map_err(|e| DeezelError::Crypto(format!("Failed to decode armored seed: {}", e)))?;

        let mnemonic_str = String::from_utf8(data)
            .map_err(|e| DeezelError::Wallet(format!("Failed to convert decoded data to mnemonic string: {}", e)))?;

        // Validate that it's a valid mnemonic, but we return the string.
        Mnemonic::from_phrase(&mnemonic_str, bip39::Language::English)
            .map_err(|e| DeezelError::Wallet(format!("Invalid mnemonic phrase: {}", e)))?;

        Ok(mnemonic_str)
    }
    pub fn get_addresses(
        &self,
        network: Network,
        address_type: &str,
        start_index: u32,
        count: u32,
    ) -> Result<Vec<crate::traits::AddressInfo>> {
        let secp = Secp256k1::new();
        let xpub = Xpub::from_str(&self.account_xpub)?;
        let mut addresses = Vec::new();

        // We'll derive from the receive path (0) for now.
        let branch = 0;

        for i in start_index..start_index + count {
            let path_str = format!("m/{}/{}", branch, i);
            let path = DerivationPath::from_str(&path_str)?;
            let derived_xpub = xpub.derive_pub(&secp, &path)?;
            let (internal_key, _) = derived_xpub.public_key.x_only_public_key();
            let address = Address::p2tr(&secp, internal_key, None, network);
            
            // Construct the full path for display, assuming a BIP-86 structure.
            let coin_type = match network {
                Network::Bitcoin => "0",
                _ => "1",
            };
            let full_path_str = format!("m/86'/{}'/0'/{}", coin_type, path_str.strip_prefix("m/").unwrap());

            addresses.push(crate::traits::AddressInfo {
                derivation_path: full_path_str,
                address: address.to_string(),
                script_type: address_type.to_string(),
                index: i,
                used: false,
            });
        }
        Ok(addresses)
    }
}

use bitcoin::{
    network::Network,
    bip32::{DerivationPath, Xpriv, Xpub},
    secp256k1::{Secp256k1, All},
    Address,
};
use core::str::FromStr;


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