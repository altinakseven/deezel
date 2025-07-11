//! Keystore management functionality for deezel-sys
//!
//! This module provides keystore creation and management functionality
//! using PGP encryption for secure seed storage.

use anyhow::{anyhow, Context, Result as AnyhowResult};
use serde::{Deserialize, Serialize};
use bitcoin::{
    Network,
    bip32::{DerivationPath, Xpriv},
    secp256k1::Secp256k1,
    Address,
    bip32::Xpub,
    CompressedPublicKey,
    PublicKey,
    ScriptBuf,
};
use bip39::{Mnemonic, MnemonicType, Seed};
use std::str::FromStr;
use deezel_rpgp::{
    composed::{ArmorOptions, MessageBuilder},
    crypto::{sym::SymmetricKeyAlgorithm, hash::HashAlgorithm},
    types::{Password, StringToKey},
};
use rand::{rngs::OsRng, RngCore};
use hex;

use crate::pgp::DeezelPgpProvider;
use deezel_common::traits::{KeystoreProvider, KeystoreAddress, KeystoreInfo};
use deezel_common::{Result as CommonResult, DeezelError};
use async_trait::async_trait;

/// Keystore structure that contains encrypted seed and master public key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Keystore {
    /// PGP ASCII armored encrypted seed data
    pub encrypted_seed: String,
    /// Master public key for address derivation (hex encoded)
    pub master_public_key: String,
    /// Master fingerprint for identification
    pub master_fingerprint: String,
    /// Creation timestamp
    pub created_at: u64,
    /// Version of the keystore format
    pub version: String,
    /// PBKDF2 parameters for key derivation
    pub pbkdf2_params: PbkdfParams,
}

/// PBKDF2 parameters for secure key derivation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PbkdfParams {
    /// Salt used for PBKDF2 (hex encoded)
    pub salt: String,
    /// Number of iterations
    pub iterations: u32,
    /// Hash algorithm used
    pub hash_algorithm: String,
}


/// Parameters for creating a new keystore
pub struct KeystoreCreateParams {
    /// Optional mnemonic (if None, a new one will be generated)
    pub mnemonic: Option<String>,
    /// Passphrase for PGP encryption
    pub passphrase: String,
    /// Bitcoin network
    pub network: Network,
    /// Number of addresses to derive for each script type
    pub address_count: u32,
}

/// Keystore manager that handles creation and management
pub struct KeystoreManager {
    pgp_provider: DeezelPgpProvider,
}

impl KeystoreManager {
    pub fn new() -> Self {
        Self {
            pgp_provider: DeezelPgpProvider::new(),
        }
    }

    /// Create a new keystore with PGP-encrypted seed and master public key
    pub async fn create_keystore(&self, params: KeystoreCreateParams) -> AnyhowResult<(Keystore, String)> {
        // Generate or use provided mnemonic
        let mnemonic = if let Some(mnemonic_str) = params.mnemonic {
            Mnemonic::from_phrase(&mnemonic_str, bip39::Language::English)
                .context("Invalid mnemonic provided")?
        } else {
            Mnemonic::new(MnemonicType::Words24, bip39::Language::English)
        };

        let mnemonic_str = mnemonic.to_string();

        // Generate seed from mnemonic
        let seed = Seed::new(&mnemonic, "");
        let secp = Secp256k1::new();
        
        // Encrypt the mnemonic using PGP with ASCII armoring
        let (encrypted_seed, pbkdf2_params) = self.encrypt_seed_with_pgp(&mnemonic_str, &params.passphrase)?;

        // Create master key (always use Bitcoin mainnet for the master key to ensure compatibility)
        let master_key = Xpriv::new_master(Network::Bitcoin, seed.as_bytes())
            .context("Failed to create master key from seed")?;
        
        // Get master public key
        let master_public_key = Xpub::from_priv(&secp, &master_key);
        
        // Get master fingerprint
        let master_fingerprint = master_key.fingerprint(&secp);

        let keystore = Keystore {
            encrypted_seed,
            master_public_key: master_public_key.to_string(),
            master_fingerprint: master_fingerprint.to_string(),
            created_at: chrono::Utc::now().timestamp() as u64,
            version: env!("CARGO_PKG_VERSION").to_string(),
            pbkdf2_params,
        };

        Ok((keystore, mnemonic_str))
    }

    /// Encrypt the seed using PGP with ASCII armoring
    fn encrypt_seed_with_pgp(&self, mnemonic: &str, passphrase: &str) -> AnyhowResult<(String, PbkdfParams)> {
        // Set up PGP encryption parameters
        let iterations = 100_000;
        let mut salt = [0u8; 8];
        OsRng.fill_bytes(&mut salt);
        let count = Self::encode_count(iterations);
        let s2k = StringToKey::IteratedAndSalted {
            hash_alg: HashAlgorithm::Sha256,
            salt,
            count,
        };
        
        let sym_key_algo = SymmetricKeyAlgorithm::AES256;

        // Encrypt and armor the mnemonic
        let message = MessageBuilder::from_reader("deezel-keystore", mnemonic.as_bytes());
        let mut enc_builder = message.seipd_v1(&mut OsRng, sym_key_algo);
        enc_builder.encrypt_with_password(s2k, &Password::from(passphrase))
            .context("Failed to encrypt seed with PGP")?;

        let armored_message = enc_builder.to_armored_string(OsRng, ArmorOptions::default())
            .context("Failed to create ASCII armored message")?;

        // Store PBKDF2 parameters for later decryption
        let pbkdf2_params = PbkdfParams {
            salt: hex::encode(salt),
            iterations,
            hash_algorithm: "SHA256".to_string(),
        };

        Ok((armored_message, pbkdf2_params))
    }

    /// Prompt for passphrase securely using a TUI
    pub fn prompt_for_passphrase(prompt: &str, confirm: bool) -> AnyhowResult<String> {
        use dialoguer::Password;
        
        if confirm {
            // For new passphrases, require confirmation
            loop {
                let passphrase = Password::new()
                    .with_prompt(prompt)
                    .interact()
                    .context("Failed to read passphrase")?;
                
                if passphrase.is_empty() {
                    println!("❌ Passphrase cannot be empty. Please try again.");
                    continue;
                }
                
                let confirm_passphrase = Password::new()
                    .with_prompt("Confirm passphrase")
                    .interact()
                    .context("Failed to read passphrase confirmation")?;
                
                if passphrase == confirm_passphrase {
                    return Ok(passphrase);
                } else {
                    println!("❌ Passphrases do not match. Please try again.");
                }
            }
        } else {
            // For existing passphrases, just prompt once
            let passphrase = Password::new()
                .with_prompt(prompt)
                .interact()
                .context("Failed to read passphrase")?;
            
            if passphrase.is_empty() {
                return Err(anyhow!("Passphrase cannot be empty"));
            }
            
            Ok(passphrase)
        }
    }

    /// Encode count for PGP S2K (from RFC 4880)
    fn encode_count(iterations: u32) -> u8 {
        if iterations >= 65011712 {
            return 255;
        }
        if iterations == 0 {
            return 0;
        }

        let mut c = iterations;
        let mut e = 0;
        while c > 32 {
            c = (c + 15) / 16;
            e += 1;
        }
        c -= 16;

        (e << 4) | c as u8
    }

    /// Load and decrypt a keystore
    pub async fn load_keystore(&self, keystore_data: &str, passphrase: &str) -> AnyhowResult<(Keystore, String)> {
        // Parse the keystore JSON
        let keystore: Keystore = serde_json::from_str(keystore_data)
            .context("Failed to parse keystore JSON")?;

        // Decrypt the mnemonic using PGP
        let mnemonic = self.decrypt_seed_with_pgp(&keystore.encrypted_seed, passphrase, &keystore.pbkdf2_params)?;
        
        Ok((keystore, mnemonic))
    }
    
    /// Decrypt the seed using PGP with stored PBKDF2 parameters
    fn decrypt_seed_with_pgp(&self, encrypted_seed: &str, passphrase: &str, pbkdf2_params: &PbkdfParams) -> AnyhowResult<String> {
        // Decode hex salt back to bytes
        let _salt = hex::decode(&pbkdf2_params.salt)
            .map_err(|e| anyhow::anyhow!("Failed to decode salt from hex: {}", e))?;
        
        // Note: The PBKDF2 parameters are stored for future use, but the current PGP implementation
        // handles the key derivation internally. In a more advanced implementation, we would
        // use these parameters to derive the key manually and then decrypt.
        
        // For now, we use the PGP library's built-in password-based decryption
        // which should handle the S2K parameters that were used during encryption
        use deezel_rpgp::composed::Message;
        
        let (message, _headers) = Message::from_string(encrypted_seed)
            .context("Failed to parse armored PGP message")?;
            
        let mut decrypted_message = message.decrypt_with_password(&Password::from(passphrase))
            .context("Failed to decrypt PGP message with passphrase")?;
            
        let decrypted_data = decrypted_message.as_data_vec()
            .context("Failed to read decrypted data")?;
            
        let mnemonic = String::from_utf8(decrypted_data)
            .context("Failed to convert decrypted data to UTF-8 string")?;
            
        Ok(mnemonic)
    }

    /// Save keystore to file
    pub async fn save_keystore(&self, keystore: &Keystore, file_path: &str) -> AnyhowResult<()> {
        let keystore_json = serde_json::to_string_pretty(keystore)
            .context("Failed to serialize keystore")?;

        std::fs::write(file_path, keystore_json)
            .with_context(|| format!("Failed to write keystore to file: {}", file_path))?;

        Ok(())
    }

    /// Load keystore from file
    pub async fn load_keystore_from_file(&self, file_path: &str, passphrase: &str) -> AnyhowResult<(Keystore, String)> {
        let keystore_data = std::fs::read_to_string(file_path)
            .with_context(|| format!("Failed to read keystore file: {}", file_path))?;

        self.load_keystore(&keystore_data, passphrase).await
    }

    /// Load keystore metadata (master public key, fingerprint, etc.) without decryption
    pub async fn load_keystore_metadata_from_file(&self, file_path: &str) -> AnyhowResult<Keystore> {
        let keystore_data = std::fs::read_to_string(file_path)
            .with_context(|| format!("Failed to read keystore file: {}", file_path))?;

        // Parse the keystore JSON - we only need the metadata, not the encrypted seed
        let keystore: Keystore = serde_json::from_str(&keystore_data)
            .context("Failed to parse keystore JSON")?;

        Ok(keystore)
    }

    /// Derive addresses dynamically from master public key
    pub fn derive_addresses(&self, keystore: &Keystore, network: Network, script_types: &[&str], start_index: u32, count: u32) -> AnyhowResult<Vec<KeystoreAddress>> {
        let master_xpub = Xpub::from_str(&keystore.master_public_key)
            .context("Failed to parse master public key")?;
        
        let secp = Secp256k1::new();
        let mut addresses = Vec::new();
        
        for script_type in script_types {
            for index in start_index..(start_index + count) {
                let address = self.derive_single_address(&master_xpub, &secp, network, script_type, index)?;
                addresses.push(address);
            }
        }
        
        Ok(addresses)
    }
    
    /// Derive a single address from master public key
    fn derive_single_address(&self, master_xpub: &Xpub, secp: &Secp256k1<bitcoin::secp256k1::All>, network: Network, script_type: &str, index: u32) -> AnyhowResult<KeystoreAddress> {
        // Get the correct coin type for the network
        let coin_type = match network {
            Network::Bitcoin => "0",      // Bitcoin mainnet
            Network::Testnet => "1",      // Bitcoin testnet
            Network::Signet => "1",       // Bitcoin signet (uses testnet coin type)
            Network::Regtest => "1",      // Bitcoin regtest (uses testnet coin type)
            _ => "0",                     // Default to mainnet
        };
        
        // Define derivation paths for different script types
        // Note: We can only derive non-hardened paths from public keys
        let (derivation_path, address) = match script_type {
            "p2pkh" => {
                let path_str = format!("m/44'/{}'/0'/0/{}", coin_type, index);
                let path = DerivationPath::from_str(&format!("m/44/{}/0/0/{}", coin_type, index))
                    .context("Failed to create P2PKH derivation path")?;
                let derived_key = master_xpub.derive_pub(secp, &path)
                    .with_context(|| format!("Failed to derive public key for path: {}", path))?;
                let bitcoin_pubkey = PublicKey::new(derived_key.public_key);
                let compressed_pubkey = CompressedPublicKey::try_from(bitcoin_pubkey)
                    .context("Failed to create compressed public key")?;
                let address = Address::p2pkh(compressed_pubkey, network);
                (path_str, address.to_string())
            },
            "p2sh" => {
                let path_str = format!("m/49'/{}'/0'/0/{}", coin_type, index);
                let path = DerivationPath::from_str(&format!("m/49/{}/0/0/{}", coin_type, index))
                    .context("Failed to create P2SH derivation path")?;
                let derived_key = master_xpub.derive_pub(secp, &path)
                    .context("Failed to derive public key")?;
                let bitcoin_pubkey = PublicKey::new(derived_key.public_key);
                let compressed_pubkey = CompressedPublicKey::try_from(bitcoin_pubkey)
                    .context("Failed to create compressed public key")?;
                let wpkh_script = ScriptBuf::new_p2wpkh(&compressed_pubkey.wpubkey_hash());
                let address = Address::p2sh(&wpkh_script, network)
                    .context("Failed to create P2SH address")?;
                (path_str, address.to_string())
            },
            "p2wpkh" => {
                let path_str = format!("m/84'/{}'/0'/0/{}", coin_type, index);
                let path = DerivationPath::from_str(&format!("m/84/{}/0/0/{}", coin_type, index))
                    .context("Failed to create P2WPKH derivation path")?;
                let derived_key = master_xpub.derive_pub(secp, &path)
                    .context("Failed to derive public key")?;
                let bitcoin_pubkey = PublicKey::new(derived_key.public_key);
                let compressed_pubkey = CompressedPublicKey::try_from(bitcoin_pubkey)
                    .context("Failed to create compressed public key")?;
                let address = Address::p2wpkh(&compressed_pubkey, network);
                (path_str, address.to_string())
            },
            "p2wsh" => {
                let path_str = format!("m/84'/{}'/0'/0/{}", coin_type, index);
                let path = DerivationPath::from_str(&format!("m/84/{}/0/0/{}", coin_type, index))
                    .context("Failed to create P2WSH derivation path")?;
                let derived_key = master_xpub.derive_pub(secp, &path)
                    .context("Failed to derive public key")?;
                let bitcoin_pubkey = PublicKey::new(derived_key.public_key);
                let compressed_pubkey = CompressedPublicKey::try_from(bitcoin_pubkey)
                    .context("Failed to create compressed public key")?;
                // Create a simple P2WPKH script for P2WSH wrapping
                let script = ScriptBuf::new_p2wpkh(&compressed_pubkey.wpubkey_hash());
                let address = Address::p2wsh(&script, network);
                (path_str, address.to_string())
            },
            "p2tr" => {
                let path_str = format!("m/86'/{}'/0'/0/{}", coin_type, index);
                let path = DerivationPath::from_str(&format!("m/86/{}/0/0/{}", coin_type, index))
                    .context("Failed to create P2TR derivation path")?;
                let derived_key = master_xpub.derive_pub(secp, &path)
                    .context("Failed to derive public key")?;
                let internal_key = bitcoin::key::UntweakedPublicKey::from(derived_key.public_key);
                let address = Address::p2tr(secp, internal_key, None, network);
                (path_str, address.to_string())
            },
            _ => return Err(anyhow!("Unsupported script type: {}", script_type)),
        };
        
        Ok(KeystoreAddress {
            address,
            derivation_path,
            index,
            script_type: script_type.to_string(),
            network: None, // Will be set by caller if needed
        })
    }
    
    /// Get default addresses for display (first 5 of each type for given network)
    pub fn get_default_addresses(&self, keystore: &Keystore, network: Network) -> AnyhowResult<Vec<KeystoreAddress>> {
        let script_types = ["p2pkh", "p2sh", "p2wpkh", "p2wsh", "p2tr"];
        self.derive_addresses(keystore, network, &script_types, 0, 5)
    }

    /// Create a keystore info summary
    pub fn get_keystore_info(&self, keystore: &Keystore) -> KeystoreInfo {
        KeystoreInfo {
            master_public_key: keystore.master_public_key.clone(),
            master_fingerprint: keystore.master_fingerprint.clone(),
            created_at: keystore.created_at,
            version: keystore.version.clone(),
        }
    }
    
    /// Parse address range specification (e.g., "p2tr:0-1000", "p2sh:0-500")
    pub fn parse_address_range(&self, range_spec: &str) -> AnyhowResult<(String, u32, u32)> {
        let parts: Vec<&str> = range_spec.split(':').collect();
        if parts.len() != 2 {
            return Err(anyhow!("Invalid range specification. Expected format: script_type:start-end"));
        }
        
        let script_type = parts[0].to_string();
        let range_parts: Vec<&str> = parts[1].split('-').collect();
        if range_parts.len() != 2 {
            return Err(anyhow!("Invalid range format. Expected format: start-end"));
        }
        
        let start_index: u32 = range_parts[0].parse()
            .map_err(|_| anyhow!("Invalid start index: {}", range_parts[0]))?;
        let end_index: u32 = range_parts[1].parse()
            .map_err(|_| anyhow!("Invalid end index: {}", range_parts[1]))?;
            
        if end_index <= start_index {
            return Err(anyhow!("End index must be greater than start index"));
        }
        
        Ok((script_type, start_index, end_index - start_index))
    }
    
    /// Derive addresses from keystore metadata without requiring decryption
    pub fn derive_addresses_from_metadata(&self, keystore_metadata: &Keystore, network: Network, script_types: &[&str], start_index: u32, count: u32, custom_network_params: Option<&deezel_common::network::NetworkParams>) -> AnyhowResult<Vec<KeystoreAddress>> {
        let master_xpub = Xpub::from_str(&keystore_metadata.master_public_key)
            .context("Failed to parse master public key")?;
        
        let secp = Secp256k1::new();
        let mut addresses = Vec::new();
        
        for script_type in script_types {
            for index in start_index..(start_index + count) {
                let mut address = self.derive_single_address(&master_xpub, &secp, network, script_type, index)?;
                
                // Apply custom network parameters if provided
                if let Some(network_params) = custom_network_params {
                    address = self.apply_custom_network_params(address, network_params)?;
                }
                
                addresses.push(address);
            }
        }
        
        Ok(addresses)
    }
    
    /// Get default addresses from keystore metadata without requiring decryption
    pub fn get_default_addresses_from_metadata(&self, keystore_metadata: &Keystore, network: Network, custom_network_params: Option<&deezel_common::network::NetworkParams>) -> AnyhowResult<Vec<KeystoreAddress>> {
        let script_types = ["p2pkh", "p2sh", "p2wpkh", "p2wsh", "p2tr"];
        self.derive_addresses_from_metadata(keystore_metadata, network, &script_types, 0, 5, custom_network_params)
    }
    
    /// Apply custom network parameters to an address (re-derive with custom magic bytes)
    fn apply_custom_network_params(&self, address: KeystoreAddress, _network_params: &deezel_common::network::NetworkParams) -> AnyhowResult<KeystoreAddress> {
        // For now, we'll keep the original address since re-deriving with custom network parameters
        // would require more complex address generation logic. This is a placeholder for future enhancement.
        // The custom network parameters are primarily used for global network configuration.
        
        // TODO: Implement proper address re-derivation with custom magic bytes
        // This would involve:
        // 1. Parsing the derivation path
        // 2. Re-deriving the public key
        // 3. Creating the address with custom network parameters
        
        Ok(address)
    }
}

/// Implementation of KeystoreProvider trait for KeystoreManager
#[async_trait(?Send)]
impl KeystoreProvider for KeystoreManager {
    async fn derive_addresses(&self, master_public_key: &str, network: Network, script_types: &[&str], start_index: u32, count: u32) -> CommonResult<Vec<KeystoreAddress>> {
        let master_xpub = Xpub::from_str(master_public_key)
            .map_err(|e| DeezelError::Crypto(format!("Failed to parse master public key: {}", e)))?;
        
        let secp = Secp256k1::new();
        let mut addresses = Vec::new();
        
        for script_type in script_types {
            for index in start_index..(start_index + count) {
                let address = self.derive_single_address(&master_xpub, &secp, network, script_type, index)
                    .map_err(|e| DeezelError::Crypto(format!("Failed to derive address: {}", e)))?;
                addresses.push(address);
            }
        }
        
        Ok(addresses)
    }
    
    async fn get_default_addresses(&self, master_public_key: &str, network: Network) -> CommonResult<Vec<KeystoreAddress>> {
        let script_types = ["p2pkh", "p2sh", "p2wpkh", "p2wsh", "p2tr"];
        // Call the trait method, not the struct method
        KeystoreProvider::derive_addresses(self, master_public_key, network, &script_types, 0, 5).await
    }
    
    fn parse_address_range(&self, range_spec: &str) -> CommonResult<(String, u32, u32)> {
        // Call the struct method directly to avoid infinite recursion
        KeystoreManager::parse_address_range(self, range_spec)
            .map_err(|e| DeezelError::Parse(format!("Failed to parse address range: {}", e)))
    }
    
    async fn get_keystore_info(&self, master_public_key: &str, master_fingerprint: &str, created_at: u64, version: &str) -> CommonResult<KeystoreInfo> {
        Ok(KeystoreInfo {
            master_public_key: master_public_key.to_string(),
            master_fingerprint: master_fingerprint.to_string(),
            created_at,
            version: version.to_string(),
        })
    }
}

/// Create a keystore with the given parameters
pub async fn create_keystore(params: KeystoreCreateParams) -> AnyhowResult<(Keystore, String)> {
    let manager = KeystoreManager::new();
    manager.create_keystore(params).await
}

/// Load a keystore from file
pub async fn load_keystore_from_file(file_path: &str, passphrase: &str) -> AnyhowResult<(Keystore, String)> {
    let manager = KeystoreManager::new();
    manager.load_keystore_from_file(file_path, passphrase).await
}

/// Save a keystore to file
pub async fn save_keystore_to_file(keystore: &Keystore, file_path: &str) -> AnyhowResult<()> {
    let manager = KeystoreManager::new();
    manager.save_keystore(keystore, file_path).await
}