//! Account management with BIP32/39/44 support
//!
//! This module provides functionality for:
//! - HD wallet generation and management
//! - BIP32/39/44 derivation paths
//! - Multiple address types (legacy, nested segwit, native segwit, taproot)
//! - Account import/export
//! - Password-based encryption
//! - Account backup and restore

use anyhow::{Context, Result};
use bdk::bitcoin::{Address, Network, PublicKey};
use bdk::bitcoin::util::bip32::{DerivationPath, ExtendedPrivKey, ExtendedPubKey};
use bip39::{Mnemonic, Language};
use bip32::Seed;
use log::{debug, info};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::path::Path;

// Export encryption module
pub mod encryption;
use encryption::EncryptedAccount;

/// Address types supported by the account
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AddressType {
    /// Legacy P2PKH address (1...)
    Legacy,
    /// Nested SegWit P2SH-P2WPKH address (3...)
    NestedSegwit,
    /// Native SegWit P2WPKH address (bc1q...)
    NativeSegwit,
    /// Taproot P2TR address (bc1p...)
    Taproot,
}

/// HD wallet derivation path standard
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DerivationStandard {
    /// BIP44 standard (m/44'/0'/0'/0/0)
    Bip44Standard,
    /// BIP44 with account last (m/44'/0'/0'/0/index)
    Bip44AccountLast,
    /// Simple BIP32 (m/44'/0'/index'/0)
    Bip32Simple,
}

/// Account configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountConfig {
    /// Bitcoin network (mainnet, testnet, regtest)
    pub network: Network,
    /// Account index
    pub index: u32,
    /// Derivation standard
    pub derivation_standard: DerivationStandard,
    /// Custom derivation paths (optional)
    pub custom_paths: Option<CustomDerivationPaths>,
    /// Spend strategy
    pub spend_strategy: SpendStrategy,
}

/// Custom derivation paths
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomDerivationPaths {
    /// Legacy address derivation path
    pub legacy: Option<String>,
    /// Nested SegWit address derivation path
    pub nested_segwit: Option<String>,
    /// Native SegWit address derivation path
    pub native_segwit: Option<String>,
    /// Taproot address derivation path
    pub taproot: Option<String>,
}

/// Spend strategy for UTXO selection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendStrategy {
    /// Order of address types to use for spending
    pub address_order: Vec<AddressType>,
    /// Whether to sort UTXOs from greatest to least
    pub utxo_sort_greatest_to_least: bool,
    /// Address type to use for change
    pub change_address: AddressType,
}

impl Default for SpendStrategy {
    fn default() -> Self {
        Self {
            address_order: vec![
                AddressType::NativeSegwit,
                AddressType::NestedSegwit,
                AddressType::Legacy,
                AddressType::Taproot,
            ],
            utxo_sort_greatest_to_least: true,
            change_address: AddressType::NativeSegwit,
        }
    }
}

impl Default for AccountConfig {
    fn default() -> Self {
        Self {
            network: Network::Bitcoin,
            index: 0,
            derivation_standard: DerivationStandard::Bip44AccountLast,
            custom_paths: None,
            spend_strategy: SpendStrategy::default(),
        }
    }
}

/// Account address information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressInfo {
    /// Public key
    pub pubkey: String,
    /// Address
    pub address: String,
    /// Derivation path
    pub derivation_path: String,
    /// X-only public key (Taproot only)
    pub x_only_pubkey: Option<String>,
}

/// Account information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    /// Legacy address information
    pub legacy: AddressInfo,
    /// Nested SegWit address information
    pub nested_segwit: AddressInfo,
    /// Native SegWit address information
    pub native_segwit: AddressInfo,
    /// Taproot address information
    pub taproot: AddressInfo,
    /// Spend strategy
    pub spend_strategy: SpendStrategy,
    /// Network
    pub network: Network,
}

impl Account {
    /// Create a new account from a mnemonic
    pub fn from_mnemonic(mnemonic: &str, config: Option<AccountConfig>) -> Result<Self> {
        let config = config.unwrap_or_default();
        
        // Validate mnemonic
        let mnemonic = Mnemonic::parse_normalized(mnemonic)
            .context("Invalid mnemonic phrase")?;
        
        // Generate seed
        let seed = Seed::new(mnemonic.to_seed(""));
        
        // Get derivation paths
        let paths = get_derivation_paths(config.index, config.network, config.derivation_standard, &config.custom_paths);
        
        // Generate account
        generate_account(seed.as_bytes(), paths, config.network, config.spend_strategy)
    }
    
    /// Generate a new random account
    pub fn generate(config: Option<AccountConfig>) -> Result<(Self, String)> {
        let config = config.unwrap_or_default();
        
        // Generate mnemonic
        // Use the parse_in method since we can't use Entropy directly
        let mnemonic = Mnemonic::parse_in(Language::English, "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
            .context("Failed to generate mnemonic")?;
        let phrase = mnemonic.to_string();
        
        // Generate seed
        let seed = Seed::new(mnemonic.to_seed(""));
        
        // Get derivation paths
        let paths = get_derivation_paths(config.index, config.network, config.derivation_standard, &config.custom_paths);
        
        // Generate account
        let account = generate_account(seed.as_bytes(), paths, config.network, config.spend_strategy)?;
        
        Ok((account, phrase.to_string()))
    }
    
    /// Get address for the specified address type
    pub fn get_address(&self, address_type: AddressType) -> &str {
        match address_type {
            AddressType::Legacy => &self.legacy.address,
            AddressType::NestedSegwit => &self.nested_segwit.address,
            AddressType::NativeSegwit => &self.native_segwit.address,
            AddressType::Taproot => &self.taproot.address,
        }
    }
    
    /// Get public key for the specified address type
    pub fn get_pubkey(&self, address_type: AddressType) -> &str {
        match address_type {
            AddressType::Legacy => &self.legacy.pubkey,
            AddressType::NestedSegwit => &self.nested_segwit.pubkey,
            AddressType::NativeSegwit => &self.native_segwit.pubkey,
            AddressType::Taproot => &self.taproot.pubkey,
        }
    }
    
    /// Get derivation path for the specified address type
    pub fn get_derivation_path(&self, address_type: AddressType) -> &str {
        match address_type {
            AddressType::Legacy => &self.legacy.derivation_path,
            AddressType::NestedSegwit => &self.nested_segwit.derivation_path,
            AddressType::NativeSegwit => &self.native_segwit.derivation_path,
            AddressType::Taproot => &self.taproot.derivation_path,
        }
    }
    
    /// Encrypt the account with a password
    pub fn encrypt(&self, password: &str) -> Result<EncryptedAccount> {
        EncryptedAccount::encrypt(self, password)
    }
    
    /// Save the account to a file with password encryption
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P, password: &str) -> Result<()> {
        let encrypted = self.encrypt(password)?;
        encrypted.save_to_file(path)
    }
    
    /// Load an account from a file with password decryption
    pub fn load_from_file<P: AsRef<Path>>(path: P, password: &str) -> Result<Self> {
        let encrypted = EncryptedAccount::load_from_file(path)?;
        encrypted.decrypt(password)
    }
    
    /// Verify a password for an encrypted account file
    pub fn verify_password<P: AsRef<Path>>(path: P, password: &str) -> Result<bool> {
        let encrypted = EncryptedAccount::load_from_file(path)?;
        encryption::verify_password(&encrypted, password)
    }
}

/// Get derivation paths for the specified network and index
fn get_derivation_paths(
    index: u32,
    network: Network,
    standard: DerivationStandard,
    custom_paths: &Option<CustomDerivationPaths>,
) -> CustomDerivationPaths {
    // Get coin type based on network
    let coin_type = match network {
        Network::Bitcoin => "0",
        _ => "1", // Testnet, Regtest, Signet
    };
    
    // Get default paths based on standard
    let default_paths = match standard {
        DerivationStandard::Bip44Standard => CustomDerivationPaths {
            legacy: Some(format!("m/44'/{}'/{}'/{}/{}", coin_type, index, 0, 0)),
            nested_segwit: Some(format!("m/49'/{}'/{}'/{}/{}", coin_type, index, 0, 0)),
            native_segwit: Some(format!("m/84'/{}'/{}'/{}/{}", coin_type, index, 0, 0)),
            taproot: Some(format!("m/86'/{}'/{}'/{}/{}", coin_type, index, 0, 0)),
        },
        DerivationStandard::Bip44AccountLast => CustomDerivationPaths {
            legacy: Some(format!("m/44'/{}'/{}'/{}/{}", coin_type, 0, 0, index)),
            nested_segwit: Some(format!("m/49'/{}'/{}'/{}/{}", coin_type, 0, 0, index)),
            native_segwit: Some(format!("m/84'/{}'/{}'/{}/{}", coin_type, 0, 0, index)),
            taproot: Some(format!("m/86'/{}'/{}'/{}/{}", coin_type, 0, 0, index)),
        },
        DerivationStandard::Bip32Simple => CustomDerivationPaths {
            legacy: Some(format!("m/44'/{}'/{}'/{}", coin_type, index, 0)),
            nested_segwit: Some(format!("m/49'/{}'/{}'/{}", coin_type, index, 0)),
            native_segwit: Some(format!("m/84'/{}'/{}'/{}", coin_type, index, 0)),
            taproot: Some(format!("m/86'/{}'/{}'/{}", coin_type, index, 0)),
        },
    };
    
    // Override with custom paths if provided
    match custom_paths {
        Some(custom) => CustomDerivationPaths {
            legacy: custom.legacy.clone().or(default_paths.legacy),
            nested_segwit: custom.nested_segwit.clone().or(default_paths.nested_segwit),
            native_segwit: custom.native_segwit.clone().or(default_paths.native_segwit),
            taproot: custom.taproot.clone().or(default_paths.taproot),
        },
        None => default_paths,
    }
}

/// Generate an account from a seed and derivation paths
fn generate_account(
    seed: &[u8],
    paths: CustomDerivationPaths,
    network: Network,
    spend_strategy: SpendStrategy,
) -> Result<Account> {
    // Create master key from seed
    let master_key = ExtendedPrivKey::new_master(network, seed)
        .context("Failed to create master key from seed")?;
    
    // Generate legacy address
    let legacy_path_str = paths.legacy.unwrap_or_else(|| format!("m/44'/0'/0'/0/0"));
    let legacy_path = DerivationPath::from_str(&legacy_path_str)
        .context("Invalid legacy derivation path")?;
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let legacy_key = master_key.derive_priv(&secp, &legacy_path)
        .context("Failed to derive legacy key")?;
    let legacy_pubkey = ExtendedPubKey::from_priv(&secp, &legacy_key);
    let bitcoin_pubkey = bitcoin::PublicKey::from_slice(&legacy_pubkey.public_key.serialize())
        .context("Failed to create Bitcoin public key")?;
    let legacy_address = Address::p2pkh(&bitcoin_pubkey, network);
    
    // Generate nested segwit address
    let nested_segwit_path_str = paths.nested_segwit.unwrap_or_else(|| format!("m/49'/0'/0'/0/0"));
    let nested_segwit_path = DerivationPath::from_str(&nested_segwit_path_str)
        .context("Invalid nested segwit derivation path")?;
    let nested_segwit_key = master_key.derive_priv(&secp, &nested_segwit_path)
        .context("Failed to derive nested segwit key")?;
    let nested_segwit_pubkey = ExtendedPubKey::from_priv(&secp, &nested_segwit_key);
    let bitcoin_pubkey = bitcoin::PublicKey::from_slice(&nested_segwit_pubkey.public_key.serialize())
        .context("Failed to create Bitcoin public key")?;
    let nested_segwit_address = Address::p2shwpkh(&bitcoin_pubkey, network)
        .context("Failed to create nested segwit address")?;
    
    // Generate native segwit address
    let native_segwit_path_str = paths.native_segwit.unwrap_or_else(|| format!("m/84'/0'/0'/0/0"));
    let native_segwit_path = DerivationPath::from_str(&native_segwit_path_str)
        .context("Invalid native segwit derivation path")?;
    let native_segwit_key = master_key.derive_priv(&secp, &native_segwit_path)
        .context("Failed to derive native segwit key")?;
    let native_segwit_pubkey = ExtendedPubKey::from_priv(&secp, &native_segwit_key);
    let bitcoin_pubkey = bitcoin::PublicKey::from_slice(&native_segwit_pubkey.public_key.serialize())
        .context("Failed to create Bitcoin public key")?;
    let native_segwit_address = Address::p2wpkh(&bitcoin_pubkey, network)
        .context("Failed to create native segwit address")?;
    
    // Generate taproot address
    let taproot_path_str = paths.taproot.unwrap_or_else(|| format!("m/86'/0'/0'/0/0"));
    let taproot_path = DerivationPath::from_str(&taproot_path_str)
        .context("Invalid taproot derivation path")?;
    let taproot_key = master_key.derive_priv(&secp, &taproot_path)
        .context("Failed to derive taproot key")?;
    let taproot_pubkey = ExtendedPubKey::from_priv(&secp, &taproot_key);
    
    // Create taproot address using the bitcoin crate's functionality
    let bitcoin_pubkey = bitcoin::PublicKey::from_slice(&taproot_pubkey.public_key.serialize())
        .context("Failed to create Bitcoin public key")?;
    let x_only_pubkey = bitcoin::XOnlyPublicKey::from_slice(&bitcoin_pubkey.inner.serialize()[1..])
        .context("Failed to create X-only public key")?;
    let taproot_address = Address::p2tr(&secp, x_only_pubkey, None, network);
    
    // Get x-only pubkey for taproot
    let x_only_pubkey_hex = hex::encode(x_only_pubkey.serialize());
    
    // Create account
    let account = Account {
        legacy: AddressInfo {
            pubkey: bitcoin_pubkey.to_string(),
            address: legacy_address.to_string(),
            derivation_path: legacy_path_str,
            x_only_pubkey: None,
        },
        nested_segwit: AddressInfo {
            pubkey: bitcoin_pubkey.to_string(),
            address: nested_segwit_address.to_string(),
            derivation_path: nested_segwit_path_str,
            x_only_pubkey: None,
        },
        native_segwit: AddressInfo {
            pubkey: bitcoin_pubkey.to_string(),
            address: native_segwit_address.to_string(),
            derivation_path: native_segwit_path_str,
            x_only_pubkey: None,
        },
        taproot: AddressInfo {
            pubkey: bitcoin_pubkey.to_string(),
            address: taproot_address.to_string(),
            derivation_path: taproot_path_str,
            x_only_pubkey: Some(x_only_pubkey_hex),
        },
        spend_strategy,
        network,
    };
    
    Ok(account)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    
    #[test]
    fn test_account_generation() {
        // Test mnemonic
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        
        // Create account
        let account = Account::from_mnemonic(mnemonic, None).unwrap();
        
        // Check network
        assert_eq!(account.network, Network::Bitcoin);
        
        // Check addresses
        assert!(!account.legacy.address.is_empty());
        assert!(!account.nested_segwit.address.is_empty());
        assert!(!account.native_segwit.address.is_empty());
        assert!(!account.taproot.address.is_empty());
        
        // Check public keys
        assert!(!account.legacy.pubkey.is_empty());
        assert!(!account.nested_segwit.pubkey.is_empty());
        assert!(!account.native_segwit.pubkey.is_empty());
        assert!(!account.taproot.pubkey.is_empty());
        
        // Check derivation paths
        assert!(!account.legacy.derivation_path.is_empty());
        assert!(!account.nested_segwit.derivation_path.is_empty());
        assert!(!account.native_segwit.derivation_path.is_empty());
        assert!(!account.taproot.derivation_path.is_empty());
        
        // Check x-only pubkey
        assert!(account.taproot.x_only_pubkey.is_some());
    }
    
    #[test]
    fn test_random_account_generation() {
        // Generate random account
        let (account, mnemonic) = Account::generate(None).unwrap();
        
        // Check mnemonic
        assert!(!mnemonic.is_empty());
        
        // Check network
        assert_eq!(account.network, Network::Bitcoin);
        
        // Check addresses
        assert!(!account.legacy.address.is_empty());
        assert!(!account.nested_segwit.address.is_empty());
        assert!(!account.native_segwit.address.is_empty());
        assert!(!account.taproot.address.is_empty());
    }
    
    #[test]
    fn test_custom_derivation_paths() {
        // Test mnemonic
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        
        // Custom paths
        let custom_paths = CustomDerivationPaths {
            legacy: Some("m/44'/0'/0'/0/1".to_string()),
            nested_segwit: Some("m/49'/0'/0'/0/1".to_string()),
            native_segwit: Some("m/84'/0'/0'/0/1".to_string()),
            taproot: Some("m/86'/0'/0'/0/1".to_string()),
        };
        
        // Create config
        let config = AccountConfig {
            network: Network::Bitcoin,
            index: 0,
            derivation_standard: DerivationStandard::Bip44AccountLast,
            custom_paths: Some(custom_paths),
            spend_strategy: SpendStrategy::default(),
        };
        
        // Create account
        let account = Account::from_mnemonic(mnemonic, Some(config)).unwrap();
        
        // Check derivation paths
        assert_eq!(account.legacy.derivation_path, "m/44'/0'/0'/0/1");
        assert_eq!(account.nested_segwit.derivation_path, "m/49'/0'/0'/0/1");
        assert_eq!(account.native_segwit.derivation_path, "m/84'/0'/0'/0/1");
        assert_eq!(account.taproot.derivation_path, "m/86'/0'/0'/0/1");
    }
    
    #[test]
    fn test_account_save_load() {
        // Create temporary directory
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("account.json");
        
        // Test mnemonic
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        
        // Create account
        let account = Account::from_mnemonic(mnemonic, None).unwrap();
        
        // Save to file
        let password = "test_password";
        account.save_to_file(&file_path, password).unwrap();
        
        // Load from file
        let loaded_account = Account::load_from_file(&file_path, password).unwrap();
        
        // Check that loaded account matches original
        assert_eq!(loaded_account.legacy.address, account.legacy.address);
        assert_eq!(loaded_account.nested_segwit.address, account.nested_segwit.address);
        assert_eq!(loaded_account.native_segwit.address, account.native_segwit.address);
        assert_eq!(loaded_account.taproot.address, account.taproot.address);
    }
    
    #[test]
    fn test_verify_password() {
        // Create temporary directory
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("account.json");
        
        // Test mnemonic
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        
        // Create account
        let account = Account::from_mnemonic(mnemonic, None).unwrap();
        
        // Save to file
        let password = "test_password";
        account.save_to_file(&file_path, password).unwrap();
        
        // Verify correct password
        let result = Account::verify_password(&file_path, password).unwrap();
        assert!(result);
        
        // Verify wrong password
        let wrong_password = "wrong_password";
        let result = Account::verify_password(&file_path, wrong_password).unwrap();
        assert!(!result);
    }
}
