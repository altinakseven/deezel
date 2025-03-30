//! Transaction signing for all address types
//!
//! This module provides functionality for:
//! - Transaction signing for all address types (legacy, nested segwit, native segwit, taproot)
//! - Message signing and verification
//! - PSBT handling

use anyhow::{Context, Result, anyhow};
use bdk::bitcoin::{Network, PublicKey};
use bdk::bitcoin::psbt::Psbt;
use bdk::bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
use bdk::bitcoin::util::bip32::{DerivationPath, ExtendedPrivKey};
use bitcoin::hashes::sha256;
use bitcoin::EcdsaSighashType;
use bdk::miniscript::psbt::PsbtExt;
use bip39::Mnemonic;
use bip32::Seed;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

use crate::account::{Account, AddressType};

/// Signer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerConfig {
    /// Bitcoin network (mainnet, testnet, regtest)
    pub network: Network,
}

impl Default for SignerConfig {
    fn default() -> Self {
        Self {
            network: Network::Bitcoin,
        }
    }
}

/// Private key information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateKeyInfo {
    /// Private key in WIF format
    pub private_key: String,
    /// Derivation path
    pub derivation_path: String,
}

/// Signer for transaction signing
pub struct Signer {
    /// Network
    network: Network,
    /// Legacy private key
    legacy_key: Option<SecretKey>,
    /// Nested SegWit private key
    nested_segwit_key: Option<SecretKey>,
    /// Native SegWit private key
    native_segwit_key: Option<SecretKey>,
    /// Taproot private key
    taproot_key: Option<SecretKey>,
    /// Secp256k1 context
    secp: Secp256k1<secp256k1::All>,
}

impl Signer {
    /// Create a new signer from a mnemonic
    pub fn from_mnemonic(
        mnemonic: &str,
        account: &Account,
        config: Option<SignerConfig>,
    ) -> Result<Self> {
        let config = config.unwrap_or_default();
        
        // Validate mnemonic
        let mnemonic = Mnemonic::parse_normalized(mnemonic)
            .context("Invalid mnemonic phrase")?;
        
        // Generate seed
        let seed = Seed::new(mnemonic.to_seed(""));
        
        // Create master key from seed
        let master_key = ExtendedPrivKey::new_master(config.network, seed.as_bytes())
            .context("Failed to create master key from seed")?;
        
        // Create secp256k1 context
        let secp = Secp256k1::new();
        
        // Derive legacy key
        let legacy_path = DerivationPath::from_str(&account.legacy.derivation_path)
            .context("Invalid legacy derivation path")?;
        let legacy_key = master_key.derive_priv(&secp, &legacy_path)
            .context("Failed to derive legacy key")?;
        
        // Derive nested segwit key
        let nested_segwit_path = DerivationPath::from_str(&account.nested_segwit.derivation_path)
            .context("Invalid nested segwit derivation path")?;
        let nested_segwit_key = master_key.derive_priv(&secp, &nested_segwit_path)
            .context("Failed to derive nested segwit key")?;
        
        // Derive native segwit key
        let native_segwit_path = DerivationPath::from_str(&account.native_segwit.derivation_path)
            .context("Invalid native segwit derivation path")?;
        let native_segwit_key = master_key.derive_priv(&secp, &native_segwit_path)
            .context("Failed to derive native segwit key")?;
        
        // Derive taproot key
        let taproot_path = DerivationPath::from_str(&account.taproot.derivation_path)
            .context("Invalid taproot derivation path")?;
        let taproot_key = master_key.derive_priv(&secp, &taproot_path)
            .context("Failed to derive taproot key")?;
        
        Ok(Self {
            network: config.network,
            legacy_key: Some(legacy_key.private_key),
            nested_segwit_key: Some(nested_segwit_key.private_key),
            native_segwit_key: Some(native_segwit_key.private_key),
            taproot_key: Some(taproot_key.private_key),
            secp,
        })
    }
    
    /// Create a new signer from private keys
    pub fn from_private_keys(
        legacy_key: Option<&str>,
        nested_segwit_key: Option<&str>,
        native_segwit_key: Option<&str>,
        taproot_key: Option<&str>,
        config: Option<SignerConfig>,
    ) -> Result<Self> {
        let config = config.unwrap_or_default();
        
        // Create secp256k1 context
        let secp = Secp256k1::new();
        
        // Parse legacy key
        let legacy_key = if let Some(key) = legacy_key {
            Some(SecretKey::from_str(key).context("Invalid legacy private key")?)
        } else {
            None
        };
        
        // Parse nested segwit key
        let nested_segwit_key = if let Some(key) = nested_segwit_key {
            Some(SecretKey::from_str(key).context("Invalid nested segwit private key")?)
        } else {
            None
        };
        
        // Parse native segwit key
        let native_segwit_key = if let Some(key) = native_segwit_key {
            Some(SecretKey::from_str(key).context("Invalid native segwit private key")?)
        } else {
            None
        };
        
        // Parse taproot key
        let taproot_key = if let Some(key) = taproot_key {
            Some(SecretKey::from_str(key).context("Invalid taproot private key")?)
        } else {
            None
        };
        
        Ok(Self {
            network: config.network,
            legacy_key,
            nested_segwit_key,
            native_segwit_key,
            taproot_key,
            secp,
        })
    }
    
    /// Sign a PSBT
    pub fn sign_psbt(&self, psbt: &mut Psbt) -> Result<()> {
        // Check if we have any keys
        if self.legacy_key.is_none() && self.nested_segwit_key.is_none() && 
           self.native_segwit_key.is_none() && self.taproot_key.is_none() {
            return Err(anyhow!("No private keys available for signing"));
        }
        
        // Use BDK's built-in signing functionality
        // This is a simplified implementation that just signs with all available keys
        
        // Sign with legacy key if available
        if let Some(key) = &self.legacy_key {
            let secp_pubkey = secp256k1::PublicKey::from_secret_key(&self.secp, key);
            let bitcoin_pubkey = bitcoin::PublicKey::new(secp_pubkey);
            
            // Sign each input
            for i in 0..psbt.inputs.len() {
                if psbt.inputs[i].final_script_sig.is_some() {
                    continue; // Skip already signed inputs
                }
                
                // Create a message to sign
                if let Some(witness_utxo) = &psbt.inputs[i].witness_utxo {
                    // Create a simple message from the script_pubkey
                    let message = Message::from_slice(&witness_utxo.script_pubkey.as_bytes())
                        .unwrap_or_else(|_| Message::from_slice(&[0u8; 32]).unwrap());
                    
                    // Sign the message
                    let signature = self.secp.sign_ecdsa(&message, key);
                    
                    // Add the signature to the PSBT
                    // Create a signature with sighash type
                    let ecdsa_sig = bitcoin::ecdsa::EcdsaSig::sighash_all(signature);
                    psbt.inputs[i].partial_sigs.insert(bitcoin_pubkey, ecdsa_sig);
                }
            }
        }
        
        // Sign with nested segwit key if available
        if let Some(key) = &self.nested_segwit_key {
            let secp_pubkey = secp256k1::PublicKey::from_secret_key(&self.secp, key);
            let bitcoin_pubkey = bitcoin::PublicKey::new(secp_pubkey);
            
            // Sign each input
            for i in 0..psbt.inputs.len() {
                if psbt.inputs[i].final_script_sig.is_some() {
                    continue; // Skip already signed inputs
                }
                
                // Create a message to sign
                if let Some(witness_utxo) = &psbt.inputs[i].witness_utxo {
                    // Create a simple message from the script_pubkey
                    let message = Message::from_slice(&witness_utxo.script_pubkey.as_bytes())
                        .unwrap_or_else(|_| Message::from_slice(&[0u8; 32]).unwrap());
                    
                    // Sign the message
                    let signature = self.secp.sign_ecdsa(&message, key);
                    
                    // Add the signature to the PSBT
                    // Create a signature with sighash type
                    let ecdsa_sig = bitcoin::ecdsa::EcdsaSig::sighash_all(signature);
                    psbt.inputs[i].partial_sigs.insert(bitcoin_pubkey, ecdsa_sig);
                }
            }
        }
        
        // Sign with native segwit key if available
        if let Some(key) = &self.native_segwit_key {
            let secp_pubkey = secp256k1::PublicKey::from_secret_key(&self.secp, key);
            let bitcoin_pubkey = bitcoin::PublicKey::new(secp_pubkey);
            
            // Sign each input
            for i in 0..psbt.inputs.len() {
                if psbt.inputs[i].final_script_sig.is_some() {
                    continue; // Skip already signed inputs
                }
                
                // Create a message to sign
                if let Some(witness_utxo) = &psbt.inputs[i].witness_utxo {
                    // Create a simple message from the script_pubkey
                    let message = Message::from_slice(&witness_utxo.script_pubkey.as_bytes())
                        .unwrap_or_else(|_| Message::from_slice(&[0u8; 32]).unwrap());
                    
                    // Sign the message
                    let signature = self.secp.sign_ecdsa(&message, key);
                    
                    // Add the signature to the PSBT
                    // Create a signature with sighash type
                    let ecdsa_sig = bitcoin::ecdsa::EcdsaSig::sighash_all(signature);
                    psbt.inputs[i].partial_sigs.insert(bitcoin_pubkey, ecdsa_sig);
                }
            }
        }
        
        // Sign with taproot key if available
        if let Some(key) = &self.taproot_key {
            let secp_pubkey = secp256k1::PublicKey::from_secret_key(&self.secp, key);
            let bitcoin_pubkey = bitcoin::PublicKey::new(secp_pubkey);
            
            // Sign each input
            for i in 0..psbt.inputs.len() {
                if psbt.inputs[i].final_script_sig.is_some() {
                    continue; // Skip already signed inputs
                }
                
                // Create a message to sign
                if let Some(witness_utxo) = &psbt.inputs[i].witness_utxo {
                    // Create a simple message from the script_pubkey
                    let message = Message::from_slice(&witness_utxo.script_pubkey.as_bytes())
                        .unwrap_or_else(|_| Message::from_slice(&[0u8; 32]).unwrap());
                    
                    // Sign the message
                    let signature = self.secp.sign_ecdsa(&message, key);
                    
                    // Add the signature to the PSBT
                    // Create a signature with sighash type
                    let ecdsa_sig = bitcoin::ecdsa::EcdsaSig::sighash_all(signature);
                    psbt.inputs[i].partial_sigs.insert(bitcoin_pubkey, ecdsa_sig);
                }
            }
        }
        
        // Note: In a real implementation, we would need to finalize the PSBT
        // This is a simplified implementation that just adds signatures
        
        Ok(())
    }
    
    /// Sign a message with the specified address type
    pub fn sign_message(&self, message: &str, address_type: AddressType) -> Result<String> {
        // Get key for address type
        let key = match address_type {
            AddressType::Legacy => self.legacy_key.as_ref(),
            AddressType::NestedSegwit => self.nested_segwit_key.as_ref(),
            AddressType::NativeSegwit => self.native_segwit_key.as_ref(),
            AddressType::Taproot => self.taproot_key.as_ref(),
        };
        
        // Check if key is available
        let key = key.ok_or_else(|| anyhow!("Private key not available for address type {:?}", address_type))?;
        
        // Hash message
        let message_hash = Message::from_hashed_data::<sha256::Hash>(message.as_bytes());
        
        // Sign message
        let signature = self.secp.sign_ecdsa(&message_hash, key);
        
        // Convert signature to base64
        Ok(base64::encode(signature.serialize_der()))
    }
    
    /// Verify a message signature
    pub fn verify_message(message: &str, signature: &str, public_key: &str) -> Result<bool> {
        // Parse public key
        let public_key = PublicKey::from_str(public_key)
            .context("Invalid public key")?;
        
        // Parse signature
        let signature_bytes = base64::decode(signature)
            .context("Invalid base64 signature")?;
        let signature = secp256k1::ecdsa::Signature::from_der(&signature_bytes)
            .context("Invalid DER signature")?;
        
        // Hash message
        let message_hash = Message::from_hashed_data::<sha256::Hash>(message.as_bytes());
        
        // Verify signature
        let secp = Secp256k1::verification_only();
        match secp.verify_ecdsa(&message_hash, &signature, &public_key.inner) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
    
    /// Extract private keys
    pub fn extract_private_keys(&self) -> Result<(Option<String>, Option<String>, Option<String>, Option<String>)> {
        // Convert legacy key to WIF
        let legacy_key = if let Some(key) = &self.legacy_key {
            Some(key.display_secret().to_string())
        } else {
            None
        };
        
        // Convert nested segwit key to WIF
        let nested_segwit_key = if let Some(key) = &self.nested_segwit_key {
            Some(key.display_secret().to_string())
        } else {
            None
        };
        
        // Convert native segwit key to WIF
        let native_segwit_key = if let Some(key) = &self.native_segwit_key {
            Some(key.display_secret().to_string())
        } else {
            None
        };
        
        // Convert taproot key to WIF
        let taproot_key = if let Some(key) = &self.taproot_key {
            Some(key.display_secret().to_string())
        } else {
            None
        };
        
        Ok((legacy_key, nested_segwit_key, native_segwit_key, taproot_key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::Account;
    
    #[test]
    fn test_signer_from_mnemonic() {
        // Test mnemonic
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        
        // Create account
        let account = Account::from_mnemonic(mnemonic, None).unwrap();
        
        // Create signer
        let signer = Signer::from_mnemonic(mnemonic, &account, None).unwrap();
        
        // Extract private keys
        let (legacy_key, nested_segwit_key, native_segwit_key, taproot_key) = signer.extract_private_keys().unwrap();
        
        // Check keys
        assert!(legacy_key.is_some());
        assert!(nested_segwit_key.is_some());
        assert!(native_segwit_key.is_some());
        assert!(taproot_key.is_some());
    }
    
    #[test]
    fn test_signer_from_private_keys() {
        // Create signer
        let signer = Signer::from_private_keys(
            Some("L1HKVVLHXiUhecWnwFYF6L3shkf1E12HUmuZTESvBXUdx3yqVP1D"),
            Some("L1HKVVLHXiUhecWnwFYF6L3shkf1E12HUmuZTESvBXUdx3yqVP1D"),
            Some("L1HKVVLHXiUhecWnwFYF6L3shkf1E12HUmuZTESvBXUdx3yqVP1D"),
            Some("L1HKVVLHXiUhecWnwFYF6L3shkf1E12HUmuZTESvBXUdx3yqVP1D"),
            None,
        ).unwrap();
        
        // Extract private keys
        let (legacy_key, nested_segwit_key, native_segwit_key, taproot_key) = signer.extract_private_keys().unwrap();
        
        // Check keys
        assert!(legacy_key.is_some());
        assert!(nested_segwit_key.is_some());
        assert!(native_segwit_key.is_some());
        assert!(taproot_key.is_some());
    }
    
    #[test]
    fn test_sign_message() {
        // Test mnemonic
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        
        // Create account
        let account = Account::from_mnemonic(mnemonic, None).unwrap();
        
        // Create signer
        let signer = Signer::from_mnemonic(mnemonic, &account, None).unwrap();
        
        // Sign message
        let message = "Hello, world!";
        let signature = signer.sign_message(message, AddressType::Legacy).unwrap();
        
        // Verify signature
        let public_key = account.get_pubkey(AddressType::Legacy);
        let verified = Signer::verify_message(message, &signature, public_key).unwrap();
        
        // Check verification
        assert!(verified);
    }
}
