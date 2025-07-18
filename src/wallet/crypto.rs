//! Cryptographic utilities for wallet encryption and key derivation
//!
//! This module provides:
//! - PBKDF2 key derivation for wallet encryption
//! - AES-GCM encryption/decryption for wallet data
//! - GPG integration for interactive encryption
//! - Secure key management utilities

use anyhow::{Context, Result, anyhow};
use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit};
use aes_gcm::aead::{Aead, OsRng};
use pbkdf2::{pbkdf2_hmac};
use sha2::Sha256;
use rand::RngCore;
use serde::{Serialize, Deserialize};
use std::process::{Command, Stdio};
use std::io::Write;
use log::info;

/// Encrypted wallet data structure
#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptedWalletData {
    /// Salt for PBKDF2 key derivation
    pub salt: Vec<u8>,
    /// Nonce for AES-GCM encryption
    pub nonce: Vec<u8>,
    /// Encrypted wallet data
    pub encrypted_data: Vec<u8>,
    /// Number of PBKDF2 iterations
    pub iterations: u32,
    /// Creation timestamp
    pub created_at: u64,
    /// Encryption method used
    pub encryption_method: String,
}

/// Raw wallet data before encryption
#[derive(Serialize, Deserialize, Debug)]
pub struct WalletData {
    /// Mnemonic phrase
    pub mnemonic: String,
    /// Network
    pub network: String,
    /// Master private key (hex encoded)
    pub master_private_key: String,
    /// Master public key (hex encoded)
    pub master_public_key: String,
    /// Creation timestamp
    pub created_at: u64,
}

/// Wallet encryption manager
pub struct WalletCrypto {
    /// PBKDF2 iterations for key derivation
    iterations: u32,
}

impl WalletCrypto {
    /// Create a new wallet crypto manager
    pub fn new() -> Self {
        Self {
            iterations: 100_000, // Standard PBKDF2 iterations
        }
    }

    /// Encrypt wallet data using PBKDF2 + AES-GCM
    pub fn encrypt_wallet_data(&self, data: &WalletData, passphrase: &str) -> Result<EncryptedWalletData> {
        info!("Encrypting wallet data with PBKDF2 + AES-GCM");

        // Generate random salt and nonce
        let mut salt = vec![0u8; 32];
        let mut nonce_bytes = vec![0u8; 12];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce_bytes);

        // Derive key using PBKDF2
        let mut key_bytes = [0u8; 32];
        pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), &salt, self.iterations, &mut key_bytes);
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);

        // Serialize wallet data
        let plaintext = serde_json::to_vec(data)
            .context("Failed to serialize wallet data")?;

        // Encrypt using AES-GCM
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let encrypted_data = cipher.encrypt(nonce, plaintext.as_ref())
            .map_err(|e| anyhow!("Encryption failed: {}", e))?;

        Ok(EncryptedWalletData {
            salt,
            nonce: nonce_bytes,
            encrypted_data,
            iterations: self.iterations,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            encryption_method: "PBKDF2-AES256-GCM".to_string(),
        })
    }

    /// Decrypt wallet data using PBKDF2 + AES-GCM
    pub fn decrypt_wallet_data(&self, encrypted: &EncryptedWalletData, passphrase: &str) -> Result<WalletData> {
        info!("Decrypting wallet data with PBKDF2 + AES-GCM");

        // Derive key using PBKDF2 with stored salt and iterations
        let mut key_bytes = [0u8; 32];
        pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), &encrypted.salt, encrypted.iterations, &mut key_bytes);
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);

        // Decrypt using AES-GCM
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(&encrypted.nonce);
        let decrypted_data = cipher.decrypt(nonce, encrypted.encrypted_data.as_ref())
            .map_err(|e| anyhow!("Decryption failed: {}", e))?;

        // Deserialize wallet data
        let wallet_data: WalletData = serde_json::from_slice(&decrypted_data)
            .context("Failed to deserialize wallet data")?;

        Ok(wallet_data)
    }

    /// Encrypt wallet data using GPG (interactive mode)
    #[cfg(feature = "gpg")]
    pub fn encrypt_with_gpg(&self, data: &WalletData) -> Result<Vec<u8>> {
        info!("Encrypting wallet data with GPG (interactive mode)");

        // Serialize wallet data
        let plaintext = serde_json::to_string_pretty(data)
            .context("Failed to serialize wallet data")?;

        // Start GPG process for symmetric encryption
        let mut gpg_process = Command::new("gpg")
            .args(&[
                "--symmetric",
                "--cipher-algo", "AES256",
                "--compress-algo", "2",
                "--armor",
                "--pinentry-mode", "loopback",
                "--no-use-agent",
            ])
            .env("GPG_TTY", "/dev/tty")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit()) // Show GPG prompts to user
            .spawn()
            .context("Failed to start GPG process. Make sure GPG is installed and available in PATH")?;

        // Write plaintext to GPG stdin
        if let Some(stdin) = gpg_process.stdin.as_mut() {
            stdin.write_all(plaintext.as_bytes())
                .context("Failed to write data to GPG")?;
        }

        // Wait for GPG to complete and read output
        let output = gpg_process.wait_with_output()
            .context("Failed to wait for GPG process")?;

        if !output.status.success() {
            return Err(anyhow!("GPG encryption failed with exit code: {}", output.status));
        }

        Ok(output.stdout)
    }

    /// Fallback for GPG encryption when feature is disabled
    #[cfg(not(feature = "gpg"))]
    pub fn encrypt_with_gpg(&self, _data: &WalletData) -> Result<Vec<u8>> {
        Err(anyhow!("GPG support not compiled in. Use PBKDF2+AES-GCM encryption instead."))
    }

    /// Decrypt wallet data using GPG (interactive mode)
    #[cfg(feature = "gpg")]
    pub fn decrypt_with_gpg(&self, encrypted_data: &[u8]) -> Result<WalletData> {
        info!("Decrypting wallet data with GPG (interactive mode)");

        // Start GPG process for decryption
        let mut gpg_process = Command::new("gpg")
            .args(&[
                "--decrypt",
                "--pinentry-mode", "loopback",
                "--no-use-agent",
            ])
            .env("GPG_TTY", "/dev/tty")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit()) // Show GPG prompts to user
            .spawn()
            .context("Failed to start GPG process")?;

        // Write encrypted data to GPG stdin
        if let Some(stdin) = gpg_process.stdin.as_mut() {
            stdin.write_all(encrypted_data)
                .context("Failed to write encrypted data to GPG")?;
        }

        // Wait for GPG to complete and read output
        let output = gpg_process.wait_with_output()
            .context("Failed to wait for GPG process")?;

        if !output.status.success() {
            return Err(anyhow!("GPG decryption failed with exit code: {}", output.status));
        }

        // Parse decrypted JSON
        let wallet_data: WalletData = serde_json::from_slice(&output.stdout)
            .context("Failed to parse decrypted wallet data")?;

        Ok(wallet_data)
    }

    /// Fallback for GPG decryption when feature is disabled
    #[cfg(not(feature = "gpg"))]
    pub fn decrypt_with_gpg(&self, _encrypted_data: &[u8]) -> Result<WalletData> {
        Err(anyhow!("GPG support not compiled in. Cannot decrypt GPG-encrypted wallet."))
    }

    /// Encrypt wallet with passphrase (non-interactive mode)
    #[cfg(feature = "gpg")]
    pub fn encrypt_with_passphrase(&self, data: &WalletData, passphrase: &str) -> Result<Vec<u8>> {
        info!("Encrypting wallet data with passphrase (non-interactive mode)");

        // Serialize wallet data
        let plaintext = serde_json::to_string_pretty(data)
            .context("Failed to serialize wallet data")?;

        // Start GPG process for symmetric encryption with passphrase
        let mut gpg_process = Command::new("gpg")
            .args(&[
                "--symmetric",
                "--cipher-algo", "AES256",
                "--compress-algo", "2",
                "--armor",
                "--batch",
                "--yes",
                "--passphrase-fd", "0", // Read passphrase from stdin
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to start GPG process")?;

        // Write passphrase and plaintext to GPG stdin
        if let Some(stdin) = gpg_process.stdin.as_mut() {
            // First write the passphrase followed by newline
            stdin.write_all(passphrase.as_bytes())
                .context("Failed to write passphrase to GPG")?;
            stdin.write_all(b"\n")
                .context("Failed to write newline after passphrase")?;
            // Then write the plaintext
            stdin.write_all(plaintext.as_bytes())
                .context("Failed to write data to GPG")?;
        }

        // Wait for GPG to complete and read output
        let output = gpg_process.wait_with_output()
            .context("Failed to wait for GPG process")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("GPG encryption failed: {}", stderr));
        }

        Ok(output.stdout)
    }

    /// Fallback for GPG encryption when feature is disabled
    #[cfg(not(feature = "gpg"))]
    pub fn encrypt_with_passphrase(&self, _data: &WalletData, _passphrase: &str) -> Result<Vec<u8>> {
        Err(anyhow!("GPG support not compiled in. Use PBKDF2+AES-GCM encryption instead."))
    }

    /// Decrypt wallet with passphrase (non-interactive mode)
    #[cfg(feature = "gpg")]
    pub fn decrypt_with_passphrase(&self, encrypted_data: &[u8], passphrase: &str) -> Result<WalletData> {
        info!("Decrypting wallet data with passphrase (non-interactive mode)");

        // Start GPG process for decryption with passphrase
        let mut gpg_process = Command::new("gpg")
            .args(&[
                "--decrypt",
                "--batch",
                "--yes",
                "--passphrase-fd", "0", // Read passphrase from stdin
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to start GPG process")?;

        // Write passphrase and encrypted data to GPG stdin
        if let Some(stdin) = gpg_process.stdin.as_mut() {
            // First write the passphrase followed by newline
            stdin.write_all(passphrase.as_bytes())
                .context("Failed to write passphrase to GPG")?;
            stdin.write_all(b"\n")
                .context("Failed to write newline after passphrase")?;
            // Then write the encrypted data
            stdin.write_all(encrypted_data)
                .context("Failed to write encrypted data to GPG")?;
        }

        // Wait for GPG to complete and read output
        let output = gpg_process.wait_with_output()
            .context("Failed to wait for GPG process")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("GPG decryption failed: {}", stderr));
        }

        // Parse decrypted JSON
        let wallet_data: WalletData = serde_json::from_slice(&output.stdout)
            .context("Failed to parse decrypted wallet data")?;

        Ok(wallet_data)
    }

    /// Fallback for GPG decryption when feature is disabled
    #[cfg(not(feature = "gpg"))]
    pub fn decrypt_with_passphrase(&self, _encrypted_data: &[u8], _passphrase: &str) -> Result<WalletData> {
        Err(anyhow!("GPG support not compiled in. Cannot decrypt GPG-encrypted wallet."))
    }

    /// Check if GPG is available on the system
    pub fn check_gpg_available() -> bool {
        #[cfg(feature = "gpg")]
        {
            match Command::new("gpg").arg("--version").output() {
                Ok(output) => output.status.success(),
                Err(_) => false,
            }
        }
        #[cfg(not(feature = "gpg"))]
        {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pbkdf2_encryption_decryption() {
        let crypto = WalletCrypto::new();
        
        let wallet_data = WalletData {
            mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
            network: "regtest".to_string(),
            master_private_key: "test_private_key".to_string(),
            master_public_key: "test_public_key".to_string(),
            created_at: 1234567890,
        };

        let passphrase = "test_passphrase_123";

        // Test encryption
        let encrypted = crypto.encrypt_wallet_data(&wallet_data, passphrase).unwrap();
        assert!(!encrypted.encrypted_data.is_empty());
        assert_eq!(encrypted.encryption_method, "PBKDF2-AES256-GCM");

        // Test decryption
        let decrypted = crypto.decrypt_wallet_data(&encrypted, passphrase).unwrap();
        assert_eq!(decrypted.mnemonic, wallet_data.mnemonic);
        assert_eq!(decrypted.network, wallet_data.network);
        assert_eq!(decrypted.master_private_key, wallet_data.master_private_key);
        assert_eq!(decrypted.master_public_key, wallet_data.master_public_key);
    }

    #[test]
    fn test_wrong_passphrase_fails() {
        let crypto = WalletCrypto::new();
        
        let wallet_data = WalletData {
            mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
            network: "regtest".to_string(),
            master_private_key: "test_private_key".to_string(),
            master_public_key: "test_public_key".to_string(),
            created_at: 1234567890,
        };

        let passphrase = "correct_passphrase";
        let wrong_passphrase = "wrong_passphrase";

        // Encrypt with correct passphrase
        let encrypted = crypto.encrypt_wallet_data(&wallet_data, passphrase).unwrap();

        // Try to decrypt with wrong passphrase - should fail
        let result = crypto.decrypt_wallet_data(&encrypted, wrong_passphrase);
        assert!(result.is_err());
    }
}