//! Account encryption and decryption functionality
//!
//! This module provides functionality for:
//! - Password-based encryption of account data
//! - Secure storage of account information
//! - Account backup and restore

use anyhow::{Result, anyhow, Context};
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use argon2::{
    password_hash::{
        rand_core::OsRng as Argon2OsRng,
        PasswordHash, PasswordHasher, PasswordVerifier, SaltString
    },
    Argon2
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

use super::Account;

/// Encrypted account data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedAccount {
    /// Salt for key derivation
    pub salt: String,
    /// Nonce for encryption
    pub nonce: String,
    /// Encrypted account data
    pub encrypted_data: String,
}

impl EncryptedAccount {
    /// Encrypt an account with a password
    pub fn encrypt(account: &Account, password: &str) -> Result<Self> {
        // Generate salt
        let salt = SaltString::generate(&mut Argon2OsRng);
        
        // Derive key from password
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(password.as_bytes(), &salt)
            .map_err(|e| anyhow!("Failed to hash password: {}", e))?;
        
        // Create key from password hash
        // Note: We're using unwrap() here because we know the hash is present
        let hash_bytes = password_hash.hash.unwrap();
        let key_bytes = hash_bytes.as_bytes();
        let key = Key::<Aes256Gcm>::clone_from_slice(key_bytes);
        
        // Serialize account
        let account_json = serde_json::to_string(account)
            .with_context(|| "Failed to serialize account")?;
        
        // Generate nonce
        let cipher = Aes256Gcm::new(&key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        
        // Encrypt account data
        let encrypted_data = cipher.encrypt(&nonce, account_json.as_bytes())
            .map_err(|e| anyhow!("Failed to encrypt account data: {}", e))?;
        
        Ok(Self {
            salt: salt.to_string(),
            nonce: hex::encode(nonce),
            encrypted_data: hex::encode(encrypted_data),
        })
    }
    
    /// Decrypt an account with a password
    pub fn decrypt(&self, password: &str) -> Result<Account> {
        // Parse salt
        let salt = SaltString::from_b64(&self.salt)
            .map_err(|e| anyhow!("Failed to parse salt: {}", e))?;
        
        // Derive key from password
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(password.as_bytes(), &salt)
            .map_err(|e| anyhow!("Failed to hash password: {}", e))?;
        
        // Create key from password hash
        let hash_bytes = password_hash.hash.unwrap();
        let key_bytes = hash_bytes.as_bytes();
        let key = Key::<Aes256Gcm>::clone_from_slice(key_bytes);
        
        // Parse nonce
        let nonce_bytes = hex::decode(&self.nonce)
            .with_context(|| "Failed to decode nonce")?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        // Parse encrypted data
        let encrypted_data = hex::decode(&self.encrypted_data)
            .with_context(|| "Failed to decode encrypted data")?;
        
        // Decrypt account data
        let cipher = Aes256Gcm::new(&key);
        let decrypted_data = cipher.decrypt(nonce, encrypted_data.as_ref())
            .map_err(|e| anyhow!("Failed to decrypt account data (incorrect password?): {}", e))?;
        
        // Deserialize account
        let account: Account = serde_json::from_slice(&decrypted_data)
            .with_context(|| "Failed to deserialize account")?;
        
        Ok(account)
    }
    
    /// Save encrypted account to a file
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        // Create parent directory if it doesn't exist
        if let Some(parent) = path.as_ref().parent() {
            fs::create_dir_all(parent)
                .with_context(|| "Failed to create parent directory")?;
        }
        
        // Serialize encrypted account
        let json = serde_json::to_string(self)
            .with_context(|| "Failed to serialize encrypted account")?;
        
        // Write to file
        fs::write(path, json)
            .with_context(|| "Failed to write encrypted account to file")?;
        
        Ok(())
    }
    
    /// Load encrypted account from a file
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        // Read file
        let json = fs::read_to_string(path)
            .with_context(|| "Failed to read encrypted account from file")?;
        
        // Deserialize encrypted account
        let encrypted_account: Self = serde_json::from_str(&json)
            .with_context(|| "Failed to deserialize encrypted account")?;
        
        Ok(encrypted_account)
    }
}

/// Verify a password against an encrypted account
pub fn verify_password(encrypted_account: &EncryptedAccount, password: &str) -> Result<bool> {
    // Parse salt
    let salt = SaltString::from_b64(&encrypted_account.salt)
        .map_err(|e| anyhow!("Failed to parse salt: {}", e))?;
    
    // Derive key from password
    let argon2 = Argon2::default();
    let password_hash = argon2.hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow!("Failed to hash password: {}", e))?;
    
    // Create key from password hash
    let hash_bytes = password_hash.hash.unwrap();
    let key_bytes = hash_bytes.as_bytes();
    let key = Key::<Aes256Gcm>::clone_from_slice(key_bytes);
    
    // Parse nonce
    let nonce_bytes = hex::decode(&encrypted_account.nonce)
        .with_context(|| "Failed to decode nonce")?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    // Parse encrypted data
    let encrypted_data = hex::decode(&encrypted_account.encrypted_data)
        .with_context(|| "Failed to decode encrypted data")?;
    
    // Try to decrypt account data
    let cipher = Aes256Gcm::new(&key);
    match cipher.decrypt(nonce, encrypted_data.as_ref()) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::Account;
    use tempfile::tempdir;
    
    #[test]
    fn test_account_encryption_decryption() {
        // Test mnemonic
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        
        // Create account
        let account = Account::from_mnemonic(mnemonic, None).unwrap();
        
        // Encrypt account
        let password = "test_password";
        let encrypted_account = EncryptedAccount::encrypt(&account, password).unwrap();
        
        // Decrypt account
        let decrypted_account = encrypted_account.decrypt(password).unwrap();
        
        // Check that decrypted account matches original
        assert_eq!(decrypted_account.legacy.address, account.legacy.address);
        assert_eq!(decrypted_account.nested_segwit.address, account.nested_segwit.address);
        assert_eq!(decrypted_account.native_segwit.address, account.native_segwit.address);
        assert_eq!(decrypted_account.taproot.address, account.taproot.address);
    }
    
    #[test]
    fn test_account_encryption_wrong_password() {
        // Test mnemonic
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        
        // Create account
        let account = Account::from_mnemonic(mnemonic, None).unwrap();
        
        // Encrypt account
        let password = "test_password";
        let encrypted_account = EncryptedAccount::encrypt(&account, password).unwrap();
        
        // Try to decrypt with wrong password
        let wrong_password = "wrong_password";
        let result = encrypted_account.decrypt(wrong_password);
        
        // Check that decryption failed
        assert!(result.is_err());
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
        
        // Encrypt account
        let password = "test_password";
        let encrypted_account = EncryptedAccount::encrypt(&account, password).unwrap();
        
        // Save to file
        encrypted_account.save_to_file(&file_path).unwrap();
        
        // Load from file
        let loaded_account = EncryptedAccount::load_from_file(&file_path).unwrap();
        
        // Decrypt loaded account
        let decrypted_account = loaded_account.decrypt(password).unwrap();
        
        // Check that decrypted account matches original
        assert_eq!(decrypted_account.legacy.address, account.legacy.address);
        assert_eq!(decrypted_account.nested_segwit.address, account.nested_segwit.address);
        assert_eq!(decrypted_account.native_segwit.address, account.native_segwit.address);
        assert_eq!(decrypted_account.taproot.address, account.taproot.address);
    }
    
    #[test]
    fn test_verify_password() {
        // Test mnemonic
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        
        // Create account
        let account = Account::from_mnemonic(mnemonic, None).unwrap();
        
        // Encrypt account
        let password = "test_password";
        let encrypted_account = EncryptedAccount::encrypt(&account, password).unwrap();
        
        // Verify correct password
        let result = verify_password(&encrypted_account, password).unwrap();
        assert!(result);
        
        // Verify wrong password
        let wrong_password = "wrong_password";
        let result = verify_password(&encrypted_account, wrong_password).unwrap();
        assert!(!result);
    }
}
