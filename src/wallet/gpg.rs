//! GPG encryption/decryption functionality for wallet files
//!
//! This module handles GPG operations for encrypting and decrypting wallet data
//! using symmetric encryption with armor and 1000 PBKDF2 iterations.

use anyhow::{Context, Result, anyhow};
use std::process::{Command, Stdio};
use std::io::Write;
use log::{debug, info};

/// GPG manager for wallet encryption/decryption
pub struct GpgManager;

impl GpgManager {
    /// Create a new GPG manager
    pub fn new() -> Self {
        Self
    }

    /// Encrypt data using GPG with symmetric encryption
    /// Uses --armor --symmetric with 1000 PBKDF2 iterations
    pub fn encrypt_data(&self, data: &str, passphrase: &str) -> Result<String> {
        info!("Encrypting wallet data with GPG");
        
        let mut command = Command::new("gpg");
        command.args(&[
            "--armor",
            "--symmetric",
            "--cipher-algo", "AES256",
            "--digest-algo", "SHA256",
            "--s2k-mode", "3",
            "--s2k-digest-algo", "SHA256",
            "--s2k-count", "1000",
            "--compress-algo", "0",
            "--quiet",
            "--batch",
            "--yes",
            "--pinentry-mode", "loopback",
            "--passphrase", passphrase,
        ]);

        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to start GPG process for encryption")?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(data.as_bytes())
                .context("Failed to write to GPG stdin")?;
            drop(stdin);
        }

        let output = child.wait_with_output()
            .context("Failed to wait for GPG encryption process")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("GPG encryption failed: {}", stderr));
        }

        let encrypted_data = String::from_utf8(output.stdout)
            .context("Failed to convert GPG output to string")?;

        debug!("Successfully encrypted wallet data");
        Ok(encrypted_data)
    }

    /// Decrypt data using GPG
    pub fn decrypt_data(&self, encrypted_data: &str, passphrase: &str) -> Result<String> {
        info!("Decrypting wallet data with GPG");
        
        let mut command = Command::new("gpg");
        command.args(&[
            "--decrypt",
            "--quiet",
            "--batch",
            "--yes",
            "--pinentry-mode", "loopback",
            "--passphrase", passphrase,
        ]);

        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to start GPG process for decryption")?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(encrypted_data.as_bytes())
                .context("Failed to write to GPG stdin")?;
            drop(stdin);
        }

        let output = child.wait_with_output()
            .context("Failed to wait for GPG decryption process")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("GPG decryption failed: {}", stderr));
        }

        let decrypted_data = String::from_utf8(output.stdout)
            .context("Failed to convert GPG output to string")?;

        debug!("Successfully decrypted wallet data");
        Ok(decrypted_data)
    }


    /// Check if GPG is available on the system
    pub fn check_gpg_available(&self) -> Result<()> {
        let output = Command::new("gpg")
            .args(&["--version"])
            .output()
            .context("Failed to check GPG availability")?;

        if !output.status.success() {
            return Err(anyhow!("GPG is not available on this system"));
        }

        debug!("GPG is available");
        Ok(())
    }
}