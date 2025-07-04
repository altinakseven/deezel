//! Envelope functionality for alkanes commit-reveal transactions
//!
//! This module implements envelope creation and witness stack encoding
//! using the official alkanes-support envelope structures for commit-reveal transactions.

use anyhow::{anyhow, Context, Result};
use alkanes_support::envelope::RawEnvelope;
use bitcoin::{
    secp256k1::{Secp256k1, XOnlyPublicKey},
    Address, Network,
};
use log::{debug, info};

/// Envelope manager for alkanes commit-reveal transactions
pub struct EnvelopeManager {
    envelope: RawEnvelope,
}

impl EnvelopeManager {
    /// Create a new envelope manager from raw data
    pub fn new(data: Vec<u8>) -> Self {
        info!("Creating envelope manager with {} bytes of data", data.len());
        let envelope = RawEnvelope::from(data);
        Self { envelope }
    }

    /// Get the underlying envelope
    pub fn envelope(&self) -> &RawEnvelope {
        &self.envelope
    }

    /// Create commit address for the envelope
    pub fn create_commit_address(&self, network: Network, internal_key: XOnlyPublicKey) -> Result<Address> {
        self.envelope
            .to_commit_address(network, internal_key)
            .map_err(|e| anyhow!("Failed to create commit address: {:?}", e))
    }

    /// Create witness stack for the reveal transaction
    pub fn create_witness(&self) -> bitcoin::Witness {
        info!("Creating witness for envelope reveal");
        self.envelope.to_gzipped_witness()
    }

    /// Preview the envelope contents for user approval
    pub fn preview(&self) -> String {
        let mut preview = String::new();
        
        preview.push_str("📦 Envelope Preview\n");
        preview.push_str("═══════════════════\n\n");
        
        let total_size: usize = self.envelope.payload.iter().map(|chunk| chunk.len()).sum();
        preview.push_str(&format!("📊 Total payload size: {} bytes\n", total_size));
        preview.push_str(&format!("📦 Payload chunks: {}\n", self.envelope.payload.len()));
        
        // Show first few bytes as hex for verification
        if let Some(first_chunk) = self.envelope.payload.first() {
            let preview_bytes = if first_chunk.len() > 32 { &first_chunk[..32] } else { first_chunk };
            preview.push_str(&format!("🔍 First bytes: {}\n", hex::encode(preview_bytes)));
            if first_chunk.len() > 32 {
                preview.push_str("   ... (truncated)\n");
            }
        }
        
        // Try to detect file type
        if let Some(first_chunk) = self.envelope.payload.first() {
            if first_chunk.len() >= 4 {
                let magic = &first_chunk[..4];
                let file_type = match magic {
                    [0x1f, 0x8b, _, _] => "Gzip compressed file",
                    [0x00, 0x61, 0x73, 0x6d] => "WebAssembly module",
                    [0x7f, 0x45, 0x4c, 0x46] => "ELF executable",
                    [0x50, 0x4b, 0x03, 0x04] => "ZIP archive",
                    _ => "Unknown file type",
                };
                preview.push_str(&format!("📄 Detected type: {}\n", file_type));
            }
        }
        
        preview.push_str("\n💡 This envelope will be committed as the FIRST input in the transaction.\n");
        preview.push_str("🔗 The reveal will be encoded in the witness stack according to alkanes envelope format.\n");
        preview.push_str("🎯 This enables large contract deployments with commit-reveal pattern.\n");
        
        preview
    }

    /// Get taproot spend info for the envelope
    pub fn get_taproot_spend_info(&self, internal_key: XOnlyPublicKey) -> Result<bitcoin::taproot::TaprootSpendInfo> {
        self.envelope
            .to_taproot_spend_info(internal_key)
            .map_err(|e| anyhow!("Failed to create taproot spend info: {:?}", e))
    }

    /// Get control block for the envelope
    pub fn get_control_block(&self, internal_key: XOnlyPublicKey) -> Result<bitcoin::taproot::ControlBlock> {
        self.envelope
            .to_control_block(internal_key)
            .map_err(|e| anyhow!("Failed to create control block: {:?}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_envelope_manager_creation() {
        let test_data = b"Hello, alkanes envelope!".to_vec();
        let manager = EnvelopeManager::new(test_data.clone());
        
        assert_eq!(manager.envelope().payload.len(), 1);
        assert_eq!(manager.envelope().payload[0], test_data);
    }

    #[test]
    fn test_envelope_preview() {
        let test_data = b"Hello, alkanes envelope!".to_vec();
        let manager = EnvelopeManager::new(test_data);
        
        let preview = manager.preview();
        assert!(preview.contains("Envelope Preview"));
        assert!(preview.contains("Total payload size: 24 bytes"));
        assert!(preview.contains("Payload chunks: 1"));
    }
}
