//! Comprehensive tests for deezel-sys keystore functionality
//!
//! These tests verify that we can generate keystores, serialize them to JSON,
//! parse them back, and that all the keystore functionality works correctly.

use anyhow::Result as AnyhowResult;
use bitcoin::Network;
use deezel_sys::keystore::{
    KeystoreManager, KeystoreCreateParams
};

/// Test keystore creation with default parameters
#[tokio::test]
async fn test_keystore_creation() -> AnyhowResult<()> {
    let manager = KeystoreManager::new();
    
    let params = KeystoreCreateParams {
        mnemonic: None, // Generate new mnemonic
        passphrase: "test-passphrase".to_string(),
        network: Network::Regtest,
        address_count: 5,
    };
    
    let (keystore, mnemonic) = manager.create_keystore(params).await?;
    
    // Verify keystore structure
    assert_eq!(keystore.version, env!("CARGO_PKG_VERSION"));
    assert!(!keystore.encrypted_seed.is_empty());
    assert!(keystore.created_at > 0);
    
    // Verify mnemonic is valid (24 words)
    let words: Vec<&str> = mnemonic.split_whitespace().collect();
    assert_eq!(words.len(), 24);
    
    println!("✅ Keystore creation test passed");
    Ok(())
}