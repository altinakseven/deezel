//! Tests for keystore generation functionality in deezel-web
//!
//! These tests verify that keystore creation works properly in the web environment
//! and demonstrate the JSON output format.

use deezel_web::prelude::*;
use deezel_common::keystore::create_keystore;
use wasm_bindgen_test::*;
use serde_json;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
pub fn test_keystore_creation_basic() {
    let passphrase = "test_passphrase_123";
    let keystore_result = create_keystore(passphrase, None);
    
    assert!(keystore_result.is_ok(), "Keystore creation should succeed");
    
    let (keystore, _) = keystore_result.unwrap();
    
    // Verify basic structure
    assert_eq!(keystore.version, "1");
    assert!(keystore.encrypted_seed.starts_with("-----BEGIN PGP MESSAGE-----"));
    assert!(keystore.encrypted_seed.ends_with("-----END PGP MESSAGE-----\n"));
    
    // Verify PBKDF2 parameters
    assert_eq!(keystore.pbkdf2_params.iterations, 100_000);
    assert_eq!(keystore.pbkdf2_params.algorithm, Some("AES256".to_string()));
    assert_eq!(keystore.pbkdf2_params.salt.len(), 16); // 8 bytes = 16 hex chars
    
    // Verify networks
    assert_eq!(keystore.addresses.len(), 4);
    assert!(keystore.addresses.contains_key("mainnet"));
    assert!(keystore.addresses.contains_key("testnet"));
    assert!(keystore.addresses.contains_key("signet"));
    assert!(keystore.addresses.contains_key("regtest"));
    
    // Verify address counts (10 P2WPKH + 10 P2TR = 20 per network)
    for (network, addresses) in &keystore.addresses {
        assert_eq!(addresses.len(), 20, "Network {} should have 20 addresses", network);
        
        // Verify we have both address types
        let p2wpkh_count = addresses.iter().filter(|a| a.address_type == "p2wpkh").count();
        let p2tr_count = addresses.iter().filter(|a| a.address_type == "p2tr").count();
        assert_eq!(p2wpkh_count, 10);
        assert_eq!(p2tr_count, 10);
    }
}

#[wasm_bindgen_test]
pub fn test_keystore_json_serialization() {
    let passphrase = "demo_passphrase_456";
    let (keystore, _) = create_keystore(passphrase, None).unwrap();
    
    // Test JSON serialization
    let json_result = serde_json::to_string_pretty(&keystore);
    assert!(json_result.is_ok(), "Keystore should serialize to JSON");
    
    let json_string = json_result.unwrap();
    
    // Verify JSON contains expected fields
    assert!(json_string.contains("\"encrypted_seed\""));
    assert!(json_string.contains("\"pbkdf2_params\""));
    assert!(json_string.contains("\"addresses\""));
    assert!(json_string.contains("\"version\""));
    assert!(json_string.contains("\"salt\""));
    assert!(json_string.contains("\"iterations\""));
    assert!(json_string.contains("\"algorithm\""));
    
    // Test deserialization
    let deserialized_result = serde_json::from_str::<deezel_common::keystore::Keystore>(&json_string);
    assert!(deserialized_result.is_ok(), "JSON should deserialize back to Keystore");
    
    let deserialized = deserialized_result.unwrap();
    assert_eq!(deserialized.version, keystore.version);
    assert_eq!(deserialized.encrypted_seed, keystore.encrypted_seed);
    assert_eq!(deserialized.addresses.len(), keystore.addresses.len());
}

#[wasm_bindgen_test]
pub fn test_keystore_address_formats() {
    let passphrase = "address_test_789";
    let (keystore, _) = create_keystore(passphrase, None).unwrap();
    
    // Test mainnet addresses
    let mainnet_addresses = keystore.addresses.get("mainnet").unwrap();
    
    // Check P2WPKH addresses (should start with bc1q)
    let p2wpkh_addresses: Vec<_> = mainnet_addresses.iter()
        .filter(|a| a.address_type == "p2wpkh")
        .collect();
    
    for addr_info in p2wpkh_addresses {
        assert!(addr_info.address.starts_with("bc1q"), 
               "P2WPKH mainnet address should start with bc1q: {}", addr_info.address);
        assert!(addr_info.path.starts_with("m/84'/0'/0'/0/"), 
               "P2WPKH path should use BIP84: {}", addr_info.path);
    }
    
    // Check P2TR addresses (should start with bc1p)
    let p2tr_addresses: Vec<_> = mainnet_addresses.iter()
        .filter(|a| a.address_type == "p2tr")
        .collect();
    
    for addr_info in p2tr_addresses {
        assert!(addr_info.address.starts_with("bc1p"), 
               "P2TR mainnet address should start with bc1p: {}", addr_info.address);
        assert!(addr_info.path.starts_with("m/86'/0'/0'/0/"), 
               "P2TR path should use BIP86: {}", addr_info.path);
    }
    
    // Test testnet addresses
    let testnet_addresses = keystore.addresses.get("testnet").unwrap();
    let testnet_p2wpkh: Vec<_> = testnet_addresses.iter()
        .filter(|a| a.address_type == "p2wpkh")
        .collect();
    
    for addr_info in testnet_p2wpkh {
        assert!(addr_info.address.starts_with("tb1q"), 
               "P2WPKH testnet address should start with tb1q: {}", addr_info.address);
    }
}

#[wasm_bindgen_test]
pub fn test_keystore_encryption_uniqueness() {
    let passphrase = "uniqueness_test";
    
    // Create two keystores with same passphrase
    let (keystore1, _) = create_keystore(passphrase, None).unwrap();
    let (keystore2, _) = create_keystore(passphrase, None).unwrap();
    
    // They should have different encrypted seeds (due to random salt/entropy)
    assert_ne!(keystore1.encrypted_seed, keystore2.encrypted_seed);
    assert_ne!(keystore1.pbkdf2_params.salt, keystore2.pbkdf2_params.salt);
    
    // But same parameters
    assert_eq!(keystore1.pbkdf2_params.iterations, keystore2.pbkdf2_params.iterations);
    assert_eq!(keystore1.pbkdf2_params.algorithm, keystore2.pbkdf2_params.algorithm);
    assert_eq!(keystore1.version, keystore2.version);
}

/// Example function to demonstrate keystore JSON output
/// This is not a test but shows the actual JSON structure
#[wasm_bindgen_test]
pub fn demonstrate_keystore_json_output() {
    let passphrase = "example_demo_passphrase";
    let (keystore, _) = create_keystore(passphrase, None).unwrap();
    
    // Create a pretty-printed JSON for demonstration
    let json = serde_json::to_string_pretty(&keystore).unwrap();
    
    // Log the JSON structure (will appear in browser console)
    web_sys::console::log_1(&format!("=== KEYSTORE JSON EXAMPLE ===").into());
    web_sys::console::log_1(&format!("Passphrase used: {}", passphrase).into());
    web_sys::console::log_1(&format!("JSON length: {} characters", json.len()).into());
    web_sys::console::log_1(&format!("Encrypted seed length: {} characters", keystore.encrypted_seed.len()).into());
    web_sys::console::log_1(&format!("Number of networks: {}", keystore.addresses.len()).into());
    
    // Log first few lines of JSON structure (truncated for readability)
    let lines: Vec<&str> = json.lines().take(20).collect();
    for line in lines {
        web_sys::console::log_1(&line.into());
    }
    web_sys::console::log_1(&"... (truncated for readability)".into());
    web_sys::console::log_1(&format!("=== END KEYSTORE EXAMPLE ===").into());
    
    // Verify the structure is valid
    assert!(json.len() > 1000, "JSON should be substantial in size");
    assert!(json.contains("mainnet"), "Should contain mainnet addresses");
}