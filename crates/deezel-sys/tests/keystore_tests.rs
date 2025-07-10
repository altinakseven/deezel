//! Comprehensive tests for deezel-sys keystore functionality
//!
//! These tests verify that we can generate keystores, serialize them to JSON,
//! parse them back, and that all the keystore functionality works correctly.

use anyhow::Result as AnyhowResult;
use bitcoin::Network;
use serde_json;
use std::collections::HashMap;

use deezel_sys::keystore::{
    KeystoreManager, KeystoreCreateParams, Keystore, KeystoreAddress, KeystoreInfo
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
    assert_eq!(keystore.network, "regtest");
    assert_eq!(keystore.version, "1.0.0");
    assert!(!keystore.encrypted_seed.is_empty());
    assert!(keystore.created_at > 0);
    
    // Verify mnemonic is valid (24 words)
    let words: Vec<&str> = mnemonic.split_whitespace().collect();
    assert_eq!(words.len(), 24);
    
    // Verify addresses were generated
    assert!(keystore.addresses.contains_key("P2WPKH"));
    assert!(keystore.addresses.contains_key("P2TR"));
    
    let p2wpkh_addresses = keystore.addresses.get("P2WPKH").unwrap();
    let p2tr_addresses = keystore.addresses.get("P2TR").unwrap();
    
    assert_eq!(p2wpkh_addresses.len(), 5);
    assert_eq!(p2tr_addresses.len(), 5);
    
    // Verify address structure
    for (i, addr) in p2wpkh_addresses.iter().enumerate() {
        assert_eq!(addr.index, i as u32);
        assert_eq!(addr.script_type, "P2WPKH");
        assert!(addr.address.starts_with("bc1q"));
        assert!(addr.derivation_path.contains(&format!("/{}", i)));
    }
    
    for (i, addr) in p2tr_addresses.iter().enumerate() {
        assert_eq!(addr.index, i as u32);
        assert_eq!(addr.script_type, "P2TR");
        assert!(addr.address.starts_with("bc1p"));
        assert!(addr.derivation_path.contains(&format!("/{}", i)));
    }
    
    println!("✅ Keystore creation test passed");
    Ok(())
}

/// Test keystore creation with provided mnemonic
#[tokio::test]
async fn test_keystore_creation_with_mnemonic() -> AnyhowResult<()> {
    let manager = KeystoreManager::new();
    
    let test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
    
    let params = KeystoreCreateParams {
        mnemonic: Some(test_mnemonic.clone()),
        passphrase: "test-passphrase".to_string(),
        network: Network::Testnet,
        address_count: 3,
    };
    
    let (keystore, returned_mnemonic) = manager.create_keystore(params).await?;
    
    // Verify the mnemonic matches
    assert_eq!(returned_mnemonic, test_mnemonic);
    
    // Verify network
    assert_eq!(keystore.network, "testnet");
    
    // Verify address count
    let p2wpkh_addresses = keystore.addresses.get("P2WPKH").unwrap();
    assert_eq!(p2wpkh_addresses.len(), 3);
    
    println!("✅ Keystore creation with mnemonic test passed");
    Ok(())
}

/// Test keystore JSON serialization and deserialization
#[tokio::test]
async fn test_keystore_json_serialization() -> AnyhowResult<()> {
    let manager = KeystoreManager::new();
    
    let params = KeystoreCreateParams {
        mnemonic: None,
        passphrase: "test-passphrase".to_string(),
        network: Network::Bitcoin,
        address_count: 2,
    };
    
    let (original_keystore, _mnemonic) = manager.create_keystore(params).await?;
    
    // Serialize to JSON
    let json_string = serde_json::to_string_pretty(&original_keystore)?;
    
    // Verify JSON structure
    assert!(json_string.contains("encrypted_seed"));
    assert!(json_string.contains("network"));
    assert!(json_string.contains("addresses"));
    assert!(json_string.contains("created_at"));
    assert!(json_string.contains("version"));
    assert!(json_string.contains("P2WPKH"));
    assert!(json_string.contains("P2TR"));
    
    // Deserialize from JSON
    let parsed_keystore: Keystore = serde_json::from_str(&json_string)?;
    
    // Verify all fields match
    assert_eq!(parsed_keystore.encrypted_seed, original_keystore.encrypted_seed);
    assert_eq!(parsed_keystore.network, original_keystore.network);
    assert_eq!(parsed_keystore.created_at, original_keystore.created_at);
    assert_eq!(parsed_keystore.version, original_keystore.version);
    assert_eq!(parsed_keystore.addresses.len(), original_keystore.addresses.len());
    
    // Verify addresses match
    for (script_type, original_addresses) in &original_keystore.addresses {
        let parsed_addresses = parsed_keystore.addresses.get(script_type).unwrap();
        assert_eq!(parsed_addresses.len(), original_addresses.len());
        
        for (original_addr, parsed_addr) in original_addresses.iter().zip(parsed_addresses.iter()) {
            assert_eq!(parsed_addr.address, original_addr.address);
            assert_eq!(parsed_addr.derivation_path, original_addr.derivation_path);
            assert_eq!(parsed_addr.index, original_addr.index);
            assert_eq!(parsed_addr.script_type, original_addr.script_type);
        }
    }
    
    println!("✅ Keystore JSON serialization test passed");
    Ok(())
}

/// Test keystore manager utility functions
#[tokio::test]
async fn test_keystore_manager_utilities() -> AnyhowResult<()> {
    let manager = KeystoreManager::new();
    
    let params = KeystoreCreateParams {
        mnemonic: None,
        passphrase: "test-passphrase".to_string(),
        network: Network::Signet,
        address_count: 4,
    };
    
    let (keystore, _mnemonic) = manager.create_keystore(params).await?;
    
    // Test get_addresses with specific script type
    let p2wpkh_addresses = manager.get_addresses(&keystore, Some("P2WPKH"));
    assert_eq!(p2wpkh_addresses.len(), 4);
    
    let p2tr_addresses = manager.get_addresses(&keystore, Some("P2TR"));
    assert_eq!(p2tr_addresses.len(), 4);
    
    // Test get_addresses with no filter (all addresses)
    let all_addresses = manager.get_addresses(&keystore, None);
    assert_eq!(all_addresses.len(), 8); // 4 P2WPKH + 4 P2TR
    
    // Test get_address_by_index
    let first_p2wpkh = manager.get_address_by_index(&keystore, "P2WPKH", 0);
    assert!(first_p2wpkh.is_some());
    assert_eq!(first_p2wpkh.unwrap().index, 0);
    assert_eq!(first_p2wpkh.unwrap().script_type, "P2WPKH");
    
    let nonexistent_address = manager.get_address_by_index(&keystore, "P2WPKH", 10);
    assert!(nonexistent_address.is_none());
    
    // Test get_keystore_info
    let info = manager.get_keystore_info(&keystore);
    assert_eq!(info.network, "signet");
    assert_eq!(info.total_addresses, 8);
    assert_eq!(info.script_types.len(), 2);
    assert!(info.script_types.contains(&"P2WPKH".to_string()));
    assert!(info.script_types.contains(&"P2TR".to_string()));
    assert_eq!(info.version, "1.0.0");
    assert!(info.created_at > 0);
    
    println!("✅ Keystore manager utilities test passed");
    Ok(())
}

/// Test keystore file operations
#[tokio::test]
async fn test_keystore_file_operations() -> AnyhowResult<()> {
    let manager = KeystoreManager::new();
    
    let params = KeystoreCreateParams {
        mnemonic: None,
        passphrase: "test-passphrase".to_string(),
        network: Network::Regtest,
        address_count: 2,
    };
    
    let (original_keystore, _mnemonic) = manager.create_keystore(params).await?;
    
    // Create a temporary file path
    let temp_file = "/tmp/test_keystore.json";
    
    // Save keystore to file
    manager.save_keystore(&original_keystore, temp_file).await?;
    
    // Verify file exists and has content
    let file_content = std::fs::read_to_string(temp_file)?;
    assert!(!file_content.is_empty());
    assert!(file_content.contains("encrypted_seed"));
    
    // Load keystore from file
    let (loaded_keystore, _loaded_mnemonic) = manager.load_keystore_from_file(temp_file, "test-passphrase").await?;
    
    // Verify loaded keystore matches original
    assert_eq!(loaded_keystore.encrypted_seed, original_keystore.encrypted_seed);
    assert_eq!(loaded_keystore.network, original_keystore.network);
    assert_eq!(loaded_keystore.created_at, original_keystore.created_at);
    assert_eq!(loaded_keystore.version, original_keystore.version);
    
    // Clean up
    std::fs::remove_file(temp_file).ok();
    
    println!("✅ Keystore file operations test passed");
    Ok(())
}

/// Test keystore with different networks
#[tokio::test]
async fn test_keystore_different_networks() -> AnyhowResult<()> {
    let manager = KeystoreManager::new();
    
    let networks = vec![
        (Network::Bitcoin, "bitcoin"),
        (Network::Testnet, "testnet"),
        (Network::Signet, "signet"),
        (Network::Regtest, "regtest"),
    ];
    
    for (network, expected_name) in networks {
        let params = KeystoreCreateParams {
            mnemonic: None,
            passphrase: "test-passphrase".to_string(),
            network,
            address_count: 1,
        };
        
        let (keystore, _mnemonic) = manager.create_keystore(params).await?;
        assert_eq!(keystore.network, expected_name);
        
        // Verify addresses are generated for all networks
        assert!(keystore.addresses.contains_key("P2WPKH"));
        assert!(keystore.addresses.contains_key("P2TR"));
    }
    
    println!("✅ Keystore different networks test passed");
    Ok(())
}

/// Test keystore JSON structure matches expected format
#[tokio::test]
async fn test_keystore_json_structure() -> AnyhowResult<()> {
    let manager = KeystoreManager::new();
    
    let params = KeystoreCreateParams {
        mnemonic: Some("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string()),
        passphrase: "test-passphrase".to_string(),
        network: Network::Regtest,
        address_count: 1,
    };
    
    let (keystore, _mnemonic) = manager.create_keystore(params).await?;
    
    // Serialize to JSON
    let json_string = serde_json::to_string_pretty(&keystore)?;
    
    // Parse as generic JSON to verify structure
    let json_value: serde_json::Value = serde_json::from_str(&json_string)?;
    
    // Verify top-level fields
    assert!(json_value.get("encrypted_seed").is_some());
    assert!(json_value.get("network").is_some());
    assert!(json_value.get("addresses").is_some());
    assert!(json_value.get("created_at").is_some());
    assert!(json_value.get("version").is_some());
    
    // Verify network value
    assert_eq!(json_value["network"].as_str().unwrap(), "regtest");
    assert_eq!(json_value["version"].as_str().unwrap(), "1.0.0");
    
    // Verify addresses structure
    let addresses = json_value["addresses"].as_object().unwrap();
    assert!(addresses.contains_key("P2WPKH"));
    assert!(addresses.contains_key("P2TR"));
    
    // Verify address array structure
    let p2wpkh_addresses = addresses["P2WPKH"].as_array().unwrap();
    assert_eq!(p2wpkh_addresses.len(), 1);
    
    let first_address = &p2wpkh_addresses[0];
    assert!(first_address.get("address").is_some());
    assert!(first_address.get("derivation_path").is_some());
    assert!(first_address.get("index").is_some());
    assert!(first_address.get("script_type").is_some());
    
    assert_eq!(first_address["script_type"].as_str().unwrap(), "P2WPKH");
    assert_eq!(first_address["index"].as_u64().unwrap(), 0);
    
    println!("✅ Keystore JSON structure test passed");
    println!("📄 Example keystore JSON:\n{}", json_string);
    
    Ok(())
}

/// Integration test that demonstrates the complete keystore workflow
#[tokio::test]
async fn test_complete_keystore_workflow() -> AnyhowResult<()> {
    println!("🚀 Starting complete keystore workflow test...");
    
    let manager = KeystoreManager::new();
    
    // Step 1: Create keystore
    println!("📝 Step 1: Creating keystore...");
    let params = KeystoreCreateParams {
        mnemonic: None,
        passphrase: "secure-passphrase-123".to_string(),
        network: Network::Regtest,
        address_count: 3,
    };
    
    let (keystore, mnemonic) = manager.create_keystore(params).await?;
    println!("✅ Keystore created with {} total addresses", 
             keystore.addresses.values().map(|v| v.len()).sum::<usize>());
    
    // Step 2: Serialize to JSON
    println!("📝 Step 2: Serializing to JSON...");
    let json_string = serde_json::to_string_pretty(&keystore)?;
    println!("✅ JSON serialization successful ({} bytes)", json_string.len());
    
    // Step 3: Parse JSON back
    println!("📝 Step 3: Parsing JSON back...");
    let parsed_keystore: Keystore = serde_json::from_str(&json_string)?;
    println!("✅ JSON parsing successful");
    
    // Step 4: Verify data integrity
    println!("📝 Step 4: Verifying data integrity...");
    assert_eq!(parsed_keystore.network, keystore.network);
    assert_eq!(parsed_keystore.version, keystore.version);
    assert_eq!(parsed_keystore.encrypted_seed, keystore.encrypted_seed);
    assert_eq!(parsed_keystore.addresses.len(), keystore.addresses.len());
    println!("✅ Data integrity verified");
    
    // Step 5: Test utility functions
    println!("📝 Step 5: Testing utility functions...");
    let info = manager.get_keystore_info(&parsed_keystore);
    assert_eq!(info.total_addresses, 6); // 3 P2WPKH + 3 P2TR
    
    let p2wpkh_addresses = manager.get_addresses(&parsed_keystore, Some("P2WPKH"));
    assert_eq!(p2wpkh_addresses.len(), 3);
    
    let first_address = manager.get_address_by_index(&parsed_keystore, "P2WPKH", 0);
    assert!(first_address.is_some());
    println!("✅ Utility functions working correctly");
    
    // Step 6: Save and load from file
    println!("📝 Step 6: Testing file operations...");
    let temp_file = "/tmp/workflow_test_keystore.json";
    manager.save_keystore(&parsed_keystore, temp_file).await?;
    
    let (file_keystore, _file_mnemonic) = manager.load_keystore_from_file(temp_file, "secure-passphrase-123").await?;
    assert_eq!(file_keystore.encrypted_seed, keystore.encrypted_seed);
    
    // Clean up
    std::fs::remove_file(temp_file).ok();
    println!("✅ File operations successful");
    
    println!("🎉 Complete keystore workflow test passed!");
    println!("📊 Summary:");
    println!("   - Keystore created with {} script types", keystore.addresses.len());
    println!("   - Total addresses: {}", info.total_addresses);
    println!("   - Mnemonic words: {}", mnemonic.split_whitespace().count());
    println!("   - JSON size: {} bytes", json_string.len());
    println!("   - Network: {}", keystore.network);
    
    Ok(())
}