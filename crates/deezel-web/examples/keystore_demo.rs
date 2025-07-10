//! Keystore Generation Demo
//!
//! This example demonstrates keystore creation and shows the JSON output format.
//! Run with: cargo run --example keystore_demo

use deezel_common::keystore::create_keystore;
use serde_json;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔐 Deezel Keystore Generation Demo");
    println!("==================================\n");

    let passphrase = "demo_passphrase_123";
    println!("Creating keystore with passphrase: '{}'", passphrase);
    
    // Create the keystore
    let keystore = create_keystore(passphrase)?;
    
    // Display basic information
    println!("\n📊 Keystore Summary:");
    println!("├─ Version: {}", keystore.version);
    println!("├─ PBKDF2 Algorithm: {}", keystore.pbkdf2_params.algorithm);
    println!("├─ PBKDF2 Iterations: {}", keystore.pbkdf2_params.iterations);
    println!("├─ Salt Length: {} bytes", keystore.pbkdf2_params.salt.len() / 2);
    println!("├─ Encrypted Seed Length: {} characters", keystore.encrypted_seed.len());
    println!("└─ Networks: {}", keystore.addresses.len());
    
    // Show network breakdown
    println!("\n🌐 Address Breakdown by Network:");
    for (network, addresses) in &keystore.addresses {
        let p2wpkh_count = addresses.iter().filter(|a| a.address_type == "p2wpkh").count();
        let p2tr_count = addresses.iter().filter(|a| a.address_type == "p2tr").count();
        println!("├─ {}: {} addresses ({} P2WPKH, {} P2TR)", 
                 network, addresses.len(), p2wpkh_count, p2tr_count);
    }
    
    // Show sample addresses
    println!("\n📍 Sample Addresses (first 2 from mainnet):");
    if let Some(mainnet_addresses) = keystore.addresses.get("mainnet") {
        for (i, addr_info) in mainnet_addresses.iter().take(2).enumerate() {
            println!("├─ Address {}: {}", i + 1, addr_info.address);
            println!("│  ├─ Type: {}", addr_info.address_type);
            println!("│  └─ Path: {}", addr_info.path);
        }
    }
    
    // Show encrypted seed preview
    println!("\n🔒 Encrypted Seed (PGP Armored):");
    let seed_lines: Vec<&str> = keystore.encrypted_seed.lines().collect();
    for (i, line) in seed_lines.iter().take(5).enumerate() {
        if i == 0 {
            println!("├─ {}", line);
        } else {
            println!("│  {}", line);
        }
    }
    if seed_lines.len() > 5 {
        println!("│  ... ({} more lines)", seed_lines.len() - 5);
    }
    
    // Generate and display JSON
    println!("\n📄 JSON Output:");
    let json = serde_json::to_string_pretty(&keystore)?;
    
    // Show truncated JSON for readability
    let json_lines: Vec<&str> = json.lines().collect();
    let preview_lines = 30;
    
    for (i, line) in json_lines.iter().take(preview_lines).enumerate() {
        if i == 0 {
            println!("┌─ {}", line);
        } else if i == preview_lines - 1 && json_lines.len() > preview_lines {
            println!("│  {}", line);
        } else {
            println!("│  {}", line);
        }
    }
    
    if json_lines.len() > preview_lines {
        println!("│  ... ({} more lines)", json_lines.len() - preview_lines);
        // Show the last few lines
        for line in json_lines.iter().rev().take(3).rev() {
            println!("│  {}", line);
        }
    }
    println!("└─ Total JSON size: {} characters", json.len());
    
    // Verify the keystore can be deserialized
    println!("\n✅ Verification:");
    let deserialized = serde_json::from_str::<deezel_common::keystore::Keystore>(&json)?;
    println!("├─ JSON deserialization: ✓");
    println!("├─ Version match: {}", if deserialized.version == keystore.version { "✓" } else { "✗" });
    println!("├─ Address count match: {}", if deserialized.addresses.len() == keystore.addresses.len() { "✓" } else { "✗" });
    println!("└─ Encrypted seed match: {}", if deserialized.encrypted_seed == keystore.encrypted_seed { "✓" } else { "✗" });
    
    println!("\n🎉 Keystore generation and verification completed successfully!");
    
    Ok(())
}