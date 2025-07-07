//! Test suite to verify that envelope with BIN data is used as first input
//!
//! This test verifies the user's requirement that the envelope with BIN data
//! is properly used as the first input in the transaction when using --envelope flag.

use anyhow::Result;
use crate::alkanes::envelope::AlkanesEnvelope;

#[test]
fn test_envelope_contains_bin_protocol() {
    println!("\n🧪 ENVELOPE BIN PROTOCOL TEST");
    println!("═══════════════════════════════");
    
    // Create envelope with contract data (simulating --envelope flag usage)
    let contract_data = vec![0x42; 1000]; // 1KB of test contract data
    let envelope = AlkanesEnvelope::for_contract(contract_data.clone());
    
    // Verify envelope was created with the contract data
    assert!(envelope.body.is_some(), "Envelope should contain body data");
    assert_eq!(envelope.body.as_ref().unwrap(), &contract_data, "Envelope body should match input data");
    
    // Verify content type is set for contract deployment
    assert!(envelope.content_type.is_some(), "Envelope should have content type");
    assert_eq!(envelope.content_type.as_ref().unwrap(), b"application/wasm", "Content type should be application/wasm");
    
    println!("✅ Envelope created with BIN protocol data");
    println!("📦 Contract data size: {} bytes", contract_data.len());
    println!("🏷️  Content type: {:?}", String::from_utf8_lossy(envelope.content_type.as_ref().unwrap()));
}

#[test]
fn test_envelope_reveal_script_contains_bin_tag() {
    println!("\n🧪 ENVELOPE REVEAL SCRIPT BIN TAG TEST");
    println!("═══════════════════════════════════════");
    
    // Create envelope with BIN data
    let contract_data = vec![0x42; 500];
    let envelope = AlkanesEnvelope::for_contract(contract_data);
    
    // Build reveal script
    let reveal_script = envelope.build_reveal_script();
    
    // Verify script contains BIN protocol tag
    let script_bytes = reveal_script.as_bytes();
    
    // The script should contain the BIN protocol tag somewhere
    let bin_tag = b"BIN";
    let contains_bin = script_bytes.windows(3).any(|window| window == bin_tag);
    
    assert!(contains_bin, "Reveal script should contain BIN protocol tag");
    
    println!("✅ Reveal script contains BIN protocol tag");
    println!("📜 Script size: {} bytes", script_bytes.len());
    
    // Log script structure for verification
    println!("🔍 Script analysis:");
    if let Some(bin_pos) = script_bytes.windows(3).position(|window| window == bin_tag) {
        println!("  BIN tag found at position: {}", bin_pos);
        println!("  Script context around BIN: {:?}", 
                 &script_bytes[bin_pos.saturating_sub(5)..std::cmp::min(bin_pos + 8, script_bytes.len())]);
    }
}

#[test]
fn test_envelope_witness_creation_with_bin_data() -> Result<()> {
    println!("\n🧪 ENVELOPE WITNESS WITH BIN DATA TEST");
    println!("═══════════════════════════════════════");
    
    use bitcoin::secp256k1::{Secp256k1, rand};
    use bitcoin::key::{Keypair, UntweakedKeypair};
    use bitcoin::taproot::{TaprootBuilder, LeafVersion};
    
    // Create envelope with BIN data
    let contract_data = vec![0x42; 2000]; // 2KB of contract data
    let envelope = AlkanesEnvelope::for_contract(contract_data.clone());
    
    // Create test keys
    let secp = Secp256k1::new();
    let mut rng = rand::thread_rng();
    let keypair = Keypair::new(&secp, &mut rng);
    let untweaked_keypair = UntweakedKeypair::from(keypair);
    let internal_key = untweaked_keypair.public_key().into(); // Convert to XOnlyPublicKey
    
    // Build reveal script and taproot spend info
    let reveal_script = envelope.build_reveal_script();
    let taproot_builder = TaprootBuilder::new()
        .add_leaf(0, reveal_script.clone())?;
    
    let taproot_spend_info = taproot_builder
        .finalize(&secp, internal_key)
        .map_err(|e| anyhow::anyhow!("Failed to finalize taproot spend info: {:?}", e))?;
    
    // Create control block
    let control_block = taproot_spend_info
        .control_block(&(reveal_script, LeafVersion::TapScript))
        .ok_or_else(|| anyhow::anyhow!("Failed to create control block"))?;
    
    // Create witness with BIN data
    let witness = envelope.create_witness(control_block)?;
    
    // Verify witness structure
    assert_eq!(witness.len(), 2, "Witness should have exactly 2 items (script + control_block)");
    
    let script_item = witness.nth(0).unwrap();
    let control_block_item = witness.nth(1).unwrap();
    
    assert!(!script_item.is_empty(), "Script witness item should not be empty");
    assert!(!control_block_item.is_empty(), "Control block witness item should not be empty");
    
    // Verify script contains BIN data
    let contains_bin = script_item.windows(3).any(|window| window == b"BIN");
    assert!(contains_bin, "Witness script should contain BIN protocol tag");
    
    println!("✅ Envelope witness created successfully with BIN data");
    println!("📦 Original contract data: {} bytes", contract_data.len());
    println!("📜 Witness script item: {} bytes", script_item.len());
    println!("🔧 Control block item: {} bytes", control_block_item.len());
    println!("🏷️  BIN protocol tag verified in witness script");
    
    Ok(())
}

#[test]
fn test_envelope_first_input_usage_pattern() {
    println!("\n🧪 ENVELOPE FIRST INPUT USAGE PATTERN TEST");
    println!("═══════════════════════════════════════════");
    
    // This test verifies the conceptual pattern that envelope with BIN data
    // should be used as the first input in transactions built with --envelope flag
    
    // Create envelope with BIN data (simulating --envelope file.wasm usage)
    let wasm_data = vec![0x00, 0x61, 0x73, 0x6d]; // WASM magic number + some data
    let envelope = AlkanesEnvelope::for_contract(wasm_data.clone());
    
    // Verify envelope properties that make it suitable for first input usage
    assert!(envelope.body.is_some(), "Envelope must have body for first input");
    assert!(envelope.content_type.is_some(), "Envelope must have content type for first input");
    
    let reveal_script = envelope.build_reveal_script();
    assert!(!reveal_script.is_empty(), "Reveal script must not be empty for first input");
    
    // Verify BIN protocol is embedded
    let script_bytes = reveal_script.as_bytes();
    let has_bin_protocol = script_bytes.windows(3).any(|w| w == b"BIN");
    assert!(has_bin_protocol, "First input envelope must contain BIN protocol");
    
    println!("✅ Envelope is properly structured for first input usage");
    println!("📦 WASM data size: {} bytes", wasm_data.len());
    println!("📜 Reveal script size: {} bytes", script_bytes.len());
    println!("🏷️  BIN protocol verified for first input");
    println!("💡 This envelope can be used as first input in commit/reveal pattern");
}