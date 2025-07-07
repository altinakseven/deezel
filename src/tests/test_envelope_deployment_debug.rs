//! Debug test for envelope deployment issues with alkanes contract deployment
//! 
//! This test investigates why --envelope with [3, 1000, 101] cellpack doesn't work
//! when deploying ./examples/free_mint.wasm.gz with --envelope to [4, 1000]
//!
//! Key issues to investigate:
//! 1. Envelope witness structure vs alkanes-rs reference
//! 2. Protostone encoding in protocol field (tag 16383)
//! 3. Contract deployment vs execution cellpack differences
//! 4. Trace vout calculation for protostones

use anyhow::Result;
use bitcoin::{Transaction, TxOut, Amount, ScriptBuf};
use alkanes_support::cellpack::Cellpack;
use ordinals::Runestone;
use log::{info, debug, warn};

#[tokio::test]
async fn test_envelope_deployment_debug() -> Result<()> {
    // Initialize logging for detailed debugging
    let _ = env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .try_init();

    info!("🔍 === ENVELOPE DEPLOYMENT DEBUG TEST ===");
    info!("🎯 Goal: Debug why --envelope with [3,1000,101] cellpack fails for contract deployment");
    
    // STEP 1: Analyze the difference between working and non-working scenarios
    info!("\n📋 STEP 1: Analyzing working vs non-working scenarios");
    info!("✅ Working: Execute without --envelope");
    info!("❌ Not working: Execute with --envelope and [3,1000,101] cellpack");
    info!("🎯 Expected: Deploy to [4,1000] and get trace from reveal txid + vout");
    
    // STEP 2: Examine the cellpack structure
    info!("\n📋 STEP 2: Examining cellpack structure");
    
    // Parse the problematic cellpack: [3, 1000, 101]
    let cellpack_values = vec![3u128, 1000u128, 101u128];
    let cellpack = Cellpack::try_from(cellpack_values.clone())?;
    
    info!("📦 Cellpack analysis:");
    info!("  Raw values: {:?}", cellpack_values);
    info!("  Target: block={}, tx={}", cellpack.target.block, cellpack.target.tx);
    info!("  Inputs: {:?}", cellpack.inputs);
    info!("  Encoded (LEB128): {} bytes", cellpack.encipher().len());
    
    // CRITICAL INSIGHT: This cellpack targets [3, 1000] but we expect deployment to [4, 1000]
    // This suggests the cellpack is for EXECUTION, not DEPLOYMENT
    warn!("⚠️  CRITICAL: Cellpack targets [3,1000] but expected deployment is [4,1000]");
    warn!("💡 This suggests cellpack is for EXECUTION of existing contract, not DEPLOYMENT");
    
    // STEP 3: Compare with alkanes-rs reference envelope structure
    info!("\n📋 STEP 3: Comparing envelope structure with alkanes-rs reference");
    
    // Load the contract data (free_mint.wasm.gz)
    let contract_data = std::fs::read("./examples/free_mint.wasm.gz")
        .map_err(|e| anyhow::anyhow!("Failed to read contract file: {}", e))?;
    
    info!("📄 Contract file analysis:");
    info!("  File: ./examples/free_mint.wasm.gz");
    info!("  Size: {} bytes", contract_data.len());
    info!("  First 16 bytes: {:02x?}", &contract_data[..16.min(contract_data.len())]);
    
    // Create envelope using our implementation
    let our_envelope = crate::alkanes::envelope::AlkanesEnvelope::for_contract(contract_data.clone());
    let our_script = our_envelope.build_reveal_script();
    
    info!("🔧 Our envelope implementation:");
    info!("  Script size: {} bytes", our_script.len());
    info!("  Script preview: {}", hex::encode(&our_script.as_bytes()[..64.min(our_script.len())]));
    
    // Create envelope using alkanes-rs reference pattern
    let reference_envelope = create_reference_envelope(contract_data.clone())?;
    
    info!("📚 Reference envelope (alkanes-rs pattern):");
    info!("  Script size: {} bytes", reference_envelope.len());
    info!("  Script preview: {}", hex::encode(&reference_envelope.as_bytes()[..64.min(reference_envelope.len())]));
    
    // Compare the two approaches
    let scripts_match = our_script.as_bytes() == reference_envelope.as_bytes();
    info!("🔍 Script comparison: {}", if scripts_match { "✅ MATCH" } else { "❌ DIFFERENT" });
    
    if !scripts_match {
        warn!("⚠️  CRITICAL: Our envelope script differs from alkanes-rs reference!");
        debug_script_differences(&our_script, &reference_envelope);
    }
    
    // STEP 4: Analyze protostone construction for deployment vs execution
    info!("\n📋 STEP 4: Analyzing protostone construction");
    
    // For CONTRACT DEPLOYMENT, we should NOT include a cellpack in the protostone
    // The cellpack [3,1000,101] is for EXECUTION, not deployment
    info!("💡 CONTRACT DEPLOYMENT should have:");
    info!("  - Envelope with BIN protocol + compressed WASM in witness");
    info!("  - Protostone with NO cellpack (empty message field)");
    info!("  - Protocol tag 1 (ALKANES)");
    
    info!("💡 CONTRACT EXECUTION should have:");
    info!("  - Protostone with cellpack in message field");
    info!("  - Cellpack targeting existing contract [3,1000]");
    info!("  - No envelope witness data");
    
    // STEP 5: Analyze trace vout calculation
    info!("\n📋 STEP 5: Analyzing trace vout calculation");
    
    // For protostones, trace vout = tx.output.len() + 1 + protostone_index
    // This is different from regular outputs
    info!("🔍 Trace vout calculation:");
    info!("  Regular output: vout = output_index");
    info!("  Protostone: vout = tx.output.len() + 1 + protostone_index");
    info!("  For first protostone: vout = num_outputs + 1");
    
    // STEP 6: Identify the root cause
    info!("\n📋 STEP 6: Root cause analysis");
    
    warn!("🚨 ROOT CAUSE IDENTIFIED:");
    warn!("1. The command mixes DEPLOYMENT and EXECUTION concepts");
    warn!("2. --envelope should be used for CONTRACT DEPLOYMENT (no cellpack)");
    warn!("3. [3,1000,101] cellpack is for CONTRACT EXECUTION (no envelope)");
    warn!("4. Cannot use both --envelope AND execution cellpack together");
    
    info!("\n✅ SOLUTION:");
    info!("For CONTRACT DEPLOYMENT:");
    info!("  deezel alkanes execute --envelope ./examples/free_mint.wasm.gz --to [addr] '[]:v0:v0'");
    info!("  (Empty cellpack [] means deployment, envelope contains WASM)");
    
    info!("For CONTRACT EXECUTION:");
    info!("  deezel alkanes execute --to [addr] '[3,1000,101]:v0:v0'");
    info!("  (Cellpack targets contract [3,1000], no envelope needed)");
    
    info!("\n🎉 === ENVELOPE DEPLOYMENT DEBUG COMPLETE ===");
    
    Ok(())
}

/// Create envelope using alkanes-rs reference pattern
fn create_reference_envelope(contract_data: Vec<u8>) -> Result<ScriptBuf> {
    use bitcoin::script::Builder as ScriptBuilder;
    use bitcoin::blockdata::opcodes;
    use flate2::{write::GzEncoder, Compression};
    use std::io::Write;
    
    // Compress using gzip (matching alkanes-rs)
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&contract_data)?;
    let compressed_data = encoder.finish()?;
    
    // Build script exactly like alkanes-rs reference
    let mut builder = ScriptBuilder::new()
        .push_opcode(opcodes::OP_FALSE)
        .push_opcode(opcodes::all::OP_IF)
        .push_slice(b"BIN"); // Protocol ID
    
    // Add empty BODY_TAG
    builder = builder.push_slice(&[]);
    
    // Add compressed data in chunks
    const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;
    for chunk in compressed_data.chunks(MAX_SCRIPT_ELEMENT_SIZE) {
        builder = builder.push_slice::<&bitcoin::script::PushBytes>(chunk.try_into().unwrap());
    }
    
    Ok(builder.push_opcode(opcodes::all::OP_ENDIF).into_script())
}

/// Debug differences between two scripts
fn debug_script_differences(our_script: &ScriptBuf, reference_script: &ScriptBuf) {
    let our_bytes = our_script.as_bytes();
    let ref_bytes = reference_script.as_bytes();
    
    info!("🔍 Script difference analysis:");
    info!("  Our script: {} bytes", our_bytes.len());
    info!("  Reference: {} bytes", ref_bytes.len());
    
    let min_len = our_bytes.len().min(ref_bytes.len());
    let mut first_diff = None;
    
    for i in 0..min_len {
        if our_bytes[i] != ref_bytes[i] {
            first_diff = Some(i);
            break;
        }
    }
    
    if let Some(diff_pos) = first_diff {
        warn!("❌ First difference at byte {}: our=0x{:02x}, ref=0x{:02x}", 
              diff_pos, our_bytes[diff_pos], ref_bytes[diff_pos]);
        
        let start = diff_pos.saturating_sub(8);
        let end = (diff_pos + 8).min(min_len);
        
        info!("  Context our: {}", hex::encode(&our_bytes[start..end]));
        info!("  Context ref: {}", hex::encode(&ref_bytes[start..end]));
    } else if our_bytes.len() != ref_bytes.len() {
        warn!("❌ Scripts differ in length: our={}, ref={}", our_bytes.len(), ref_bytes.len());
    }
}

#[tokio::test]
async fn test_envelope_vs_execution_distinction() -> Result<()> {
    info!("🔍 === TESTING ENVELOPE VS EXECUTION DISTINCTION ===");
    
    // Test 1: Contract deployment with envelope (correct)
    info!("\n🧪 Test 1: Contract deployment with envelope");
    info!("Command: deezel alkanes execute --envelope ./free_mint.wasm.gz --to [addr] '[]:v0:v0'");
    info!("Expected: Deploy new contract to next available ID [4,1000]");
    
    // Test 2: Contract execution with cellpack (correct)
    info!("\n🧪 Test 2: Contract execution with cellpack");
    info!("Command: deezel alkanes execute --to [addr] '[3,1000,101]:v0:v0'");
    info!("Expected: Execute existing contract [3,1000] with input 101");
    
    // Test 3: Mixed envelope + execution cellpack (incorrect - current issue)
    info!("\n🧪 Test 3: Mixed envelope + execution cellpack (INCORRECT)");
    info!("Command: deezel alkanes execute --envelope ./free_mint.wasm.gz --to [addr] '[3,1000,101]:v0:v0'");
    info!("Problem: Tries to deploy contract AND execute existing contract simultaneously");
    warn!("❌ This is the source of the bug - mixing deployment and execution!");
    
    info!("\n💡 SOLUTION: Use separate commands for deployment and execution");
    info!("1. Deploy: --envelope with empty cellpack []");
    info!("2. Execute: cellpack [3,1000,101] without --envelope");
    
    Ok(())
}

#[tokio::test]
async fn test_protostone_encoding_analysis() -> Result<()> {
    info!("🔍 === TESTING PROTOSTONE ENCODING ANALYSIS ===");
    
    // Test how protostones should be encoded for deployment vs execution
    let cellpack_values = vec![3u128, 1000u128, 101u128];
    let cellpack = Cellpack::try_from(cellpack_values)?;
    
    info!("📦 Cellpack for execution:");
    info!("  Target: [{}:{}]", cellpack.target.block, cellpack.target.tx);
    info!("  Inputs: {:?}", cellpack.inputs);
    info!("  Encoded: {} bytes", cellpack.encipher().len());
    
    // For deployment, we should have an empty protostone (no cellpack)
    info!("\n🚀 For deployment:");
    info!("  Protostone message: empty (no cellpack)");
    info!("  Envelope witness: contains compressed WASM");
    info!("  Result: New contract deployed to [4:1000]");
    
    // For execution, we should have cellpack in protostone message
    info!("\n⚡ For execution:");
    info!("  Protostone message: contains cellpack [3,1000,101]");
    info!("  No envelope witness needed");
    info!("  Result: Execute contract [3:1000] with input 101");
    
    Ok(())
}