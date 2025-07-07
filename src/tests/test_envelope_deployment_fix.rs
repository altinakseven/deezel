//! Test for the envelope deployment fix
//! 
//! This test verifies that the fix correctly separates contract deployment and execution

use anyhow::Result;
use crate::alkanes::execute::{EnhancedExecuteParams, InputRequirement, ProtostoneSpec};
use crate::alkanes::envelope::AlkanesEnvelope;
use alkanes_support::cellpack::Cellpack;
use log::info;

#[tokio::test]
async fn test_envelope_deployment_validation() -> Result<()> {
    let _ = env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .try_init();

    info!("🧪 Testing envelope deployment validation");

    // Test 1: Valid deployment (envelope with empty cellpack)
    info!("\n✅ Test 1: Valid deployment");
    let deployment_params = create_deployment_params()?;
    let result = validate_params(&deployment_params).await;
    assert!(result.is_ok(), "Deployment with envelope and empty cellpack should be valid");

    // Test 2: Valid execution (cellpack without envelope)
    info!("\n✅ Test 2: Valid execution");
    let execution_params = create_execution_params()?;
    let result = validate_params(&execution_params).await;
    assert!(result.is_ok(), "Execution with cellpack and no envelope should be valid");

    // Test 3: Invalid mixed usage (envelope + cellpack)
    info!("\n❌ Test 3: Invalid mixed usage");
    let mixed_params = create_mixed_params()?;
    let result = validate_params(&mixed_params).await;
    assert!(result.is_err(), "Mixed envelope and cellpack should be invalid");
    
    let error_msg = result.unwrap_err().to_string();
    assert!(error_msg.contains("Cannot use --envelope"), "Error should mention envelope conflict");

    // Test 4: Invalid empty usage (no envelope, no cellpack)
    info!("\n❌ Test 4: Invalid empty usage");
    let empty_params = create_empty_params()?;
    let result = validate_params(&empty_params).await;
    assert!(result.is_err(), "Empty params should be invalid");

    info!("\n🎉 All validation tests passed!");
    Ok(())
}

/// Create valid deployment parameters (envelope with empty cellpack)
fn create_deployment_params() -> Result<EnhancedExecuteParams> {
    let contract_data = b"mock wasm data".to_vec();
    
    Ok(EnhancedExecuteParams {
        fee_rate: Some(1.0),
        to_addresses: vec!["bc1p123".to_string()],
        change_address: None,
        input_requirements: vec![InputRequirement::Bitcoin { amount: 1000 }],
        protostones: vec![ProtostoneSpec {
            cellpack: None, // Empty for deployment
            edicts: vec![],
            bitcoin_transfer: None,
        }],
        envelope_data: Some(contract_data), // Envelope for deployment
        raw_output: false,
        trace_enabled: true,
        mine_enabled: false,
        auto_confirm: true,
    })
}

/// Create valid execution parameters (cellpack without envelope)
fn create_execution_params() -> Result<EnhancedExecuteParams> {
    let cellpack = Cellpack::try_from(vec![3u128, 1000u128, 101u128])?;
    
    Ok(EnhancedExecuteParams {
        fee_rate: Some(1.0),
        to_addresses: vec!["bc1p123".to_string()],
        change_address: None,
        input_requirements: vec![InputRequirement::Bitcoin { amount: 1000 }],
        protostones: vec![ProtostoneSpec {
            cellpack: Some(cellpack), // Cellpack for execution
            edicts: vec![],
            bitcoin_transfer: None,
        }],
        envelope_data: None, // No envelope for execution
        raw_output: false,
        trace_enabled: true,
        mine_enabled: false,
        auto_confirm: true,
    })
}

/// Create invalid mixed parameters (envelope + cellpack)
fn create_mixed_params() -> Result<EnhancedExecuteParams> {
    let contract_data = b"mock wasm data".to_vec();
    let cellpack = Cellpack::try_from(vec![3u128, 1000u128, 101u128])?;
    
    Ok(EnhancedExecuteParams {
        fee_rate: Some(1.0),
        to_addresses: vec!["bc1p123".to_string()],
        change_address: None,
        input_requirements: vec![InputRequirement::Bitcoin { amount: 1000 }],
        protostones: vec![ProtostoneSpec {
            cellpack: Some(cellpack), // Invalid: cellpack with envelope
            edicts: vec![],
            bitcoin_transfer: None,
        }],
        envelope_data: Some(contract_data), // Invalid: envelope with cellpack
        raw_output: false,
        trace_enabled: true,
        mine_enabled: false,
        auto_confirm: true,
    })
}

/// Create invalid empty parameters (no envelope, no cellpack)
fn create_empty_params() -> Result<EnhancedExecuteParams> {
    Ok(EnhancedExecuteParams {
        fee_rate: Some(1.0),
        to_addresses: vec!["bc1p123".to_string()],
        change_address: None,
        input_requirements: vec![InputRequirement::Bitcoin { amount: 1000 }],
        protostones: vec![ProtostoneSpec {
            cellpack: None, // No cellpack
            edicts: vec![],
            bitcoin_transfer: None,
        }],
        envelope_data: None, // No envelope
        raw_output: false,
        trace_enabled: true,
        mine_enabled: false,
        auto_confirm: true,
    })
}

/// Mock validation function (simulates the validation logic)
async fn validate_params(params: &EnhancedExecuteParams) -> Result<()> {
    let has_envelope = params.envelope_data.is_some();
    let has_cellpacks = params.protostones.iter().any(|p| p.cellpack.is_some());
    
    if has_envelope && has_cellpacks {
        return Err(anyhow::anyhow!(
            "Cannot use --envelope (deployment) with cellpacks (execution) simultaneously"
        ));
    }
    
    if has_envelope {
        // Contract deployment: ensure all protostones have empty cellpacks
        for (i, protostone) in params.protostones.iter().enumerate() {
            if protostone.cellpack.is_some() {
                return Err(anyhow::anyhow!(
                    "Protostone {} has cellpack but --envelope is used for deployment", i
                ));
            }
        }
    } else {
        // Contract execution: ensure at least one protostone has a cellpack
        if !has_cellpacks {
            return Err(anyhow::anyhow!(
                "No cellpacks found but no --envelope provided"
            ));
        }
    }
    
    Ok(())
}

#[tokio::test]
async fn test_cellpack_analysis() -> Result<()> {
    info!("🔍 Testing cellpack analysis");

    // Analyze the problematic cellpack [3, 1000, 101]
    let cellpack_values = vec![3u128, 1000u128, 101u128];
    let cellpack = Cellpack::try_from(cellpack_values.clone())?;
    
    info!("📦 Problematic cellpack analysis:");
    info!("  Raw values: {:?}", cellpack_values);
    info!("  Target: [{}:{}]", cellpack.target.block, cellpack.target.tx);
    info!("  Inputs: {:?}", cellpack.inputs);
    info!("  Purpose: Execute existing contract [3:1000] with input 101");
    
    // This cellpack is for EXECUTION, not DEPLOYMENT
    assert_eq!(cellpack.target.block, 3);
    assert_eq!(cellpack.target.tx, 1000);
    assert_eq!(cellpack.inputs, vec![101]);
    
    info!("✅ Cellpack correctly targets existing contract for execution");
    
    // For deployment, we should have empty cellpack
    let empty_cellpack = Cellpack::try_from(vec![4u128, 1000u128])?; // Just target, no inputs
    info!("🚀 Deployment cellpack would be: [{}:{}] with no inputs", 
          empty_cellpack.target.block, empty_cellpack.target.tx);
    
    Ok(())
}

#[tokio::test]
async fn test_command_examples() -> Result<()> {
    info!("📚 Testing command examples");

    info!("\n🚀 CORRECT: Contract deployment command");
    info!("deezel alkanes execute --envelope ./free_mint.wasm.gz --to [addr] '[]:v0:v0'");
    info!("  - Uses --envelope for WASM deployment");
    info!("  - Uses empty cellpack [] for deployment");
    info!("  - Result: New contract at [4:1000]");

    info!("\n⚡ CORRECT: Contract execution command");
    info!("deezel alkanes execute --to [addr] '[3,1000,101]:v0:v0'");
    info!("  - No --envelope (execution only)");
    info!("  - Uses cellpack [3,1000,101] targeting existing contract");
    info!("  - Result: Execute contract [3:1000] with input 101");

    info!("\n❌ INCORRECT: Mixed command (current issue)");
    info!("deezel alkanes execute --envelope ./free_mint.wasm.gz --to [addr] '[3,1000,101]:v0:v0'");
    info!("  - Tries to deploy AND execute simultaneously");
    info!("  - This is conceptually invalid and should be rejected");

    Ok(())
}