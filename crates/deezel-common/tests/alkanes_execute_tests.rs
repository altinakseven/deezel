//! tests for the enhanced alkanes executor

#[path = "mock_provider.rs"]
mod mock_provider;

use deezel_common::alkanes::execute::{EnhancedAlkanesExecutor, EnhancedExecuteParams};
use deezel_common::alkanes::types::EnhancedExecuteResult;
use mock_provider::MockProvider;
use anyhow::Result;

use serde_json::json;

#[tokio::test]
async fn test_execute_single_transaction_flow() -> Result<()> {
    // 1. Setup the mock provider with a canned response
    let mock_response = EnhancedExecuteResult {
        commit_txid: None,
        reveal_txid: "dummy_txid".to_string(),
        commit_fee: None,
        reveal_fee: 1000,
        inputs_used: vec![],
        outputs_created: vec![],
        traces: None,
    };
    let mock_provider = MockProvider::new()
        .with_response("alkanes_execute", json!(mock_response));

    // 2. Create the executor with the mock provider
    let executor = EnhancedAlkanesExecutor::new(&mock_provider);

    // 3. Define the parameters for the execute call
    let params = EnhancedExecuteParams {
        fee_rate: Some(1.0),
        to_addresses: vec!["bcrt1q...".to_string()],
        change_address: None,
        input_requirements: vec![],
        protostones: vec![],
        envelope_data: None,
        raw_output: false,
        trace_enabled: false,
        mine_enabled: false,
        auto_confirm: true,
    };

    // 4. Execute the call
    let result = executor.execute(params).await?;

    // 5. Assert the results match the canned response
    assert!(result.commit_txid.is_none());
    assert_eq!(result.reveal_txid, "dummy_txid");
    assert!(result.commit_fee.is_none());
    assert_eq!(result.reveal_fee, 1000);

    Ok(())
}