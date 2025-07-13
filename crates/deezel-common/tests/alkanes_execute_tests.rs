//! tests for the enhanced alkanes executor

use super::*;
use crate::alkanes::execute::{EnhancedAlkanesExecutor, EnhancedExecuteParams, InputRequirement, ProtostoneSpec};
use crate::provider::MockDeezelProvider;
use anyhow::Result;
use async_trait::async_trait;
use std::sync::{Arc, Mutex};

#[tokio::test]
async fn test_execute_single_transaction_flow() -> Result<()> {
    let mut mock_provider = MockDeezelProvider::new();

    // Setup mock expectations
    mock_provider
        .expect_get_network()
        .returning(|| bitcoin::Network::Regtest);
    mock_provider
        .expect_validate_protostones()
        .returning(|_| Ok(()));
    mock_provider
        .expect_select_utxos()
        .returning(|_, _| Ok(vec![]));
    mock_provider
        .expect_construct_runestone()
        .returning(|_| Ok(None));
    mock_provider
        .expect_build_transaction()
        .returning(|_, _, _, _, _| Ok(("dummy_psbt".to_string(), 1000)));
    mock_provider
        .expect_sign_transaction()
        .returning(|_| Ok("dummy_signed_tx".to_string()));
    mock_provider
        .expect_broadcast()
        .returning(|_| Ok("dummy_txid".to_string()));

    let executor = EnhancedAlkanesExecutor::new(&mock_provider);

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

    let result = executor.execute(params).await?;

    assert!(result.commit_txid.is_none());
    assert_eq!(result.reveal_txid.unwrap(), "dummy_txid");
    assert!(result.commit_fee.is_none());
    assert_eq!(result.reveal_fee.unwrap(), 1000);

    Ok(())
}