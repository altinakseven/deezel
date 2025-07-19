//! E2E integration tests for deezel CLI
//!
//! This module contains comprehensive end-to-end tests that simulate
//! real-world user workflows using the deezel CLI against a mock
//! backend environment.

use super::e2e_helpers::{E2ETestScenario, TestStep};
use super::TestConfig;
use anyhow::Result;

/// E2E test for deploying an AMM contract and verifying its deployment.
///
/// This test simulates the following user workflow:
/// 1. Creates a new, encrypted wallet with a known passphrase.
/// 2. Builds the smart contracts.
/// 3. Generates blocks to fund the wallet.
/// 4. Deploys the AMM contract using the `--wallet-passphrase` for non-interactive execution.
/// 5. Extracts the new `alkane_id` from the `deploy` command's output.
/// 6. Uses the `alkane_id` to run `alkanes token-info` and verify the contract exists.
#[tokio::test]
async fn e2e_deploy_amm_and_verify() -> Result<()> {
    let config = TestConfig::default();
    let scenario = E2ETestScenario::new(config).await?
        .step(TestStep::CreateWallet {
            name: "test_wallet".to_string(),
            passphrase: Some("test_passphrase".to_string()),
        })
        .step(TestStep::GetNewAddress)
        .step(TestStep::RunCommand {
            args: vec!["build-contracts".to_string()],
            expect_success: true,
            extract_alkane_id: false,
        })
        .step(TestStep::RunCommand {
            args: vec![
                "bitcoind".to_string(),
                "generatetoaddress".to_string(),
                "101".to_string(),
                "<generated_address>".to_string(),
            ],
            expect_success: true,
            extract_alkane_id: false,
        })
        .step(TestStep::RunCommand {
            args: vec![
                "--wallet-passphrase".to_string(),
                "test_passphrase".to_string(),
                "deploy".to_string(),
                "amm".to_string(),
                "--yes".to_string(),
            ],
            expect_success: true,
            extract_alkane_id: true,
        })
        .step(TestStep::RunCommand {
            args: vec![
                "alkanes".to_string(),
                "token-info".to_string(),
                "<alkane_id>".to_string(), // Placeholder will be replaced
            ],
            expect_success: true,
            extract_alkane_id: false,
        });

    scenario.execute().await
}