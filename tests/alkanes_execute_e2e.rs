//! E2E tests for the `alkanes execute` command, focusing on dust outputs and --from-addresses flag.

use anyhow::Result;
use tokio;

use super::e2e_helpers::{E2ETestScenario, TestStep};
use super::mock_metashrew::create_test_utxos;
use crate::tests::TestConfig;

/// Test case for the "dust" output fix.
/// Verifies that `alkanes execute` with only a `to_address` creates a valid transaction.
#[tokio::test]
async fn test_alkanes_execute_dust_output() -> Result<()> {
    let config = TestConfig {
        rpc_port: 18091, // Use a unique port for this test
        ..Default::default()
    };

    let mut scenario = E2ETestScenario::new(config).await?
        .step(TestStep::CreateWallet { name: "dust_fix_wallet".to_string() });

    let from_address = scenario.get_new_address().await?;
    let to_address = scenario.get_new_address().await?;
    let test_utxos = create_test_utxos(&from_address, 1);

    scenario
        .step(TestStep::AddUtxos { address: from_address.clone(), utxos: test_utxos })
        .step(TestStep::RunCommand {
            args: vec![
                "alkanes".to_string(),
                "execute".to_string(),
                "--to-addresses".to_string(),
                to_address,
                "--auto-confirm".to_string(),
            ],
            expect_success: true,
        })
        .execute()
        .await
}

/// Test that `--from-addresses` correctly sources UTXOs.
#[tokio::test]
async fn test_alkanes_execute_from_address_success() -> Result<()> {
    let config = TestConfig {
        rpc_port: 18092,
        ..Default::default()
    };

    let mut scenario = E2ETestScenario::new(config).await?
        .step(TestStep::CreateWallet { name: "from_addr_wallet".to_string() });

    let address_a = scenario.get_new_address().await?;
    let address_b = scenario.get_new_address().await?;
    let to_address = scenario.get_new_address().await?;

    scenario
        .step(TestStep::AddUtxos { address: address_a.clone(), utxos: create_test_utxos(&address_a, 1) })
        .step(TestStep::AddUtxos { address: address_b.clone(), utxos: create_test_utxos(&address_b, 1) })
        .step(TestStep::RunCommand {
            args: vec![
                "alkanes".to_string(),
                "execute".to_string(),
                "--to-addresses".to_string(),
                to_address,
                "--from-addresses".to_string(),
                address_a,
                "--auto-confirm".to_string(),
            ],
            expect_success: true,
        })
        .execute()
        .await
}

/// Test that the command fails if `--from-addresses` has insufficient funds.
#[tokio::test]
async fn test_alkanes_execute_from_address_failure() -> Result<()> {
    let config = TestConfig {
        rpc_port: 18093,
        ..Default::default()
    };

    let mut scenario = E2ETestScenario::new(config).await?
        .step(TestStep::CreateWallet { name: "from_addr_fail_wallet".to_string() });

    let address_a = scenario.get_new_address().await?;
    let address_b = scenario.get_new_address().await?;
    let to_address = scenario.get_new_address().await?;

    scenario
        .step(TestStep::AddUtxos { address: address_a, utxos: create_test_utxos(&address_a, 1) })
        .step(TestStep::RunCommand {
            args: vec![
                "alkanes".to_string(),
                "execute".to_string(),
                "--to-addresses".to_string(),
                to_address,
                "--from-addresses".to_string(),
                address_b,
                "--auto-confirm".to_string(),
            ],
            expect_success: false,
        })
        .execute()
        .await
}

/// Test that the wallet uses any available UTXOs when `--from-addresses` is omitted.
#[tokio::test]
async fn test_alkanes_execute_without_from_address() -> Result<()> {
    let config = TestConfig {
        rpc_port: 18094,
        ..Default::default()
    };

    let mut scenario = E2ETestScenario::new(config).await?
        .step(TestStep::CreateWallet { name: "no_from_addr_wallet".to_string() });

    let address_a = scenario.get_new_address().await?;
    let address_b = scenario.get_new_address().await?;
    let to_address = scenario.get_new_address().await?;

    scenario
        .step(TestStep::AddUtxos { address: address_a.clone(), utxos: create_test_utxos(&address_a, 1) })
        .step(TestStep::AddUtxos { address: address_b.clone(), utxos: create_test_utxos(&address_b, 1) })
        .step(TestStep::RunCommand {
            args: vec![
                "alkanes".to_string(),
                "execute".to_string(),
                "--to-addresses".to_string(),
                to_address,
                "--auto-confirm".to_string(),
            ],
            expect_success: true,
        })
        .execute()
        .await
}


/// Test case for the user-reported dust error in a commit/reveal transaction.
#[tokio::test]
async fn test_alkanes_execute_commit_reveal_dust_error() -> Result<()> {
    let config = TestConfig {
        rpc_port: 18095,
        ..Default::default()
    };

    let mut scenario = E2ETestScenario::new(config).await?
        .step(TestStep::CreateWallet { name: "commit_reveal_dust_wallet".to_string() });

    let from_address = scenario.get_new_address().await?;
    let to_address = scenario.get_new_address().await?;
    let change_address = scenario.get_new_address().await?;
    let test_utxos = create_test_utxos(&from_address, 5); // 5 UTXOs of 100,000 sats

    scenario
        .step(TestStep::AddUtxos { address: from_address.clone(), utxos: test_utxos })
        .step(TestStep::RunCommand {
            args: vec![
                "alkanes".to_string(),
                "execute".to_string(),
                "--envelope".to_string(),
                "tests/dummy_envelope.wasm".to_string(),
                "--to-addresses".to_string(),
                to_address,
                "--change-address".to_string(),
                change_address,
                "--protostones".to_string(),
                "'[3,797,101]:v0:v0,B:9000:v0'".to_string(),
                "--input-requirements".to_string(),
                "'B:10000'".to_string(),
                "--from-addresses".to_string(),
                from_address,
                "--auto-confirm".to_string(),
            ],
            expect_success: true, // This should now succeed
        })
        .execute()
        .await
}
