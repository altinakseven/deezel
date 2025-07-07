//! Integration tests for deezel CLI with mock metashrew
//!
//! These tests demonstrate end-to-end functionality of the deezel CLI
//! using the mock metashrew server implementation.

use tokio;


/// Test basic wallet operations
#[tokio::test]
async fn test_wallet_operations() -> Result<()> {
    let config = TestConfig {
        start_height: 840000,
        network: "regtest".to_string(),
        rpc_port: 18081,
        debug: true,
    };

    E2ETestScenario::new(config).await?
        .step(TestStep::CreateWallet { 
            name: "test_wallet".to_string() 
        })
        .step(TestStep::RunCommand { 
            args: vec!["wallet".to_string(), "list".to_string()], 
            expect_success: true 
        })
        .step(TestStep::RunCommand { 
            args: vec!["wallet".to_string(), "info".to_string(), "test_wallet".to_string()], 
            expect_success: true 
        })
        .execute()
        .await
}

/// Test DIESEL balance checking
#[tokio::test]
async fn test_diesel_balance_check() -> Result<()> {
    let config = TestConfig {
        start_height: 840000,
        network: "regtest".to_string(),
        rpc_port: 18082,
        debug: true,
    };

    let test_address = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

    E2ETestScenario::new(config).await?
        .step(TestStep::CreateWallet { 
            name: "diesel_wallet".to_string() 
        })
        .step(TestStep::AddDieselBalance { 
            address: test_address.to_string(), 
            amount: 100000000 // 1 DIESEL
        })
        .step(TestStep::RunCommand { 
            args: vec![
                "balance".to_string(), 
                "--address".to_string(), 
                test_address.to_string()
            ], 
            expect_success: true 
        })
        .execute()
        .await
}

/// Test UTXO listing
#[tokio::test]
async fn test_utxo_listing() -> Result<()> {
    let config = TestConfig {
        start_height: 840000,
        network: "regtest".to_string(),
        rpc_port: 18083,
        debug: true,
    };

    let test_address = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
    let test_utxos = create_test_utxos(test_address, 3); // 3 UTXOs of varying amounts

    E2ETestScenario::new(config).await?
        .step(TestStep::CreateWallet { 
            name: "utxo_wallet".to_string() 
        })
        .step(TestStep::AddUtxos { 
            address: test_address.to_string(), 
            utxos: test_utxos 
        })
        .step(TestStep::RunCommand { 
            args: vec![
                "utxos".to_string(), 
                "--address".to_string(), 
                test_address.to_string()
            ], 
            expect_success: true 
        })
        .execute()
        .await
}

/// Test DIESEL minting simulation
#[tokio::test]
async fn test_diesel_minting() -> Result<()> {
    let config = TestConfig {
        start_height: 840000,
        network: "regtest".to_string(),
        rpc_port: 18084,
        debug: true,
    };

    let test_address = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
    let test_utxos = create_test_utxos(test_address, 1); // 1 UTXO

    E2ETestScenario::new(config).await?
        .step(TestStep::CreateWallet { 
            name: "mint_wallet".to_string() 
        })
        .step(TestStep::AddUtxos { 
            address: test_address.to_string(), 
            utxos: test_utxos 
        })
        .step(TestStep::SetHeight { height: 840001 })
        .step(TestStep::RunCommand { 
            args: vec![
                "mint".to_string(),
                "--address".to_string(), 
                test_address.to_string(),
                "--amount".to_string(),
                "50000000".to_string(), // 0.5 DIESEL
                "--dry-run".to_string() // Don't actually broadcast
            ], 
            expect_success: true 
        })
        .execute()
        .await
}

/// Test transaction monitoring
#[tokio::test]
async fn test_transaction_monitoring() -> Result<()> {
    let config = TestConfig {
        start_height: 840000,
        network: "regtest".to_string(),
        rpc_port: 18085,
        debug: true,
    };

    E2ETestScenario::new(config).await?
        .step(TestStep::CreateWallet { 
            name: "monitor_wallet".to_string() 
        })
        .step(TestStep::SetHeight { height: 840005 })
        .step(TestStep::RunCommand { 
            args: vec![
                "monitor".to_string(),
                "--start-height".to_string(),
                "840000".to_string(),
                "--end-height".to_string(),
                "840005".to_string()
            ], 
            expect_success: true 
        })
        .execute()
        .await
}

/// Test RPC connectivity
#[tokio::test]
async fn test_rpc_connectivity() -> Result<()> {
    let config = TestConfig {
        start_height: 840000,
        network: "regtest".to_string(),
        rpc_port: 18086,
        debug: true,
    };

    E2ETestScenario::new(config).await?
        .step(TestStep::RunCommand { 
            args: vec![
                "status".to_string()
            ], 
            expect_success: true 
        })
        .execute()
        .await
}

/// Test error handling with invalid commands
#[tokio::test]
async fn test_error_handling() -> Result<()> {
    let config = TestConfig {
        start_height: 840000,
        network: "regtest".to_string(),
        rpc_port: 18087,
        debug: true,
    };

    E2ETestScenario::new(config).await?
        .step(TestStep::RunCommand { 
            args: vec![
                "invalid-command".to_string()
            ], 
            expect_success: false // Expect this to fail
        })
        .step(TestStep::RunCommand { 
            args: vec![
                "balance".to_string(),
                "--address".to_string(),
                "invalid-address".to_string()
            ], 
            expect_success: false // Expect this to fail
        })
        .execute()
        .await
}

/// Test comprehensive DIESEL workflow
#[tokio::test]
async fn test_comprehensive_diesel_workflow() -> Result<()> {
    let config = TestConfig {
        start_height: 840000,
        network: "regtest".to_string(),
        rpc_port: 18088,
        debug: true,
    };

    let test_address = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
    let test_utxos = create_test_utxos(test_address, 2); // 2 UTXOs

    E2ETestScenario::new(config).await?
        // Setup
        .step(TestStep::CreateWallet { 
            name: "comprehensive_wallet".to_string() 
        })
        .step(TestStep::AddUtxos { 
            address: test_address.to_string(), 
            utxos: test_utxos 
        })
        .step(TestStep::SetHeight { height: 840001 })
        
        // Check initial state
        .step(TestStep::RunCommand { 
            args: vec![
                "status".to_string()
            ], 
            expect_success: true 
        })
        .step(TestStep::RunCommand { 
            args: vec![
                "balance".to_string(),
                "--address".to_string(), 
                test_address.to_string()
            ], 
            expect_success: true 
        })
        .step(TestStep::RunCommand { 
            args: vec![
                "utxos".to_string(),
                "--address".to_string(), 
                test_address.to_string()
            ], 
            expect_success: true 
        })
        
        // Simulate DIESEL minting
        .step(TestStep::RunCommand { 
            args: vec![
                "mint".to_string(),
                "--address".to_string(), 
                test_address.to_string(),
                "--amount".to_string(),
                "50000000".to_string(), // 0.5 DIESEL
                "--dry-run".to_string()
            ], 
            expect_success: true 
        })
        
        // Add some DIESEL balance and check again
        .step(TestStep::AddDieselBalance { 
            address: test_address.to_string(), 
            amount: 50000000 // 0.5 DIESEL
        })
        .step(TestStep::RunCommand { 
            args: vec![
                "balance".to_string(),
                "--address".to_string(), 
                test_address.to_string()
            ], 
            expect_success: true 
        })
        
        // Monitor recent blocks
        .step(TestStep::RunCommand { 
            args: vec![
                "monitor".to_string(),
                "--start-height".to_string(),
                "840000".to_string(),
                "--end-height".to_string(),
                "840001".to_string()
            ], 
            expect_success: true 
        })
        
        .execute()
        .await
}

/// Test concurrent operations
#[tokio::test]
async fn test_concurrent_operations() -> Result<()> {
    let config = TestConfig {
        start_height: 840000,
        network: "regtest".to_string(),
        rpc_port: 18089,
        debug: true,
    };

    let test_address1 = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
    let test_address2 = "bcrt1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3";
    
    let test_utxos1 = create_test_utxos(test_address1, 1);
    let test_utxos2 = create_test_utxos(test_address2, 1);

    E2ETestScenario::new(config).await?
        .step(TestStep::CreateWallet { 
            name: "concurrent_wallet".to_string() 
        })
        .step(TestStep::AddUtxos { 
            address: test_address1.to_string(), 
            utxos: test_utxos1 
        })
        .step(TestStep::AddUtxos { 
            address: test_address2.to_string(), 
            utxos: test_utxos2 
        })
        .step(TestStep::AddDieselBalance { 
            address: test_address1.to_string(), 
            amount: 25000000 
        })
        .step(TestStep::AddDieselBalance { 
            address: test_address2.to_string(), 
            amount: 75000000 
        })
        
        // Check balances for both addresses
        .step(TestStep::RunCommand { 
            args: vec![
                "balance".to_string(),
                "--address".to_string(), 
                test_address1.to_string()
            ], 
            expect_success: true 
        })
        .step(TestStep::RunCommand { 
            args: vec![
                "balance".to_string(),
                "--address".to_string(), 
                test_address2.to_string()
            ], 
            expect_success: true 
        })
        
        .execute()
        .await
}

/// Test performance with many UTXOs
#[tokio::test]
async fn test_performance_many_utxos() -> Result<()> {
    let config = TestConfig {
        start_height: 840000,
        network: "regtest".to_string(),
        rpc_port: 18090,
        debug: false, // Disable debug for performance test
    };

    let test_address = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
    let test_utxos = create_test_utxos(test_address, 100); // 100 UTXOs

    E2ETestScenario::new(config).await?
        .step(TestStep::CreateWallet { 
            name: "performance_wallet".to_string() 
        })
        .step(TestStep::AddUtxos { 
            address: test_address.to_string(), 
            utxos: test_utxos 
        })
        .step(TestStep::RunCommand { 
            args: vec![
                "utxos".to_string(),
                "--address".to_string(), 
                test_address.to_string()
            ], 
            expect_success: true 
        })
        .step(TestStep::RunCommand { 
            args: vec![
                "balance".to_string(),
                "--address".to_string(), 
                test_address.to_string()
            ], 
            expect_success: true 
        })
        .execute()
        .await
}

#[cfg(test)]
mod test_helpers {
    use super::*;
    
    /// Helper to run a quick test scenario
    pub async fn run_quick_test(port: u16, steps: Vec<TestStep>) -> Result<()> {
        let config = TestConfig {
            start_height: 840000,
            network: "regtest".to_string(),
            rpc_port: port,
            debug: true,
        };

        let mut scenario = E2ETestScenario::new(config).await?;
        for step in steps {
            scenario = scenario.step(step);
        }
        scenario.execute().await
    }
}