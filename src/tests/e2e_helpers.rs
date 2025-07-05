//! End-to-end testing helpers for deezel CLI
//!
//! This module provides utilities for running complete e2e tests of the deezel CLI
//! with mock metashrew and Bitcoin RPC servers.

use anyhow::{Result, anyhow};
use std::process::{Command, Stdio};
use std::time::Duration;
use tokio::time::sleep;
use log::{info, debug, error};
use std::path::PathBuf;
use std::fs;
use tempfile::TempDir;

use super::{
    TestConfig, TestState, init_test_state, get_test_state,
    mock_metashrew::{MockMetashrewServer, add_mock_utxos, add_mock_protorune_balance, set_mock_height},
    test_blocks::{create_test_utxos, setup_test_blockchain},
    MockUtxo,
};

/// E2E test environment
pub struct E2ETestEnv {
    /// Test configuration
    pub config: TestConfig,
    /// Mock metashrew server
    pub metashrew_server: Option<MockMetashrewServer>,
    /// Temporary directory for test files
    pub temp_dir: TempDir,
    /// Test wallet directory
    pub wallet_dir: PathBuf,
    /// Test state
    pub state: std::sync::Arc<std::sync::Mutex<TestState>>,
}

impl E2ETestEnv {
    /// Create a new e2e test environment
    pub async fn new(config: TestConfig) -> Result<Self> {
        info!("Setting up E2E test environment");
        
        // Initialize test state
        let state = init_test_state(config.clone())?;
        
        // Create temporary directory for test files
        let temp_dir = tempfile::tempdir()
            .map_err(|e| anyhow!("Failed to create temp directory: {}", e))?;
        
        let wallet_dir = temp_dir.path().join("wallet");
        fs::create_dir_all(&wallet_dir)
            .map_err(|e| anyhow!("Failed to create wallet directory: {}", e))?;
        
        Ok(Self {
            config,
            metashrew_server: None,
            temp_dir,
            wallet_dir,
            state,
        })
    }
    
    /// Start the mock metashrew server
    pub async fn start_metashrew_server(&mut self) -> Result<()> {
        info!("Starting mock metashrew server on port {}", self.config.rpc_port);
        
        let server = MockMetashrewServer::new(self.config.rpc_port)?;
        
        // Start server in background task
        let server_handle = server.clone();
        tokio::spawn(async move {
            if let Err(e) = server_handle.start().await {
                error!("Mock metashrew server error: {}", e);
            }
        });
        
        self.metashrew_server = Some(server);
        
        // Wait a bit for server to start
        sleep(Duration::from_millis(100)).await;
        
        info!("Mock metashrew server started");
        Ok(())
    }
    
    /// Setup test blockchain with blocks and UTXOs
    pub async fn setup_blockchain(&self, num_blocks: u32) -> Result<()> {
        info!("Setting up test blockchain with {} blocks", num_blocks);
        
        setup_test_blockchain(self.config.start_height, num_blocks)?;
        
        info!("Test blockchain setup complete");
        Ok(())
    }
    
    /// Add test UTXOs for an address
    pub fn add_test_utxos(&self, address: &str, utxos: Vec<MockUtxo>) -> Result<()> {
        debug!("Adding {} test UTXOs for address {}", utxos.len(), address);
        add_mock_utxos(address, utxos)
    }
    
    /// Add test DIESEL balance for an address
    pub fn add_test_diesel_balance(&self, address: &str, amount: u64) -> Result<()> {
        debug!("Adding {} DIESEL balance for address {}", amount, address);
        add_mock_protorune_balance(address, "2:0", amount) // DIESEL rune ID
    }
    
    /// Set the current block height
    pub fn set_block_height(&self, height: u32) -> Result<()> {
        debug!("Setting block height to {}", height);
        set_mock_height(height)
    }
    
    /// Create a test wallet
    pub async fn create_test_wallet(&self, wallet_name: &str) -> Result<PathBuf> {
        let wallet_path = self.wallet_dir.join(format!("{}.wallet", wallet_name));
        
        info!("Creating test wallet at {:?}", wallet_path);
        
        // Create a simple wallet file for testing
        let wallet_data = serde_json::json!({
            "version": 1,
            "network": self.config.network,
            "created_at": chrono::Utc::now().timestamp(),
            "descriptor": "wpkh([00000000/84'/1'/0']tpubD6NzVbkrYhZ4XgiXtGrdW5XDAPFCL9h7we1vwNCpn8tGbBcgfVYjXyhWo4E1xkh56hjod1RhGjxbaTLV3X4FyWuejifB9jusQ46QzG87VKp/0/*)#rhhth4s9"
        });
        
        fs::write(&wallet_path, wallet_data.to_string())
            .map_err(|e| anyhow!("Failed to create wallet file: {}", e))?;
        
        Ok(wallet_path)
    }
    
    /// Run deezel CLI command
    pub async fn run_deezel_command(&self, args: &[&str]) -> Result<DeezelCommandResult> {
        let deezel_binary = self.find_deezel_binary()?;
        
        debug!("Running deezel command: {:?} with args: {:?}", deezel_binary, args);
        
        let mut cmd = Command::new(deezel_binary);
        cmd.args(args);
        
        // Set environment variables for test configuration
        // FIXED: Use Sandshrew RPC for both Bitcoin and Metashrew operations
        let sandshrew_rpc_url = format!("http://localhost:{}", self.config.rpc_port);
        cmd.env("DEEZEL_BITCOIN_RPC_URL", &sandshrew_rpc_url);
        cmd.env("DEEZEL_METASHREW_RPC_URL", &sandshrew_rpc_url);
        
        // Journal: Updated test environment to use consistent Sandshrew RPC endpoint
        // for both Bitcoin and Metashrew operations to avoid network mismatch issues
        cmd.env("DEEZEL_WALLET_DIR", &self.wallet_dir);
        
        if self.config.debug {
            cmd.env("RUST_LOG", "debug");
        }
        
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        
        let output = cmd.output()
            .map_err(|e| anyhow!("Failed to execute deezel command: {}", e))?;
        
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        
        debug!("Command output - stdout: {}, stderr: {}", stdout, stderr);
        
        Ok(DeezelCommandResult {
            success: output.status.success(),
            exit_code: output.status.code().unwrap_or(-1),
            stdout,
            stderr,
        })
    }
    
    /// Find the deezel binary
    fn find_deezel_binary(&self) -> Result<PathBuf> {
        // Try to find the binary in target directory
        let possible_paths = [
            "target/debug/deezel",
            "target/release/deezel",
            "./target/debug/deezel",
            "./target/release/deezel",
            "deezel", // In PATH
        ];
        
        for path in &possible_paths {
            let path_buf = PathBuf::from(path);
            if path_buf.exists() || path == &"deezel" {
                return Ok(path_buf);
            }
        }
        
        Err(anyhow!("Could not find deezel binary. Make sure it's built with 'cargo build'"))
    }
    
    /// Wait for metashrew server to be ready
    pub async fn wait_for_metashrew_ready(&self) -> Result<()> {
        let client = reqwest::Client::new();
        let url = format!("http://localhost:{}", self.config.rpc_port);
        
        for attempt in 1..=10 {
            debug!("Checking if metashrew server is ready (attempt {})", attempt);
            
            let request = serde_json::json!({
                "jsonrpc": "2.0",
                "method": "metashrew_height",
                "params": [],
                "id": 1
            });
            
            match client.post(&url)
                .header("Content-Type", "application/json")
                .json(&request)
                .send()
                .await
            {
                Ok(response) if response.status().is_success() => {
                    info!("Metashrew server is ready");
                    return Ok(());
                }
                Ok(_) => {
                    debug!("Metashrew server returned error status");
                }
                Err(e) => {
                    debug!("Failed to connect to metashrew server: {}", e);
                }
            }
            
            sleep(Duration::from_millis(500)).await;
        }
        
        Err(anyhow!("Metashrew server did not become ready within timeout"))
    }
}

/// Result of running a deezel CLI command
#[derive(Debug, Clone)]
pub struct DeezelCommandResult {
    /// Whether the command succeeded
    pub success: bool,
    /// Exit code
    pub exit_code: i32,
    /// Standard output
    pub stdout: String,
    /// Standard error
    pub stderr: String,
}

impl DeezelCommandResult {
    /// Check if the command was successful
    pub fn is_success(&self) -> bool {
        self.success
    }
    
    /// Get the output as a string
    pub fn output(&self) -> &str {
        &self.stdout
    }
    
    /// Get the error output as a string
    pub fn error(&self) -> &str {
        &self.stderr
    }
    
    /// Assert that the command was successful
    pub fn assert_success(&self) -> Result<&Self> {
        if !self.success {
            return Err(anyhow!(
                "Command failed with exit code {}: {}",
                self.exit_code,
                self.stderr
            ));
        }
        Ok(self)
    }
    
    /// Assert that the output contains a specific string
    pub fn assert_output_contains(&self, expected: &str) -> Result<&Self> {
        if !self.stdout.contains(expected) {
            return Err(anyhow!(
                "Output does not contain '{}'. Actual output: {}",
                expected,
                self.stdout
            ));
        }
        Ok(self)
    }
    
    /// Assert that the error contains a specific string
    pub fn assert_error_contains(&self, expected: &str) -> Result<&Self> {
        if !self.stderr.contains(expected) {
            return Err(anyhow!(
                "Error output does not contain '{}'. Actual error: {}",
                expected,
                self.stderr
            ));
        }
        Ok(self)
    }
}

/// E2E test scenario builder
pub struct E2ETestScenario {
    /// Test environment
    pub env: E2ETestEnv,
    /// Test steps
    pub steps: Vec<TestStep>,
}

#[derive(Debug)]
pub enum TestStep {
    /// Create a wallet
    CreateWallet { name: String },
    /// Add UTXOs to an address
    AddUtxos { address: String, utxos: Vec<MockUtxo> },
    /// Add DIESEL balance to an address
    AddDieselBalance { address: String, amount: u64 },
    /// Set block height
    SetHeight { height: u32 },
    /// Run a deezel command
    RunCommand { args: Vec<String>, expect_success: bool },
    /// Wait for a duration
    Wait { duration: Duration },
}

impl E2ETestScenario {
    /// Create a new test scenario
    pub async fn new(config: TestConfig) -> Result<Self> {
        let env = E2ETestEnv::new(config).await?;
        Ok(Self {
            env,
            steps: Vec::new(),
        })
    }
    
    /// Add a test step
    pub fn step(mut self, step: TestStep) -> Self {
        self.steps.push(step);
        self
    }
    
    /// Execute the test scenario
    pub async fn execute(mut self) -> Result<()> {
        info!("Executing E2E test scenario with {} steps", self.steps.len());
        
        // Start metashrew server
        self.env.start_metashrew_server().await?;
        self.env.wait_for_metashrew_ready().await?;
        
        // Setup basic blockchain
        self.env.setup_blockchain(10).await?;
        
        // Execute each step
        for (i, step) in self.steps.into_iter().enumerate() {
            info!("Executing step {}: {:?}", i + 1, step);
            
            match step {
                TestStep::CreateWallet { name } => {
                    self.env.create_test_wallet(&name).await?;
                }
                TestStep::AddUtxos { address, utxos } => {
                    self.env.add_test_utxos(&address, utxos)?;
                }
                TestStep::AddDieselBalance { address, amount } => {
                    self.env.add_test_diesel_balance(&address, amount)?;
                }
                TestStep::SetHeight { height } => {
                    self.env.set_block_height(height)?;
                }
                TestStep::RunCommand { args, expect_success } => {
                    let args_str: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
                    let result = self.env.run_deezel_command(&args_str).await?;
                    
                    if expect_success && !result.is_success() {
                        return Err(anyhow!(
                            "Expected command to succeed but it failed: {}",
                            result.stderr
                        ));
                    } else if !expect_success && result.is_success() {
                        return Err(anyhow!(
                            "Expected command to fail but it succeeded: {}",
                            result.stdout
                        ));
                    }
                }
                TestStep::Wait { duration } => {
                    sleep(duration).await;
                }
            }
        }
        
        info!("E2E test scenario completed successfully");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_e2e_env_creation() {
        let config = TestConfig::default();
        let env = E2ETestEnv::new(config).await.unwrap();
        
        assert!(env.wallet_dir.exists());
        assert_eq!(env.config.start_height, 840000);
    }
    
    #[tokio::test]
    async fn test_create_test_wallet() {
        let config = TestConfig::default();
        let env = E2ETestEnv::new(config).await.unwrap();
        
        let wallet_path = env.create_test_wallet("test").await.unwrap();
        assert!(wallet_path.exists());
        
        let wallet_content = fs::read_to_string(wallet_path).unwrap();
        assert!(wallet_content.contains("version"));
    }
}