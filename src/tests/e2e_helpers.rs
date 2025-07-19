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
    TestConfig, TestState, init_test_state,
    mock_metashrew::{MockMetashrewServer, add_mock_utxos, add_mock_protorune_balance, set_mock_height}, MockUtxo, setup_test_blockchain,
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
        
        setup_test_blockchain(self.config.start_height)?;
        
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
    pub async fn create_test_wallet(&self, wallet_name: &str, passphrase: Option<&str>) -> Result<PathBuf> {
        let wallet_path = self.wallet_dir.join(format!("{}.json", wallet_name));
        info!("Creating test wallet at {:?}", wallet_path);
        let mut args_vec = vec![
            "--wallet-file".to_string(),
            wallet_path.to_str().unwrap().to_string(),
        ];
        if let Some(p) = passphrase {
            args_vec.push("--wallet-passphrase".to_string());
            args_vec.push(p.to_string());
        }
        args_vec.extend(vec![
            "wallet".to_string(),
            "create".to_string(),
            "--mnemonic".to_string(),
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
        ]);
        let args_str: Vec<&str> = args_vec.iter().map(|s| s.as_str()).collect();
        self.run_deezel_command(&args_str).await?;
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
        
        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        
        let child = cmd.spawn()
            .map_err(|e| anyhow!("Failed to execute deezel command: {}", e))?;

        let output = child.wait_with_output()
            .map_err(|e| anyhow!("Failed to wait for deezel command: {}", e))?;
        
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
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let deezel_binary = manifest_dir.join("target/debug/deezel");

        if !deezel_binary.exists() {
            return Err(anyhow!(
                "Could not find deezel binary at {:?}. Make sure it's built with 'cargo build'",
                deezel_binary
            ));
        }
        Ok(deezel_binary)
    }
    
    /// Wait for metashrew server to be ready (polls indefinitely)
    pub async fn wait_for_metashrew_ready(&self) -> Result<()> {
        let client = reqwest::Client::new();
        let url = format!("http://localhost:{}", self.config.rpc_port);
        
        let mut attempt = 0;
        loop {
            attempt += 1;
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
                Ok(response) => {
                    let status = response.status();
                    let text = response.text().await.unwrap_or_else(|_| "failed to get response text".to_string());
                    debug!("Metashrew server response: status={}, body={}", status, text);
                    if status.is_success() {
                        info!("Metashrew server is ready after {} attempts", attempt);
                        return Ok(());
                    } else {
                        debug!("Metashrew server returned error status");
                    }
                }
                Err(e) => {
                    debug!("Failed to connect to metashrew server: {}", e);
                }
            }
            
            // Log progress every 20 attempts (10 seconds)
            if attempt % 20 == 0 {
                info!("Still waiting for metashrew server to be ready (attempt {})...", attempt);
            }
            
            sleep(Duration::from_millis(500)).await;
        }
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
    wallet_path: Option<PathBuf>,
    wallet_passphrase: Option<String>,
    alkane_id: Option<String>,
    generated_address: Option<String>,
}

#[derive(Debug, Clone)]
pub enum TestStep {
    /// Create a wallet
    CreateWallet { name: String, passphrase: Option<String> },
    /// Get a new address
    GetNewAddress,
    /// Add UTXOs to an address
    AddUtxos { address: String, utxos: Vec<MockUtxo> },
    /// Add DIESEL balance to an address
    AddDieselBalance { address: String, amount: u64 },
    /// Set block height
    SetHeight { height: u32 },
    /// Run a deezel command
    RunCommand { args: Vec<String>, expect_success: bool, extract_alkane_id: bool },
    /// Deploy a contract
    DeployContract { name: String, calldata: Option<Vec<String>> },
    /// Initialize the free mint contract
    InitFreeMint,
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
            wallet_path: None,
            wallet_passphrase: None,
            alkane_id: None,
            generated_address: None,
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
        for (i, step) in self.steps.iter().enumerate() {
            info!("[E2E TRACE] Executing step {} of {}: {:?}", i + 1, self.steps.len(), step);
            match step.clone() {
                TestStep::CreateWallet { name, passphrase } => {
                    self.wallet_path = Some(self.env.create_test_wallet(&name, passphrase.as_deref()).await?);
                    self.wallet_passphrase = passphrase;
                }
                TestStep::GetNewAddress => {
                    let args = vec!["wallet".to_string(), "addresses".to_string(), "--count".to_string(), "1".to_string(), "--raw".to_string()];
                    let final_args = self.build_final_args(args);
                    let result = self.env.run_deezel_command(&final_args.iter().map(|s| s.as_str()).collect::<Vec<_>>()).await?;
                    result.assert_success()?;
                    let addresses: Vec<serde_json::Value> = serde_json::from_str(&result.stdout)?;
                    let address = addresses.get(0)
                        .and_then(|v| v.get("address"))
                        .and_then(|a| a.as_str())
                        .ok_or_else(|| anyhow!("Could not parse address from wallet addresses command"))?
                        .to_string();
                    self.generated_address = Some(address);
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
                TestStep::RunCommand {
                    args,
                    expect_success,
                    extract_alkane_id,
                } => {
                    let final_args = self.build_final_args(args);
                    let args_str: Vec<&str> = final_args.iter().map(|s| s.as_str()).collect();
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

                    if extract_alkane_id {
                        let alkane_id = result.stdout.lines()
                            .find(|line| line.starts_with("alkane_id: "))
                            .map(|line| line.trim_start_matches("alkane_id: ").to_string())
                            .ok_or_else(|| anyhow!("Could not find alkane_id in command output"))?;
                        self.alkane_id = Some(alkane_id);
                    }
                }
                TestStep::DeployContract { name, calldata } => {
                    let wasm_file_name = match name.as_str() {
                        "free-mint" => "free_mint.wasm",
                        "vault-factory" => "vault_factory.wasm",
                        "amm" => "amm.wasm",
                        _ => return Err(anyhow!("Unsupported contract type: {}", name)),
                    };
                    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
                    let wasm_path = manifest_dir.join("out").join(wasm_file_name);

                    // Explicitly check if the wasm file exists before deploying
                    if !wasm_path.exists() {
                        return Err(anyhow!(
                            "WASM file for contract '{}' not found at expected path: {:?}",
                            name,
                            wasm_path
                        ));
                    }

                    let mut args = vec![
                        "deploy".to_string(),
                        name.clone(),
                        "--yes".to_string(),
                    ];
                    if let Some(calldata) = calldata {
                        args.extend(calldata);
                    }
                    let final_args = self.build_final_args(args);
                    let result = self.env.run_deezel_command(&final_args.iter().map(|s| s.as_str()).collect::<Vec<_>>()).await?;
                    result.assert_success()?;
                    let alkane_id = result.stdout.lines()
                        .find(|line| line.starts_with("alkane_id: "))
                        .map(|line| line.trim_start_matches("alkane_id: ").to_string())
                        .ok_or_else(|| anyhow!("Could not find alkane_id in command output"))?;
                    self.alkane_id = Some(alkane_id);
                }
                TestStep::InitFreeMint => {
                    let args = vec![
                        "alkanes".to_string(),
                        "call".to_string(),
                        self.alkane_id.as_ref().unwrap().clone(),
                        "0".to_string(), // initialize opcode
                        "1000000".to_string(), // token_units
                        "100000".to_string(), // value_per_mint
                        "1000000000".to_string(), // cap
                        "0x54455354".to_string(), // name_part1
                        "0x434f494e".to_string(), // name_part2
                        "0x545354".to_string(), // symbol
                    ];
                    let final_args = self.build_final_args(args);
                    let result = self.env.run_deezel_command(&final_args.iter().map(|s| s.as_str()).collect::<Vec<_>>()).await?;
                    result.assert_success()?;
                }
                TestStep::Wait { duration } => {
                    sleep(duration).await;
                }
            }
        }
        
        info!("E2E test scenario completed successfully");
        Ok(())
    }

    fn build_final_args(&self, args: Vec<String>) -> Vec<String> {
        let mut final_args = Vec::new();

        // Add global options first
        if let Some(wallet_path) = &self.wallet_path {
            if !args.contains(&"--wallet-file".to_string()) {
                final_args.push("--wallet-file".to_string());
                final_args.push(wallet_path.to_str().unwrap().to_string());
            }
        }
        if let Some(passphrase) = &self.wallet_passphrase {
            if !args.contains(&"--wallet-passphrase".to_string()) {
                final_args.push("--wallet-passphrase".to_string());
                final_args.push(passphrase.clone());
            }
        }

        // Add command-specific args
        let mut processed_args = args.clone();
        if let Some(alkane_id) = &self.alkane_id {
            for arg in &mut processed_args {
                if arg.contains("<alkane_id>") {
                    *arg = arg.replace("<alkane_id>", alkane_id);
                }
            }
        }
        if let Some(address) = &self.generated_address {
            for arg in &mut processed_args {
                if arg.contains("<generated_address>") {
                    *arg = arg.replace("<generated_address>", address);
                }
            }
        }
        final_args.extend(processed_args);
        final_args
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
    
}