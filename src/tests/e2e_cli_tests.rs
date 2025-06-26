//! End-to-end CLI tests for the deezel application
//! 
//! These tests verify the complete CLI workflows using the new crate structure
//! with the generic runtime and filesystem-based adapters.

use anyhow::Result;
use std::process::Command;
use std::path::PathBuf;
use tempfile::TempDir;

/// Test helper for CLI operations
pub struct CliTestHelper {
    temp_dir: TempDir,
    config_dir: PathBuf,
}

impl CliTestHelper {
    pub fn new() -> Result<Self> {
        let temp_dir = TempDir::new()?;
        let config_dir = temp_dir.path().join(".deezel");
        std::fs::create_dir_all(&config_dir)?;
        
        Ok(Self {
            temp_dir,
            config_dir,
        })
    }
    
    pub fn run_cli(&self, args: &[&str]) -> Result<std::process::Output> {
        let mut cmd = Command::new("cargo");
        cmd.arg("run")
           .arg("-p")
           .arg("deezel")
           .arg("--")
           .arg("--config-dir")
           .arg(&self.config_dir)
           .args(args);
        
        let output = cmd.output()?;
        Ok(output)
    }
    
    pub fn config_dir(&self) -> &PathBuf {
        &self.config_dir
    }
}

#[tokio::test]
async fn test_cli_help() -> Result<()> {
    let helper = CliTestHelper::new()?;
    
    let output = helper.run_cli(&["--help"])?;
    assert!(output.status.success());
    
    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains("A Bitcoin wallet CLI tool"));
    assert!(stdout.contains("wallet"));
    assert!(stdout.contains("transaction"));
    assert!(stdout.contains("alkanes"));
    assert!(stdout.contains("deploy"));
    assert!(stdout.contains("config"));
    
    Ok(())
}

#[tokio::test]
async fn test_config_workflow() -> Result<()> {
    let helper = CliTestHelper::new()?;
    
    // Test config show (should show defaults or empty)
    let output = helper.run_cli(&["config", "show"])?;
    assert!(output.status.success());
    
    // Test config set
    let output = helper.run_cli(&["config", "set", "test.key", "test_value"])?;
    assert!(output.status.success());
    
    // Test config get
    let output = helper.run_cli(&["config", "get", "test.key"])?;
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains("test_value"));
    
    Ok(())
}

#[tokio::test]
async fn test_wallet_list() -> Result<()> {
    let helper = CliTestHelper::new()?;
    
    // Test wallet list (should be empty initially)
    let output = helper.run_cli(&["wallet", "list"])?;
    assert!(output.status.success());
    
    Ok(())
}
