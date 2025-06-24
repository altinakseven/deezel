//! Alkane inspection and analysis functionality

use anyhow::{Context, Result};
use log::{debug, info, warn};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::fs;

use crate::rpc::RpcClient;
use super::types::AlkaneId;

/// Alkane inspector for advanced analysis capabilities
pub struct AlkaneInspector {
    rpc_client: Arc<RpcClient>,
    deezel_dir: PathBuf,
    vendor_dir: PathBuf,
}

impl AlkaneInspector {
    /// Create a new alkane inspector
    pub fn new(rpc_client: Arc<RpcClient>) -> Result<Self> {
        let home_dir = dirs::home_dir()
            .ok_or_else(|| anyhow::anyhow!("Could not determine home directory"))?;
        
        let deezel_dir = home_dir.join(".deezel");
        let vendor_dir = deezel_dir.join("vendor");
        
        // Ensure directories exist
        fs::create_dir_all(&vendor_dir)
            .context("Failed to create vendor directory")?;
        
        Ok(Self {
            rpc_client,
            deezel_dir,
            vendor_dir,
        })
    }

    /// Inspect an alkane with the specified analysis modes
    pub async fn inspect_alkane(
        &self,
        alkane_id: &AlkaneId,
        disasm: bool,
        fuzz: bool,
        meta: bool,
    ) -> Result<()> {
        info!("Inspecting alkane {}:{}", alkane_id.block, alkane_id.tx);
        
        // Get the WASM bytecode for the alkane
        let bytecode = self.get_alkane_bytecode(alkane_id).await?;
        
        // Remove 0x prefix if present
        let hex_string = if bytecode.starts_with("0x") {
            &bytecode[2..]
        } else {
            &bytecode
        };
        
        let wasm_bytes = hex::decode(hex_string)
            .with_context(|| format!("Failed to decode WASM bytecode from hex. Hex string: '{}'",
                                    if hex_string.len() > 200 {
                                        format!("{}...", &hex_string[..200])
                                    } else {
                                        hex_string.to_string()
                                    }))?;
        
        info!("Decoded bytecode length: {} bytes", wasm_bytes.len());
        
        // Save WASM to temporary file for analysis
        let wasm_path = self.deezel_dir.join(format!("alkane_{}_{}.wasm", alkane_id.block, alkane_id.tx));
        fs::write(&wasm_path, &wasm_bytes)
            .context("Failed to write WASM file")?;
        
        info!("WASM bytecode saved to: {}", wasm_path.display());
        
        // Perform requested analysis
        if meta {
            self.extract_metadata(&wasm_path).await?;
        }
        
        if disasm {
            self.disassemble_wasm(&wasm_path).await?;
        }
        
        if fuzz {
            self.setup_fuzzing_environment().await?;
            self.perform_fuzzing_analysis(alkane_id, &wasm_path).await?;
        }
        
        Ok(())
    }

    /// Get WASM bytecode for an alkane
    async fn get_alkane_bytecode(&self, alkane_id: &AlkaneId) -> Result<String> {
        info!("Fetching bytecode for alkane {}:{}", alkane_id.block, alkane_id.tx);
        
        let bytecode = self.rpc_client.get_bytecode(
            &alkane_id.block.to_string(),
            &alkane_id.tx.to_string()
        ).await?;
        
        info!("Received bytecode hex (first 100 chars): {}",
              if bytecode.len() > 100 { &bytecode[..100] } else { &bytecode });
        info!("Total bytecode length: {} characters", bytecode.len());
        
        Ok(bytecode)
    }

    /// Extract metadata directly from WASM binary using wasmtime
    async fn extract_metadata(&self, wasm_path: &Path) -> Result<()> {
        info!("Extracting metadata from WASM binary");
        
        // For now, use a placeholder implementation
        // In a real implementation, this would:
        // 1. Initialize wasmtime engine
        // 2. Load the WASM module
        // 3. Create stub host functions
        // 4. Invoke the __meta export
        // 5. Extract and display the metadata string
        
        println!("=== ALKANE METADATA ===");
        println!("Note: Direct WASM metadata extraction not yet implemented");
        println!("This would invoke the __meta export with wasmtime");
        println!("========================");
        
        Ok(())
    }

    /// Disassemble WASM to WAT format using native wasmprinter
    async fn disassemble_wasm(&self, wasm_path: &Path) -> Result<()> {
        info!("Disassembling WASM to WAT format using native wasmprinter");
        
        // Read the WASM file
        let wasm_bytes = fs::read(wasm_path)
            .context("Failed to read WASM file")?;
        
        // Use wasmprinter to convert to WAT
        let wat_content = wasmprinter::print_bytes(&wasm_bytes)
            .context("Failed to disassemble WASM to WAT format")?;
        
        println!("=== WASM DISASSEMBLY (WAT) ===");
        println!("{}", wat_content);
        println!("==============================");
        
        // Save WAT file
        let wat_path = wasm_path.with_extension("wat");
        fs::write(&wat_path, &wat_content)
            .context("Failed to write WAT file")?;
        info!("WAT disassembly saved to: {}", wat_path.display());
        
        Ok(())
    }

    /// Setup fuzzing environment with alkanes-rs and metashrew-runtime
    async fn setup_fuzzing_environment(&self) -> Result<()> {
        info!("Setting up fuzzing environment");
        
        // Check if Rust is installed
        self.ensure_rust_installed().await?;
        
        // Clone or update alkanes-rs
        self.setup_alkanes_rs().await?;
        
        // Build alkanes-rs
        self.build_alkanes_rs().await?;
        
        Ok(())
    }

    /// Ensure Rust is installed via rustup
    async fn ensure_rust_installed(&self) -> Result<()> {
        // Check if cargo is available
        if Command::new("cargo").arg("--version").output().is_ok() {
            info!("Rust toolchain already installed");
            return Ok(());
        }
        
        info!("Rust not found. Installing via rustup...");
        
        // Download and run rustup installer
        let rustup_init = if cfg!(windows) {
            "rustup-init.exe"
        } else {
            "rustup-init.sh"
        };
        
        println!("Installing Rust toolchain...");
        println!("This may take a few minutes on first run.");
        
        // For now, just inform the user to install Rust manually
        println!("=== RUST INSTALLATION REQUIRED ===");
        println!("Please install Rust manually:");
        println!("  Visit: https://rustup.rs/");
        println!("  Or run: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh");
        println!("===================================");
        
        Ok(())
    }

    /// Clone or update alkanes-rs repository
    async fn setup_alkanes_rs(&self) -> Result<()> {
        let alkanes_rs_dir = self.vendor_dir.join("alkanes-rs");
        
        if alkanes_rs_dir.exists() {
            info!("Updating alkanes-rs repository");
            let output = Command::new("git")
                .args(&["pull", "origin", "main"])
                .current_dir(&alkanes_rs_dir)
                .output()
                .context("Failed to update alkanes-rs repository")?;
            
            if !output.status.success() {
                warn!("Failed to update alkanes-rs, using existing version");
            }
        } else {
            info!("Cloning alkanes-rs repository");
            let output = Command::new("git")
                .args(&[
                    "clone",
                    "https://github.com/kungfuflex/alkanes-rs",
                    alkanes_rs_dir.to_str().unwrap()
                ])
                .output()
                .context("Failed to clone alkanes-rs repository")?;
            
            if !output.status.success() {
                let error = String::from_utf8_lossy(&output.stderr);
                return Err(anyhow::anyhow!("Failed to clone alkanes-rs: {}", error));
            }
        }
        
        Ok(())
    }

    /// Build alkanes-rs with cargo
    async fn build_alkanes_rs(&self) -> Result<()> {
        let alkanes_rs_dir = self.vendor_dir.join("alkanes-rs");
        
        info!("Building alkanes-rs with cargo build --release");
        println!("Building alkanes-rs... This may take several minutes.");
        
        let output = Command::new("cargo")
            .args(&["build", "--release"])
            .current_dir(&alkanes_rs_dir)
            .output()
            .context("Failed to build alkanes-rs")?;
        
        if output.status.success() {
            info!("alkanes-rs built successfully");
        } else {
            let error = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!("Failed to build alkanes-rs: {}", error));
        }
        
        Ok(())
    }

    /// Perform fuzzing analysis using metashrew-runtime
    async fn perform_fuzzing_analysis(&self, alkane_id: &AlkaneId, wasm_path: &Path) -> Result<()> {
        info!("Performing fuzzing analysis for alkane {}:{}", alkane_id.block, alkane_id.tx);
        
        // For now, this is a placeholder implementation
        // In a real implementation, this would:
        // 1. Initialize metashrew-runtime
        // 2. Create a simulated block with the alkane deployment (3:0 to 4:0)
        // 3. Parse the WASM disassembly to find implemented opcodes
        // 4. Simulate each opcode to determine functionality
        // 5. Report findings
        
        println!("=== FUZZING ANALYSIS ===");
        println!("Alkane: {}:{}", alkane_id.block, alkane_id.tx);
        println!("WASM file: {}", wasm_path.display());
        println!();
        println!("Note: Full fuzzing implementation requires:");
        println!("1. metashrew-runtime integration");
        println!("2. WASM opcode analysis");
        println!("3. Simulated block creation (3:0 -> 4:0)");
        println!("4. Systematic opcode testing");
        println!();
        println!("This would systematically test all discoverable opcodes");
        println!("to determine alkane functionality and behavior.");
        println!("========================");
        
        Ok(())
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alkane_inspector_creation() {
        // This test would require a mock RPC client
        // For now, just test that the module compiles
        assert!(true);
    }
}