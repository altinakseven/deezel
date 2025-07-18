use anyhow::{Context, Result};
use std::process::Command;
use std::fs;

pub fn build_contracts() -> Result<()> {
    println!("Building contracts...");

    let contracts_dir = "contracts";
    let out_dir = "out";

    // Create the output directory if it doesn't exist
    fs::create_dir_all(out_dir).context("Failed to create output directory")?;

    // Build the contracts
    let status = Command::new("cargo")
        .arg("build")
        .arg("--release")
        .arg("--target")
        .arg("wasm32-unknown-unknown")
        .arg("--features")
        .arg("mainnet")
        .current_dir(contracts_dir)
        .status()
        .context("Failed to execute cargo build command")?;

    if !status.success() {
        anyhow::bail!("Failed to build contracts");
    }

    // Copy the compiled WASM files to the output directory
    let wasm_dir = format!("{}/target/wasm32-unknown-unknown/release", contracts_dir);
    for entry in fs::read_dir(wasm_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("wasm") {
            let file_name = path.file_name().unwrap();
            let dest_path = format!("{}/{}", out_dir, file_name.to_str().unwrap());
            fs::copy(&path, &dest_path).context(format!("Failed to copy {:?}", path))?;
            println!("Copied {} to {}", path.display(), dest_path);
        }
    }

    println!("Contracts built successfully!");
    Ok(())
}