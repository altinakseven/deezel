use anyhow::{anyhow, Context, Result};
use std::path::PathBuf;
use std::process::Command;
use std::fs;

pub fn build() -> Result<()> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let contracts_dir = fs::canonicalize(manifest_dir.join("contracts"))
        .with_context(|| format!("Failed to find contracts directory at {:?}", manifest_dir.join("contracts")))?;
    let out_dir = fs::canonicalize(manifest_dir.join("out")).unwrap_or_else(|_| {
        let path = manifest_dir.join("out");
        fs::create_dir_all(&path).unwrap();
        path
    });

    println!("[BUILD] Contracts dir (absolute): {:?}", contracts_dir);
    println!("[BUILD] Output dir (absolute): {:?}", out_dir);

    let status = Command::new("cargo")
        .args(["build", "--release", "--target", "wasm32-unknown-unknown"])
        .current_dir(&contracts_dir)
        .status()
        .context("Failed to execute 'cargo build' for contracts")?;

    if !status.success() {
        return Err(anyhow!("'cargo build' for contracts failed with status: {}", status));
    }

    let wasm_dir = contracts_dir.join("target/wasm32-unknown-unknown/release");
    println!("[BUILD] Checking for WASM files in: {:?}", wasm_dir);

    if !wasm_dir.exists() {
        return Err(anyhow!("WASM output directory not found at {:?}", wasm_dir));
    }

    println!("[BUILD] Found WASM directory. Contents:");
    for entry in fs::read_dir(&wasm_dir)? {
        println!("[BUILD]   - {:?}", entry?.path());
    }

    for entry in fs::read_dir(&wasm_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("wasm") {
            if let Some(file_name) = path.file_name() {
                let dest_path = out_dir.join(file_name);
                println!("[BUILD] Copying {:?} to {:?}", path, dest_path);
                fs::copy(&path, &dest_path).with_context(|| format!("Failed to copy wasm file to {:?}", dest_path))?;
            }
        }
    }
    
    println!("[BUILD] Verifying files in output directory: {:?}", out_dir);
    for entry in fs::read_dir(&out_dir)? {
        println!("[BUILD]   - {:?}", entry?.path());
    }

    Ok(())
}