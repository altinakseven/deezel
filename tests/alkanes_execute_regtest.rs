//! End-to-End Tests for Alkanes Execute Command with a Regtest Environment
//
// This module contains tests that execute the `deezel` binary against a
// running `bitcoind` regtest instance. These tests ensure that the
// transaction preview and execution flow work correctly with a real
// blockchain backend.

use anyhow::Result;
use std::{env, fs::File, io::Write, path::PathBuf};
use assert_cmd::Command;
use bitcoind::bitcoincore_rpc::{Auth, Client, RpcApi};
use bitcoind::BitcoinD;
use deezel_common::keystore::DeezelWallet;
use serde_json::json;
use tempfile::tempdir;

use bitcoin::address::{Address, NetworkUnchecked};

/// Sets up a regtest environment with a funded deezel wallet.
///
/// This function initializes a `bitcoind` regtest instance, creates a new
/// `deezel` wallet, saves it to a temporary keystore file, and funds the
/// wallet's first address with some regtest coins.
///
/// Returns a tuple containing the `BitcoinD` instance, the RPC client,
/// the temporary directory, the path to the keystore file, and the funded
/// address string.
fn setup_regtest() -> Result<(BitcoinD, Client, tempfile::TempDir, PathBuf, String)> {
    let bitcoind_path = bitcoind::exe_path()?;
    let bitcoind = BitcoinD::new(bitcoind_path)?;
    let client = Client::new(&bitcoind.rpc_url(), Auth::CookieFile(bitcoind.params.cookie_file.clone()))?;

    // Generate blocks to activate regtest
    let address = client.get_new_address(None, None)?.require_network(bitcoin::Network::Regtest)?;
    client.generate_to_address(101, &address)?;

    let temp_dir = tempdir()?;
    let keystore_path = temp_dir.path().join("keystore.json");
    let passphrase = "testpass";

    // Create a new deezel wallet and save it to the keystore
    let wallet = DeezelWallet::new(passphrase)?;
    let mnemonic_phrase = wallet.mnemonic_phrase();
    let keystore_content = json!({
        "mnemonic": mnemonic_phrase,
        "passphrase": passphrase
    });
    let mut file = File::create(&keystore_path)?;
    file.write_all(keystore_content.to_string().as_bytes())?;

    // Get the first address to fund
    let deezel_address_str = wallet.get_address(0)?.to_string();
    let deezel_address: Address = deezel_address_str.parse::<Address<NetworkUnchecked>>()?.require_network(bitcoin::Network::Regtest)?;

    // Fund the deezel wallet
    client.send_to_address(
        &deezel_address,
        bitcoin::Amount::from_sat(50_000),
        None, None, None, None, None, None,
    )?;
    client.generate_to_address(1, &address)?;

    Ok((bitcoind, client, temp_dir, keystore_path, deezel_address_str))
}

#[test]
fn test_alkanes_execute_regtest_preview() -> Result<()> {
    env::set_var("BITCOIND_EXE", "/home/ubuntu/alkanes/system/submodules/bitcoin/build/bin/bitcoind");
    let (bitcoind, _client, _temp_dir, keystore_path, deezel_address_str) = setup_regtest()?;
    let keystore_path_str = keystore_path.to_str().unwrap();

    // Now, run the alkanes execute command
    let mut cmd = Command::cargo_bin("deezel")?;
    cmd.args([
        "--keystore",
        keystore_path_str,
        "--bitcoin-rpc-url",
        &bitcoind.rpc_url(),
        "alkanes",
        "execute",
        "--to",
        "bcrt1qsdn4y2n5z2u0p82j22827z2q9gqgqgqgqgqgqgqg",
        "--fee-rate",
        "1.0",
        "--change",
        &deezel_address_str,
    ]);

    cmd.write_stdin("y\n");

    let output = cmd.output()?;
    if !output.status.success() {
        println!("stdout: {}", String::from_utf8_lossy(&output.stdout));
        println!("stderr: {}", String::from_utf8_lossy(&output.stderr));
    }
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("--- Transaction Preview ---"));

    Ok(())
}

#[test]
fn test_alkanes_execute_with_mine_and_trace() -> Result<()> {
    env::set_var("BITCOIND_EXE", "/home/ubuntu/alkanes/system/submodules/bitcoin/build/bin/bitcoind");
    let (bitcoind, client, _temp_dir, keystore_path, deezel_address_str) = setup_regtest()?;
    let keystore_path_str = keystore_path.to_str().unwrap();

    let initial_block_count = client.get_block_count()?;

    // Now, run the alkanes execute command with --mine and --trace
    let mut cmd = Command::cargo_bin("deezel")?;
    cmd.args([
        "--keystore",
        keystore_path_str,
        "--bitcoin-rpc-url",
        &bitcoind.rpc_url(),
        "alkanes",
        "execute",
        "--to",
        "bcrt1qsdn4y2n5z2u0p82j22827z2q9gqgqgqgqgqgqgqg",
        "--fee-rate",
        "1.0",
        "--change",
        &deezel_address_str,
        "--mine",
        "--trace",
    ]);

    cmd.write_stdin("y\n");

    let output = cmd.output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if !output.status.success() {
        println!("stdout: {stdout}");
        println!("stderr: {stderr}");
    }
    assert!(output.status.success());

    // Assertions
    assert!(stdout.contains("--- Transaction Preview ---"));
    assert!(stdout.contains("Mining blocks on regtest network..."));
    assert!(stdout.contains("Tracing protostone execution results..."));
    assert!(stdout.contains("Tracing protostone #0"));

    let final_block_count = client.get_block_count()?;
    assert_eq!(final_block_count, initial_block_count + 1);

    Ok(())
}

#[test]
fn test_alkanes_execute_regtest_simulation_preview() -> Result<()> {
    env::set_var("BITCOIND_EXE", "/home/ubuntu/alkanes/system/submodules/bitcoin/build/bin/bitcoind");
    let (bitcoind, _client, _temp_dir, keystore_path, deezel_address_str) = setup_regtest()?;
    let keystore_path_str = keystore_path.to_str().unwrap();

    // Now, run the alkanes execute command with an envelope
    let mut cmd = Command::cargo_bin("deezel")?;
    cmd.args([
        "--keystore",
        keystore_path_str,
        "--bitcoin-rpc-url",
        &bitcoind.rpc_url(),
        "alkanes",
        "execute",
        "--to",
        "bcrt1qsdn4y2n5z2u0p82j22827z2q9gqgqgqgqgqgqgqg",
        "--fee-rate",
        "1.0",
        "--change",
        &deezel_address_str,
        "--envelope",
        "../../tests/dummy_envelope.wasm",
        "[1,2,3]",
    ]);

    cmd.write_stdin("y\n");

    let output = cmd.output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if !output.status.success() {
        println!("stdout: {stdout}");
        println!("stderr: {stderr}");
    }
    assert!(output.status.success());
    assert!(stdout.contains("--- Transaction Preview ---"));
    assert!(stdout.contains("--- Inspection Preview ---"));

    Ok(())
}