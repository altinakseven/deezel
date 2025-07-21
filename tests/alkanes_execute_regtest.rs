//! End-to-End Tests for Alkanes Execute Command with a Regtest Environment
//
// This module contains tests that execute the `deezel` binary against a
// running `bitcoind` regtest instance. These tests ensure that the
// transaction preview and execution flow work correctly with a real
// blockchain backend.

use anyhow::Result;
use std::env;
use assert_cmd::Command;
use bitcoind::bitcoincore_rpc::{Auth, Client, RpcApi};
use bitcoind::BitcoinD;
use predicates::prelude::*;
use tempfile::tempdir;

use bitcoin::address::{Address, NetworkUnchecked};

/// Sets up a regtest environment with a funded wallet.
fn setup_regtest() -> Result<(BitcoinD, Client, tempfile::TempDir)> {
    let bitcoind_path = bitcoind::exe_path()?;
    let bitcoind = BitcoinD::new(bitcoind_path)?;
    let client = Client::new(&bitcoind.rpc_url(), Auth::CookieFile(bitcoind.params.cookie_file.clone()))?;

    // Generate blocks to activate regtest and get some funds
    let address = client.get_new_address(None, None)?.require_network(bitcoin::Network::Regtest)?;
    client.generate_to_address(101, &address)?;

    let temp_dir = tempdir()?;
    Ok((bitcoind, client, temp_dir))
}

#[test]
fn test_alkanes_execute_regtest_preview() -> Result<()> {
    env::set_var("BITCOIND_EXE", "/home/ubuntu/alkanes/system/submodules/bitcoin/build/bin/bitcoind");
    let (bitcoind, client, temp_dir) = setup_regtest()?;
    let wallet_path = temp_dir.path().join("test_wallet.json");
    let wallet_path_str = wallet_path.to_str().unwrap();

    // Create a deezel wallet
    Command::cargo_bin("deezel")?
        .args(&[
            "--wallet-file",
            wallet_path_str,
            "--passphrase",
            "testpass",
            "wallet",
            "create",
        ])
        .assert()
        .success();

    // Get a new address from the deezel wallet to fund
    let output = Command::cargo_bin("deezel")?
        .args(&[
            "--wallet-file",
            wallet_path_str,
            "wallet",
            "addresses",
            "--raw",
        ])
        .output()?;
    let addresses: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    let deezel_address_str = addresses[0]["address"].as_str().unwrap();
    let deezel_address: Address = deezel_address_str.parse::<Address<NetworkUnchecked>>()?.require_network(bitcoin::Network::Regtest)?;

    // Fund the deezel wallet
    let txid = client.send_to_address(
        &deezel_address,
        bitcoin::Amount::from_sat(50_000),
        None,
        None,
        None,
        None,
        None,
        None,
    )?;
    let new_address = client.get_new_address(None, None)?.require_network(bitcoin::Network::Regtest)?;
    client.generate_to_address(1, &new_address)?;

    // Get the UTXO for the funding transaction
    let tx_info = client.get_transaction(&txid, None)?;
    let vout = tx_info.decode()?.vout.iter().position(|out| {
        out.script_pubkey.address.as_ref() == Some(&deezel_address)
    }).unwrap() as u32;
    let utxo = format!("{}:{}", txid, vout);

    // Now, run the alkanes execute command
    let mut cmd = Command::cargo_bin("deezel")?;
    cmd.args(&[
        "--wallet-file",
        wallet_path_str,
        "--passphrase",
        "testpass",
        "--bitcoin-rpc-url",
        &bitcoind.rpc_url(),
        "alkanes",
        "execute",
        "--inputs",
        &utxo,
        "--to",
        "bcrt1qsdn4y2n5z2u0p82j22827z2q9gqgqgqgqgqgqgqg",
        "--protostones",
        "B:1000:v0",
        "--fee-rate",
        "1.0",
        "--change",
        deezel_address_str,
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
    let (bitcoind, client, temp_dir) = setup_regtest()?;
    let wallet_path = temp_dir.path().join("test_wallet_mine_trace.json");
    let wallet_path_str = wallet_path.to_str().unwrap();

    // Create a deezel wallet
    Command::cargo_bin("deezel")?
        .args(&[
            "--wallet-file",
            wallet_path_str,
            "--passphrase",
            "testpass",
            "wallet",
            "create",
        ])
        .assert()
        .success();

    // Get a new address from the deezel wallet to fund
    let output = Command::cargo_bin("deezel")?
        .args(&[
            "--wallet-file",
            wallet_path_str,
            "wallet",
            "addresses",
            "--raw",
        ])
        .output()?;
    let addresses: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    let deezel_address_str = addresses[0]["address"].as_str().unwrap();
    let deezel_address: Address = deezel_address_str.parse::<Address<NetworkUnchecked>>()?.require_network(bitcoin::Network::Regtest)?;

    // Fund the deezel wallet
    let txid = client.send_to_address(
        &deezel_address,
        bitcoin::Amount::from_sat(50_000),
        None,
        None,
        None,
        None,
        None,
        None,
    )?;
    let new_address = client.get_new_address(None, None)?.require_network(bitcoin::Network::Regtest)?;
    client.generate_to_address(1, &new_address)?;

    // Get the UTXO for the funding transaction
    let tx_info = client.get_transaction(&txid, None)?;
    let vout = tx_info.decode()?.vout.iter().position(|out| {
        out.script_pubkey.address.as_ref() == Some(&deezel_address)
    }).unwrap() as u32;
    let utxo = format!("{}:{}", txid, vout);

    let initial_block_count = client.get_block_count()?;

    // Now, run the alkanes execute command with --mine and --trace
    let mut cmd = Command::cargo_bin("deezel")?;
    cmd.args(&[
        "--wallet-file",
        wallet_path_str,
        "--passphrase",
        "testpass",
        "--bitcoin-rpc-url",
        &bitcoind.rpc_url(),
        "alkanes",
        "execute",
        "--inputs",
        &utxo,
        "--to",
        "bcrt1qsdn4y2n5z2u0p82j22827z2q9gqgqgqgqgqgqgqg",
        "--protostones",
        "B:1000:v0",
        "--fee-rate",
        "1.0",
        "--change",
        deezel_address_str,
        "--mine",
        "--trace",
    ]);

    cmd.write_stdin("y\n");

    let output = cmd.output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if !output.status.success() {
        println!("stdout: {}", stdout);
        println!("stderr: {}", stderr);
    }
    assert!(output.status.success());

    // Assertions
    assert!(stdout.contains("--- Transaction Preview ---"));
    assert!(stdout.contains("Mining a new block..."));
    assert!(stdout.contains("Block mined successfully to address:"));
    assert!(stdout.contains("Synchronizing backends..."));
    assert!(stdout.contains("Backends synchronized."));
    assert!(stdout.contains("Tracing protostone execution results..."));
    assert!(stdout.contains("Tracing protostone #0"));

    let final_block_count = client.get_block_count()?;
    assert_eq!(final_block_count, initial_block_count + 1);

    Ok(())
}