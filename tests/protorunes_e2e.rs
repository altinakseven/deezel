//! End-to-End Tests for Protorunes Commands
use anyhow::Result;
use assert_cmd::Command;
use predicates::prelude::*;

/// Sets up the test environment.
fn setup() -> Command {
    let mut cmd = Command::cargo_bin("deezel").unwrap();
    cmd.env("RUST_LOG", "info");
    cmd
}

#[test]
fn test_protorunes_by_address_pretty_output() -> Result<()> {
    let mut cmd = setup();
    cmd.args(&[
        "protorunes",
        "by-address",
        "bc1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    ]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Protorune Wallet Balances"));
    Ok(())
}

#[test]
fn test_protorunes_by_outpoint_pretty_output() -> Result<()> {
    let mut cmd = setup();
    cmd.args(&[
        "protorunes",
        "by-outpoint",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0",
    ]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Protorune Outpoint Response"));
    Ok(())
}