//! End-to-End Tests for Runestone Commands
//!
//! This module contains tests that execute the `deezel` binary to verify
//! the functionality of the `runestone` subcommand, particularly the `analyze`
//! command. These tests ensure that the output matches the expected format,
//! both for raw JSON and pretty-printed text.
use anyhow::Result;
use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value as JsonValue;
use std::fs;

const TEST_TXID: &str = "2aa5e9bb0e0edae08deefc8273f32d7f8606871a0fbd738e68756b3e67448adc";

/// Sets up the test environment.
fn setup() -> Command {
    let mut cmd = Command::cargo_bin("deezel").unwrap();
    cmd.env("RUST_LOG", "info");
    cmd
}

#[test]
fn test_runestone_analyze_pretty_output() -> Result<()> {
    let mut cmd = setup();
    cmd.args([
        "runestone",
        "analyze",
        TEST_TXID,
    ]);

    // Expected pretty-printed output. This should be carefully crafted
    // to match the reference output provided by the user.
    let expected_output = fs::read_to_string("./reference/runestone_analyze_pretty.txt").unwrap();

    cmd.assert()
        .success()
        .stdout(predicate::str::contains(expected_output));

    Ok(())
}

#[test]
fn test_runestone_analyze_raw_output() -> Result<()> {
    let mut cmd = setup();
    cmd.args([
        "runestone",
        "analyze",
        TEST_TXID,
        "--raw",
    ]);

    let expected_json: JsonValue =
        serde_json::from_str(&fs::read_to_string("./reference/runestone_analyze_raw.json").unwrap())?;

    let output = cmd.output()?.stdout;
    let output_json: JsonValue = serde_json::from_slice(&output)?;

    assert_eq!(output_json, expected_json);

    Ok(())
}