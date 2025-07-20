//! End-to-end tests for the `deezel alkanes inspect` command.
//!
//! This test suite verifies that the output of the `inspect` command matches the
//! reference implementation from `deezel-old` for both pretty-printed and raw JSON formats.

use std::process::Command;
use std::fs;
use std::path::Path;
use std::env;
use assert_cmd::prelude::*;
use predicates::prelude::*;

fn get_deezel_cmd() -> Command {
    Command::cargo_bin("deezel").unwrap()
}

#[test]
fn test_alkanes_inspect_pretty_output() {
    let mut cmd = get_deezel_cmd();
    cmd.args([
        "alkanes",
        "inspect",
        // TODO: Use a real alkane ID from the test environment
        "0:0", 
        "--fuzz",
        "--meta",
    ]);

    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let golden_file_path = Path::new(&manifest_dir)
        .parent() // Move up from crates/deezel to crates/
        .unwrap()
        .parent() // Move up from crates/ to the workspace root
        .unwrap()
        .join("tests/golden/inspect_pretty.txt");
    let expected_output = fs::read_to_string(golden_file_path)
        .expect("Failed to read pretty-print golden file");

    cmd.assert()
        .success()
        .stdout(predicate::str::diff(expected_output).trim());
}

#[test]
fn test_alkanes_inspect_raw_output() {
    let mut cmd = get_deezel_cmd();
    cmd.args([
        "alkanes",
        "inspect",
        // TODO: Use a real alkane ID from the test environment
        "0:0",
        "--fuzz",
        "--meta",
        "--raw",
    ]);

    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let golden_file_path = Path::new(&manifest_dir)
        .parent() // Move up from crates/deezel to crates/
        .unwrap()
        .parent() // Move up from crates/ to the workspace root
        .unwrap()
        .join("tests/golden/inspect_raw.json");
    let expected_output = fs::read_to_string(golden_file_path)
        .expect("Failed to read raw JSON golden file");

    // Parse both actual and expected as JSON to ignore formatting differences
    let actual_json: serde_json::Value = serde_json::from_str(
        &String::from_utf8(cmd.output().unwrap().stdout).unwrap()
    ).unwrap();
    
    let expected_json: serde_json::Value = serde_json::from_str(&expected_output).unwrap();

    assert_eq!(actual_json, expected_json);
}