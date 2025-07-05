//! Test runner for envelope witness corruption issue
//! 
//! Run with: cargo run --bin test_envelope_witness
//! 
//! This binary provides a focused test environment to reproduce and debug
//! the envelope witness data corruption issue that occurs during transaction
//! serialization/deserialization.

use anyhow::Result;
use deezel::tests::test_envelope_witness_corruption::run_envelope_witness_tests;

fn main() -> Result<()> {
    // Initialize logging
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    println!("🧪 Envelope Witness Corruption Test Suite");
    println!("==========================================");
    println!();
    println!("This test suite reproduces the issue where envelope witness data");
    println!("(~118KB) is created correctly but gets corrupted to only 2 bytes");
    println!("during transaction serialization, causing Bitcoin Core to reject");
    println!("with 'Witness program was passed an empty witness'.");
    println!();

    // Run the comprehensive test suite
    match run_envelope_witness_tests() {
        Ok(_) => {
            println!("\n🎉 All tests completed successfully!");
            println!("If the issue was reproduced, check the test output above for details.");
        }
        Err(e) => {
            println!("\n❌ Test suite failed: {}", e);
            println!("This may indicate the issue was successfully reproduced.");
            std::process::exit(1);
        }
    }

    Ok(())
}