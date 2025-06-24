# Deezel E2E Testing with Mock Metashrew

This directory contains a complete end-to-end testing framework for the deezel CLI that uses a mock metashrew server implementation. This allows you to test all deezel functionality without requiring a full metashrew indexer setup.

## Overview

The testing framework consists of several key components:

### Core Components

1. **Mock Metashrew Server** (`mock_metashrew.rs`)
   - Complete RPC server implementation that mimics metashrew behavior
   - Supports all metashrew RPC methods used by deezel
   - Provides configurable test data and responses

2. **Test Block Generation** (`test_blocks.rs`)
   - Utilities for creating Bitcoin test blocks
   - DIESEL token transaction generation
   - Mock blockchain state management

3. **E2E Test Helpers** (`e2e_helpers.rs`)
   - High-level test scenario builder
   - Deezel CLI command execution
   - Test environment management

4. **Integration Tests** (`integration_tests.rs`)
   - Complete e2e test scenarios
   - Demonstrates all deezel functionality
   - Performance and error handling tests

## Architecture

The mock metashrew implementation is based on patterns learned from the alkanes-rs and metashrew reference implementations:

### From Alkanes-RS Reference
- Test block creation with [`create_block_with_coinbase_tx()`](../../reference/alkanes-rs/src/tests/helpers.rs:98)
- Network configuration with [`configure_network()`](../../reference/alkanes-rs/src/tests/helpers.rs:43)
- State management with [`clear()`](../../reference/alkanes-rs/src/tests/helpers.rs:92) pattern
- Cellpack and protorune handling

### From Metashrew Reference
- WASM runtime patterns from [`MetashrewRuntime`](../../reference/metashrew/crates/metashrew-runtime/src/runtime.rs:253)
- Host function interface (`__get`, `__flush`, `__load_input`)
- Storage abstraction with [`KeyValueStoreLike`](../../reference/metashrew/crates/metashrew-runtime/src/traits.rs)
- Caching and state management from [`metashrew-core`](../../reference/metashrew/crates/metashrew-core/src/lib.rs)

## Usage

### Running Individual Tests

```bash
# Run a specific test
cargo test test_wallet_operations

# Run all integration tests
cargo test integration_tests

# Run with debug output
RUST_LOG=debug cargo test test_comprehensive_diesel_workflow -- --nocapture
```

### Running All E2E Tests

```bash
# Run all tests in the tests module
cargo test tests::

# Run with parallel execution disabled (recommended for e2e tests)
cargo test tests:: -- --test-threads=1
```

### Creating Custom Test Scenarios

```rust
use deezel_cli::tests::{
    TestConfig,
    e2e_helpers::{E2ETestScenario, TestStep},
    test_blocks::create_test_utxos,
};

#[tokio::test]
async fn my_custom_test() -> Result<()> {
    let config = TestConfig {
        start_height: 840000,
        network: "regtest".to_string(),
        rpc_port: 18091, // Use unique port for each test
        debug: true,
    };

    let test_address = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
    let test_utxos = create_test_utxos(test_address, 1, 100000000);

    E2ETestScenario::new(config).await?
        .step(TestStep::CreateWallet { 
            name: "my_wallet".to_string() 
        })
        .step(TestStep::AddUtxos { 
            address: test_address.to_string(), 
            utxos: test_utxos 
        })
        .step(TestStep::RunCommand { 
            args: vec![
                "balance".to_string(),
                "--address".to_string(), 
                test_address.to_string()
            ], 
            expect_success: true 
        })
        .execute()
        .await
}
```

## Test Data Management

### Mock UTXOs

```rust
use deezel_cli::tests::{
    mock_metashrew::add_mock_utxos,
    test_blocks::create_test_utxos,
    MockUtxo,
};

// Create test UTXOs
let utxos = vec![
    MockUtxo {
        txid: "abc123...".to_string(),
        vout: 0,
        amount: 100000000, // 1 BTC in sats
        script_pubkey: "76a914...88ac".to_string(),
        confirmations: 6,
    }
];

// Add to mock server
add_mock_utxos("bcrt1q...", utxos)?;
```

### Mock DIESEL Balances

```rust
use deezel_cli::tests::mock_metashrew::add_mock_protorune_balance;

// Add DIESEL balance for an address
add_mock_protorune_balance(
    "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080",
    "2:0", // DIESEL rune ID
    50000000 // 0.5 DIESEL in base units
)?;
```

### Mock Block Heights

```rust
use deezel_cli::tests::mock_metashrew::set_mock_height;

// Set current block height
set_mock_height(840001)?;
```

## Supported RPC Methods

The mock metashrew server implements all RPC methods used by deezel:

### Core Methods
- `metashrew_height` - Get current block height
- `metashrew_view` - Generic view function calls
- `spendablesbyaddress` - Get UTXOs for an address
- `alkanes_protorunesbyaddress` - Get DIESEL balances
- `alkanes_protorunesbyoutpoint` - Get protorunes for specific outpoint
- `alkanes_trace` - Trace DIESEL transactions
- `alkanes_simulate` - Simulate contract execution
- `alkanes_meta` - Get contract metadata
- `esplora_gettransaction` - Get transaction data

### View Functions
- `getblock` - Get block data
- `getbytecode` - Get contract bytecode
- `traceblock` - Trace entire block
- `spendablesbyaddress` - Address UTXO lookup
- `protorunesbyaddress` - Address protorune lookup
- `protorunesbyoutpoint` - Outpoint protorune lookup
- `trace` - Transaction trace

## Test Configuration

### TestConfig Options

```rust
pub struct TestConfig {
    /// Starting block height for tests
    pub start_height: u32,
    /// Network type (regtest, testnet, mainnet)
    pub network: String,
    /// Mock RPC server port (use unique port per test)
    pub rpc_port: u16,
    /// Enable debug logging
    pub debug: bool,
}
```

### Environment Variables

The test framework sets these environment variables for deezel CLI:

- `DEEZEL_BITCOIN_RPC_URL` - Bitcoin RPC endpoint
- `DEEZEL_METASHREW_RPC_URL` - Metashrew RPC endpoint (mock server)
- `DEEZEL_WALLET_DIR` - Temporary wallet directory
- `RUST_LOG` - Logging level (if debug enabled)

## Best Practices

### Port Management
- Use unique ports for each test to avoid conflicts
- Ports 18081-18099 are reserved for tests
- Tests run in parallel by default

### Test Isolation
- Each test gets its own temporary directory
- Mock server state is isolated per test
- Use `clear_test_state()` if needed

### Error Handling
- Always use `expect_success: false` for negative tests
- Check both stdout and stderr in assertions
- Use `assert_output_contains()` for specific checks

### Performance
- Disable debug logging for performance tests
- Use fewer UTXOs for faster tests
- Consider `--test-threads=1` for complex scenarios

## Debugging

### Enable Debug Logging

```bash
RUST_LOG=debug cargo test test_name -- --nocapture
```

### Mock Server Debugging

The mock server logs all incoming requests and responses when debug is enabled:

```
[DEBUG] Received request: {"jsonrpc":"2.0","method":"metashrew_height","params":[],"id":1}
[DEBUG] Handling RPC method: metashrew_height
```

### CLI Command Debugging

Test output includes full command execution details:

```
[DEBUG] Running deezel command: "target/debug/deezel" with args: ["balance", "--address", "bcrt1q..."]
[DEBUG] Command output - stdout: {...}, stderr: {...}
```

## Extending the Framework

### Adding New RPC Methods

1. Add method handler in `mock_metashrew.rs`:

```rust
async fn handle_new_method(params: &Value, state: Arc<Mutex<TestState>>) -> Result<Value> {
    // Implementation
    Ok(json!({"result": "success"}))
}
```

2. Add to method dispatcher:

```rust
match method {
    // ... existing methods
    "new_method" => Self::handle_new_method(params, state).await,
    _ => Err(anyhow!("Unknown method: {}", method)),
}
```

### Adding New Test Steps

1. Add step type in `e2e_helpers.rs`:

```rust
pub enum TestStep {
    // ... existing steps
    NewStep { param: String },
}
```

2. Add execution logic:

```rust
match step {
    // ... existing steps
    TestStep::NewStep { param } => {
        // Implementation
    }
}
```

## Troubleshooting

### Common Issues

1. **Port conflicts**: Use unique ports for each test
2. **Binary not found**: Run `cargo build` before tests
3. **Server startup timeout**: Increase wait time in `wait_for_metashrew_ready()`
4. **Test isolation**: Ensure each test uses its own `TestConfig`

### Getting Help

- Check the integration tests for examples
- Enable debug logging for detailed output
- Review the reference implementations in `./reference/`
- Look at the alkanes-rs test patterns for inspiration

This mock metashrew setup provides everything needed to test deezel end-to-end without external dependencies, making it perfect for CI/CD, development testing, and feature validation.