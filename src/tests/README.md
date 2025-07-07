# Deezel E2E Test Suite

This directory contains comprehensive end-to-end tests for deezel alkanes functionality.

## Test Structure

### Core Test Modules

- **`test_alkanes_e2e.rs`** - Comprehensive e2e tests for alkanes envelope and cellpack functionality
- **`integration_tests.rs`** - Integration tests for core deezel functionality
- **`e2e_helpers.rs`** - Helper utilities for e2e testing
- **`mock_metashrew.rs`** - Mock metashrew server for testing

### Test Coverage

The test suite covers:

#### 1. Contract Deployment (Envelope + Cellpack)
- ✅ Envelope with WASM bytecode in witness data
- ✅ Cellpack in protostone message to trigger deployment
- ✅ Validation of correct deployment patterns
- ✅ Various cellpack compositions and target formats

#### 2. Contract Execution (Cellpack Only)
- ✅ Cellpack without envelope for existing contract execution
- ✅ Multiple input patterns and edict structures
- ✅ Output target validation (v0, p1, split, etc.)

#### 3. Input Requirements
- ✅ Bitcoin requirements (B:amount)
- ✅ Alkanes token requirements (block:tx:amount)
- ✅ Mixed requirement parsing and validation

#### 4. Validation Error Cases
- ✅ Incomplete deployment (envelope without cellpack)
- ✅ Empty operations (no envelope, no cellpack)
- ✅ Invalid argument combinations

#### 5. Complex Protostone Parsing
- ✅ Multi-edict protostones: `[3,797,101]:v0:v0:[4:797:1:p1]:[4:797:2:p2]`
- ✅ Cellpack encoding/decoding roundtrip
- ✅ Output target format validation

## Running Tests

### Run All Tests
```bash
cargo test
```

### Run Alkanes E2E Tests Only
```bash
cargo test test_alkanes_e2e
```

### Run Specific Test
```bash
cargo test test_contract_deployment_envelope_cellpack
```

### Run with Output
```bash
cargo test -- --nocapture
```

## Test Examples

### Working Deployment Command
The test suite validates the corrected deployment pattern:

```bash
deezel alkanes execute \
    --envelope ./examples/free_mint.wasm.gz \
    --to [address] \
    '[3,1000,101]:v0:v0'
```

This command:
1. ✅ Passes validation (envelope + cellpack = deployment)
2. ✅ Creates commit transaction with envelope script
3. ✅ Creates reveal transaction with envelope witness AND protostone
4. ✅ Deploys new contract to `[4,1000]`
5. ✅ Provides trace from reveal txid + vout

### Execution Command
For executing existing contracts:

```bash
deezel alkanes execute \
    --to [address] \
    '[3,1000,101]:v0:v0'
```

This command:
1. ✅ Executes existing contract `[3,1000]` with input `101`
2. ✅ No new contract deployment
3. ✅ Single transaction without envelope

## Key Insights from alkanes-rs Reference

The test suite validates the correct alkanes deployment pattern based on the alkanes-rs reference implementation:

1. **Contract deployment requires BOTH**:
   - Envelope with WASM bytecode (accessed via `find_witness_payload`)
   - Cellpack in protostone message (triggers `cellpack.target.is_create()`)

2. **Contract execution requires**:
   - Cellpack only (no envelope)
   - Targets existing contract

3. **Trace calculation**:
   - For protostones: `vout = tx.output.len() + 1 + protostone_index`

## Mock Environment

The test suite uses mock implementations for:
- Bitcoin RPC server
- Metashrew indexer
- Wallet management
- Transaction broadcasting

This allows comprehensive testing without requiring a full Bitcoin node setup.

## Contributing

When adding new tests:

1. Follow the existing test structure
2. Use descriptive test names
3. Include both positive and negative test cases
4. Add documentation for complex test scenarios
5. Ensure tests are deterministic and isolated

## Debugging

For debugging test failures:

1. Run with `--nocapture` to see println! output
2. Check the mock server logs
3. Verify test data setup
4. Use `cargo test -- --test-threads=1` for sequential execution