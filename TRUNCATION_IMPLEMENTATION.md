# JSON RPC Response Logging Truncation Implementation

## Overview

This implementation adds intelligent truncation for large JSON RPC responses in debug logging to prevent log spam while preserving important structural information.

## Problem Solved

Previously, large JSON RPC responses (especially UTXO queries) would flood debug logs with massive amounts of data, making logs difficult to read and potentially causing performance issues. This was particularly problematic for addresses with many UTXOs.

## Solution

### Core Implementation

**File: `src/rpc/mod.rs`**

1. **Constants**:
   - `MAX_LOG_SIZE: usize = 2000` - Maximum characters for logged JSON responses

2. **Helper Functions**:
   - `truncate_json_for_logging()` - Intelligently truncates large JSON values
   - `truncate_rpc_response_for_logging()` - Truncates RPC responses while preserving errors

3. **Truncation Strategy**:
   - **Small responses** (≤2000 chars): Logged in full
   - **Large arrays**: Show first 2-3 elements + metadata about total count
   - **Large strings**: Show first 100 characters + metadata about total length
   - **Large objects**: Truncate individual fields while preserving structure
   - **Error responses**: Never truncated (always show full error details)

### Integration Points

The truncation is applied at all JSON RPC logging points:

1. **Generic RPC calls** (`_call` method) - Lines 181, 202
2. **Protobuf RPC calls** (`call_rpc` method) - Lines 228, 249  
3. **UTXO queries** (`get_address_utxos` method) - Line 1024

## Example Output

### Before (Large UTXO Response)
```
JSON-RPC Response: {
  "result": [
    {"txid": "abc123...", "vout": 0, "amount": 50000, ...},
    {"txid": "def456...", "vout": 1, "amount": 75000, ...},
    // ... 500 more UTXO objects flooding the logs
  ],
  "id": 1
}
```

### After (Truncated)
```
JSON-RPC Response: {
  "result": {
    "_truncated": "Array with 500 elements",
    "_first_few": [
      {"txid": "abc123...", "vout": 0, "amount": 50000, ...},
      {"txid": "def456...", "vout": 1, "amount": 75000, ...}
    ]
  },
  "id": 1
}
```

## Testing

### Test Files

1. **`src/tests/test_rpc_logging_truncation.rs`**:
   - Unit tests for truncation logic
   - Tests for error preservation
   - Validation of size limits

2. **`src/tests/demo_rpc_truncation.rs`**:
   - Interactive demonstration of truncation
   - Shows before/after examples
   - Can be run with: `cargo test demo_rpc_truncation::tests::test_demo_runs_without_panic -- --nocapture`

### Test Coverage

- ✅ Small responses not truncated
- ✅ Large arrays properly truncated with metadata
- ✅ Large strings truncated with preview
- ✅ Error responses never truncated
- ✅ Size limits properly enforced

## Benefits

1. **Improved Log Readability**: Debug logs no longer flooded with massive JSON responses
2. **Better Performance**: Reduced memory usage and I/O for logging operations
3. **Preserved Debugging Info**: Important structural information and errors still visible
4. **Configurable**: Easy to adjust `MAX_LOG_SIZE` if needed
5. **Backward Compatible**: No changes to actual RPC functionality, only logging

## Configuration

To adjust the truncation threshold, modify the `MAX_LOG_SIZE` constant in `src/rpc/mod.rs`:

```rust
/// Maximum size for logging JSON responses (in characters)
pub const MAX_LOG_SIZE: usize = 2000; // Adjust as needed
```

## Future Enhancements

Potential improvements for the future:

1. **Environment Variable**: Make `MAX_LOG_SIZE` configurable via environment variable
2. **Log Level Awareness**: Different truncation levels for different log levels
3. **Smart Field Selection**: Prioritize important fields in truncated objects
4. **Compression**: Use compression for very large responses instead of truncation

## Files Modified

- `src/rpc/mod.rs` - Core implementation
- `src/tests/mod.rs` - Added test modules
- `src/tests/test_rpc_logging_truncation.rs` - Unit tests
- `src/tests/demo_rpc_truncation.rs` - Demo and examples

## Verification

Run the following commands to verify the implementation:

```bash
# Run truncation tests
cargo test test_rpc_logging_truncation

# See truncation demo in action
cargo test demo_rpc_truncation::tests::test_demo_runs_without_panic -- --nocapture

# Verify overall build
cargo check
```

All tests pass and the implementation is ready for production use.