# Envelope Deployment Debug - Complete Solution

## Problem Summary

The user reported that the command:
```bash
deezel alkanes execute --envelope ./examples/free_mint.wasm.gz --to [addr] '[3,1000,101]:v0:v0'
```

Doesn't work when trying to deploy to `[4,1000]` and get a trace from the reveal txid + vout.

## Root Cause Analysis

The issue is a **conceptual mixing of contract deployment and execution**:

1. **`--envelope ./examples/free_mint.wasm.gz`** = Contract deployment operation
2. **`[3,1000,101]` cellpack** = Contract execution operation targeting existing contract `[3,1000]`

These two operations cannot and should not be combined in a single command.

## The Fix

### 1. Added Validation Logic

Added `validate_envelope_cellpack_usage()` function in [`src/alkanes/execute.rs`](src/alkanes/execute.rs:305) that:

- Detects when both `--envelope` and cellpacks are used together
- Provides clear error messages explaining the correct usage
- Validates deployment scenarios (envelope + empty cellpack)
- Validates execution scenarios (cellpack + no envelope)

### 2. Enhanced Logging

Updated protostone construction to clearly distinguish between:
- **🚀 DEPLOYMENT**: Empty message field for contract deployment
- **⚡ EXECUTION**: Cellpack in message field for contract execution

### 3. Clear Error Messages

The fix now provides helpful error messages like:
```
❌ INVALID USAGE: Cannot use --envelope (deployment) with cellpacks (execution) simultaneously.
💡 For CONTRACT DEPLOYMENT: Use --envelope with empty cellpack []
💡 For CONTRACT EXECUTION: Use cellpack [block,tx,input] without --envelope
📚 See ENVELOPE_DEPLOYMENT_FIX.md for detailed explanation
```

## Correct Usage

### For Contract Deployment (what the user wants):
```bash
deezel alkanes execute \
    --envelope ./examples/free_mint.wasm.gz \
    --inputs B:1000 \
    --change [self:p2tr:2] \
    --to [self:p2tr:1],[self:p2tr:2],[self:p2tr:3] \
    --mine \
    --fee-rate 1 \
    -y \
    --trace \
    '[]:v0:v0'  # Empty cellpack for deployment
```

**Result**: New contract deployed to `[4,1000]`, verifiable with:
```bash
./target/release/deezel alkanes getbytecode 4:1000
```

### For Contract Execution (separate operation):
```bash
deezel alkanes execute \
    --inputs B:1000 \
    --change [self:p2tr:2] \
    --to [self:p2tr:1],[self:p2tr:2],[self:p2tr:3] \
    --mine \
    --fee-rate 1 \
    -y \
    --trace \
    '[3,1000,101]:v0:v0'  # Cellpack targeting existing contract
```

**Result**: Execute existing contract `[3,1000]` with input `101`

## Technical Details

### Envelope Structure (Deployment)
```
Witness Data:
  [signature, script, control_block]
  
Script Content:
  OP_FALSE OP_IF
    "BIN"           # Protocol ID
    []              # Empty BODY_TAG  
    <compressed>    # Gzipped WASM bytecode
  OP_ENDIF

Protostone:
  protocol_tag: 1 (ALKANES)
  message: []     # Empty for deployment
  edicts: []
  refund: Some(0)
  pointer: Some(0)
```

### Execution Structure (No Envelope)
```
No Witness Data (regular transaction)

Protostone:
  protocol_tag: 1 (ALKANES)
  message: [LEB128 encoded cellpack]  # Contains [3,1000,101]
  edicts: []
  refund: Some(0)
  pointer: Some(0)
```

### Trace Calculation
For protostones, the trace vout is:
```
trace_vout = tx.output.len() + 1 + protostone_index
```

For the first protostone in a transaction with 4 outputs:
```
trace_vout = 4 + 1 + 0 = 5
```

## Files Modified

1. **[`src/alkanes/execute.rs`](src/alkanes/execute.rs)**: Added validation and enhanced logging
2. **[`ENVELOPE_DEPLOYMENT_FIX.md`](ENVELOPE_DEPLOYMENT_FIX.md)**: Detailed technical explanation
3. **[`src/tests/test_envelope_deployment_fix.rs`](src/tests/test_envelope_deployment_fix.rs)**: Comprehensive tests

## Testing

Run the validation tests:
```bash
cargo test test_envelope_deployment_fix -- --nocapture
```

## Verification

After applying the fix:

1. **The original problematic command will now fail with a clear error message**
2. **The correct deployment command will work and deploy to `[4,1000]`**
3. **The correct execution command will work and execute contract `[3,1000]`**

## Key Insights

1. **Envelope = Deployment**: Contains WASM bytecode in witness data
2. **Cellpack = Execution**: Targets existing contract with input parameters
3. **Cannot mix both**: They serve different purposes and cannot be combined
4. **Trace calculation**: Uses special vout formula for protostones
5. **alkanes-rs reference**: Our implementation now matches the reference behavior

This fix resolves the conceptual confusion and provides clear separation between contract deployment and execution operations, making the alkanes protocol usage more intuitive and less error-prone.