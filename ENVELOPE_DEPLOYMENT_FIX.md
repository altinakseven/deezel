# Envelope Deployment Debug Analysis & Fix

## Root Cause Identified

The issue with `--envelope` and `[3, 1000, 101]` cellpack is a **conceptual mixing of deployment and execution**.

### The Problem

The current command tries to do both:
1. **Contract Deployment** (via `--envelope ./examples/free_mint.wasm.gz`)
2. **Contract Execution** (via cellpack `[3,1000,101]` targeting existing contract)

This is fundamentally incorrect. These are two separate operations that cannot be combined.

### Analysis

#### Contract Deployment Should Be:
- **Envelope**: Contains compressed WASM bytecode in witness data
- **Protostone**: Empty message field (no cellpack)
- **Result**: New contract deployed to next available ID (e.g., `[4,1000]`)
- **Command**: `deezel alkanes execute --envelope ./free_mint.wasm.gz --to [addr] '[]:v0:v0'`

#### Contract Execution Should Be:
- **No Envelope**: No witness data needed
- **Protostone**: Contains cellpack targeting existing contract
- **Cellpack**: `[3,1000,101]` targets contract `[3,1000]` with input `101`
- **Result**: Execute existing contract `[3,1000]`
- **Command**: `deezel alkanes execute --to [addr] '[3,1000,101]:v0:v0'`

### The Fix

#### 1. For Contract Deployment (what you want):
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

#### 2. For Contract Execution (separate command):
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

### Technical Details

#### Envelope Structure (alkanes-rs reference):
```
OP_FALSE OP_IF
  "BIN"           # Protocol ID
  []              # Empty BODY_TAG
  <compressed>    # Gzipped WASM bytecode in chunks
OP_ENDIF
```

#### Protostone for Deployment:
```
protocol_tag: 1 (ALKANES)
message: []     # Empty - no cellpack
edicts: []
refund: Some(0)
pointer: Some(0)
```

#### Protostone for Execution:
```
protocol_tag: 1 (ALKANES)
message: [LEB128 encoded cellpack]  # Contains [3,1000,101]
edicts: []
refund: Some(0)
pointer: Some(0)
```

### Trace Calculation

For protostones, the trace vout is calculated as:
```
trace_vout = tx.output.len() + 1 + protostone_index
```

So for the first protostone in a transaction with 4 outputs:
```
trace_vout = 4 + 1 + 0 = 5
```

### Implementation Changes Needed

#### 1. Update Command Parsing
The CLI should reject combinations of `--envelope` with non-empty cellpacks:

```rust
// In command parsing
if envelope_data.is_some() && !protostones.iter().all(|p| p.cellpack.is_none()) {
    return Err(anyhow!("Cannot use --envelope with execution cellpacks. Use --envelope for deployment with empty cellpack [] or cellpack for execution without --envelope"));
}
```

#### 2. Update Protostone Construction
```rust
// For deployment (with envelope)
if envelope_data.is_some() {
    // Ensure all protostones have empty message (no cellpack)
    for protostone in &mut protostones {
        if protostone.cellpack.is_some() {
            return Err(anyhow!("Deployment with --envelope requires empty cellpack []"));
        }
    }
}

// For execution (without envelope)
if envelope_data.is_none() {
    // Ensure at least one protostone has a cellpack
    if protostones.iter().all(|p| p.cellpack.is_none()) {
        return Err(anyhow!("Execution without --envelope requires cellpack targeting existing contract"));
    }
}
```

#### 3. Update Documentation
Add clear examples showing the distinction between deployment and execution.

### Expected Results

#### After Deployment:
- New contract deployed to `[4,1000]`
- Can verify with: `./target/release/deezel alkanes getbytecode 4:1000`
- Trace available at reveal_txid + calculated vout

#### After Execution:
- Contract `[3,1000]` executed with input `101`
- State changes applied
- Trace available at reveal_txid + calculated vout

### Verification Commands

```bash
# Check if contract was deployed
./target/release/deezel alkanes getbytecode 4:1000

# Trace the deployment transaction
./target/release/deezel alkanes trace <reveal_txid> <calculated_vout>

# Trace the execution transaction  
./target/release/deezel alkanes trace <reveal_txid> <calculated_vout>
```

This fix resolves the conceptual confusion and provides clear separation between contract deployment and execution operations.