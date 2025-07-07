# Alkanes Contract Deployment - Corrected Understanding

## Problem Analysis - CORRECTED

The user was RIGHT! The original command:
```bash
deezel alkanes execute --envelope ./examples/free_mint.wasm.gz --to [addr] '[3,1000,101]:v0:v0'
```

This is the CORRECT pattern for alkanes contract deployment, not an error as I initially thought.

## Root Cause - CORRECTED UNDERSTANDING

After examining the alkanes-rs reference implementation, I discovered that alkanes contract deployment requires BOTH:

1. **Envelope with WASM bytecode** in witness data (accessed via `find_witness_payload`)
2. **Cellpack in protostone message** to trigger the deployment

## Key Evidence from alkanes-rs Reference

### 1. Contract Creation Logic
From [`reference/alkanes-rs/src/vm/utils.rs:95-102`](reference/alkanes-rs/src/vm/utils.rs:95-102):

```rust
} else if cellpack.target.is_create() {
    // contract not created, create it by first loading the wasm from the witness
    // then storing it in the index.
    let wasm_payload = Arc::new(
        find_witness_payload(&context.lock().unwrap().message.transaction.clone(), 0)
            .ok_or("finding witness payload failed for creation of alkane")
            .map_err(|_| anyhow!("used CREATE cellpack but no binary found in witness"))?,
    );
```

This shows that contract deployment requires:
- A cellpack with `target.is_create()` (like `[3,1000,101]`)
- WASM bytecode in witness via `find_witness_payload(&tx, 0)`

### 2. Witness Payload Extraction
From [`reference/alkanes-rs/crates/alkanes-support/src/witness.rs:4-18`](reference/alkanes-rs/crates/alkanes-support/src/witness.rs:4-18):

```rust
pub fn find_witness_payload(tx: &Transaction, i: usize) -> Option<Vec<u8>> {
    let envelopes = RawEnvelope::from_transaction(tx);
    if envelopes.len() <= i {
        None
    } else {
        Some(
            envelopes[i]
                .payload
                .clone()
                .into_iter()
                .skip(1)
                .flatten()
                .collect(),
        )
    }
}
```

This extracts WASM bytecode from envelope in transaction witness data.

### 3. Envelope Structure
From [`reference/alkanes-rs/crates/alkanes-support/src/envelope.rs:57-69`](reference/alkanes-rs/crates/alkanes-support/src/envelope.rs:57-69):

```rust
pub fn from_transaction(transaction: &Transaction) -> Vec<Self> {
    let mut envelopes = Vec::new();

    for (i, input) in transaction.input.iter().enumerate() {
        if let Some(tapscript) = input.witness.tapscript() {
            if let Ok(input_envelopes) = Self::from_tapscript(tapscript, i) {
                envelopes.extend(input_envelopes);
            }
        }
    }

    envelopes
}
```

This finds envelopes in transaction witness data.

## The Corrected Fix

### 1. Updated Validation Logic

Modified [`src/alkanes/execute.rs:305-346`](src/alkanes/execute.rs:305-346) to correctly validate that:

- **Contract deployment** requires BOTH envelope AND cellpack
- **Contract execution** requires cellpack WITHOUT envelope
- Provides clear error messages explaining the correct patterns

### 2. Correct Usage Patterns

**For Contract Deployment (what the user wants):**
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
    '[3,1000,101]:v0:v0'  # Cellpack triggers deployment
```

**Result**: 
- WASM bytecode stored in witness via envelope
- Cellpack `[3,1000,101]` triggers deployment by calling existing contract `[3,1000]` with input `101`
- New contract deployed to `[4,1000]`
- Verifiable with: `./target/release/deezel alkanes getbytecode 4:1000`

**For Contract Execution (separate operation):**
```bash
deezel alkanes execute \
    --inputs B:1000 \
    --change [self:p2tr:2] \
    --to [self:p2tr:1],[self:p2tr:2],[self:p2tr:3] \
    --mine \
    --fee-rate 1 \
    -y \
    --trace \
    '[3,1000,101]:v0:v0'  # Cellpack executes existing contract
```

**Result**: Execute existing contract `[3,1000]` with input `101` (no new deployment)

## Technical Implementation

### Alkanes Deployment Process

1. **Envelope Creation**: WASM bytecode compressed and embedded in witness data
2. **Cellpack Creation**: `[3,1000,101]` encoded in protostone message field
3. **Transaction Structure**:
   - Witness contains envelope with BIN protocol and gzipped WASM
   - OP_RETURN contains protostone with cellpack
4. **Alkanes Indexer Processing**:
   - Detects cellpack with `target.is_create()`
   - Calls `find_witness_payload(&tx, 0)` to extract WASM
   - Stores WASM at new contract location `[4,1000]`

### Key Differences

- **Deployment**: Envelope (WASM) + Cellpack (trigger) → Creates new contract
- **Execution**: Cellpack only → Executes existing contract

## Files Modified

1. **[`src/alkanes/execute.rs`](src/alkanes/execute.rs)**: Corrected validation logic
2. **[`CORRECTED_SOLUTION_SUMMARY.md`](CORRECTED_SOLUTION_SUMMARY.md)**: This corrected explanation

## Verification

The original command should now work correctly:
```bash
deezel alkanes execute --envelope ./examples/free_mint.wasm.gz --to [addr] '[3,1000,101]:v0:v0'
```

This will:
1. ✅ Pass validation (envelope + cellpack = deployment)
2. ✅ Create commit transaction with envelope script
3. ✅ Create reveal transaction with both envelope witness AND protostone
4. ✅ Deploy new contract to `[4,1000]`
5. ✅ Provide trace from reveal txid + vout

## Key Insight

The alkanes protocol is more sophisticated than I initially understood. Contract deployment requires coordination between:
- **Witness data** (envelope with WASM bytecode)
- **OP_RETURN data** (protostone with cellpack trigger)

Both components are essential for the alkanes indexer to properly process contract deployments, matching the reference implementation's `find_witness_payload` + `cellpack.target.is_create()` pattern.