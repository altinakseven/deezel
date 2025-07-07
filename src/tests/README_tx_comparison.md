# Transaction Comparison Analysis

## Overview

The `test_tx_comparison.rs` test compares two reveal transactions:
- `./examples/tx.hex` - Transaction built by deezel
- `./examples/working-tx.hex` - Working transaction from integration test

## Key Findings

### Major Differences

1. **Transaction Size**
   - Deezel tx: 118,934 bytes (29,952 vbytes)
   - Working tx: 78,606 bytes (19,731 vbytes)
   - **Difference: 40,328 bytes larger (10,221 vbytes)**

2. **Input Count**
   - Deezel tx: 2 inputs
   - Working tx: 1 input
   - **Deezel has an extra input**

3. **Output Count**
   - Deezel tx: 5 outputs
   - Working tx: 2 outputs
   - **Deezel has 3 extra outputs**

4. **Witness Data**
   - Deezel input 0: 2 witness elements
   - Working input 0: 3 witness elements
   - **Different witness structure**

### Detailed Analysis

#### Input Differences
- **Input 0 Outpoints**: Completely different UTXOs being spent
- **Sequence Numbers**: Deezel uses 4294967293, Working uses 4294967295
- **Extra Input**: Deezel has a second input that working tx doesn't have

#### Output Differences
- **Output 0**: 
  - Deezel: 546 sats (dust), 34-byte script (P2TR)
  - Working: 2,499,963,116 sats, 22-byte script (P2WPKH)
- **Output 1**:
  - Deezel: 546 sats (dust), 34-byte script (P2TR)
  - Working: 0 sats, 14-byte OP_RETURN script
- **Outputs 2-4**: Only exist in deezel transaction

#### Witness Structure - CRITICAL FINDINGS

**Working Transaction (Input 0):**
- Element 0: 64 bytes - **Schnorr signature** (first element)
- Element 1: 78,394 bytes - **Large alkanes payload** (second element)
- Element 2: 33 bytes - **Control block/pubkey** (third element)

**Deezel Transaction (Input 0):**
- Element 0: 118,535 bytes - **Large alkanes payload** (first element) ❌
- Element 1: 33 bytes - **Control block/pubkey** (second element)

**Deezel Transaction (Input 1):**
- Element 0: 64 bytes - **Schnorr signature** (first element)

### KEY ISSUE IDENTIFIED

**The deezel transaction has the large payload in the FIRST witness element instead of the SECOND element!**

In the working transaction:
1. **First element**: Signature (64 bytes)
2. **Second element**: Alkanes payload (78,394 bytes)
3. **Third element**: Control block (33 bytes)

In the deezel transaction:
1. **First element**: Alkanes payload (118,535 bytes) ❌ WRONG POSITION
2. **Second element**: Control block (33 bytes)

**The first witness element should be the signature, not the payload!**

## Implications

1. **Size Efficiency**: The working transaction is significantly more efficient
2. **UTXO Management**: Different input selection strategies
3. **Output Strategy**: Deezel creates multiple dust outputs vs working's single change output
4. **Script Types**: Different address/script types being used
5. **Witness Optimization**: Working tx has more complete witness data

## Running the Test

```bash
cargo test test_compare_reveal_transactions -- --nocapture
```

This will output detailed comparison information including:
- Transaction IDs
- Input/output analysis
- Witness data comparison
- Byte-by-byte difference analysis
- Size and weight metrics

## Next Steps

The analysis suggests that deezel's transaction construction may need optimization in:
1. Input selection (why 2 inputs vs 1?)
2. Output creation (why 5 outputs vs 2?)
3. Witness data structure
4. Overall transaction efficiency