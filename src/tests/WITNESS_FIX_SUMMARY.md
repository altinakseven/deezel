# Witness Stack Fix Summary

## Problem Identified
The deezel transaction was placing the alkanes payload in the **wrong witness position**.

**Working Transaction (Correct):**
1. **Element 0**: 64 bytes - Schnorr Signature ✅
2. **Element 1**: 78,394 bytes - Alkanes Payload ✅  
3. **Element 2**: 33 bytes - Control Block ✅

**Deezel Transaction (Before Fix):**
1. **Element 0**: 118,535 bytes - Alkanes Payload ❌ WRONG!
2. **Element 1**: 33 bytes - Control Block ❌ WRONG!

## Fix Applied

### Code Changes Made

**File: `src/alkanes/execute.rs`**

**Lines 926-936**: Added detection that envelope witness needs signature first
**Lines 1006-1040**: Fixed witness construction to use proper P2TR script-path order:
```rust
// Step 1: Add the signature as the FIRST element
if let Some(psbt_input) = signed_psbt.inputs.get(i) {
    if let Some(tap_script_sig) = psbt_input.tap_script_sigs.values().next() {
        new_witness.push(tap_script_sig.to_vec());
    } else if let Some(tap_key_sig) = &psbt_input.tap_key_sig {
        new_witness.push(tap_key_sig.to_vec());
    }
}

// Step 2: Add the script (alkanes payload) as the SECOND element
new_witness.push(&envelope_witness[0]);

// Step 3: Add the control block as the THIRD element  
new_witness.push(&envelope_witness[1]);
```

**Lines 1023-1050**: Updated witness verification to expect 3 elements
**Lines 1167-1180**: Updated logging to show proper witness element types

## Expected Result After Fix

**Deezel Transaction (After Fix):**
1. **Element 0**: 64 bytes - Schnorr Signature ✅
2. **Element 1**: ~118,535 bytes - Alkanes Payload ✅  
3. **Element 2**: 33 bytes - Control Block ✅

## Testing the Fix

The current test still shows the old results because it's comparing pre-generated hex files. To test the fix:

1. **Generate a new transaction** using the fixed deezel code
2. **Compare the new transaction** with the working transaction
3. **Verify the witness stack order** is now correct

## Key Technical Details

- **P2TR Script-Path Spending** requires: `[signature, script, control_block]`
- **envelope.create_witness()** returns: `[script, control_block]` 
- **Our fix** adds the signature from PSBT as the first element
- **tap_script_sigs** contains script-path signatures from PSBT
- **tap_key_sig** is fallback for key-path signatures

## Next Steps

1. Run deezel with the fixed code to generate a new reveal transaction
2. Save the new transaction hex to compare with working transaction
3. Verify the witness stack now matches the working transaction structure
4. Test that the transaction validates and broadcasts successfully

The fix addresses the root cause: **deezel was missing the signature as the first witness element** for P2TR script-path spending.