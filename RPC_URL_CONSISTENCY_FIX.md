# RPC URL Consistency Fix - Network Mismatch Resolution

## Problem Summary

The deezel CLI tool was experiencing network configuration mismatches where:
- The wallet was configured for regtest network
- Bitcoin RPC endpoint was connecting to mainnet (localhost:8332, height 904194)
- This caused alkanes execution failures with "No trace events found"
- Transactions failed to broadcast properly due to network mismatch
- Wallet loading was being attempted for ALL alkanes commands, even those that don't need it

## Root Cause

1. When `--sandshrew-rpc-url` was specified, it should be used for ALL RPC operations, but hardcoded URLs throughout the codebase were still pointing to separate Bitcoin RPC endpoints (localhost:8332 or localhost:18332).
2. Wallet loading logic was incorrectly attempting to load wallets for alkanes commands that only need RPC access (getbytecode, trace, inspect, tokeninfo, simulate).

## Solution Implemented

### Core Fix: Consistent RPC URL Usage

Updated the codebase to ensure that when `--sandshrew-rpc-url` is specified, it's used for ALL RPC operations (both Bitcoin and Sandshrew calls).

### Files Modified

#### 1. src/main.rs
- **Lines 696-702**: Updated wallet loading config to use `sandshrew_rpc_url` for both `bitcoin_rpc_url` and `metashrew_rpc_url`
- **Lines 875-881**: Updated wallet creation config to use `sandshrew_rpc_url` consistently
- **Lines 763-777**: Added journal comments explaining the RPC URL handling logic
- **Lines 809-814**: FIXED wallet loading logic to only load wallet for alkanes commands that need it (Execute and Balance)
- **Lines 1112-1300**: Restructured alkanes command handling to separate RPC-only commands from wallet-requiring commands

#### 2. src/wallet/bitcoin_wallet.rs
- **Lines 2219-2225**: Updated test RPC config to use consistent Sandshrew endpoint (localhost:8080)

#### 3. src/tests/e2e_helpers.rs
- **Lines 141-147**: Updated test environment to use consistent Sandshrew RPC endpoint for both Bitcoin and Metashrew operations

#### 4. src/monitor/mod.rs
- **Line 230**: Changed hardcoded `localhost:18332` to `localhost:8080` (Sandshrew endpoint)

#### 5. src/transaction/mod.rs
- **Line 227**: Changed hardcoded `localhost:18332` to `localhost:8080`
- **Line 235**: Changed hardcoded `localhost:18332` to `localhost:8080`

#### 6. src/rpc/mod.rs
- **Line 1788**: Updated test config to use `localhost:8080`

#### 7. src/tests/demo_rpc_truncation.rs
- **Line 14**: Changed hardcoded `localhost:18332` to `localhost:8080`

#### 8. src/tests/test_rpc_logging_truncation.rs
- **Line 17**: Changed hardcoded `localhost:18332` to `localhost:8080`
- **Line 57**: Changed hardcoded `localhost:18332` to `localhost:8080`

#### 9. src/wallet/mod.rs
- **Line 553**: Changed hardcoded `localhost:18332` to `localhost:8080`

### Key Changes Summary

1. **Eliminated Network Mismatch**: All RPC operations now use the same endpoint when `--sandshrew-rpc-url` is specified
2. **Consistent Test Configuration**: All test files now use `localhost:8080` (Sandshrew) instead of separate Bitcoin RPC endpoints
3. **Preserved Default Behavior**: The default command-line argument and fallback logic in main.rs remain unchanged for backward compatibility
4. **Fixed Wallet Loading Logic**: Only alkanes commands that actually need wallet access (Execute and Balance) will attempt to load the wallet
5. **Separated Command Handling**: RPC-only alkanes commands (getbytecode, trace, inspect, tokeninfo, simulate) now work without wallet loading
6. **Added Documentation**: Journal comments explain the reasoning behind the changes

## Expected Results

With these changes:
1. When using `--sandshrew-rpc-url`, all RPC calls (Bitcoin and Sandshrew) will use the same endpoint
2. Network configuration mismatches should be eliminated
3. Alkanes execution should work properly with correct transaction broadcasting and mining
4. Traces should appear correctly for alkanes deployments
5. The `[3, 797, 101]` cellpack should deploy an alkane to `4:797` and show proper trace events

## Testing

The project builds successfully with no compilation errors. The next step is to test the alkanes execution with the fixed RPC configuration.

## Verification Commands

To verify the fix works:

```bash
# Test with explicit Sandshrew RPC URL
./target/debug/deezel --sandshrew-rpc-url http://localhost:8080 alkanes execute \
  --inputs "B:1000000" \
  --to "p2tr:0" \
  --envelope examples/free_mint.wasm.gz \
  "[3,797,101]" \
  --trace --mine --yes

# Check that all RPC calls go to the same endpoint
# Monitor network traffic to confirm no calls to localhost:8332
```

## Impact

This fix ensures that the deezel CLI tool maintains network consistency throughout all operations, resolving the core issue that was preventing alkanes smart contract deployments from being properly indexed and traced.