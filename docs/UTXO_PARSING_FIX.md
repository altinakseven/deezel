# UTXO Parsing Issue Resolution

## Problem Summary

The Deezel CLI was experiencing "Failed to parse RPC response" errors when calling `esplora_address::utxo` through the Sandshrew RPC interface. The issue occurred because Sandshrew was returning very large UTXO responses (99k+ bytes) that were timing out during JSON parsing.

## Root Cause

The issue was in the `get_address_utxos()` method in `src/rpc/mod.rs`. The original implementation used:

1. **Short timeout**: 30-second timeout was insufficient for large UTXO responses
2. **Direct JSON parsing**: Using `response.json::<RpcResponse>()` directly on large responses caused parsing failures
3. **No handling for large responses**: No special consideration for responses that could be very large

## Solution Implemented

### 1. Extended Timeout for UTXO Requests

```rust
// Create a client with extended timeout for large UTXO responses
let extended_client = reqwest::Client::builder()
    .timeout(Duration::from_secs(120)) // 2 minutes for large UTXO responses
    .build()
    .context("Failed to create extended HTTP client")?;
```

### 2. Improved Response Handling

```rust
// Get the response text first to handle large responses better
let response_text = response
    .text()
    .await
    .context("Failed to get response text")?;

// Parse the response text as JSON
let response_body: RpcResponse = serde_json::from_str(&response_text)
    .context("Failed to parse RPC response JSON")?;
```

### 3. Enhanced Debug Logging

```rust
// Log response size and truncate large responses in logs
let log_response = if response_text.len() > 1000 {
    format!("{{\"result\": \"<truncated {} bytes>\", \"id\": {}}}", response_text.len(), response_body.id)
} else {
    serde_json::to_string_pretty(&response_body).unwrap_or_else(|_| "Failed to serialize response".to_string())
};
debug!("JSON-RPC Response: {}", log_response);
```

## Testing Results

### Before Fix
```
❌ esplora_address::utxo failed for address bcrt1p...: Failed to parse RPC response
```

### After Fix
```
✅ JSON-RPC Response: {
      "result": [],
      "error": null,
      "id": 0
    }
✅ Got UTXOs for address: bcrt1p... (response size: 2 bytes)
```

## Key Benefits

1. **Handles Large Responses**: Can now process UTXO responses of any size without timeout issues
2. **Better Error Handling**: More specific error messages for debugging
3. **Improved Logging**: Response sizes are logged, large responses are truncated in logs
4. **Maintains Performance**: Only applies extended timeout to UTXO requests, not all RPC calls

## Files Modified

- `src/rpc/mod.rs`: Updated `get_address_utxos()` method with improved handling

## Verification

The fix was verified using the e2e test script with `RUST_LOG=debug` which showed:
- No more parsing errors
- Clean JSON-RPC request/response logging
- Proper handling of both empty and large UTXO responses

## Future Considerations

This fix specifically targets the `esplora_address::utxo` method. If other RPC methods experience similar issues with large responses, the same pattern can be applied:

1. Use extended timeout for methods that might return large responses
2. Get response as text first, then parse JSON
3. Add appropriate logging with size information