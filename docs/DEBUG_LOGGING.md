# Debug Logging for JSON-RPC Requests and Responses

The Deezel CLI now includes comprehensive debug logging for all JSON-RPC requests and responses. This feature helps with debugging, development, and understanding the communication between the CLI and RPC servers.

## Quick Start

Enable debug logging by setting the `RUST_LOG` environment variable:

```bash
# Show all debug output including RPC requests/responses
RUST_LOG=debug ./deezel bitcoind getblockcount

# Show only RPC module debug output
RUST_LOG=deezel_cli::rpc=debug ./deezel metashrew height

# Save debug output to a file
RUST_LOG=debug ./deezel walletinfo 2> debug.log
```

## What Gets Logged

### Request Logging
For each JSON-RPC request, you'll see:
- 🎯 **Target URL**: Which RPC server (Bitcoin or Metashrew)
- 📝 **Method Name**: The RPC method being called
- 📦 **Request Payload**: Complete JSON-RPC request with parameters
- 🆔 **Request ID**: Unique identifier for tracking

Example request log:
```
[DEBUG deezel_cli::rpc] Calling RPC method: btc_getblockcount
[DEBUG deezel_cli::rpc] JSON-RPC Request to http://bitcoinrpc:bitcoinrpc@localhost:8332: {
  "jsonrpc": "1.0",
  "method": "btc_getblockcount",
  "params": [],
  "id": 1
}
```

### Response Logging
For each JSON-RPC response, you'll see:
- 📨 **Response Payload**: Complete JSON-RPC response
- ✅ **Result Data**: The actual response data
- ❌ **Error Information**: Any errors that occurred
- 🆔 **Response ID**: Matching the request ID

Example response log:
```
[DEBUG deezel_cli::rpc] JSON-RPC Response: {
  "result": 150,
  "error": null,
  "id": 1
}
```

## RPC Methods Covered

The debug logging covers all RPC methods used by the CLI:

### Bitcoin RPC Methods
- `btc_getblockcount` - Get current block height
- `btc_getrawtransaction` - Get transaction data
- `btc_sendrawtransaction` - Broadcast transactions
- `generatetoaddress` - Generate blocks (regtest)

### Metashrew RPC Methods
- `metashrew_height` - Get Metashrew block height
- `metashrew_view` - Generic view method for:
  - `protorunesbyaddress` - Get protorunes by address
  - `protorunesbyoutpoint` - Get protorunes by outpoint
  - `spendablesbyaddress` - Get spendable UTXOs
  - `getbytecode` - Get contract bytecode
  - `trace` - Trace alkanes execution
  - `simulate` - Simulate contract execution

### Esplora Methods
- `esplora_tx::hex` - Get transaction hex
- `esplora_tx::raw` - Get raw transaction
- `esplora_address::utxo` - Get address UTXOs
- `esplora_address::txs` - Get address transactions
- `esplora_fee:estimates` - Get fee estimates

### Ordinals Methods
- `ord_address` - Get ordinal inscriptions
- `ord_content` - Get inscription content
- `ord_output` - Get ordinal output info

## Log Levels

### `RUST_LOG=debug`
Shows all debug information including:
- RPC requests and responses
- Method entry/exit points
- Data processing steps
- Error details

### `RUST_LOG=info`
Shows high-level operations:
- Command execution
- Success/failure status
- Summary information

### `RUST_LOG=trace`
Shows the most detailed output:
- All debug information
- Internal function calls
- Detailed error traces

## Filtering Logs

### Module-Specific Logging
```bash
# Only RPC module debug logs
RUST_LOG=deezel_cli::rpc=debug ./deezel <command>

# Only wallet module debug logs
RUST_LOG=deezel_cli::wallet=debug ./deezel <command>

# Multiple modules
RUST_LOG=deezel_cli::rpc=debug,deezel_cli::wallet=info ./deezel <command>
```

### Method-Specific Filtering
```bash
# Filter logs in your terminal
RUST_LOG=debug ./deezel <command> 2>&1 | grep "JSON-RPC"

# Save only RPC logs
RUST_LOG=debug ./deezel <command> 2>&1 | grep -E "(Request|Response)" > rpc.log
```

## Use Cases

### 🐛 Debugging RPC Connectivity
When RPC calls fail, debug logs show:
- Exact request being sent
- HTTP status codes
- Error responses from servers
- Network timeout issues

### 🔍 Understanding API Formats
Debug logs help you understand:
- Required parameters for each method
- Response data structures
- Protobuf encoding/decoding
- Error message formats

### 📊 Monitoring API Usage
Track which APIs are being called:
- Frequency of different RPC methods
- Request/response sizes
- Performance characteristics
- Error rates

### 🧪 Development and Testing
During development:
- Verify correct parameter passing
- Check response parsing
- Test error handling
- Validate protocol compliance

## Examples

### Basic Usage
```bash
# Get block count with debug logging
RUST_LOG=debug ./deezel bitcoind getblockcount

# Check wallet balance with RPC details
RUST_LOG=debug ./deezel wallet balance

# Trace an alkanes transaction
RUST_LOG=debug ./deezel view trace abc123:0
```

### Advanced Usage
```bash
# Save all debug output to file
RUST_LOG=debug ./deezel walletinfo 2> full-debug.log

# Show only RPC calls, pipe to jq for formatting
RUST_LOG=debug ./deezel <command> 2>&1 | grep "JSON-RPC" | jq .

# Monitor RPC calls in real-time
RUST_LOG=debug ./deezel <command> 2>&1 | grep --line-buffered "JSON-RPC"
```

### Troubleshooting
```bash
# Debug connection issues
RUST_LOG=debug ./deezel --bitcoin-rpc-url http://localhost:8332 bitcoind getblockcount

# Debug protobuf encoding issues
RUST_LOG=debug ./deezel view protorunesbyaddress bc1q... --protocol-tag 1

# Debug wallet operations
RUST_LOG=debug ./deezel wallet send bc1q... 100000 --fee-rate 5
```

## Implementation Details

The debug logging is implemented in [`src/rpc/mod.rs`](../src/rpc/mod.rs) with:

- **Request logging** in the `_call()` and `call_rpc()` methods
- **Pretty-printed JSON** for readability
- **Error-safe serialization** that won't crash on malformed data
- **Consistent format** across all RPC methods
- **Performance-conscious** logging that only activates when debug level is enabled

## Security Considerations

⚠️ **Warning**: Debug logs may contain sensitive information:
- RPC URLs with authentication credentials
- Bitcoin addresses and transaction data
- Wallet information and balances

**Recommendations**:
- Don't share debug logs publicly
- Redact sensitive information before sharing
- Use log filtering to exclude sensitive methods
- Be careful with log files in production environments

## Performance Impact

Debug logging has minimal performance impact:
- ✅ Only active when `RUST_LOG=debug` is set
- ✅ JSON serialization is lazy (only when needed)
- ✅ No impact on normal CLI operation
- ✅ Async logging doesn't block RPC calls

For production use, stick to `RUST_LOG=info` or `RUST_LOG=warn` levels.