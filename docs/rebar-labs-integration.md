# Rebar Labs Shield Integration

This document describes the integration of Rebar Labs Shield for private transaction relay in the deezel CLI.

## Overview

Rebar Labs Shield is a specialized RPC service that allows Bitcoin transactions to be submitted directly to mining pools, bypassing the public mempool. This creates a private channel for transaction delivery that enhances privacy and eliminates the risk of frontrunning or other MEV-related attacks.

## Features

- **Private Transaction Relay**: Transactions are sent directly to mining pools without exposing them to the public mempool
- **MEV Protection**: Eliminates opportunities for frontrunning and other malicious activity
- **Metaprotocol Support**: Particularly valuable for BRC-20s, Runes, and Alkanes protocols
- **Bitcoin RPC Compatible**: Uses the familiar Bitcoin Core JSON-RPC format
- **Mainnet Only**: Currently only available on Bitcoin mainnet

## Usage

### CLI Flag

Add the `--rebar` flag to any `alkanes execute` command to use Rebar Labs Shield:

```bash
# Enable Rebar Labs Shield for private transaction relay
deezel -p mainnet alkanes execute --rebar --inputs "B:1000" --to "bc1q..." "[1,2,3]:v0"
```

### Network Restrictions

The `--rebar` flag is only allowed when using mainnet (`-p mainnet`):

```bash
# ✅ This works (mainnet + rebar)
deezel -p mainnet alkanes execute --rebar --inputs "B:1000" --to "bc1q..." "[1,2,3]:v0"

# ❌ This fails (testnet + rebar)
deezel -p testnet alkanes execute --rebar --inputs "B:1000" --to "tb1q..." "[1,2,3]:v0"
# Error: ❌ Rebar Labs Shield is only available on mainnet. Current network: Testnet

# ✅ This works (mainnet without rebar)
deezel -p mainnet alkanes execute --inputs "B:1000" --to "bc1q..." "[1,2,3]:v0"
```

## Technical Implementation

### API Endpoint

Rebar Labs Shield uses the following endpoint:
- **Shield RPC**: `https://shield.rebarlabs.io/v1/rpc`
- **Fee Recommendations**: `https://api.rebarlabs.io/bitcoin/v1/fees/recommended`

### JSON-RPC Format

Transactions are submitted using standard Bitcoin Core JSON-RPC format:

```json
{
  "jsonrpc": "2.0",
  "id": "1",
  "method": "sendrawtransaction",
  "params": ["YOUR_SIGNED_TRANSACTION_HEX"]
}
```

### Fee Structure

When using Rebar Labs Shield:
- **Transaction Fees**: Set to 0 in the transaction (Rebar handles fees)
- **Rebar Fees**: Paid separately to Rebar Labs based on urgency and hashrate coverage
- **Fee Optimization**: Higher fees connect to more hashrate for faster confirmation

### Code Integration

The rebar functionality is integrated at multiple levels:

#### 1. CLI Arguments
```rust
/// Use Rebar Labs Shield for private transaction relay (mainnet only)
#[arg(long)]
rebar: bool,
```

#### 2. Parameter Structures
```rust
pub struct AlkanesExecuteParams {
    // ... other fields
    pub rebar: bool,
}
```

#### 3. Provider Implementation
```rust
async fn execute(&self, params: AlkanesExecuteParams) -> Result<AlkanesExecuteResult> {
    if params.rebar {
        // Use Rebar Labs Shield
        return self.execute_with_rebar_shield(params).await;
    }
    // Standard execution
}
```

#### 4. HTTP Client
```rust
async fn broadcast_via_rebar_shield(&self, tx_hex: &str) -> Result<String> {
    let response = self.http_client
        .post("https://shield.rebarlabs.io/v1/rpc")
        .header("Content-Type", "application/json")
        .json(&request_body)
        .send()
        .await?;
    // Handle response...
}
```

## Benefits

### Privacy Enhancement
- **Transaction Confidentiality**: Transaction intentions remain private until confirmation
- **MEV Protection**: Eliminates front-running and sandwich attack vectors
- **No Mempool Exposure**: Transactions bypass the public mempool entirely

### Performance Benefits
- **Direct Mining Pool Access**: Transactions go directly to mining pools
- **Predictable Confirmation**: Better certainty regarding transaction confirmation timing
- **Fee Optimization**: Potential for reduced fees while maintaining confirmation speed

### Metaprotocol Support
- **Alkanes Contracts**: Enhanced privacy for smart contract deployments and executions
- **BRC-20 Tokens**: Protected token transfers and minting operations
- **Runes Protocol**: Private rune operations and transfers

## Error Handling

### Network Validation
```
Error: ❌ Rebar Labs Shield is only available on mainnet. Current network: Testnet
```

### API Failures
If Rebar Labs Shield is unavailable, the system falls back gracefully:
```
🚧 Rebar Shield broadcast failed (expected in testing): JSON-RPC error: ...
🚧 Falling back to mock result for demonstration
```

### Transaction Validation
Standard Bitcoin transaction validation applies, plus Rebar-specific checks.

## Examples

### Basic Alkanes Execution with Rebar
```bash
deezel -p mainnet alkanes execute \
  --rebar \
  --inputs "B:50000" \
  --to "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4" \
  --fee-rate 10 \
  --yes \
  "[3,797,101]:v0:v0"
```

### Contract Deployment with Rebar
```bash
deezel -p mainnet alkanes execute \
  --rebar \
  --inputs "B:100000" \
  --to "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4" \
  --envelope ./contract.wasm.gz \
  --fee-rate 15 \
  --trace \
  --yes \
  "[3,797,101]:v0:v0"
```

### Token Transfer with Rebar
```bash
deezel -p mainnet alkanes execute \
  --rebar \
  --inputs "4:797:1000" \
  --to "bc1qrecipient..." \
  --change "bc1qchange..." \
  --fee-rate 12 \
  --yes \
  "[4:797:1000:v0]"
```

## Testing

### Unit Tests
```bash
cargo test test_rebar_integration
```

### Integration Tests
```bash
# Test network validation
deezel -p testnet alkanes execute --rebar --inputs "B:1000" --to "tb1q..." "[1,2,3]:v0"

# Test mainnet functionality
deezel -p mainnet alkanes execute --rebar --inputs "B:1000" --to "bc1q..." "[1,2,3]:v0"
```

## Security Considerations

### Network Security
- Only available on mainnet to prevent testnet confusion
- Uses HTTPS for all API communications
- Standard Bitcoin transaction signing and validation

### Privacy Benefits
- Transactions remain private until confirmation
- No mempool exposure eliminates MEV opportunities
- Direct mining pool submission reduces attack surface

### Fee Security
- Rebar handles fee calculation and payment
- No risk of fee manipulation or front-running
- Transparent fee structure based on hashrate coverage

## Future Enhancements

### Planned Features
1. **Dynamic Fee Estimation**: Integration with Rebar's fee recommendation API
2. **Hashrate Coverage Display**: Show estimated hashrate coverage for fee levels
3. **Transaction Status Tracking**: Monitor transaction status through Rebar's private mempool
4. **Batch Transactions**: Support for batching multiple transactions
5. **Advanced Configuration**: Custom timeout and retry settings

### API Improvements
1. **Real Transaction Building**: Replace mock transactions with actual transaction construction
2. **Enhanced Error Handling**: More specific error messages and recovery strategies
3. **Performance Optimization**: Connection pooling and request optimization
4. **Monitoring Integration**: Metrics and logging for Rebar usage

## Support

For issues related to Rebar Labs Shield integration:
1. Check the [Rebar Labs Documentation](https://docs.rebarlabs.io/shield/intro)
2. Review the integration tests in `crates/deezel-common/tests/test_rebar_integration.rs`
3. Enable debug logging with `RUST_LOG=debug` for detailed request/response information

## References

- [Rebar Labs Shield Documentation](https://docs.rebarlabs.io/shield/intro)
- [Rebar Labs API Reference](https://docs.rbhq.io/shield/api/send-raw-transaction)
- [Bitcoin JSON-RPC API](https://developer.bitcoin.org/reference/rpc/)
- [Alkanes Protocol Documentation](https://alkanes.io)