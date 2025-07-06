# Esplora API Commands

The deezel CLI now includes a comprehensive `esplora` subcommand that provides access to all Esplora API endpoints. This allows you to query blockchain data, transaction information, address details, and more directly from the command line.

## Overview

The esplora subcommand translates CLI commands to the appropriate RPC method calls that interface with the Sandshrew/Metashrew server's esplora endpoints. All commands support address identifier resolution, allowing you to use wallet address identifiers like `[self:p2tr:0]` or shorthand forms like `p2tr:0`.

## Command Categories

### Block Information

#### Get Blocks Tip Information
```bash
# Get the hash of the latest block
deezel esplora blocks-tip-hash

# Get the height of the latest block
deezel esplora blocks-tip-height
```

#### Get Block Information
```bash
# Get blocks starting from a specific height
deezel esplora blocks [start_height]

# Get block hash by height
deezel esplora block-height 800000

# Get complete block information by hash
deezel esplora block 00000000000000000002a7c4c1e48d76c5a37902165a270156b7a8d72728a054

# Get block status
deezel esplora block-status 00000000000000000002a7c4c1e48d76c5a37902165a270156b7a8d72728a054

# Get block transaction IDs
deezel esplora block-txids 00000000000000000002a7c4c1e48d76c5a37902165a270156b7a8d72728a054

# Get block header (hex)
deezel esplora block-header 00000000000000000002a7c4c1e48d76c5a37902165a270156b7a8d72728a054

# Get raw block data
deezel esplora block-raw 00000000000000000002a7c4c1e48d76c5a37902165a270156b7a8d72728a054

# Get specific transaction ID from block by index
deezel esplora block-txid 00000000000000000002a7c4c1e48d76c5a37902165a270156b7a8d72728a054 0

# Get block transactions with optional start index
deezel esplora block-txs 00000000000000000002a7c4c1e48d76c5a37902165a270156b7a8d72728a054
deezel esplora block-txs 00000000000000000002a7c4c1e48d76c5a37902165a270156b7a8d72728a054 25
```

### Address Information

#### Basic Address Queries
```bash
# Get address information (supports address identifiers)
deezel esplora address bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
deezel esplora address [self:p2tr]
deezel esplora address p2tr:0

# Get address transactions
deezel esplora address-txs bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
deezel esplora address-txs [self:p2tr:1]

# Get address chain transactions (with optional last seen txid)
deezel esplora address-txs-chain bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
deezel esplora address-txs-chain bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4:4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b

# Get address mempool transactions
deezel esplora address-txs-mempool bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
deezel esplora address-txs-mempool [self:p2tr]

# Get address UTXOs
deezel esplora address-utxo bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
deezel esplora address-utxo [self:p2tr:0]
deezel esplora address-utxo p2wpkh:1

# Search addresses by prefix
deezel esplora address-prefix bc1qw508
```

### Transaction Information

#### Basic Transaction Queries
```bash
# Get complete transaction information
deezel esplora tx 4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b

# Get transaction hex
deezel esplora tx-hex 4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b

# Get raw transaction data
deezel esplora tx-raw 4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b

# Get transaction status
deezel esplora tx-status 4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b
```

#### Transaction Proofs and Spends
```bash
# Get transaction merkle proof
deezel esplora tx-merkle-proof 4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b

# Get transaction merkle block proof
deezel esplora tx-merkleblock-proof 4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b

# Get specific output spend status
deezel esplora tx-outspend 4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b 0

# Get all output spends for a transaction
deezel esplora tx-outspends 4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b
```

### Mempool Information

```bash
# Get mempool statistics
deezel esplora mempool

# Get all mempool transaction IDs
deezel esplora mempool-txids

# Get recent mempool transactions
deezel esplora mempool-recent
```

### Fee Information

```bash
# Get current fee estimates
deezel esplora fee-estimates
```

### Broadcasting

```bash
# Broadcast a transaction
deezel esplora broadcast 0200000001...

# Alternative broadcast method
deezel esplora post-tx 0200000001...
```

## Address Identifier Support

The esplora commands support the same address identifier system used throughout deezel:

### Full Format Identifiers
- `[self:p2tr]` - Your wallet's default taproot address
- `[self:p2tr:0]` - Your wallet's first taproot address (index 0)
- `[self:p2wpkh:1]` - Your wallet's second native segwit address (index 1)
- `[self:mainnet:p2tr]` - Network-specific address
- `[self:testnet:p2tr:5]` - Network-specific address with index

### Shorthand Format
- `p2tr` - Equivalent to `[self:p2tr]`
- `p2tr:0` - Equivalent to `[self:p2tr:0]`
- `p2wpkh:1` - Equivalent to `[self:p2wpkh:1]`

### Supported Address Types
- `p2tr` - Taproot (P2TR)
- `p2wpkh` - Native SegWit (P2WPKH)
- `p2pkh` - Legacy (P2PKH)
- `p2sh` - Script Hash (P2SH)
- `p2wsh` - Native SegWit Script Hash (P2WSH)

## Examples

### Check Your Wallet's UTXOs
```bash
# Get UTXOs for your default taproot address
deezel esplora address-utxo [self:p2tr]

# Get UTXOs for a specific address index
deezel esplora address-utxo p2tr:5
```

### Monitor Address Activity
```bash
# Get all transactions for an address
deezel esplora address-txs [self:p2wpkh]

# Get only mempool transactions
deezel esplora address-txs-mempool [self:p2tr:0]
```

### Analyze Transaction Details
```bash
# Get full transaction details
deezel esplora tx 4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b

# Check if outputs are spent
deezel esplora tx-outspends 4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b

# Get transaction status and confirmations
deezel esplora tx-status 4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b
```

### Get Current Network Information
```bash
# Get latest block information
deezel esplora blocks-tip-height
deezel esplora blocks-tip-hash

# Get current fee estimates
deezel esplora fee-estimates

# Check mempool status
deezel esplora mempool
```

## Integration with Other Commands

The esplora commands work seamlessly with other deezel functionality:

```bash
# Use with wallet operations
deezel wallet utxos --addresses p2tr:0,p2wpkh:1
deezel esplora address-utxo p2tr:0

# Use with alkanes operations
deezel alkanes balance --address [self:p2tr]
deezel esplora address [self:p2tr]

# Use with transaction broadcasting
deezel wallet create-tx [self:p2tr] 100000 --fee-rate 10
# ... get transaction hex ...
deezel esplora broadcast <tx_hex>
```

## Error Handling

The esplora commands provide clear error messages and handle common scenarios:

- **Address Resolution**: If an address identifier cannot be resolved, you'll get a clear error message
- **Network Errors**: Connection issues with the RPC server are reported with context
- **Invalid Parameters**: Malformed transaction IDs, block hashes, or other parameters are validated
- **Not Found**: When querying non-existent transactions, blocks, or addresses, appropriate error messages are shown

## Output Formats

All esplora commands output JSON data that can be:
- Viewed directly in the terminal with pretty formatting
- Piped to other commands for processing
- Used in scripts for automation

Example output processing:
```bash
# Get fee estimates and extract specific confirmation target
deezel esplora fee-estimates | jq '.["6"]'

# Get address UTXOs and count them
deezel esplora address-utxo [self:p2tr] | jq 'length'

# Get transaction status and check confirmation count
deezel esplora tx-status <txid> | jq '.block_height'
```

This comprehensive esplora integration makes deezel a powerful tool for Bitcoin blockchain analysis and interaction.