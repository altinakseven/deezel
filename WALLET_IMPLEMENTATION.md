# Bitcoin Wallet Implementation using BDK and Sandshrew RPC

## Overview

We have successfully implemented a comprehensive Bitcoin wallet using the Bitcoin Development Kit (BDK) with Sandshrew RPC support for esplora and ord interfaces. This implementation provides a full-featured CLI wallet with extensive functionality.

## Key Features Implemented

### 1. Wallet Management
- **Create new wallets** with mnemonic generation
- **Restore wallets** from existing mnemonic phrases
- **Backup functionality** to display mnemonic phrases
- **Persistent wallet storage** with JSON serialization
- **Multiple address generation** support

### 2. Transaction Operations
- **Send Bitcoin** to addresses with custom fee rates
- **Send all funds** functionality
- **Create transactions** without broadcasting
- **Sign transactions** (framework in place)
- **Broadcast transactions** via Sandshrew RPC
- **Transaction history** viewing
- **Transaction details** lookup

### 3. UTXO Management
- **List all UTXOs** with detailed information
- **Freeze/unfreeze UTXOs** for coin control
- **UTXO filtering** in transaction creation
- **Address-based UTXO tracking**

### 4. Fee Management
- **Fee rate estimation** via Sandshrew RPC
- **Custom fee rate** specification
- **Fee calculation** for transactions
- **Current network fee rates** display

### 5. Blockchain Integration
- **Sandshrew RPC integration** for esplora functionality
- **Bitcoin Core RPC** support
- **Wallet synchronization** with blockchain
- **Address transaction history** via esplora interface
- **Mempool transaction** monitoring

## CLI Commands Available

### Wallet Commands
```bash
# Wallet Management
deezel wallet create [--mnemonic <MNEMONIC>] [--passphrase <PASSPHRASE>]
deezel wallet restore <MNEMONIC> [--passphrase <PASSPHRASE>]
deezel wallet info
deezel wallet backup

# Address Management
deezel wallet addresses [--count <COUNT>]

# Balance and Sync
deezel wallet balance
deezel wallet sync

# Transaction Operations
deezel wallet send <ADDRESS> <AMOUNT> [--fee-rate <RATE>]
deezel wallet send-all <ADDRESS> [--fee-rate <RATE>]
deezel wallet create-tx <ADDRESS> <AMOUNT> [--fee-rate <RATE>]
deezel wallet sign-tx <TX_HEX>
deezel wallet broadcast-tx <TX_HEX>

# UTXO Management
deezel wallet utxos
deezel wallet freeze-utxo <TXID> <VOUT>
deezel wallet unfreeze-utxo <TXID> <VOUT>

# Transaction History
deezel wallet history [--limit <LIMIT>]
deezel wallet tx-details <TXID>

# Fee Estimation
deezel wallet estimate-fee <ADDRESS> <AMOUNT>
deezel wallet fee-rates
```

### Legacy Commands (Still Available)
```bash
# Basic wallet info (legacy)
deezel walletinfo

# Metashrew/Sandshrew RPC
deezel metashrew height
deezel bitcoind getblockcount

# Alkanes/Protorunes
deezel alkanes protorunesbyaddress <ADDRESS>
deezel alkanes spendablesbyaddress <ADDRESS>
deezel view spendablesbyaddress <ADDRESS>

# Runestone Analysis
deezel runestone <TXID_OR_HEX>
```

## Technical Implementation Details

### 1. BDK Integration
- Uses **Native SegWit (bech32)** addresses by default
- **HD wallet** implementation with proper derivation paths
- **Mnemonic-based** wallet creation and restoration
- **Memory database** for wallet state (can be extended to persistent storage)

### 2. Sandshrew RPC Integration
- **Esplora API** mapping via JSON-RPC
- **Ord interface** for inscriptions and runes
- **Custom backend** implementation for BDK
- **Fee estimation** via network APIs

### 3. Network Support
- **Configurable networks** (mainnet, testnet, signet, regtest)
- **Provider-based** RPC URL configuration
- **Network magic** value support
- **Cross-network** compatibility

### 4. Data Structures
```rust
// Wallet configuration
pub struct WalletConfig {
    pub wallet_path: String,
    pub network: Network,
    pub bitcoin_rpc_url: String,
    pub metashrew_rpc_url: String,
}

// Transaction parameters
pub struct SendParams {
    pub address: String,
    pub amount: u64,
    pub fee_rate: Option<f32>,
    pub send_all: bool,
}

// UTXO information
pub struct UtxoInfo {
    pub txid: String,
    pub vout: u32,
    pub amount: u64,
    pub address: String,
    pub confirmations: u32,
    pub frozen: bool,
}
```

### 5. Error Handling
- **Comprehensive error handling** with anyhow
- **Context-aware error messages**
- **Graceful fallbacks** for network issues
- **User-friendly error reporting**

## Usage Examples

### Create a New Wallet
```bash
# Generate new wallet with random mnemonic
deezel wallet create

# Create wallet with specific mnemonic
deezel wallet create --mnemonic "word1 word2 ... word12"

# Create wallet with passphrase protection
deezel wallet create --passphrase "my-secure-passphrase"
```

### Send Bitcoin
```bash
# Send specific amount
deezel wallet send bc1qexampleaddress 100000

# Send with custom fee rate
deezel wallet send bc1qexampleaddress 100000 --fee-rate 5.0

# Send all available funds
deezel wallet send-all bc1qexampleaddress
```

### UTXO Management
```bash
# List all UTXOs
deezel wallet utxos

# Freeze a specific UTXO
deezel wallet freeze-utxo abc123...def 0

# Unfreeze a UTXO
deezel wallet unfreeze-utxo abc123...def 0
```

## Configuration

### Default Settings
- **Wallet file**: `wallet.dat`
- **Network**: Configurable via provider
- **Bitcoin RPC**: `http://bitcoinrpc:bitcoinrpc@localhost:8332`
- **Sandshrew RPC**: Provider-dependent
- **Log level**: `info`

### Provider Configuration
```bash
# Use mainnet
deezel --provider mainnet wallet info

# Use testnet
deezel --provider testnet wallet info

# Use custom RPC URLs
deezel --bitcoin-rpc-url http://custom:8332 --sandshrew-rpc-url http://custom:8080 wallet info
```

## Security Features

1. **Mnemonic-based** wallet creation following BIP39
2. **HD wallet** derivation following BIP84 (Native SegWit)
3. **Passphrase protection** support
4. **Local wallet storage** with JSON serialization
5. **UTXO freezing** for enhanced coin control
6. **Fee rate validation** and estimation

## Future Enhancements

1. **Hardware wallet** integration
2. **Multi-signature** wallet support
3. **Persistent database** backend (SQLite/RocksDB)
4. **Watch-only** wallet functionality
5. **Batch transaction** creation
6. **Advanced coin selection** algorithms
7. **Wallet encryption** at rest
8. **Backup/restore** to/from files

## Dependencies

- **BDK 0.30.2** - Bitcoin Development Kit
- **Bitcoin 0.32.6** - Bitcoin protocol implementation
- **Tokio** - Async runtime
- **Clap** - CLI argument parsing
- **Anyhow** - Error handling
- **Serde** - Serialization
- **Reqwest** - HTTP client for RPC calls

This implementation provides a solid foundation for Bitcoin wallet operations with modern Rust practices and comprehensive CLI functionality.