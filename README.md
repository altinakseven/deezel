# Deezel - Alkanes CLI and Tooling Suite

Deezel is a comprehensive command-line interface and tooling suite for interacting with Bitcoin and the Alkanes metaprotocol. It provides wallet management, smart contract deployment, to ken  operations, AMM functionality, and advanced blockchain analysis capabilities.

## Features

### 🏦 Bitcoin Wallet Management
- **HD Wallet Support**: BIP39 mnemonic-based wallets with hierarchical deterministic key derivation
- **Multi-Network Support**: Bitcoin mainnet, testnet, signet, regtest, and custom networks
- **Encrypted Storage**: GPG-encrypted or PBKDF2-encrypted wallet files
- **UTXO Management**: Advanced UTXO tracking, freezing, and management
- **Transaction Construction**: Create, sign, and broadcast Bitcoin transactions
- **Fee Estimation**: Dynamic fee rate estimation and optimization
- **Address Identifiers**: Smart address resolution system for wallet addresses

### 🔗 Alkanes Metaprotocol Integration
- **Smart Contract Deployment**: Deploy WASM-based smart contracts to the Alkanes metaprotocol
- **Token Operations**: Deploy, mint, and transfer Alkanes tokens
- **AMM/DEX Functionality**: Create liquidity pools, add/remove liquidity, and perform token swaps
- **Contract Execution**: Advanced execute command with complex protostone parsing and UTXO selection
- **Envelope Support**: Commit-reveal transactions for large contract deployments using official alkanes-support
- **Transaction Preview**: Preview transactions before signing with detailed output analysis
- **Advanced Simulation**: Simulate contract executions with comprehensive result analysis

### 🔍 Blockchain Analysis Tools
- **Runestone Decoder**: Comprehensive decoding of Runestone transactions and Protostones
- **Transaction Tracing**: Trace Alkanes transactions and analyze their effects
- **Contract Inspection**: Advanced WASM contract analysis with disassembly and fuzzing capabilities
- **Balance Queries**: Query Alkanes token balances and Bitcoin UTXOs
- **Block Data Access**: Access block data and transaction information

### 🛠️ Developer Tools
- **RPC Integration**: Direct access to Bitcoin Core and Metashrew RPC endpoints
- **Debug Logging**: Comprehensive JSON-RPC request/response logging with `RUST_LOG=debug`
- **Network Flexibility**: Support for multiple Bitcoin networks and custom configurations
- **Scripting Support**: Raw JSON output modes for integration with scripts and automation
- **Transaction Preview**: Preview all transactions before signing with detailed analysis
- **Custom Change Addresses**: Specify custom change addresses for all send operations
- **Comprehensive Logging**: Detailed logging with configurable levels

## Architecture

The project is organized into several core modules:

- **`wallet/`**: Bitcoin wallet functionality using BDK with custom blockchain backends
- **`alkanes/`**: Alkanes metaprotocol integration including contracts, tokens, AMM, and envelope support
- **`rpc/`**: RPC client implementations for Bitcoin Core and Metashrew
- **`monitor/`**: Blockchain monitoring and event handling
- **`transaction/`**: Transaction construction and management with preview capabilities

## Getting Started

### Prerequisites

- Rust 1.70 or later
- Access to a Bitcoin node (for Bitcoin RPC operations)
- Access to a Metashrew/Sandshrew node (for Alkanes operations)

### Installation

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd deezel
   ```

2. Build the project:
   ```bash
   cargo build --release
   ```

3. The binary will be available at `target/release/deezel`

### Quick Start

#### Create a Wallet

```bash
# Create a new GPG-encrypted wallet
./deezel --wallet-file ~/.deezel/mainnet.json.asc wallet create

# Create a wallet with a specific mnemonic
./deezel --wallet-file ~/.deezel/mainnet.json.asc wallet create --mnemonic "your twelve word mnemonic phrase here"
```

#### Check Wallet Information

```bash
# Show wallet info including Bitcoin and Alkanes balances
./deezel --wallet-file ~/.deezel/mainnet.json.asc wallet info

# Get wallet addresses
./deezel --wallet-file ~/.deezel/mainnet.json.asc wallet addresses --count 5
```

#### Alkanes Operations

```bash
# Check Alkanes token balances
./deezel --provider mainnet alkanes balance

# Get token information
./deezel --provider mainnet alkanes token-info 2:0

# Deploy a new token
./deezel --provider mainnet alkanes deploy-token \
  --name "MyToken" \
  --symbol "MTK" \
  --cap 1000000 \
  --amount-per-mint 100 \
  --reserve-number 1

# Send tokens
./deezel --provider mainnet alkanes send-token \
  --token 2:0 \
  --amount 100 \
  --to [self:p2tr]
```

#### Blockchain Analysis

```bash
# Decode a Runestone transaction
./deezel --provider mainnet runestone <txid>

# Trace an Alkanes transaction
./deezel --provider mainnet view trace <txid:vout>

# Inspect a smart contract
./deezel --provider mainnet inspect-alkane 2:0 --disasm --meta
```

## Command Reference

### Global Options

- `--provider <PROVIDER>`: Network provider (mainnet, signet, localhost, or custom URL)
- `--wallet-file <PATH>`: Path to wallet file (supports .asc for GPG or .json for PBKDF2)
- `--passphrase <PASS>`: Passphrase for non-interactive encryption
- `--log-level <LEVEL>`: Logging level (error, warn, info, debug, trace)

### Wallet Commands

```bash
# Wallet management
deezel wallet create [--mnemonic <MNEMONIC>]
deezel wallet restore <MNEMONIC>
deezel wallet info
deezel wallet balance [--addresses <ADDRESSES>]
deezel wallet addresses [--count <N>]
deezel wallet sync

# Enhanced address listing with range notation and raw addresses
deezel walletinfo --addresses "p2tr:0-10,p2pkh:5"
deezel walletinfo --addresses "p2tr:100"
deezel walletinfo --addresses "p2tr:0-500,p2sh:100,p2wpkh:0-50"
deezel walletinfo --addresses "p2tr:0-5,bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"

# Enhanced balance checking with address-specific queries
deezel wallet balance  # Default: checks all address types at index 0
deezel wallet balance --addresses "p2tr:0-10,p2pkh:0-5"
deezel wallet balance --addresses "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
deezel wallet balance --addresses "p2tr:0-5,bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4,p2pkh:10"

# Transaction operations
deezel wallet send <ADDRESS> <AMOUNT> [--fee-rate <RATE>] [--change <ADDRESS>]
deezel wallet send-all <ADDRESS> [--fee-rate <RATE>] [--change <ADDRESS>]
deezel wallet create-tx <ADDRESS> <AMOUNT> [--fee-rate <RATE>] [--change <ADDRESS>]
deezel wallet broadcast-tx <TX_HEX>

# Examples with address identifiers and custom change addresses
deezel wallet send [self:p2tr] 100000 --fee-rate 5 --change [self:p2tr:1]
deezel wallet send-all [self:p2pkh:1] --fee-rate 3 --change [self:p2tr:0]
deezel wallet create-tx [self:testnet:p2tr:2] 50000 --change [self:testnet:p2tr:3]

# Generate blocks to address identifiers (regtest)
deezel bitcoind generatetoaddress --nblocks 10 --address [self:p2tr:0]

# UTXO management
deezel wallet utxos
deezel wallet freeze-utxo <TXID> <VOUT>
deezel wallet unfreeze-utxo <TXID> <VOUT>
deezel wallet history [--limit <N>]

# List supported address identifiers
deezel wallet list-identifiers
```

#### Enhanced Address Listing and Balance Checking

The `walletinfo --addresses` command provides detailed address information with HD paths and identifiers, and the `wallet balance --addresses` command allows checking balances for specific addresses:

**Address Specification Format:**
- `type:start-end` - Range of addresses (e.g., `p2tr:0-10` for addresses 0 through 10)
- `type:index` - Single address (e.g., `p2pkh:5` for address at index 5)
- Raw Bitcoin addresses - Any valid Bitcoin address (e.g., `bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4`)
- Multiple entries separated by commas

**Output Format:**
For each address, the command displays:
- **Index**: The derivation index
- **Address**: The actual Bitcoin address
- **Identifier**: The deezel identifier (e.g., `[self:p2tr:0]`)
- **HD Path**: The full BIP derivation path (e.g., `m/86'/0'/0'/0/0`)

**Examples:**
```bash
# List first 10 Taproot addresses and address at P2PKH index 5
deezel walletinfo --addresses "p2tr:0-10,p2pkh:5"

# List a single Taproot address at index 100
deezel walletinfo --addresses "p2tr:100"

# List multiple address types and ranges
deezel walletinfo --addresses "p2tr:0-500,p2sh:100,p2wpkh:0-50"

# Mix wallet addresses and raw Bitcoin addresses
deezel walletinfo --addresses "p2tr:0-5,bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4,p2pkh:10"

# Check balances for specific addresses (default: all types at index 0)
deezel wallet balance

# Check balances for specific wallet addresses
deezel wallet balance --addresses "p2tr:0-10,p2pkh:0-5"

# Check balance for raw Bitcoin addresses
deezel wallet balance --addresses "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4,1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"

# Mix wallet and raw addresses for balance checking
deezel wallet balance --addresses "p2tr:0-5,bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4,p2pkh:10"
```

**Limitations:**
- Maximum 1000 addresses per range for performance reasons
- Requires an initialized wallet to generate addresses

### Address Identifiers

Deezel supports smart address identifiers that automatically resolve to wallet addresses, making it easy to use different address types without manually generating them.

#### Supported Identifier Patterns

**Basic Address Types:**
- `[self:p2tr]` - Taproot address (BIP86)
- `[self:p2pkh]` - Legacy P2PKH address (BIP44)
- `[self:p2sh]` - P2SH address (BIP49)
- `[self:p2wpkh]` - Native SegWit address (BIP84) [DEFAULT]
- `[self:p2wsh]` - Native SegWit script hash (placeholder)

**Indexed Addresses:**
- `[self:p2tr:0]` - First Taproot address (derivation index 0)
- `[self:p2tr:1]` - Second Taproot address (derivation index 1)
- `[self:p2pkh:5]` - Sixth Legacy address (derivation index 5)

**Network-Specific Addresses:**
- `[self:mainnet:p2tr]` - Taproot address for mainnet
- `[self:testnet:p2tr]` - Taproot address for testnet
- `[self:regtest:p2tr]` - Taproot address for regtest
- `[self:signet:p2tr]` - Taproot address for signet

**Combined Examples:**
- `[self:mainnet:p2tr:0]` - First mainnet Taproot address
- `[self:testnet:p2pkh:3]` - Fourth testnet Legacy address

#### Usage Examples

```bash
# Send to different address types
deezel wallet send [self:p2tr] 100000 --fee-rate 5
deezel wallet send [self:p2pkh] 50000
deezel wallet send [self:p2wpkh] 25000  # Default type

# Use indexed addresses
deezel wallet send [self:p2tr:0] 100000  # First Taproot address
deezel wallet send [self:p2tr:1] 100000  # Second Taproot address

# Network-specific addresses
deezel wallet send [self:mainnet:p2tr] 100000
deezel wallet send [self:testnet:p2pkh] 100000

# Alkanes operations with identifiers
deezel alkanes send-token --token 123:456 --amount 1000 --to [self:p2tr]
deezel alkanes balance --address [self:p2pkh:1]

# Create transactions with identifiers
deezel wallet create-tx [self:regtest:p2tr:2] 50000
deezel wallet estimate-fee [self:p2sh] 25000
```

#### Technical Details

- **BIP Standards**: Uses proper BIP44/49/84/86 derivation paths for each address type
- **Network Support**: Handles custom network parameters automatically
- **Wallet Integration**: Works with any command that accepts an address parameter
- **Error Handling**: Provides clear error messages for invalid patterns

### Alkanes Commands

```bash
# Token operations
deezel alkanes deploy-token --name <NAME> --symbol <SYMBOL> --cap <CAP> --amount-per-mint <AMOUNT> --reserve-number <NUM>
deezel alkanes send-token --token <ID> --amount <AMOUNT> --to <ADDRESS> [--change <ADDRESS>]
deezel alkanes balance [--address <ADDRESS>]
deezel alkanes token-info <TOKEN_ID>

# Smart contract operations
deezel alkanes deploy-contract <WASM_FILE> --calldata <DATA>
deezel alkanes execute --calldata <DATA> [--edicts <EDICTS>]

# Contract execution with complex protostone parsing
deezel alkanes execute --fee-rate <RATE> --to <OUTPUTS> --change <ADDRESS> --inputs <INPUTS> <PROTOSTONES> [--envelope <FILE>] [--envelope-from-stdin]

# AMM operations
deezel alkanes create-pool --calldata <DATA> --tokens <TOKENS>
deezel alkanes add-liquidity --calldata <DATA> --tokens <TOKENS>
deezel alkanes remove-liquidity --calldata <DATA> --token <TOKEN> --amount <AMOUNT>
deezel alkanes swap --calldata <DATA> --token <TOKEN> --amount <AMOUNT>

# Analysis and simulation
deezel alkanes simulate-advanced --target <CONTRACT> --inputs <INPUTS> [--tokens <TOKENS>]
deezel alkanes preview-remove-liquidity --token <TOKEN> --amount <AMOUNT>
deezel alkanes inspect <ALKANE_ID> [--disasm] [--fuzz] [--meta] [--codehash]
```

### Alkanes Execute Command

The `alkanes execute` command provides advanced functionality for complex alkanes transactions with sophisticated protostone parsing, UTXO selection, and envelope support for large contract deployments.

#### Command Syntax

```bash
deezel alkanes execute --fee-rate <RATE> --to <OUTPUTS> --change <ADDRESS> --inputs <INPUTS> <PROTOSTONES> [--envelope <FILE>] [--envelope-from-stdin]
```

#### Parameters

- `--fee-rate <RATE>`: Transaction fee rate in sat/vB
- `--to <OUTPUTS>`: Comma-separated list of output addresses (supports address identifiers)
- `--change <ADDRESS>`: Change address (supports address identifiers)
- `--inputs <INPUTS>`: UTXO input specification (see Input Format below)
- `<PROTOSTONES>`: Protostone specifications (see Protostone Format below)
- `--envelope <FILE>`: Path to envelope file for commit-reveal transactions (mutually exclusive with --envelope-from-stdin)
- `--envelope-from-stdin`: Read envelope data from stdin (mutually exclusive with --envelope)

#### Input Format

Inputs specify which UTXOs to use and their alkanes token contents:

```
<token_id>:<output_index>:<amount>,<token_id>:<output_index>:<amount>,B:<bitcoin_amount>
```

**Examples:**
- `2:0:1000,2:1:500,B:10000` - Use token 2 outputs with 1000 and 500 tokens, plus 10000 sats Bitcoin
- `123:5:250,B:5000` - Use token 123 output 5 with 250 tokens, plus 5000 sats Bitcoin
- `B:50000` - Use only Bitcoin UTXOs totaling 50000 sats

#### Protostone Format

Protostones define the alkanes operations to perform. They support complex cellpack syntax and output targeting:

```
[<message>]:<target>:<pointer>:[<edict>]:[<edict>],...
```

**Message Format:**
- `[<header1>,<header2>,<opcode>,<input1>,<input2>,...]` - Cellpack format as comma-separated list of u128 values
  - First two values are the "header"
  - Third value is the "opcode"
  - Remaining values are the "inputs"
- `[<tag>,<amount>,<divisibility>]` - Common token operation format
- Numbers can be used directly for simple operations

**Target Options:**
- `v<N>` - Target the Nth output (0-indexed)
- `p<N>` - Target the Nth protostone (0-indexed)
- `split` - Distribute evenly across all outputs

**Pointer Options:**
- `v<N>` - Point to the Nth output
- `p<N>` - Point to the Nth protostone

**Edict Format:**
- `[<block>:<tx>:<amount>:<output>]` - Transfer tokens from alkane (block:tx) with specified amount to output target
  - `block`: Block number where the alkane was deployed
  - `tx`: Transaction number within that block
  - `amount`: Amount of tokens to transfer
  - `output`: Output target (vN for output N, pN for protostone N, or split)

#### Examples

**Basic Token Transfer:**
```bash
deezel alkanes execute \
  --fee-rate 1 \
  --to '[self:p2tr:0],[self:p2tr:1]' \
  --change [self:p2tr:2] \
  --inputs '2:0:1000,B:5000' \
  '[2,1000,77]:v0:v1'
```

**Complex Multi-Token Operation:**
```bash
deezel alkanes execute \
  --fee-rate 2 \
  --to '[self:p2tr:0],[self:p2tr:1],[self:p2tr:2]' \
  --change [self:p2tr:3] \
  --inputs '2:0:1000,2:1:500,123:0:250,B:15000' \
  '[2,500,77]:v0:p1:[2:500:0:v1],[123,250,18]:v1:v0,B:5000:v0,B:5000:v1'
```

**With Envelope for Large Contract Deployment:**
```bash
deezel alkanes execute \
  --fee-rate 1 \
  --to '[self:p2tr:0]' \
  --change [self:p2tr:1] \
  --inputs 'B:10000' \
  '[2,1000,77]:v0:v0' \
  --envelope ./large-contract.wasm.gz
```

**Using Envelope from Stdin:**
```bash
cat contract.wasm.gz | deezel alkanes execute \
  --fee-rate 1 \
  --to '[self:p2tr:0]' \
  --change [self:p2tr:1] \
  --inputs 'B:10000' \
  '[2,1000,77]:v0:v0' \
  --envelope-from-stdin
```

#### Envelope Support

The execute command supports envelope transactions for deploying large contracts using the commit-reveal pattern:

**Features:**
- **Official Integration**: Uses `alkanes-support` crate envelope structures
- **File Type Detection**: Automatically detects WASM, gzip, ELF, and ZIP files
- **Preview**: Shows envelope details including size, chunks, and file type before committing
- **Commit-Reveal**: Creates proper commit transaction with envelope as first input
- **Witness Encoding**: Properly encodes envelope reveal in witness stack

**Envelope Preview Example:**
```
Envelope Preview:
- File size: 1,234,567 bytes
- Chunks: 2,469 (500 bytes each)
- File type: WASM (gzipped)
- Commit address: bc1p...

Do you want to proceed with this envelope? (y/N):
```

#### Transaction Preview

All execute commands show a detailed transaction preview before signing:

```
Transaction Preview:
Inputs:
  - 2:0 (1000 tokens) from bc1p...
  - Bitcoin UTXO: 5000 sats from bc1q...

Outputs:
  - Output 0: bc1p... (500 tokens + 546 sats)
  - Output 1: bc1p... (500 tokens + 546 sats)
  - Change: bc1p... (3908 sats)

Fee: 1092 sats (1 sat/vB)
Total: 5000 sats

Do you want to sign and broadcast this transaction? (y/N):
```

#### Address Identifier Resolution

The execute command fully supports address identifiers for all address parameters:

- `--to '[self:p2tr:0],[self:p2tr:1]'` - Multiple output addresses
- `--change [self:p2tr:2]` - Change address
- Mixed formats: `--to 'bc1p..., [self:p2tr:1]'` - Raw addresses and identifiers

#### Technical Features

- **UTXO Selection**: Intelligent selection based on alkanes token requirements and Bitcoin amounts
- **Protostone Validation**: Comprehensive validation of protostone syntax and semantics
- **Fee Estimation**: Accurate fee estimation including envelope commit transaction costs
- **Error Handling**: Detailed error messages for invalid inputs, insufficient funds, and parsing errors
- **Async Resolution**: Efficient async resolution of address identifiers

### Blockchain Query Commands

```bash
# RPC operations
deezel metashrew height
deezel bitcoind getblockcount
deezel bitcoind generatetoaddress --nblocks <N> --address <ADDRESS>

# Blockchain data
deezel view getbytecode <CONTRACT_ID>
deezel view getblock <HEIGHT>
deezel view protorunesbyaddress <ADDRESS>
deezel view spendablesbyaddress <ADDRESS>
deezel view trace <TXID:VOUT>

# Transaction analysis
deezel runestone <TXID_OR_HEX> [--raw] [--preview]
deezel inspect-alkane <ALKANE_ID> [--disasm] [--fuzz] [--meta] [--codehash]
```

### Runestone Command

The `runestone` command provides comprehensive decoding and analysis of Runestone transactions with optional preview functionality:

```bash
# Decode a Runestone transaction
deezel runestone <TXID_OR_HEX> [--raw] [--preview]
```

**Options:**
- `--raw`: Show raw runestone data without formatting
- `--preview`: Show transaction preview format (same as used in execute command)

**Examples:**
```bash
# Decode runestone from transaction ID
deezel runestone abc123def456...

# Decode from raw transaction hex
deezel runestone 0200000001...

# Show raw runestone data
deezel runestone abc123def456... --raw

# Show transaction preview format
deezel runestone abc123def456... --preview
```

The runestone command decodes all Runestone protocol data including protostones, edicts, and metadata, providing detailed analysis of alkanes transactions.

## Network Configuration

Deezel supports multiple Bitcoin networks and custom configurations:

### Predefined Networks

- **mainnet**: Bitcoin mainnet with Sandshrew mainnet endpoint
- **signet**: Bitcoin signet with Sandshrew signet endpoint  
- **localhost**: Local development setup

### Custom Networks

You can specify custom network parameters using the `--magic` flag:

```bash
# Custom network with specific magic values
deezel --magic "05:00:bc" wallet info
```

### RPC Endpoints

Override default RPC endpoints:

```bash
deezel --bitcoin-rpc-url "http://user:pass@localhost:8332" \
       --sandshrew-rpc-url "http://localhost:8080" \
       wallet info
```

## Wallet Security

### Encryption Options

1. **GPG Encryption** (`.asc` files):
   - Interactive mode: Prompts for GPG recipient
   - Non-interactive mode: Uses provided passphrase

2. **PBKDF2 Encryption** (`.json` files):
   - Uses PBKDF2 key derivation with AES-GCM encryption
   - Requires passphrase for encryption/decryption

### Best Practices

- Always backup your mnemonic phrase securely
- Use strong passphrases for wallet encryption
- Store wallet files in secure locations
- Regularly backup wallet files
- Test wallet restoration before relying on backups

## Development

### Project Structure

```
deezel/
├── src/
│   ├── main.rs              # Legacy main application
│   ├── bin/
│   │   └── deezel.rs        # Primary CLI application
│   ├── alkanes/             # Alkanes metaprotocol functionality
│   │   ├── contract.rs      # Smart contract operations
│   │   ├── token.rs         # Token operations
│   │   ├── amm.rs           # AMM/DEX functionality
│   │   ├── execute.rs       # Execute command with protostone parsing
│   │   ├── envelope.rs      # Envelope support for commit-reveal transactions
│   │   ├── simulation.rs    # Contract simulation
│   │   ├── inspector.rs     # Contract analysis tools
│   │   └── types.rs         # Common types and structures
│   ├── wallet/              # Bitcoin wallet functionality
│   │   ├── bitcoin_wallet.rs    # Core wallet implementation
│   │   ├── crypto.rs            # Cryptographic utilities
│   │   ├── esplora_backend.rs   # Custom blockchain backend
│   │   └── sandshrew_blockchain.rs  # Sandshrew integration
│   ├── address_resolver.rs  # Address identifier resolution system
│   ├── runestone_enhanced.rs    # Runestone decoding with preview
│   ├── rpc/                 # RPC client implementations
│   ├── monitor/             # Blockchain monitoring
│   ├── transaction/         # Transaction construction with preview
│   └── tests/               # Test suites
├── memory-bank/             # Project documentation
├── Cargo.toml               # Project configuration
└── README.md                # This file
```

### Building and Testing

```bash
# Build the project
cargo build

# Run tests
cargo test

# Run with debug logging
RUST_LOG=debug ./target/debug/deezel wallet info

# Run end-to-end tests
./run_e2e_tests.sh
```

### Debug Logging

Deezel includes comprehensive debug logging for all JSON-RPC requests and responses. This is invaluable for debugging, development, and understanding the communication between the CLI and RPC servers.

#### Enable Debug Logging

```bash
# Show all debug output including RPC requests/responses
RUST_LOG=debug ./deezel bitcoind getblockcount

# Show only RPC module debug output
RUST_LOG=deezel_cli::rpc=debug ./deezel metashrew height

# Save debug output to a file
RUST_LOG=debug ./deezel walletinfo 2> debug.log
```

#### What Gets Logged

- **Request Details**: Target URL, method name, complete JSON-RPC payload
- **Response Details**: Complete response data, errors, and status information
- **Timing Information**: Request/response timing and performance data
- **Error Details**: Detailed error information for troubleshooting

#### Example Debug Output

```
[DEBUG deezel_cli::rpc] Calling RPC method: metashrew_height
[DEBUG deezel_cli::rpc] JSON-RPC Request to https://mainnet.sandshrew.io/v2/lasereyes: {
  "jsonrpc": "2.0",
  "method": "metashrew_height",
  "params": [],
  "id": 0
}
[DEBUG deezel_cli::rpc] JSON-RPC Response: {
  "result": "903893",
  "error": null,
  "id": 0
}
```

For complete documentation, see [`docs/DEBUG_LOGGING.md`](docs/DEBUG_LOGGING.md) and try the example script at [`examples/debug-rpc-logging.sh`](examples/debug-rpc-logging.sh).

### Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- [Bitcoin Development Kit (BDK)](https://github.com/bitcoindevkit/bdk) - Bitcoin wallet functionality
- [Alkanes](https://github.com/kungfuflex/alkanes-rs) - Alkanes metaprotocol implementation
- [Metashrew](https://github.com/sandshrewmetaprotocols/metashrew) - Metaprotocol infrastructure
- [Ordinals](https://github.com/ordinals/ord) - Ordinals and Runestone protocols

## Support

For questions, issues, or contributions, please:

1. Check the existing issues in the repository
2. Create a new issue with detailed information
3. Join the community discussions
4. Refer to the documentation in the `memory-bank/` directory

---

**Note**: This is a comprehensive toolkit for Bitcoin and Alkanes metaprotocol interactions. Always test thoroughly on testnet before using on mainnet, and ensure you understand the implications of blockchain transactions before executing them.
