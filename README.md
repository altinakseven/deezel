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

Deezel is organized as a Rust workspace monorepo with three main crates providing different levels of functionality and platform support:

### 📦 Monorepo Structure

#### **`deezel`** - Main CLI Application
The primary command-line interface and desktop application providing full Bitcoin and Alkanes functionality.

**Key Features:**
- Complete Bitcoin wallet management with BDK integration
- Full Alkanes metaprotocol support (contracts, tokens, AMM)
- Advanced blockchain analysis and debugging tools
- RPC client implementations for Bitcoin Core and Metashrew
- Transaction construction with preview capabilities
- Comprehensive CLI interface with 50+ commands

**Core Modules:**
- **`wallet/`**: Bitcoin wallet functionality using BDK with custom blockchain backends
- **`alkanes/`**: Alkanes metaprotocol integration including contracts, tokens, AMM, and envelope support
- **`rpc/`**: RPC client implementations for Bitcoin Core and Metashrew
- **`monitor/`**: Blockchain monitoring and event handling
- **`transaction/`**: Transaction construction and management with preview capabilities

#### **`deezel-common`** - Shared Core Library
Cross-platform abstractions and shared functionality used by both CLI and web implementations.

**Key Features:**
- **Provider Traits**: Abstract interfaces for network, storage, crypto, time, and logging
- **Cross-Platform Compatibility**: Works in both native and WASM environments
- **Bitcoin Integration**: Network configuration, RPC clients, and blockchain utilities
- **Alkanes Support**: Core alkanes types, operations, and protocol implementations
- **Error Handling**: Comprehensive error types with detailed context
- **Feature Flags**: Conditional compilation for different environments (`web-compat`, `native-crypto`)

**Core Traits:**
- [`NetworkProvider`](crates/deezel-common/src/traits.rs): HTTP requests and network operations
- [`StorageProvider`](crates/deezel-common/src/traits.rs): Persistent data storage
- [`CryptoProvider`](crates/deezel-common/src/traits.rs): Cryptographic operations
- [`TimeProvider`](crates/deezel-common/src/traits.rs): Time and sleep functionality
- [`LogProvider`](crates/deezel-common/src/traits.rs): Logging and debugging

#### **`deezel-web`** - Web/WASM Library
Browser-compatible implementation providing Deezel functionality for web applications.

**Key Features:**
- **WASM Compatibility**: Compiled to WebAssembly for browser environments
- **Web APIs Integration**: Uses fetch, localStorage, Web Crypto, console, and Performance APIs
- **Provider Implementations**: Web-specific implementations of all deezel-common traits
- **Privacy Features**: Rebar Labs Shield integration for private transaction broadcasting
- **Async/Await Support**: Fully async API compatible with JavaScript promises
- **TypeScript Bindings**: Generated TypeScript definitions for web integration

**Web Providers:**
- [`WebProvider`](crates/deezel-web/src/provider.rs): Main web provider implementing all traits
- [`WebNetwork`](crates/deezel-web/src/network.rs): Fetch API-based networking
- [`WebStorage`](crates/deezel-web/src/storage.rs): localStorage-based persistence
- [`WebCrypto`](crates/deezel-web/src/crypto.rs): Web Crypto API integration
- [`WebTime`](crates/deezel-web/src/time.rs): Performance API timing
- [`WebLogger`](crates/deezel-web/src/logging.rs): Console API logging

### 🏗️ Cross-Platform Design

The monorepo uses a layered architecture that enables code sharing across platforms:

```
┌─────────────────┬─────────────────┐
│   deezel CLI    │   deezel-web    │
│   (Native)      │   (WASM/Web)    │
├─────────────────┼─────────────────┤
│        deezel-common (Shared)     │
│     Traits + Core Functionality   │
└───────────────────────────────────┘
```

**Benefits:**
- **Code Reuse**: Core Bitcoin and Alkanes logic shared across platforms
- **Consistent APIs**: Same interfaces work in both native and web environments
- **Maintainability**: Single source of truth for protocol implementations
- **Testing**: Comprehensive test coverage across all platforms

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

## Web/WASM Integration with Leptos

The `deezel-web` crate provides full Bitcoin and Alkanes functionality in web browsers through WebAssembly (WASM), with first-class support for Leptos applications. This enables building decentralized web applications with the same powerful features as the CLI.

### 🌐 Web Capabilities

#### **Browser APIs Integration**
- **Fetch API**: HTTP requests for RPC calls and data fetching
- **localStorage**: Persistent storage for wallet data and configuration
- **Web Crypto API**: Hardware-accelerated cryptographic operations
- **Performance API**: High-resolution timing and benchmarking
- **Console API**: Structured logging with timestamps and levels

#### **Privacy Features**
- **Rebar Labs Shield**: Private transaction broadcasting through Tor-like network
- **Client-Side Operations**: All sensitive operations performed locally in browser
- **No Server Dependencies**: Direct communication with Bitcoin and Alkanes networks

#### **Developer Experience**
- **Leptos Integration**: Native support for Leptos reactive framework
- **TypeScript Support**: Generated TypeScript definitions for type safety
- **Async/Await**: Modern JavaScript async patterns
- **Error Handling**: Comprehensive error types with detailed messages
- **Documentation**: Full rustdoc documentation with examples

### 🦎 Leptos Integration

The `deezel-web` crate is designed to work seamlessly with Leptos applications, providing reactive Bitcoin and Alkanes functionality.

#### **Basic Setup**

Add deezel-web to your Leptos project's `Cargo.toml`:

```toml
[dependencies]
leptos = { version = "0.6", features = ["csr", "hydrate"] }
deezel-web = { path = "../path/to/deezel/crates/deezel-web" }
deezel-common = { path = "../path/to/deezel/crates/deezel-common" }
wasm-bindgen = "0.2"
wasm-bindgen-futures = "0.4"
```

#### **Provider Setup in Leptos**

```rust
use leptos::*;
use deezel_web::{WebProvider, BrowserWalletProvider, WalletConnector};
use deezel_common::*;

#[component]
pub fn App() -> impl IntoView {
    // Create provider signal
    let (provider, set_provider) = create_signal(None::<WebProvider>);
    
    // Initialize provider on mount
    create_effect(move |_| {
        spawn_local(async move {
            match WebProvider::new(
                "https://bitcoin-rpc.example.com".to_string(),
                "https://metashrew.example.com".to_string(),
                "mainnet".to_string(),
            ).await {
                Ok(web_provider) => {
                    if let Err(e) = web_provider.initialize().await {
                        log::error!("Failed to initialize provider: {}", e);
                        return;
                    }
                    set_provider.set(Some(web_provider));
                },
                Err(e) => log::error!("Failed to create provider: {}", e),
            }
        });
    });
    
    view! {
        <div class="app">
            <h1>"Deezel Leptos App"</h1>
            <Show
                when=move || provider.get().is_some()
                fallback=|| view! { <div>"Loading provider..."</div> }
            >
                <WalletSection provider=provider />
                <AlkanesSection provider=provider />
            </Show>
        </div>
    }
}
```

#### **Wallet Integration Component**

```rust
use leptos::*;
use deezel_web::wallet_provider::*;
use deezel_common::*;

#[component]
pub fn WalletConnector() -> impl IntoView {
    let (wallet_state, set_wallet_state) = create_signal(None::<BrowserWalletProvider>);
    let (available_wallets, set_available_wallets) = create_signal(Vec::<WalletInfo>::new());
    let (connection_status, set_connection_status) = create_signal("disconnected".to_string());
    
    // Detect wallets on component mount
    create_effect(move |_| {
        spawn_local(async move {
            let connector = WalletConnector::new();
            match connector.detect_wallets().await {
                Ok(wallets) => {
                    set_available_wallets.set(wallets);
                    set_connection_status.set("wallets_detected".to_string());
                },
                Err(e) => {
                    log::error!("Failed to detect wallets: {}", e);
                    set_connection_status.set("detection_failed".to_string());
                }
            }
        });
    });
    
    let connect_wallet = move |wallet_info: WalletInfo| {
        let wallet_info_clone = wallet_info.clone();
        spawn_local(async move {
            set_connection_status.set("connecting".to_string());
            
            match BrowserWalletProvider::connect(
                wallet_info_clone,
                "https://bitcoin-rpc.example.com".to_string(),
                "https://metashrew.example.com".to_string(),
                "mainnet".to_string(),
            ).await {
                Ok(provider) => {
                    if let Err(e) = provider.initialize().await {
                        log::error!("Failed to initialize wallet provider: {}", e);
                        set_connection_status.set("initialization_failed".to_string());
                        return;
                    }
                    set_wallet_state.set(Some(provider));
                    set_connection_status.set("connected".to_string());
                },
                Err(e) => {
                    log::error!("Failed to connect wallet: {}", e);
                    set_connection_status.set("connection_failed".to_string());
                }
            }
        });
    };
    
    view! {
        <div class="wallet-connector">
            <h3>"Bitcoin Wallet Connection"</h3>
            
            <div class="connection-status">
                <p>"Status: " {move || connection_status.get()}</p>
            </div>
            
            <Show
                when=move || wallet_state.get().is_some()
                fallback=move || view! {
                    <div class="wallet-selection">
                        <h4>"Available Wallets"</h4>
                        <For
                            each=move || available_wallets.get()
                            key=|wallet| wallet.id.clone()
                            children=move |wallet| {
                                let wallet_clone = wallet.clone();
                                view! {
                                    <button
                                        on:click=move |_| connect_wallet(wallet_clone.clone())
                                        class="wallet-button"
                                        disabled=move || connection_status.get() == "connecting"
                                    >
                                        <img src=wallet.icon.clone() alt=wallet.name.clone() width="24" height="24" />
                                        <span>{wallet.name.clone()}</span>
                                        <div class="wallet-features">
                                            {if wallet.supports_taproot { "✓ Taproot" } else { "" }}
                                            {if wallet.supports_psbt { " ✓ PSBT" } else { "" }}
                                            {if wallet.supports_ordinals { " ✓ Ordinals" } else { "" }}
                                        </div>
                                    </button>
                                }
                            }
                        />
                    </div>
                }
            >
                <WalletDashboard wallet_provider=wallet_state />
            </Show>
        </div>
    }
}
```

#### **Wallet Dashboard Component**

```rust
#[component]
pub fn WalletDashboard(
    wallet_provider: ReadSignal<Option<BrowserWalletProvider>>
) -> impl IntoView {
    let (balance, set_balance) = create_signal(None::<WalletBalance>);
    let (address, set_address) = create_signal(None::<String>);
    let (loading, set_loading) = create_signal(false);
    
    // Load wallet data when provider is available
    create_effect(move |_| {
        if let Some(provider) = wallet_provider.get() {
            spawn_local(async move {
                set_loading.set(true);
                
                // Get wallet address
                match WalletProvider::get_address(&provider).await {
                    Ok(addr) => set_address.set(Some(addr)),
                    Err(e) => log::error!("Failed to get address: {}", e),
                }
                
                // Get wallet balance
                match WalletProvider::get_balance(&provider).await {
                    Ok(bal) => set_balance.set(Some(bal)),
                    Err(e) => log::error!("Failed to get balance: {}", e),
                }
                
                set_loading.set(false);
            });
        }
    });
    
    let refresh_data = move |_| {
        if let Some(provider) = wallet_provider.get() {
            spawn_local(async move {
                set_loading.set(true);
                
                match WalletProvider::get_balance(&provider).await {
                    Ok(bal) => set_balance.set(Some(bal)),
                    Err(e) => log::error!("Failed to refresh balance: {}", e),
                }
                
                set_loading.set(false);
            });
        }
    };
    
    view! {
        <div class="wallet-dashboard">
            <h4>"Wallet Dashboard"</h4>
            
            <Show
                when=move || !loading.get()
                fallback=|| view! { <div class="loading">"Loading wallet data..."</div> }
            >
                <div class="wallet-info">
                    <div class="address-section">
                        <label>"Address:"</label>
                        <code>{move || address.get().unwrap_or_else(|| "Loading...".to_string())}</code>
                    </div>
                    
                    <div class="balance-section">
                        <label>"Balance:"</label>
                        <div class="balance-details">
                            {move || {
                                if let Some(bal) = balance.get() {
                                    view! {
                                        <div>
                                            <div>"Confirmed: " {bal.confirmed} " sats"</div>
                                            <div>"Pending: " {bal.trusted_pending + bal.untrusted_pending} " sats"</div>
                                            <div class="total">"Total: " {bal.confirmed + bal.trusted_pending + bal.untrusted_pending} " sats"</div>
                                        </div>
                                    }
                                } else {
                                    view! { <div>"Loading balance..."</div> }
                                }
                            }}
                        </div>
                    </div>
                    
                    <button on:click=refresh_data class="refresh-button">
                        "Refresh"
                    </button>
                </div>
            </Show>
        </div>
    }
}
```

#### **Alkanes Integration Component**

```rust
#[component]
pub fn AlkanesSection(
    provider: ReadSignal<Option<WebProvider>>
) -> impl IntoView {
    let (alkanes_balance, set_alkanes_balance) = create_signal(Vec::<AlkanesBalance>::new());
    let (loading, set_loading) = create_signal(false);
    
    let load_alkanes_data = move |_| {
        if let Some(prov) = provider.get() {
            spawn_local(async move {
                set_loading.set(true);
                
                match AlkanesProvider::get_balance(&prov, None).await {
                    Ok(balances) => set_alkanes_balance.set(balances),
                    Err(e) => log::error!("Failed to get alkanes balance: {}", e),
                }
                
                set_loading.set(false);
            });
        }
    };
    
    // Load data when provider becomes available
    create_effect(move |_| {
        if provider.get().is_some() {
            load_alkanes_data(());
        }
    });
    
    view! {
        <div class="alkanes-section">
            <h4>"Alkanes Tokens"</h4>
            
            <Show
                when=move || !loading.get()
                fallback=|| view! { <div class="loading">"Loading alkanes data..."</div> }
            >
                <div class="alkanes-balances">
                    <For
                        each=move || alkanes_balance.get()
                        key=|balance| format!("{}:{}", balance.alkane_id.block, balance.alkane_id.tx)
                        children=move |balance| {
                            view! {
                                <div class="token-balance">
                                    <div class="token-info">
                                        <span class="token-name">{balance.name.clone()}</span>
                                        <span class="token-symbol">({balance.symbol.clone()})</span>
                                    </div>
                                    <div class="token-amount">{balance.balance.to_string()}</div>
                                    <div class="token-id">
                                        "ID: " {balance.alkane_id.block} ":" {balance.alkane_id.tx}
                                    </div>
                                </div>
                            }
                        }
                    />
                </div>
                
                <button on:click=load_alkanes_data class="refresh-button">
                    "Refresh Alkanes Data"
                </button>
            </Show>
        </div>
    }
}
```

#### **Transaction Component**

```rust
#[component]
pub fn TransactionSender(
    wallet_provider: ReadSignal<Option<BrowserWalletProvider>>
) -> impl IntoView {
    let (recipient, set_recipient) = create_signal(String::new());
    let (amount, set_amount) = create_signal(String::new());
    let (fee_rate, set_fee_rate) = create_signal(String::from("1"));
    let (sending, set_sending) = create_signal(false);
    let (result, set_result) = create_signal(None::<String>);
    
    let send_transaction = move |_| {
        if let Some(provider) = wallet_provider.get() {
            let recipient_addr = recipient.get();
            let amount_str = amount.get();
            let fee_rate_str = fee_rate.get();
            
            spawn_local(async move {
                set_sending.set(true);
                set_result.set(None);
                
                // Parse amount
                let amount_sats = match amount_str.parse::<u64>() {
                    Ok(amt) => amt,
                    Err(_) => {
                        set_result.set(Some("Invalid amount".to_string()));
                        set_sending.set(false);
                        return;
                    }
                };
                
                // Parse fee rate
                let fee_rate_val = match fee_rate_str.parse::<f32>() {
                    Ok(rate) => Some(rate),
                    Err(_) => None,
                };
                
                // Create send parameters
                let send_params = SendParams {
                    address: recipient_addr,
                    amount: amount_sats,
                    fee_rate: fee_rate_val,
                    send_all: false,
                    from_address: None,
                    change_address: None,
                    auto_confirm: false,
                };
                
                // Send transaction
                match WalletProvider::send(&provider, send_params).await {
                    Ok(txid) => {
                        set_result.set(Some(format!("Transaction sent: {}", txid)));
                        set_recipient.set(String::new());
                        set_amount.set(String::new());
                    },
                    Err(e) => {
                        set_result.set(Some(format!("Error: {}", e)));
                    }
                }
                
                set_sending.set(false);
            });
        }
    };
    
    view! {
        <div class="transaction-sender">
            <h4>"Send Bitcoin"</h4>
            
            <div class="form-group">
                <label>"Recipient Address:"</label>
                <input
                    type="text"
                    prop:value=recipient
                    on:input=move |ev| set_recipient.set(event_target_value(&ev))
                    placeholder="bc1q..."
                    disabled=move || sending.get()
                />
            </div>
            
            <div class="form-group">
                <label>"Amount (sats):"</label>
                <input
                    type="number"
                    prop:value=amount
                    on:input=move |ev| set_amount.set(event_target_value(&ev))
                    placeholder="1000"
                    disabled=move || sending.get()
                />
            </div>
            
            <div class="form-group">
                <label>"Fee Rate (sat/vB):"</label>
                <input
                    type="number"
                    step="0.1"
                    prop:value=fee_rate
                    on:input=move |ev| set_fee_rate.set(event_target_value(&ev))
                    disabled=move || sending.get()
                />
            </div>
            
            <button
                on:click=send_transaction
                disabled=move || sending.get() || recipient.get().is_empty() || amount.get().is_empty()
                class="send-button"
            >
                {move || if sending.get() { "Sending..." } else { "Send Transaction" }}
            </button>
            
            <Show when=move || result.get().is_some()>
                <div class="transaction-result">
                    {move || result.get().unwrap_or_default()}
                </div>
            </Show>
        </div>
    }
}
```

### 🔧 Build Setup for Leptos

#### **Cargo.toml Configuration**

```toml
[package]
name = "my-deezel-leptos-app"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
leptos = { version = "0.6", features = ["csr", "hydrate"] }
leptos_meta = { version = "0.6", features = ["csr", "hydrate"] }
leptos_router = { version = "0.6", features = ["csr", "hydrate"] }

# Deezel dependencies
deezel-web = { path = "../path/to/deezel/crates/deezel-web" }
deezel-common = { path = "../path/to/deezel/crates/deezel-common" }

# WASM dependencies
wasm-bindgen = "0.2"
wasm-bindgen-futures = "0.4"
web-sys = "0.3"
js-sys = "0.3"

# Utilities
log = "0.4"
console_log = "1.0"
console_error_panic_hook = "0.1"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"

[features]
hydrate = ["leptos/hydrate", "leptos_meta/hydrate", "leptos_router/hydrate"]
csr = ["leptos/csr", "leptos_meta/csr", "leptos_router/csr"]

[profile.release]
opt-level = 'z'
lto = true
codegen-units = 1
panic = "abort"
```

#### **Build Commands**

```bash
# Install trunk for Leptos development
cargo install trunk

# Install wasm-pack for WASM builds
curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh

# Development server
trunk serve

# Production build
trunk build --release

# Or build with wasm-pack directly
wasm-pack build --target web --out-dir pkg
```

#### **index.html Template**

```html
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Deezel Leptos App</title>
    <link data-trunk rel="css" href="style.css">
</head>
<body>
    <div id="leptos"></div>
</body>
</html>
```

### 🎨 Styling Example

```css
/* style.css */
.wallet-connector {
    max-width: 800px;
    margin: 0 auto;
    padding: 20px;
}

.wallet-button {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 12px 16px;
    margin: 8px 0;
    border: 1px solid #ddd;
    border-radius: 8px;
    background: white;
    cursor: pointer;
    transition: all 0.2s;
    width: 100%;
}

.wallet-button:hover {
    background: #f5f5f5;
    border-color: #007bff;
}

.wallet-button:disabled {
    opacity: 0.6;
    cursor: not-allowed;
}

.wallet-features {
    font-size: 0.8em;
    color: #666;
    margin-left: auto;
}

.wallet-dashboard {
    background: #f8f9fa;
    border-radius: 8px;
    padding: 20px;
    margin-top: 20px;
}

.balance-details {
    font-family: monospace;
    background: white;
    padding: 12px;
    border-radius: 4px;
    border: 1px solid #ddd;
}

.total {
    font-weight: bold;
    border-top: 1px solid #ddd;
    padding-top: 8px;
    margin-top: 8px;
}

.alkanes-section {
    margin-top: 20px;
}

.token-balance {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 12px;
    border: 1px solid #ddd;
    border-radius: 4px;
    margin: 8px 0;
}

.token-info {
    display: flex;
    gap: 8px;
    align-items: center;
}

.token-symbol {
    color: #666;
    font-size: 0.9em;
}

.transaction-sender {
    background: white;
    border: 1px solid #ddd;
    border-radius: 8px;
    padding: 20px;
    margin-top: 20px;
}

.form-group {
    margin-bottom: 16px;
}

.form-group label {
    display: block;
    margin-bottom: 4px;
    font-weight: 500;
}

.form-group input {
    width: 100%;
    padding: 8px 12px;
    border: 1px solid #ddd;
    border-radius: 4px;
    font-size: 14px;
}

.send-button {
    background: #007bff;
    color: white;
    border: none;
    padding: 12px 24px;
    border-radius: 4px;
    cursor: pointer;
    font-size: 16px;
}

.send-button:disabled {
    background: #6c757d;
    cursor: not-allowed;
}

.transaction-result {
    margin-top: 16px;
    padding: 12px;
    border-radius: 4px;
    background: #d4edda;
    border: 1px solid #c3e6cb;
    color: #155724;
}

.loading {
    text-align: center;
    padding: 20px;
    color: #666;
}
```

### 📚 Key Features for Leptos Integration

1. **Reactive State Management**: All wallet and blockchain data is managed through Leptos signals
2. **Async Operations**: Proper handling of async wallet operations with `spawn_local`
3. **Error Handling**: Comprehensive error handling with user feedback
4. **Component Architecture**: Modular components for different functionality areas
5. **Browser Wallet Support**: Full integration with 13+ Bitcoin wallet extensions
6. **Real-time Updates**: Reactive updates when wallet state changes
7. **Type Safety**: Full Rust type safety throughout the application

This integration provides a complete foundation for building Bitcoin and Alkanes applications with Leptos, leveraging the full power of the deezel ecosystem in a reactive web framework.

### Project Structure

```
deezel/                      # Workspace root
├── crates/
│   ├── deezel/              # Main CLI application
│   │   ├── src/
│   │   │   ├── main.rs              # Legacy main application
│   │   │   ├── bin/
│   │   │   │   └── deezel.rs        # Primary CLI application
│   │   │   ├── alkanes/             # Alkanes metaprotocol functionality
│   │   │   │   ├── contract.rs      # Smart contract operations
│   │   │   │   ├── token.rs         # Token operations
│   │   │   │   ├── amm.rs           # AMM/DEX functionality
│   │   │   │   ├── execute.rs       # Execute command with protostone parsing
│   │   │   │   ├── envelope.rs      # Envelope support for commit-reveal transactions
│   │   │   │   ├── simulation.rs    # Contract simulation
│   │   │   │   ├── inspector.rs     # Contract analysis tools
│   │   │   │   └── types.rs         # Common types and structures
│   │   │   ├── wallet/              # Bitcoin wallet functionality
│   │   │   │   ├── bitcoin_wallet.rs    # Core wallet implementation
│   │   │   │   ├── crypto.rs            # Cryptographic utilities
│   │   │   │   ├── esplora_backend.rs   # Custom blockchain backend
│   │   │   │   └── sandshrew_blockchain.rs  # Sandshrew integration
│   │   │   ├── address_resolver.rs  # Address identifier resolution system
│   │   │   ├── runestone_enhanced.rs    # Runestone decoding with preview
│   │   │   ├── rpc/                 # RPC client implementations
│   │   │   ├── monitor/             # Blockchain monitoring
│   │   │   ├── transaction/         # Transaction construction with preview
│   │   │   └── tests/               # Test suites
│   │   └── Cargo.toml               # CLI crate configuration
│   ├── deezel-common/           # Shared core library
│   │   ├── src/
│   │   │   ├── lib.rs               # Library entry point
│   │   │   ├── traits.rs            # Provider trait definitions
│   │   │   ├── error.rs             # Error types and handling
│   │   │   ├── bitcoin/             # Bitcoin network utilities
│   │   │   ├── alkanes/             # Alkanes protocol implementations
│   │   │   ├── rpc.rs               # RPC client abstractions
│   │   │   └── utils.rs             # Common utilities
│   │   └── Cargo.toml               # Common crate configuration
│   └── deezel-web/              # Web/WASM library
│       ├── src/
│       │   ├── lib.rs               # WASM library entry point
│       │   ├── provider.rs          # Main web provider implementation
│       │   ├── network.rs           # Fetch API networking
│       │   ├── storage.rs           # localStorage integration
│       │   ├── crypto.rs            # Web Crypto API
│       │   ├── time.rs              # Performance API timing
│       │   ├── logging.rs           # Console API logging
│       │   └── utils.rs             # Web-specific utilities
│       ├── examples/                # Web usage examples
│       ├── tests/                   # WASM-compatible tests
│       └── Cargo.toml               # Web crate configuration
├── memory-bank/                 # Project documentation
├── examples/                    # CLI usage examples
├── Cargo.toml                   # Workspace configuration
└── README.md                    # This file
```

## API Documentation

Comprehensive API documentation is available for all crates using `cargo doc`:

### 📚 Generate Documentation

```bash
# Generate documentation for all crates
cargo doc --workspace --no-deps

# Generate documentation with private items
cargo doc --workspace --no-deps --document-private-items

# Open documentation in browser
cargo doc --workspace --no-deps --open
```

### 📖 Documentation Links

- **Main CLI**: [`target/doc/deezel/index.html`](target/doc/deezel/index.html)
- **Common Library**: [`target/doc/deezel_common/index.html`](target/doc/deezel_common/index.html)
- **Web Library**: [`target/doc/deezel_web/index.html`](target/doc/deezel_web/index.html)

### 🔍 Key Documentation Sections

#### **deezel-common**
- [Provider Traits](target/doc/deezel_common/traits/index.html) - Core abstractions for cross-platform functionality
- [Bitcoin Integration](target/doc/deezel_common/bitcoin/index.html) - Network configuration and utilities
- [Alkanes Support](target/doc/deezel_common/alkanes/index.html) - Protocol implementations and types
- [Error Handling](target/doc/deezel_common/error/index.html) - Comprehensive error types

#### **deezel-web**
- [WebProvider](target/doc/deezel_web/provider/struct.WebProvider.html) - Main web provider implementation
- [Network Module](target/doc/deezel_web/network/index.html) - Fetch API integration
- [Storage Module](target/doc/deezel_web/storage/index.html) - localStorage persistence
- [Crypto Module](target/doc/deezel_web/crypto/index.html) - Web Crypto API integration

### Building and Testing

```bash
# Build all crates
cargo build --workspace

# Build specific crates
cargo build -p deezel
cargo build -p deezel-common
cargo build -p deezel-web

# Build for release
cargo build --workspace --release

# Run all tests
cargo test --workspace

# Run tests for specific crates
cargo test -p deezel-common
cargo test -p deezel-web

# Run web tests in browser (requires wasm-pack)
cd crates/deezel-web
wasm-pack test --headless --firefox

# Run with debug logging
RUST_LOG=debug ./target/debug/deezel wallet info

# Run end-to-end tests
./run_e2e_tests.sh
```

### 🌐 Web Development

```bash
# Install wasm-pack for web builds
curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh

# Build web library
cd crates/deezel-web
wasm-pack build --target web --out-dir pkg

# Run web tests
wasm-pack test --headless --firefox

# Generate TypeScript bindings
wasm-pack build --target bundler --out-dir pkg-bundler
```

### 🧪 Testing Strategy

The project uses comprehensive testing across all platforms:

#### **Unit Tests**
- Pure Rust unit tests for core functionality
- Mock implementations for external dependencies
- Property-based testing for critical algorithms

#### **Integration Tests**
- Cross-crate integration testing
- RPC client testing with mock servers
- Wallet functionality testing

#### **Web Tests**
- WASM-compatible tests using `wasm-bindgen-test`
- Browser API integration testing
- Cross-browser compatibility testing

#### **End-to-End Tests**
- Full CLI workflow testing
- Real network integration testing
- Performance and stress testing

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

### `parse_block` Function

The `deezel-web` crate exports a `parse_block` function that can be used to parse a raw block hex string into a JSON object containing the block header, and a list of transactions with their protostone and runestone data.

#### JavaScript Usage Example

##### Browser

```javascript
import { parse_block } from 'deezel-web';

const block_hex = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5facffffffff00";

try {
  const block_data = parse_block(block_hex);
  console.log(JSON.stringify(block_data, null, 2));
} catch (e) {
  console.error("Error parsing block:", e);
}
```

##### NodeJS

```javascript
import { parse_block } from 'deezel-web';

const block_hex = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5facffffffff00";

try {
  const block_data = parse_block(block_hex);
  console.log(JSON.stringify(block_data, null, 2));
} catch (e) {
  console.error("Error parsing block:", e);
}
```
