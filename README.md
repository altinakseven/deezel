# Deezel - DIESEL Token Minting and Management Tool

Deezel is a Bitcoin wallet CLI tool for automated DIESEL token minting and management using BDK (Bitcoin Development Kit) and Sandshrew RPC.

## Features

- **Bitcoin Wallet Management**: Create and manage Bitcoin wallets using BDK
- **DIESEL Token Minting**: Mint DIESEL tokens using the Runestone protocol
- **Mempool Monitoring**: Monitor the mempool for DIESEL token minting transactions
- **Fee Optimization**: Optimize transaction fees using Replace-By-Fee (RBF)
- **Balance Tracking**: Track Bitcoin and DIESEL token balances

## Architecture

The project is organized into several modules:

- **wallet**: Bitcoin wallet functionality using BDK
- **monitor**: Block monitoring and transaction tracking
- **transaction**: Transaction construction and signing
- **rpc**: Sandshrew RPC client implementation
- **runestone**: Runestone protocol implementation for DIESEL token minting

## Getting Started

### Prerequisites

- Rust 1.70 or later
- Access to a Bitcoin node (for RPC)
- Access to a Sandshrew node (for RPC)

### Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/deezel.git
   cd deezel
   ```

2. Build the project:
   ```
   cargo build
   ```

### Usage

#### Main Application

Run the main application:

```
cargo run -- --bitcoin-rpc-url http://bitcoinrpc:bitcoinrpc@localhost:8332 --metashrew-rpc-url http://localhost:8080
```

#### DIESEL Token Minter

Run the DIESEL token minter:

```
cargo run --bin diesel_minter -- --sandshrew-rpc-url https://mainnet.sandshrew.io/v2/lasereyes --max-fee-rate 50
```

### Command-line Arguments

#### Main Application

- `--bitcoin-rpc-url`: Bitcoin RPC URL (default: http://bitcoinrpc:bitcoinrpc@localhost:8332)
- `--metashrew-rpc-url`: Metashrew RPC URL (default: http://localhost:8080)
- `--wallet-path`: Wallet file path (default: wallet.dat)
- `--log-level`: Log level (error, warn, info, debug, trace) (default: info)

#### DIESEL Token Minter

- `--bitcoin-rpc-url`: Bitcoin RPC URL (default: http://bitcoinrpc:bitcoinrpc@localhost:8332)
- `--sandshrew-rpc-url`: Sandshrew RPC URL (default: https://mainnet.sandshrew.io/v2/lasereyes)
- `--wallet-path`: Wallet file path (default: wallet.dat)
- `--max-fee-rate`: Maximum fee rate in sats/vbyte (default: 100)
- `--log-level`: Log level (error, warn, info, debug, trace) (default: info)

## DIESEL Token Minting Process

The DIESEL token minting process involves:

1. Creating a transaction with:
   - A dust output (546 sats) to a wallet address
   - An OP_RETURN output with a Runestone containing a Protostone with the DIESEL message cellpack [2, 0, 77]

2. Broadcasting the transaction to the Bitcoin network

3. Tracing the transaction to verify DIESEL token minting

## Development

### Project Structure

```
deezel/
├── src/
│   ├── bin/
│   │   └── diesel_minter.rs  # DIESEL token minter binary
│   ├── wallet/               # Bitcoin wallet functionality
│   │   ├── mod.rs
│   │   └── esplora_backend.rs
│   ├── monitor/              # Block monitoring
│   │   └── mod.rs
│   ├── transaction/          # Transaction construction
│   │   └── mod.rs
│   ├── rpc/                  # RPC client
│   │   └── mod.rs
│   ├── runestone.rs          # Runestone protocol implementation
│   ├── lib.rs                # Library exports
│   └── main.rs               # Main application
├── Cargo.toml                # Project configuration
└── README.md                 # This file
```

### Building and Testing

Build the project:

```
cargo build
```

Run tests:

```
cargo test
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- [Bitcoin Development Kit (BDK)](https://github.com/bitcoindevkit/bdk)
- [Sandshrew](https://github.com/metashrew/sandshrew)
- [Runestone Protocol](https://github.com/ordinals/ord)