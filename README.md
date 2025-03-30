# Deezel

A comprehensive Bitcoin wallet SDK and CLI tool for token management.

## Overview

Deezel is a Rust-based library and CLI tool that provides functionality for Bitcoin wallet management, transaction construction, and support for various Bitcoin protocols including DIESEL tokens, BRC20, Runes, and Collectibles.

## Features

- **Wallet Management**: Create and manage HD wallets with support for multiple address types (legacy, nested segwit, native segwit, taproot).
- **Transaction Construction**: Build and sign Bitcoin transactions with support for various output types.
- **Protocol Support**:
  - **DIESEL**: Mint and transfer DIESEL tokens.
  - **BRC20**: Deploy, mint, and transfer BRC20 tokens.
  - **Runes**: Etch, mint, and transfer Runes.
  - **Collectibles**: Create and transfer NFT collectibles.
  - **Alkanes**: Deploy and interact with Alkanes contracts.
- **RPC Clients**: Connect to various Bitcoin RPC services including Bitcoin Core, Esplora, Metashrew, and Ord.
- **CLI Tool**: Command-line interface for all functionality.

## Installation

### From Source

```bash
git clone https://github.com/deezel/deezel.git
cd deezel
cargo build --release
```

The compiled binaries will be available in the `target/release` directory.

### From Cargo

```bash
cargo install deezel
```

## Usage

### CLI

```bash
# Create a new wallet
deezel_cli wallet create

# Show wallet information
deezel_cli wallet info

# Show wallet addresses
deezel_cli wallet addresses

# Show wallet balance
deezel_cli wallet balance

# Mint DIESEL tokens
deezel_cli diesel mint --amount 100 --fee-rate 1

# Transfer DIESEL tokens
deezel_cli diesel transfer --amount 50 --recipient bc1q... --fee-rate 1

# Deploy a new BRC20 token
deezel_cli brc20 deploy --ticker TEST --supply 1000000 --limit 1000 --decimals 18 --fee-rate 1

# Mint BRC20 tokens
deezel_cli brc20 mint --ticker TEST --amount 100 --fee-rate 1

# Transfer BRC20 tokens
deezel_cli brc20 transfer --ticker TEST --amount 50 --recipient bc1q... --fee-rate 1

# Etch a new Rune
deezel_cli rune etch --symbol TEST --decimals 0 --limit 1000000 --fee-rate 1

# Mint Runes
deezel_cli rune mint --symbol TEST --amount 100 --fee-rate 1

# Transfer Runes
deezel_cli rune transfer --symbol TEST --amount 50 --recipient bc1q... --fee-rate 1

# Create a new collectible
deezel_cli collectible create --content image.png --content-type image/png --metadata metadata.json --fee-rate 1

# Transfer a collectible
deezel_cli collectible transfer --inscription-id 123... --recipient bc1q... --fee-rate 1

# Deploy an Alkanes contract
deezel_cli alkanes deploy --name "Test Token" --symbol TEST --total-supply 1000000 --cap 1000000 --mint-amount 100 --body contract.wasm --fee-rate 1

# Execute an Alkanes contract
deezel_cli alkanes execute --contract-id 2:1 --operation mint --params '{"amount": 100}' --fee-rate 1
```

### Library

```rust
use deezel::account::{Account, AccountConfig, AddressType};
use deezel::signer::Signer;
use deezel::rpc::RpcClient;

#[tokio::main]
async fn main() -> Result<()> {
    // Create RPC client
    let rpc_client = RpcClient::new(
        "http://bitcoinrpc:bitcoinrpc@localhost:8332",
        "https://blockstream.info/api",
        "http://localhost:8080",
        "http://localhost:8080",
        "http://localhost:8080",
    );
    
    // Create account
    let (account, mnemonic) = Account::generate(None)?;
    println!("Mnemonic: {}", mnemonic);
    println!("Address: {}", account.get_address(AddressType::NativeSegwit));
    
    // Create signer
    let signer = Signer::from_mnemonic(&mnemonic, &account, None)?;
    
    // Get balance
    let balance = rpc_client.get_balance(&account.get_address(AddressType::NativeSegwit)).await?;
    println!("Balance: {} satoshis", balance);
    
    Ok(())
}
```

## Configuration

Deezel can be configured using a configuration file located at `~/.deezel/config.json`. The configuration file is created automatically when you run the CLI for the first time.

```json
{
  "network": "mainnet",
  "rpc_urls": {
    "bitcoin": "http://bitcoinrpc:bitcoinrpc@localhost:8332",
    "esplora": "https://blockstream.info/api",
    "metashrew": "http://localhost:8080",
    "alkanes": "http://localhost:8080",
    "ord": "http://localhost:8080"
  },
  "wallet_path": "~/.deezel/wallet.json"
}
```

You can override these settings using command-line arguments:

```bash
deezel_cli --network testnet --bitcoin-rpc-url http://localhost:18332 wallet info
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.
