# Deezel System Patterns

This document outlines the design patterns, coding conventions, and best practices used in the Deezel project.

## Design Patterns

### Module Structure

Deezel follows a modular architecture with clear separation of concerns:

1. **Core Modules**:
   - `account`: Wallet management and address generation
   - `signer`: Transaction signing and message signing
   - `transaction`: Transaction construction and UTXO selection
   - `rpc`: RPC client for various services
   - `monitor`: Block monitoring and transaction tracking
   - `utils`: Utility functions and helpers

2. **Protocol Modules**:
   - `alkanes`: Alkanes contract deployment and interaction
   - `brc20`: BRC20 token deployment, minting, and transfer
   - `rune`: Rune etching, minting, and transfer
   - `collectible`: NFT creation and transfer

3. **CLI Module**:
   - `cli`: Command-line interface for all functionality

### Manager Pattern

Each protocol module follows the Manager pattern, which provides a high-level interface for interacting with the protocol:

```rust
pub struct AlkanesManager {
    rpc_client: RpcClient,
    network: Network,
}

impl AlkanesManager {
    pub fn new(rpc_client: RpcClient, network: Network) -> Self {
        Self {
            rpc_client,
            network,
        }
    }
    
    pub async fn get_tokens_by_address(&self, address: &str, protocol_tag: &str) -> Result<Vec<AlkanesOutpoint>> {
        // Implementation
    }
    
    // Other methods
}
```

This pattern provides several benefits:

1. **Encapsulation**: The manager encapsulates the complexity of interacting with the protocol.
2. **Dependency Injection**: Dependencies like the RPC client are injected, making testing easier.
3. **Consistency**: All protocol modules follow the same pattern, making the codebase more consistent.

### Builder Pattern

The Builder pattern is used for constructing complex objects, such as transactions:

```rust
pub struct TransactionBuilder {
    inputs: Vec<TxIn>,
    outputs: Vec<TxOut>,
    fee_rate: f64,
    change_address: Option<Address>,
    // Other fields
}

impl TransactionBuilder {
    pub fn new() -> Self {
        Self {
            inputs: Vec::new(),
            outputs: Vec::new(),
            fee_rate: 1.0,
            change_address: None,
            // Initialize other fields
        }
    }
    
    pub fn add_input(mut self, input: TxIn) -> Self {
        self.inputs.push(input);
        self
    }
    
    pub fn add_output(mut self, output: TxOut) -> Self {
        self.outputs.push(output);
        self
    }
    
    pub fn fee_rate(mut self, fee_rate: f64) -> Self {
        self.fee_rate = fee_rate;
        self
    }
    
    pub fn change_address(mut self, address: Address) -> Self {
        self.change_address = Some(address);
        self
    }
    
    pub fn build(self) -> Result<Transaction> {
        // Build the transaction
    }
}
```

This pattern provides several benefits:

1. **Fluent Interface**: The builder provides a fluent interface for constructing objects.
2. **Default Values**: The builder can provide default values for optional parameters.
3. **Validation**: The builder can validate the parameters before constructing the object.

### Factory Pattern

The Factory pattern is used for creating objects with complex initialization logic:

```rust
pub struct AccountFactory;

impl AccountFactory {
    pub fn from_mnemonic(mnemonic: &str, passphrase: Option<&str>, network: Network) -> Result<Account> {
        // Create an account from a mnemonic
    }
    
    pub fn from_xprv(xprv: &str, network: Network) -> Result<Account> {
        // Create an account from an extended private key
    }
    
    pub fn generate(network: Network) -> Result<(Account, String)> {
        // Generate a new account and return it along with the mnemonic
    }
}
```

This pattern provides several benefits:

1. **Encapsulation**: The factory encapsulates the complexity of creating objects.
2. **Centralization**: All object creation logic is centralized in one place.
3. **Flexibility**: The factory can create different types of objects based on parameters.

### Repository Pattern

The Repository pattern is used for abstracting data access:

```rust
pub trait UtxoRepository {
    async fn get_utxos(&self, address: &str) -> Result<Vec<Utxo>>;
    async fn get_utxo(&self, txid: &str, vout: u32) -> Result<Option<Utxo>>;
    async fn get_balance(&self, address: &str) -> Result<u64>;
}

pub struct EsploraUtxoRepository {
    client: EsploraClient,
}

impl UtxoRepository for EsploraUtxoRepository {
    async fn get_utxos(&self, address: &str) -> Result<Vec<Utxo>> {
        // Implementation using Esplora
    }
    
    async fn get_utxo(&self, txid: &str, vout: u32) -> Result<Option<Utxo>> {
        // Implementation using Esplora
    }
    
    async fn get_balance(&self, address: &str) -> Result<u64> {
        // Implementation using Esplora
    }
}
```

This pattern provides several benefits:

1. **Abstraction**: The repository abstracts the data access logic.
2. **Testability**: The repository can be mocked for testing.
3. **Flexibility**: Different implementations can be provided for different data sources.

### Strategy Pattern

The Strategy pattern is used for selecting algorithms at runtime:

```rust
pub trait FeeStrategy {
    fn calculate_fee(&self, tx_size: usize) -> u64;
}

pub struct StaticFeeStrategy {
    fee_rate: f64,
}

impl FeeStrategy for StaticFeeStrategy {
    fn calculate_fee(&self, tx_size: usize) -> u64 {
        (self.fee_rate * tx_size as f64).ceil() as u64
    }
}

pub struct DynamicFeeStrategy {
    rpc_client: RpcClient,
}

impl FeeStrategy for DynamicFeeStrategy {
    fn calculate_fee(&self, tx_size: usize) -> u64 {
        // Implementation using RPC client to get dynamic fee rate
    }
}
```

This pattern provides several benefits:

1. **Flexibility**: Different strategies can be selected at runtime.
2. **Encapsulation**: Each strategy encapsulates its own algorithm.
3. **Testability**: Each strategy can be tested independently.

## Coding Conventions

### Error Handling

Deezel uses the `anyhow` and `thiserror` crates for error handling:

```rust
use anyhow::{Context, Result, anyhow};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AccountError {
    #[error("Invalid mnemonic: {0}")]
    InvalidMnemonic(String),
    
    #[error("Invalid network: {0}")]
    InvalidNetwork(String),
    
    #[error("Invalid address type: {0}")]
    InvalidAddressType(String),
}

pub fn create_account(mnemonic: &str, network: &str) -> Result<Account> {
    let network = match network {
        "mainnet" => Network::Bitcoin,
        "testnet" => Network::Testnet,
        "regtest" => Network::Regtest,
        _ => return Err(AccountError::InvalidNetwork(network.to_string()).into()),
    };
    
    let mnemonic = Mnemonic::from_str(mnemonic)
        .context("Failed to parse mnemonic")?;
    
    // Create account
    
    Ok(account)
}
```

This approach provides several benefits:

1. **Context**: Errors include context about where they occurred.
2. **Propagation**: Errors can be easily propagated up the call stack.
3. **Custom Errors**: Domain-specific errors can be defined and handled appropriately.
4. **User-Friendly Messages**: Errors can be presented to users in a friendly way.

### Async/Await

Deezel uses the async/await pattern for asynchronous operations:

```rust
pub async fn get_balance(&self, address: &str) -> Result<u64> {
    let utxos = self.get_utxos(address).await?;
    let balance = utxos.iter().map(|utxo| utxo.amount).sum();
    Ok(balance)
}
```

This approach provides several benefits:

1. **Readability**: Async code is more readable than callback-based code.
2. **Composability**: Async operations can be easily composed.
3. **Error Handling**: Error handling is similar to synchronous code.
4. **Cancellation**: Async operations can be cancelled.

### Documentation

Deezel follows Rust's documentation conventions:

```rust
/// Account configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountConfig {
    /// Network (mainnet, testnet, regtest)
    pub network: Network,
    /// Mnemonic
    pub mnemonic: Option<String>,
    /// Passphrase
    pub passphrase: Option<String>,
    /// Extended private key
    pub xprv: Option<String>,
    /// Address types to generate
    pub address_types: Vec<AddressType>,
}

impl AccountConfig {
    /// Create a new account configuration
    ///
    /// # Arguments
    ///
    /// * `network` - Bitcoin network
    /// * `mnemonic` - Optional mnemonic
    /// * `passphrase` - Optional passphrase
    /// * `xprv` - Optional extended private key
    /// * `address_types` - Address types to generate
    ///
    /// # Returns
    ///
    /// A new account configuration
    ///
    /// # Examples
    ///
    /// ```
    /// use deezel::account::{AccountConfig, AddressType};
    /// use bdk::bitcoin::Network;
    ///
    /// let config = AccountConfig::new(
    ///     Network::Bitcoin,
    ///     Some("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"),
    ///     None,
    ///     None,
    ///     vec![AddressType::Legacy, AddressType::NativeSegwit],
    /// );
    /// ```
    pub fn new(
        network: Network,
        mnemonic: Option<&str>,
        passphrase: Option<&str>,
        xprv: Option<&str>,
        address_types: Vec<AddressType>,
    ) -> Self {
        Self {
            network,
            mnemonic: mnemonic.map(|s| s.to_string()),
            passphrase: passphrase.map(|s| s.to_string()),
            xprv: xprv.map(|s| s.to_string()),
            address_types,
        }
    }
}
```

This approach provides several benefits:

1. **Discoverability**: Documentation is easily discoverable using tools like `cargo doc`.
2. **Examples**: Examples show how to use the code.
3. **Consistency**: Documentation follows a consistent format.
4. **Completeness**: All public items are documented.

### Testing

Deezel follows Rust's testing conventions:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_account_creation() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let account = Account::from_mnemonic(mnemonic, None, Network::Bitcoin).unwrap();
        
        assert_eq!(account.get_address(AddressType::Legacy), "1JAd7XCBzGudGpJQSDSfpmJhiygtLQWaGL");
        assert_eq!(account.get_address(AddressType::NativeSegwit), "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
    }
    
    #[test]
    fn test_invalid_mnemonic() {
        let mnemonic = "invalid mnemonic";
        let result = Account::from_mnemonic(mnemonic, None, Network::Bitcoin);
        
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "Invalid mnemonic: invalid mnemonic");
    }
}
```

This approach provides several benefits:

1. **Isolation**: Tests are isolated from each other.
2. **Discoverability**: Tests are easily discoverable using tools like `cargo test`.
3. **Consistency**: Tests follow a consistent format.
4. **Coverage**: All code paths are tested.

## Best Practices

### Dependency Injection

Deezel uses dependency injection to make testing easier:

```rust
pub struct AlkanesManager {
    rpc_client: RpcClient,
    network: Network,
}

impl AlkanesManager {
    pub fn new(rpc_client: RpcClient, network: Network) -> Self {
        Self {
            rpc_client,
            network,
        }
    }
    
    // Methods that use rpc_client and network
}
```

This approach provides several benefits:

1. **Testability**: Dependencies can be mocked for testing.
2. **Flexibility**: Different implementations can be provided for different environments.
3. **Decoupling**: Components are decoupled from their dependencies.

### Immutability

Deezel prefers immutable data structures:

```rust
pub struct Account {
    network: Network,
    mnemonic: Option<String>,
    passphrase: Option<String>,
    xprv: Option<String>,
    address_types: Vec<AddressType>,
}

impl Account {
    pub fn with_network(mut self, network: Network) -> Self {
        self.network = network;
        self
    }
    
    pub fn with_mnemonic(mut self, mnemonic: &str) -> Self {
        self.mnemonic = Some(mnemonic.to_string());
        self
    }
    
    pub fn with_passphrase(mut self, passphrase: &str) -> Self {
        self.passphrase = Some(passphrase.to_string());
        self
    }
    
    pub fn with_xprv(mut self, xprv: &str) -> Self {
        self.xprv = Some(xprv.to_string());
        self
    }
    
    pub fn with_address_types(mut self, address_types: Vec<AddressType>) -> Self {
        self.address_types = address_types;
        self
    }
}
```

This approach provides several benefits:

1. **Thread Safety**: Immutable data structures are thread-safe.
2. **Predictability**: Immutable data structures are more predictable.
3. **Functional Style**: Immutable data structures encourage a functional programming style.

### Error Propagation

Deezel uses the `?` operator for error propagation:

```rust
pub async fn get_balance(&self, address: &str) -> Result<u64> {
    let utxos = self.get_utxos(address).await?;
    let balance = utxos.iter().map(|utxo| utxo.amount).sum();
    Ok(balance)
}
```

This approach provides several benefits:

1. **Readability**: Error propagation is more readable.
2. **Conciseness**: Error propagation is more concise.
3. **Context**: Error context can be added using the `context` method.

### Type Safety

Deezel uses Rust's type system to prevent errors:

```rust
pub enum AddressType {
    Legacy,
    NestedSegwit,
    NativeSegwit,
    Taproot,
}

impl AddressType {
    pub fn to_string(&self) -> String {
        match self {
            AddressType::Legacy => "legacy".to_string(),
            AddressType::NestedSegwit => "nested-segwit".to_string(),
            AddressType::NativeSegwit => "native-segwit".to_string(),
            AddressType::Taproot => "taproot".to_string(),
        }
    }
    
    pub fn from_str(s: &str) -> Result<Self> {
        match s {
            "legacy" => Ok(AddressType::Legacy),
            "nested-segwit" => Ok(AddressType::NestedSegwit),
            "native-segwit" => Ok(AddressType::NativeSegwit),
            "taproot" => Ok(AddressType::Taproot),
            _ => Err(anyhow!("Invalid address type: {}", s)),
        }
    }
}
```

This approach provides several benefits:

1. **Safety**: Type errors are caught at compile time.
2. **Documentation**: Types document the expected values.
3. **Refactoring**: Type changes are caught by the compiler.

### Resource Management

Deezel uses Rust's ownership system for resource management:

```rust
pub struct RpcClient {
    client: reqwest::Client,
    url: String,
    auth: Option<String>,
}

impl RpcClient {
    pub fn new(url: &str, auth: Option<&str>) -> Self {
        Self {
            client: reqwest::Client::new(),
            url: url.to_string(),
            auth: auth.map(|s| s.to_string()),
        }
    }
    
    pub async fn call(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
        // Implementation
    }
}

impl Drop for RpcClient {
    fn drop(&mut self) {
        // Clean up resources
    }
}
```

This approach provides several benefits:

1. **Safety**: Resources are automatically cleaned up when they go out of scope.
2. **Predictability**: Resource lifetimes are predictable.
3. **Efficiency**: Resources are released as soon as they are no longer needed.

### Concurrency

Deezel uses Tokio for asynchronous concurrency:

```rust
pub async fn get_utxos_and_balance(&self, address: &str) -> Result<(Vec<Utxo>, u64)> {
    let utxos_future = self.get_utxos(address);
    let balance_future = self.get_balance(address);
    
    let (utxos, balance) = tokio::join!(utxos_future, balance_future);
    
    Ok((utxos?, balance?))
}
```

This approach provides several benefits:

1. **Efficiency**: Multiple operations can be performed concurrently.
2. **Readability**: Concurrent code is more readable.
3. **Composability**: Concurrent operations can be easily composed.

### Logging

Deezel uses the `log` crate for logging:

```rust
use log::{debug, info, warn, error};

pub async fn get_balance(&self, address: &str) -> Result<u64> {
    debug!("Getting balance for address: {}", address);
    
    let utxos = match self.get_utxos(address).await {
        Ok(utxos) => utxos,
        Err(e) => {
            error!("Failed to get UTXOs for address {}: {}", address, e);
            return Err(e);
        }
    };
    
    let balance = utxos.iter().map(|utxo| utxo.amount).sum();
    
    info!("Balance for address {}: {} satoshis", address, balance);
    
    Ok(balance)
}
```

This approach provides several benefits:

1. **Flexibility**: Log levels can be configured at runtime.
2. **Performance**: Logs can be disabled for production.
3. **Context**: Logs include context about the operation.
4. **Filtering**: Logs can be filtered by level and module.

### Configuration

Deezel uses the `serde` crate for configuration:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub network: String,
    pub rpc_urls: RpcUrls,
    pub wallet_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcUrls {
    pub bitcoin: String,
    pub esplora: String,
    pub metashrew: String,
    pub alkanes: String,
    pub ord: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            network: "mainnet".to_string(),
            rpc_urls: RpcUrls {
                bitcoin: "http://bitcoinrpc:bitcoinrpc@localhost:8332".to_string(),
                esplora: "https://blockstream.info/api".to_string(),
                metashrew: "http://localhost:8080".to_string(),
                alkanes: "http://localhost:8080".to_string(),
                ord: "http://localhost:8080".to_string(),
            },
            wallet_path: PathBuf::from("~/.deezel/wallet.json"),
        }
    }
}
```

This approach provides several benefits:

1. **Flexibility**: Configuration can be loaded from various sources.
2. **Validation**: Configuration can be validated at load time.
3. **Documentation**: Configuration is self-documenting.
4. **Defaults**: Default values can be provided.

### Command-Line Interface

Deezel uses the `clap` crate for command-line parsing:

```rust
#[derive(Parser, Debug)]
#[clap(author, version, about = "Deezel CLI")]
pub struct Cli {
    /// Network (mainnet, testnet, regtest)
    #[clap(long, default_value = "mainnet")]
    pub network: String,
    
    /// Bitcoin RPC URL
    #[clap(long)]
    pub bitcoin_rpc_url: Option<String>,
    
    /// Esplora RPC URL
    #[clap(long)]
    pub esplora_rpc_url: Option<String>,
    
    /// Metashrew RPC URL
    #[clap(long)]
    pub metashrew_rpc_url: Option<String>,
    
    /// Alkanes RPC URL
    #[clap(long)]
    pub alkanes_rpc_url: Option<String>,
    
    /// Ord RPC URL
    #[clap(long)]
    pub ord_rpc_url: Option<String>,
    
    /// Wallet path
    #[clap(long)]
    pub wallet_path: Option<PathBuf>,
    
    /// Subcommand
    #[clap(subcommand)]
    pub command: Commands,
}
```

This approach provides several benefits:

1. **Usability**: Command-line arguments are well-documented.
2. **Validation**: Command-line arguments are validated at parse time.
3. **Help**: Help text is automatically generated.
4. **Completions**: Shell completions can be generated.
