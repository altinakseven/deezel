# Deezel Implementation Plan

This document outlines a detailed implementation plan for completing the deezel project based on the gap analysis between oyl-sdk and deezel.

## Phase 1: Core Functionality (Weeks 1-4)

### Week 1: Account Module Implementation

#### Day 1-2: Basic Account Structure
- Implement `Account` struct with necessary fields
- Implement account creation from mnemonic using BDK
- Implement account creation from extended private key
- Add support for different networks (mainnet, testnet, regtest)

#### Day 3-4: Address Generation
- Implement address generation for legacy addresses
- Implement address generation for nested segwit addresses
- Implement address generation for native segwit addresses
- Implement address generation for taproot addresses
- Add derivation path customization

#### Day 5: Account Serialization and Security
- Implement account serialization and deserialization
- Add password-based encryption for stored accounts
- Implement account backup and restore functionality

#### Tests to Write:
- Test account creation from mnemonic
- Test account creation from extended private key
- Test address generation for all address types
- Test account serialization/deserialization
- Test password-based encryption

### Week 2: RPC Client and Transaction Module Implementation

#### Day 1-2: RPC Client Base
- Implement base RPC client with common functionality
- Add error handling and retry logic
- Implement rate limiting
- Add connection pooling

#### Day 3: Bitcoin Core RPC Client
- Implement Bitcoin Core RPC client
- Add methods for blockchain information
- Add methods for transaction broadcasting
- Add methods for UTXO retrieval

#### Day 4: Esplora RPC Client
- Implement Esplora RPC client
- Add methods for address information
- Add methods for transaction information
- Add methods for UTXO retrieval

#### Day 5: Metashrew, Alkanes, and Ord RPC Clients
- Implement Metashrew RPC client
- Implement Alkanes RPC client
- Implement Ord RPC client

#### Tests to Write:
- Test RPC client error handling
- Test RPC client retry logic
- Test RPC client rate limiting
- Test each RPC client's methods

### Week 3: Transaction Construction and Signing

#### Day 1-2: UTXO Management
- Implement UTXO selection algorithms
- Add coin control functionality
- Implement UTXO filtering

#### Day 3-4: Transaction Building
- Implement transaction builder
- Add support for different output types
- Implement fee estimation
- Add change output handling
- Implement OP_RETURN output creation

#### Day 5: Transaction Signing
- Implement transaction signing for all address types
- Add PSBT handling
- Implement message signing and verification
- Add signature verification

#### Tests to Write:
- Test UTXO selection algorithms
- Test transaction building
- Test fee estimation
- Test change output handling
- Test transaction signing for all address types
- Test PSBT handling
- Test message signing and verification

### Week 4: Block Monitoring and Utils

#### Day 1-2: Block Monitoring
- Implement block monitoring with callbacks
- Add transaction confirmation tracking
- Implement chain reorganization handling
- Add mempool monitoring

#### Day 3-4: Utils Module
- Implement utility functions for Bitcoin operations
- Add conversion functions
- Implement validation functions
- Add helper functions for common operations

#### Day 5: Testing and Documentation
- Write comprehensive tests for all core functionality
- Document all public APIs
- Create examples for core functionality

#### Tests to Write:
- Test block monitoring
- Test transaction confirmation tracking
- Test chain reorganization handling
- Test utility functions

## Phase 2: Protocol Support (Weeks 5-8)

### Week 5: Alkanes Protocol Implementation

#### Day 1-2: Contract Deployment
- Implement contract deployment functionality
- Add support for different contract types
- Implement contract parameter validation

#### Day 3-4: Token Operations
- Implement token minting functionality
- Add token transfer functionality
- Implement token burning functionality

#### Day 5: Testing and Documentation
- Write comprehensive tests for Alkanes functionality
- Document all public APIs
- Create examples for Alkanes functionality

#### Tests to Write:
- Test contract deployment
- Test token minting
- Test token transfer
- Test token burning

### Week 6: BRC20 Protocol Implementation

#### Day 1-2: Token Deployment
- Implement BRC20 token deployment functionality
- Add support for token parameters
- Implement token parameter validation

#### Day 3-4: Token Operations
- Implement token minting functionality
- Add token transfer functionality
- Implement inscription creation and handling

#### Day 5: Testing and Documentation
- Write comprehensive tests for BRC20 functionality
- Document all public APIs
- Create examples for BRC20 functionality

#### Tests to Write:
- Test token deployment
- Test token minting
- Test token transfer
- Test inscription creation and handling

### Week 7: Rune Protocol Implementation

#### Day 1-2: Rune Etching
- Implement rune etching functionality
- Add support for rune parameters
- Implement rune parameter validation

#### Day 3-4: Rune Operations
- Implement rune minting functionality
- Add rune transfer functionality
- Implement rune burning functionality

#### Day 5: Testing and Documentation
- Write comprehensive tests for Rune functionality
- Document all public APIs
- Create examples for Rune functionality

#### Tests to Write:
- Test rune etching
- Test rune minting
- Test rune transfer
- Test rune burning

### Week 8: Collectible Protocol Implementation

#### Day 1-2: Collectible Creation
- Implement collectible creation functionality
- Add support for collectible metadata
- Implement collectible parameter validation

#### Day 3-4: Collectible Operations
- Implement collectible transfer functionality
- Add collection creation functionality
- Implement collectible metadata handling

#### Day 5: Testing and Documentation
- Write comprehensive tests for Collectible functionality
- Document all public APIs
- Create examples for Collectible functionality

#### Tests to Write:
- Test collectible creation
- Test collectible transfer
- Test collection creation
- Test collectible metadata handling

## Phase 3: CLI and JavaScript/TypeScript Bindings (Weeks 9-12)

### Week 9: CLI Implementation

#### Day 1-2: CLI Framework
- Set up CLI framework using clap
- Implement command parsing
- Add help text and documentation
- Implement configuration management

#### Day 3-4: Core Commands
- Implement account commands
- Add transaction commands
- Implement utility commands
- Add RPC commands

#### Day 5: Protocol Commands
- Implement Alkanes commands
- Add BRC20 commands
- Implement Rune commands
- Add Collectible commands

#### Tests to Write:
- Test CLI command parsing
- Test CLI configuration management
- Test each command's functionality

### Week 10: JavaScript/TypeScript Bindings

#### Day 1-2: NAPI-RS Setup
- Set up NAPI-RS for JavaScript/TypeScript bindings
- Implement basic binding structure
- Add error handling for JavaScript/TypeScript bindings

#### Day 3-4: Core Bindings
- Implement account bindings
- Add transaction bindings
- Implement RPC client bindings
- Add utility bindings

#### Day 5: Protocol Bindings
- Implement Alkanes bindings
- Add BRC20 bindings
- Implement Rune bindings
- Add Collectible bindings

#### Tests to Write:
- Test JavaScript/TypeScript bindings
- Test error handling in bindings
- Test each binding's functionality

### Week 11: Documentation and Examples

#### Day 1-2: API Documentation
- Create comprehensive API documentation
- Add code examples to documentation
- Implement documentation generation

#### Day 3-4: User Guide
- Create user guide for deezel
- Add tutorials for common operations
- Implement example projects

#### Day 5: Migration Guide
- Create migration guide from oyl-sdk to deezel
- Add examples of migration patterns
- Implement compatibility layer if needed

#### Deliverables:
- API documentation
- User guide
- Tutorials
- Example projects
- Migration guide

### Week 12: Testing and Final Release Preparation

#### Day 1-2: Integration Testing
- Implement integration tests for all functionality
- Add end-to-end tests
- Implement performance tests

#### Day 3-4: Bug Fixing and Optimization
- Fix any bugs found during testing
- Optimize performance bottlenecks
- Implement any missing functionality

#### Day 5: Release Preparation
- Prepare for crates.io release
- Add release notes
- Implement versioning strategy
- Create NPM package for JavaScript/TypeScript bindings

#### Deliverables:
- Final release of deezel crate
- NPM package for JavaScript/TypeScript bindings
- Release notes
- Versioning strategy

## Implementation Details

### Account Module

The account module will be implemented using the Bitcoin Development Kit (BDK) for wallet functionality. It will support:

```rust
pub struct Account {
    network: Network,
    wallet: Wallet<MemoryDatabase>,
    mnemonic: Option<Mnemonic>,
    xprv: Option<ExtendedPrivKey>,
    addresses: HashMap<AddressType, Address>,
}

impl Account {
    pub fn from_mnemonic(mnemonic: &str, passphrase: Option<&str>, network: Network) -> Result<Self>;
    pub fn from_xprv(xprv: &str, network: Network) -> Result<Self>;
    pub fn generate(network: Network) -> Result<(Self, String)>;
    pub fn get_address(&self, address_type: AddressType) -> String;
    pub fn sign_transaction(&self, psbt: &mut Psbt) -> Result<()>;
    pub fn sign_message(&self, message: &str, address_type: AddressType) -> Result<String>;
    pub fn verify_message(&self, message: &str, signature: &str, address: &str) -> Result<bool>;
    pub fn to_json(&self, password: Option<&str>) -> Result<String>;
    pub fn from_json(json: &str, password: Option<&str>) -> Result<Self>;
}
```

### Transaction Module

The transaction module will be implemented using the rust-bitcoin crate for transaction handling. It will support:

```rust
pub struct TransactionBuilder {
    inputs: Vec<TxIn>,
    outputs: Vec<TxOut>,
    fee_rate: f64,
    change_address: Option<Address>,
}

impl TransactionBuilder {
    pub fn new() -> Self;
    pub fn add_input(mut self, input: TxIn) -> Self;
    pub fn add_output(mut self, output: TxOut) -> Self;
    pub fn fee_rate(mut self, fee_rate: f64) -> Self;
    pub fn change_address(mut self, address: Address) -> Self;
    pub fn build(self) -> Result<Transaction>;
}

pub struct UtxoSelector {
    utxos: Vec<Utxo>,
    target_amount: u64,
    fee_rate: f64,
}

impl UtxoSelector {
    pub fn new(utxos: Vec<Utxo>, target_amount: u64, fee_rate: f64) -> Self;
    pub fn select(&self) -> Result<Vec<Utxo>>;
    pub fn select_with_strategy(&self, strategy: UtxoSelectionStrategy) -> Result<Vec<Utxo>>;
}
```

### RPC Client Module

The RPC client module will be implemented using the reqwest crate for HTTP requests. It will support:

```rust
pub trait RpcClient {
    async fn call(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value>;
}

pub struct BitcoinRpcClient {
    client: reqwest::Client,
    url: String,
    auth: Option<String>,
}

impl RpcClient for BitcoinRpcClient {
    async fn call(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value>;
}

pub struct EsploraRpcClient {
    client: reqwest::Client,
    url: String,
}

impl RpcClient for EsploraRpcClient {
    async fn call(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value>;
}

// Similar implementations for MetashrewRpcClient, AlkanesRpcClient, and OrdRpcClient
```

### Protocol Modules

Each protocol module will be implemented with a similar structure:

```rust
pub struct ProtocolManager {
    rpc_client: RpcClient,
    network: Network,
}

impl ProtocolManager {
    pub fn new(rpc_client: RpcClient, network: Network) -> Self;
    
    // Query methods
    pub async fn get_info(&self, id: &str) -> Result<ProtocolInfo>;
    pub async fn get_balances(&self, address: &str) -> Result<Vec<ProtocolBalance>>;
    
    // Transaction methods
    pub async fn create_operation_psbt(&self, operation: ProtocolOperation, ...) -> Result<Psbt>;
    pub async fn deploy(&self, ...) -> Result<String>;
    pub async fn mint(&self, ...) -> Result<String>;
    pub async fn transfer(&self, ...) -> Result<String>;
}
```

### CLI Module

The CLI module will be implemented using the clap crate for command-line parsing. It will support:

```rust
#[derive(Parser, Debug)]
#[clap(author, version, about = "Deezel CLI")]
pub struct Cli {
    /// Network (mainnet, testnet, regtest)
    #[clap(long, default_value = "mainnet")]
    pub network: String,
    
    /// RPC URLs
    #[clap(long)]
    pub bitcoin_rpc_url: Option<String>,
    #[clap(long)]
    pub esplora_rpc_url: Option<String>,
    // Other RPC URLs
    
    /// Wallet path
    #[clap(long)]
    pub wallet_path: Option<PathBuf>,
    
    /// Subcommand
    #[clap(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Account commands
    Account(AccountCommands),
    /// Transaction commands
    Transaction(TransactionCommands),
    /// Alkanes commands
    Alkanes(AlkanesCommands),
    /// BRC20 commands
    Brc20(Brc20Commands),
    /// Rune commands
    Rune(RuneCommands),
    /// Collectible commands
    Collectible(CollectibleCommands),
}
```

### JavaScript/TypeScript Bindings

The JavaScript/TypeScript bindings will be implemented using the NAPI-RS crate. It will support:

```typescript
// TypeScript definitions
export interface Account {
  fromMnemonic(mnemonic: string, passphrase?: string, network?: string): Account;
  fromXprv(xprv: string, network?: string): Account;
  generate(network?: string): [Account, string];
  getAddress(addressType: string): string;
  signTransaction(psbt: string): string;
  signMessage(message: string, addressType: string): string;
  verifyMessage(message: string, signature: string, address: string): boolean;
  toJson(password?: string): string;
  static fromJson(json: string, password?: string): Account;
}

export interface TransactionBuilder {
  addInput(input: any): TransactionBuilder;
  addOutput(output: any): TransactionBuilder;
  feeRate(feeRate: number): TransactionBuilder;
  changeAddress(address: string): TransactionBuilder;
  build(): string;
}

// Similar interfaces for other modules
```

## Conclusion

This implementation plan provides a detailed roadmap for completing the deezel project. By following this plan, we can ensure that all functionality from oyl-sdk is properly implemented in deezel, with the added benefits of Rust's performance, safety, and maintainability.

The plan is structured to prioritize core functionality first, followed by protocol support, and finally the CLI and JavaScript/TypeScript bindings. This allows us to build a solid foundation before adding more complex functionality.

Each week has specific goals and deliverables, making it easy to track progress and ensure that the project stays on schedule. The detailed implementation details provide guidance on how to implement each module, ensuring consistency and quality throughout the codebase.
