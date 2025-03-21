# Technical Context

## Technologies Used

### Core Technologies

1. **Rust**
   - Primary implementation language
   - Used for all core functionality
   - Provides memory safety and performance
   - Edition: 2024

2. **Bitcoin Development Kit (BDK)**
   - Provides wallet functionality
   - Handles transaction construction and signing
   - Manages UTXO tracking
   - Supports descriptor-based wallet architecture

3. **Bitcoin Core Libraries**
   - Used for Bitcoin protocol implementation
   - Provides transaction and block parsing
   - Handles cryptographic operations

### Protocol Implementations

1. **Runestone Protocol**
   - Implementation for creating OP_RETURN outputs with special data
   - Used for embedding Protostones in transactions
   - Handles serialization and deserialization of protocol data

2. **Protostone Protocol**
   - Extension of Runestone for DIESEL token operations
   - Defines message format for token minting
   - Implements protocol tag and message cellpack encoding

### External Services

1. **Bitcoin RPC API**
   - Used for querying current block height
   - Configurable via `--bitcoin-rpc-url` command-line argument
   - Default endpoint: http://bitcoinrpc:bitcoinrpc@localhost:8332
   - Primary method used: `getblockcount`

2. **Metashrew RPC API**
   - Primary data source for blockchain information and DIESEL token operations
   - Configurable via `--metashrew-rpc-url` command-line argument
   - Default endpoint: http://localhost:8080
   - Key methods:
     - `metashrew_view`: For general blockchain data
     - `metashrew_height`: To verify block height (should be Bitcoin height + 1)
     - `spendablesbyaddress`: For UTXO selection via protobuf scheme

## Development Setup

### Build System

- **Cargo**: Rust's package manager and build system
- **Rust Edition**: 2024
- **Target Platforms**: Linux, macOS, Windows

### Project Structure

```
deezel/
├── src/                  # Source code
│   ├── main.rs           # Application entry point
│   ├── wallet/           # Wallet implementation
│   ├── monitor/          # Block monitoring
│   ├── transaction/      # Transaction construction
│   └── rpc/              # RPC client implementation
├── reference/            # Reference implementations and protocols
├── Cargo.toml            # Project manifest
└── memory-bank/          # Project documentation
```

### Testing Strategy

1. **Unit Tests**
   - Test individual components in isolation
   - Mock external dependencies
   - Focus on core business logic

2. **Integration Tests**
   - Test component interactions
   - Use test networks (testnet/regtest)
   - Verify end-to-end workflows

3. **Simulation Tests**
   - Test against simulated blockchain data
   - Verify behavior across various scenarios
   - Test error handling and recovery

## Technical Constraints

### Bitcoin Network Constraints

1. **Block Time Variability**
   - Bitcoin blocks are mined approximately every 10 minutes
   - Actual time between blocks can vary significantly
   - Application must handle irregular block timing

2. **Transaction Fee Considerations**
   - Fees fluctuate based on network congestion
   - Application must implement fee estimation
   - Balance between timely confirmation and cost efficiency

3. **Confirmation Requirements**
   - Transactions require confirmations for security
   - Application must track confirmation status
   - Handle potential chain reorganizations

### API Constraints

1. **Rate Limiting**
   - RPC APIs may have rate limits
   - Application must implement appropriate throttling
   - Handle potential temporary service unavailability

2. **Data Consistency**
   - External API data may have delays or inconsistencies
   - Application must handle potential data discrepancies
   - Implement retry mechanisms for transient failures
   - Verify Metashrew height is Bitcoin height + 1 before using spendablesbyaddress

### Resource Constraints

1. **Memory Usage**
   - Application should maintain reasonable memory footprint
   - Avoid unnecessary caching of blockchain data
   - Implement efficient data structures

2. **CPU Usage**
   - Balance between responsiveness and resource usage
   - Implement appropriate polling intervals
   - Avoid unnecessary computation

## Dependencies

### Direct Dependencies

1. **Bitcoin Development Kit (BDK)**
   - Core wallet functionality
   - Transaction handling
   - UTXO management

2. **Reqwest**
   - HTTP client for API communication
   - Async support for efficient network operations

3. **Serde**
   - Serialization/deserialization of JSON data
   - Used for API communication and data persistence

4. **Tokio**
   - Async runtime for concurrent operations
   - Efficient handling of network requests

5. **Clap**
   - Command-line argument parsing
   - Support for `--bitcoin-rpc-url` and `--metashrew-rpc-url` arguments

### Indirect Dependencies

1. **Bitcoin Core Libraries**
   - Used by BDK for core Bitcoin functionality
   - Transaction and block parsing
   - Cryptographic operations

2. **Rust Standard Library**
   - Core language functionality
   - File I/O for persistence
   - Error handling

### Development Dependencies

1. **Cargo Tools**
   - Build system
   - Package management
   - Testing framework

2. **Clippy**
   - Static code analysis
   - Code quality enforcement

3. **Rust Formatter**
   - Code style consistency