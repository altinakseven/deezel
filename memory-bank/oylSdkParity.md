# oyl-sdk to deezel Parity Analysis

## Overview

This document analyzes the feature gap between oyl-sdk (TypeScript) and deezel (Rust) implementations, with the goal of achieving 1:1 functional parity. The analysis is organized by module, listing the functions available in oyl-sdk that need to be implemented in deezel.

## Module Comparison

### Account Module

#### oyl-sdk Functions
- `createAccount`: Create a new account from mnemonic or extended private key
- `importAccount`: Import an existing account
- `getAddresses`: Get addresses for an account (legacy, segwit, native segwit, taproot)
- `getBalance`: Get account balance
- `serializeAccount`: Serialize account data
- `deserializeAccount`: Deserialize account data
- `encryptAccount`: Encrypt account data
- `decryptAccount`: Decrypt account data
- `backupAccount`: Create account backup
- `restoreAccount`: Restore account from backup

#### deezel Implementation Status
- ✅ Account structure defined
- ✅ BIP32/39/44 wallet support
- ✅ Multiple address types support
- ✅ Account generation and import
- ✅ Password-based encryption
- ✅ Account serialization and deserialization
- ✅ Account backup and restore
- ✅ Balance retrieval

#### Missing Functionality
- None (Core account functionality is implemented)

### AMM Module

#### oyl-sdk Functions
- `createPool`: Create a new AMM pool
- `addLiquidity`: Add liquidity to a pool
- `removeLiquidity`: Remove liquidity from a pool
- `swap`: Swap tokens in a pool
- `getPoolInfo`: Get information about a pool
- `calculateSwapOutput`: Calculate the output of a swap
- `calculateLiquidityShare`: Calculate liquidity share

#### deezel Implementation Status
- ❌ AMM module not implemented

#### Missing Functionality
- Complete AMM module implementation

### BTC Module

#### oyl-sdk Functions
- `createTransaction`: Create a Bitcoin transaction
- `signTransaction`: Sign a Bitcoin transaction
- `broadcastTransaction`: Broadcast a Bitcoin transaction
- `getTransactionDetails`: Get details of a transaction
- `estimateFee`: Estimate transaction fee
- `getBlockHeight`: Get current block height
- `getBlockHash`: Get block hash
- `getBlock`: Get block details
- `getMempool`: Get mempool transactions
- `waitForConfirmation`: Wait for transaction confirmation

#### deezel Implementation Status
- ✅ Transaction structure defined
- ✅ Transaction signing for all address types
- ✅ Fee calculation
- ✅ Bitcoin RPC client implementation
- ❌ Complete transaction construction
- ❌ Complete PSBT handling
- ❌ Complete fee estimation
- ❌ Complete UTXO selection
- ❌ Block monitoring
- ❌ Transaction tracking
- ❌ Confirmation handling

#### Missing Functionality
- Complete transaction construction and broadcasting
- Comprehensive block and transaction monitoring
- Mempool interaction
- Confirmation tracking

### Network Module

#### oyl-sdk Functions
- `setNetwork`: Set the network (mainnet, testnet, regtest)
- `getNetwork`: Get the current network
- `getNetworkInfo`: Get information about the network
- `isNetworkConnected`: Check if connected to the network
- `waitForNetwork`: Wait for network connection

#### deezel Implementation Status
- ✅ Network types defined
- ❌ Network configuration and connection management
- ❌ Network status checking

#### Missing Functionality
- Network configuration management
- Network connection status
- Network information retrieval

### Provider Module

#### oyl-sdk Functions
- `setProvider`: Set the provider for blockchain interaction
- `getProvider`: Get the current provider
- `createProvider`: Create a new provider
- `isProviderConnected`: Check if provider is connected
- `waitForProvider`: Wait for provider connection

#### deezel Implementation Status
- ❌ Provider module not implemented

#### Missing Functionality
- Provider interface definition
- Provider implementation for different blockchain services
- Provider connection management

### PSBT Module

#### oyl-sdk Functions
- `createPsbt`: Create a new PSBT
- `signPsbt`: Sign a PSBT
- `combinePsbt`: Combine multiple PSBTs
- `finalizePsbt`: Finalize a PSBT
- `extractTransaction`: Extract transaction from PSBT
- `analyzePsbt`: Analyze a PSBT
- `updatePsbt`: Update a PSBT

#### deezel Implementation Status
- ✅ Basic PSBT handling
- ❌ Comprehensive PSBT operations

#### Missing Functionality
- Complete PSBT creation, signing, combining, and finalizing
- PSBT analysis and updating

### RPC Client Module

#### oyl-sdk Functions
- `callRpc`: Call an RPC method
- `getBitcoinRpc`: Get Bitcoin RPC client
- `getEsploraRpc`: Get Esplora RPC client
- `getMetashrewRpc`: Get Metashrew RPC client
- `getAlkanesRpc`: Get Alkanes RPC client
- `getOrdRpc`: Get Ord RPC client

#### deezel Implementation Status
- ✅ Bitcoin RPC client implementation
- ✅ Esplora RPC client implementation
- ❌ Metashrew RPC client implementation
- ❌ Alkanes RPC client implementation
- ❌ Ord RPC client implementation

#### Missing Functionality
- Complete Metashrew, Alkanes, and Ord RPC client implementations

### Shared Module

#### oyl-sdk Functions
- `formatSatoshis`: Format satoshi amount
- `parseSatoshis`: Parse satoshi amount
- `validateAddress`: Validate Bitcoin address
- `validateTxid`: Validate transaction ID
- `sleep`: Sleep for a specified time
- `retry`: Retry a function with exponential backoff
- `debounce`: Debounce a function
- `throttle`: Throttle a function

#### deezel Implementation Status
- ✅ Some conversion utilities
- ✅ Some cryptographic utilities
- ❌ Complete shared utilities

#### Missing Functionality
- Complete set of formatting and parsing utilities
- Validation utilities
- Retry, debounce, and throttle utilities

### UTXO Module

#### oyl-sdk Functions
- `selectUtxos`: Select UTXOs for a transaction
- `getUtxos`: Get UTXOs for an address
- `getUtxoDetails`: Get details of a UTXO
- `trackUtxo`: Track a UTXO
- `isUtxoSpent`: Check if a UTXO is spent
- `waitForUtxo`: Wait for a UTXO to be available

#### deezel Implementation Status
- ✅ Basic UTXO selection
- ❌ Comprehensive UTXO management

#### Missing Functionality
- Complete UTXO selection strategies
- UTXO tracking and status checking
- UTXO waiting and availability checking

### Protocol Modules

#### Alkanes Module
- ✅ Module structure defined
- ❌ Contract deployment
- ❌ Token minting
- ❌ Token transfer
- ❌ Contract interaction
- ❌ Balance tracking

#### BRC20 Module
- ✅ Module structure defined
- ❌ Token deployment
- ❌ Token minting
- ❌ Token transfer
- ❌ Balance tracking

#### Rune Module
- ✅ Module structure defined
- ❌ Rune etching
- ❌ Rune minting
- ❌ Rune transfer
- ❌ Balance tracking

#### Collectible Module
- ✅ Module structure defined
- ❌ Collectible creation
- ❌ Collectible transfer
- ❌ Collection management

#### DIESEL Module
- ✅ Runestone protocol implementation
- ✅ DIESEL token minting
- ❌ DIESEL token transfer
- ❌ DIESEL balance tracking

## Integration Plan

### Phase 1: Core Infrastructure Completion (Current)
- ✅ Complete account module
- ✅ Complete signer module
- 🔄 RPC client implementation
  - ✅ Bitcoin RPC client
  - ✅ Esplora RPC client
  - ✅ Metashrew RPC client (structure only, not fully tested with real API calls)
  - ❌ Alkanes RPC client
  - ❌ Ord RPC client
- ✅ Basic utils module
- ✅ DIESEL token minting functionality

### Phase 2: Transaction and UTXO Management
- Complete transaction construction
- Complete PSBT handling
- Implement comprehensive UTXO selection and management
- Implement fee estimation
- Implement transaction broadcasting and confirmation tracking

### Phase 3: Network and Provider Integration
- Implement network module
- Implement provider module
- Complete RPC client implementations (Metashrew, Alkanes, Ord)
- Implement shared utilities

### Phase 4: Protocol Implementation
- Complete Alkanes module
- Complete BRC20 module
- Complete Rune module
- Complete Collectible module
- Complete DIESEL module

### Phase 5: AMM and Advanced Features
- Implement AMM module
- Implement advanced features (batch transactions, complex UTXO management)
- Performance optimizations

### Phase 6: JavaScript/TypeScript Bindings
- Implement NAPI-RS bindings
- Create TypeScript type definitions
- Implement API compatibility layer
- Create comprehensive documentation

## Testing Strategy

For each module and function, we will:

1. Create unit tests to verify individual function behavior
2. Create integration tests to verify interaction between modules
3. Create end-to-end tests to verify complete workflows
4. Create performance benchmarks to ensure efficiency

We will use the testing approach established for the DIESEL token minting functionality as a template for testing other modules.

## Conclusion

Achieving 1:1 parity between oyl-sdk and deezel requires implementing several missing modules and functions. The integration plan outlines a phased approach to completing this work, with a focus on core infrastructure first, followed by transaction and UTXO management, network and provider integration, protocol implementation, AMM and advanced features, and finally JavaScript/TypeScript bindings.
