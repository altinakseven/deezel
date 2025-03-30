# Deezel Active Context

## Current State

As of March 29, 2025, the Deezel project is in the early stages of development. We have set up the project structure and implemented the basic module structure for the core functionality and protocol support. The current focus is on implementing the core functionality and protocol support.

We have made significant progress in implementing and testing the DIESEL token minting functionality, including the Runestone protocol implementation. This functionality has been thoroughly tested and verified to work correctly.

We have completed a comprehensive analysis of the feature gap between oyl-sdk and deezel, documented in `memory-bank/oylSdkParity.md`. This analysis will guide our development efforts to achieve 1:1 functional parity between the two SDKs.

## Current Priorities

1. **Core Functionality**:
   - ✅ Implement the account module
   - ✅ Implement the signer module
   - 🔄 Implement the RPC client module (partially complete)
   - 🔄 Implement the transaction module (partially complete)
   - 🔄 Implement the monitor module (partially complete)

2. **Protocol Support**:
   - 🔄 Implement the Alkanes module (structure defined)
   - 🔄 Implement the BRC20 module (structure defined)
   - 🔄 Implement the Rune module (structure defined)
   - 🔄 Implement the Collectible module (structure defined)
   - 🔄 Implement the DIESEL module (minting functionality complete)

3. **Missing Modules from oyl-sdk**:
   - Implement the AMM module
   - Implement the Network module
   - Implement the Provider module
   - Implement the PSBT module (comprehensive operations)
   - Implement the Shared module (complete utilities)
   - Implement the UTXO module (comprehensive management)

4. **CLI Tool**:
   - 🔄 Implement the CLI module (structure defined)
   - 🔄 Implement the command handlers (placeholder implementations)

## Next Steps

Following our oyl-sdk parity analysis, we will implement the missing functionality in phases:

### Phase 1: Core Infrastructure Completion (Current)
- ✅ Complete account module
- ✅ Complete signer module
- 🔄 Complete RPC client implementations
- 🔄 Complete utils module
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

## Current Challenges

1. **RPC Integration**:
   - Integration with various RPC services may be complex
   - Different services may have different APIs and response formats
   - Error handling may be challenging

2. **Protocol Implementation**:
   - Implementing all protocols and features may be challenging
   - Different protocols may have different requirements and constraints
   - Testing may be challenging

3. **Testing Coverage**:
   - We have successfully implemented tests for the DIESEL token minting functionality
   - We need to extend this testing approach to other protocol implementations
   - Integration testing with real blockchain networks remains a challenge

## Current Decisions

1. **Rust vs. TypeScript**:
   - We have decided to implement Deezel in Rust for performance, safety, and ecosystem reasons
   - We will provide JavaScript/TypeScript bindings for compatibility with oyl-sdk

2. **Modular Architecture**:
   - We have decided to use a modular architecture for flexibility, testability, and maintainability
   - Each module has a clear responsibility and interface

3. **Error Handling**:
   - We have decided to use the `anyhow` and `thiserror` crates for error handling
   - We will provide context for errors and use custom error types where appropriate

4. **Async/Await**:
   - We have decided to use the async/await pattern for asynchronous operations
   - We will use Tokio as the async runtime

## Current Questions

1. **API Compatibility**:
   - How closely should we match the oyl-sdk API?
   - What are the most important API features to maintain compatibility with?

2. **Protocol Support**:
   - Which protocols should we prioritize?
   - What are the most important features of each protocol?

3. **Testing Strategy**:
   - How should we test the RPC client integration?
   - How should we test the protocol implementations?
   - Can we use the DIESEL token minting testing approach as a template for other protocols?
   - How can we automate testing of blockchain interactions?

## Current Risks

1. **Schedule Risk**:
   - The project timeline may be too ambitious
   - Unforeseen technical challenges may delay the project

2. **Technical Risk**:
   - Integration with various RPC services may be more complex than anticipated
   - Protocol implementations may be more challenging than anticipated

3. **Resource Risk**:
   - Limited resources for development and maintenance
   - Limited expertise in certain areas

## Verified Functionality

1. **Runestone Protocol**:
   - Creation of Runestone objects with specific protocol parameters
   - Encoding Runestone data into Bitcoin scripts (OP_RETURN outputs)
   - DIESEL token minting protocol implementation (Protocol tag: 1, Message cellpack: [2, 0, 77])
   - Extraction of Runestone data from Bitcoin transactions

2. **Transaction Analysis**:
   - Identification of DIESEL token minting transactions in the mempool
   - Fee rate calculation for Bitcoin transactions
   - Transaction weight and size calculation
   - Transaction input/output value calculation

3. **Wallet Integration**:
   - Address generation for dust outputs
   - Balance retrieval from wallet
   - Transaction construction with proper outputs (dust + OP_RETURN)
