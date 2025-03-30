# Project Symmetry: oyl-sdk vs. deezel

This document outlines the symmetrical and asymmetrical aspects between the original oyl-sdk (TypeScript) and the new deezel (Rust) implementation.

## Symmetrical Aspects

### API Structure

1. **Module Organization**:
   - Both projects organize functionality into similar modules:
     - Account/wallet management
     - Transaction construction and signing
     - Protocol-specific modules (Alkanes, BRC20, Rune, Collectible)
     - RPC client interfaces
     - Utility functions

2. **Protocol Support**:
   - Both projects support the same set of Bitcoin protocols:
     - DIESEL tokens
     - BRC20 tokens
     - Runes
     - Collectibles (NFTs)
     - Alkanes contracts

3. **Core Functionality**:
   - Both provide wallet creation and management
   - Both support multiple address types (legacy, nested segwit, native segwit, taproot)
   - Both handle transaction construction and signing
   - Both include fee estimation and UTXO selection

4. **RPC Services**:
   - Both connect to the same set of RPC services:
     - Bitcoin Core
     - Esplora
     - Metashrew
     - Alkanes
     - Ord

### User-Facing Features

1. **CLI Commands**:
   - Both provide similar CLI commands for:
     - Wallet management
     - DIESEL operations
     - BRC20 operations
     - Rune operations
     - Collectible operations
     - Alkanes operations

2. **Configuration**:
   - Both use similar configuration options:
     - Network selection
     - RPC URLs
     - Wallet path

3. **Error Handling**:
   - Both provide meaningful error messages
   - Both include context for errors
   - Both handle RPC errors appropriately

## Asymmetrical Aspects

### Language and Ecosystem

1. **Programming Language**:
   - oyl-sdk: TypeScript (JavaScript ecosystem)
   - deezel: Rust (systems programming ecosystem)

2. **Dependencies**:
   - oyl-sdk: Node.js libraries, web3 libraries
   - deezel: Rust crates, Bitcoin Development Kit (BDK)

3. **Compilation**:
   - oyl-sdk: Interpreted/JIT compiled
   - deezel: Ahead-of-time compiled to native code

### Architecture

1. **Error Handling**:
   - oyl-sdk: JavaScript-style error handling with try/catch
   - deezel: Rust's Result type with ? operator and anyhow/thiserror

2. **Concurrency Model**:
   - oyl-sdk: JavaScript's event loop and Promise-based concurrency
   - deezel: Rust's async/await with Tokio runtime

3. **Memory Management**:
   - oyl-sdk: Garbage collected
   - deezel: Ownership system with RAII

4. **Type System**:
   - oyl-sdk: Gradual typing with TypeScript
   - deezel: Strong static typing with Rust

### Implementation Details

1. **Transaction Handling**:
   - oyl-sdk: Uses JavaScript Bitcoin libraries
   - deezel: Uses BDK and rust-bitcoin

2. **Cryptography**:
   - oyl-sdk: Uses JavaScript cryptography libraries
   - deezel: Uses Rust cryptography libraries (often faster and more secure)

3. **RPC Client Implementation**:
   - oyl-sdk: Uses fetch or axios
   - deezel: Uses reqwest

4. **CLI Implementation**:
   - oyl-sdk: Uses commander or yargs
   - deezel: Uses clap

### Additional Features in deezel

1. **Performance Optimizations**:
   - More efficient UTXO selection algorithms
   - Optimized transaction construction
   - Faster cryptographic operations

2. **Safety Improvements**:
   - Memory safety guarantees from Rust
   - No null/undefined errors
   - Exhaustive pattern matching

3. **Modularity**:
   - More explicit module boundaries
   - Clearer separation of concerns
   - More testable components

4. **Documentation**:
   - More comprehensive API documentation
   - More examples
   - Memory bank for project context

## API Compatibility Layer

To ensure a smooth migration path from oyl-sdk to deezel, we're implementing:

1. **JavaScript/TypeScript Bindings**:
   - NAPI-RS bindings to expose deezel functionality to JavaScript/TypeScript
   - TypeScript type definitions that match oyl-sdk

2. **API Compatibility**:
   - Function signatures that match oyl-sdk
   - Similar object structures
   - Equivalent error types

3. **Migration Guide**:
   - Documentation on how to migrate from oyl-sdk to deezel
   - Examples of common migration patterns
   - Compatibility notes

## Current State of Symmetry

As of March 29, 2025, we have achieved:

1. **Module Structure Symmetry**: ✅
   - All major modules from oyl-sdk have equivalent modules in deezel

2. **Protocol Support Symmetry**: ✅
   - All protocols supported by oyl-sdk have placeholder implementations in deezel

3. **CLI Command Symmetry**: ✅
   - All CLI commands from oyl-sdk have equivalent commands in deezel

4. **API Compatibility**: 🔄
   - Basic API structure is in place
   - JavaScript/TypeScript bindings are not yet implemented

5. **Implementation Completeness**: 🔄
   - Core structure is in place
   - Many implementations are still placeholders

## Next Steps for Improving Symmetry

1. **Complete Core Implementations**:
   - Implement account module functionality
   - Implement signer module functionality
   - Implement RPC client functionality
   - Implement transaction module functionality

2. **Complete Protocol Implementations**:
   - Implement Alkanes protocol functionality
   - Implement BRC20 protocol functionality
   - Implement Rune protocol functionality
   - Implement Collectible protocol functionality

3. **Implement JavaScript/TypeScript Bindings**:
   - Set up NAPI-RS
   - Create TypeScript type definitions
   - Ensure API compatibility

4. **Comprehensive Testing**:
   - Test against the same scenarios as oyl-sdk
   - Ensure equivalent behavior
   - Verify performance improvements
