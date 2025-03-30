# Deezel Active Context

## Current State

As of March 29, 2025, the Deezel project is in the early stages of development. We have set up the project structure and implemented the basic module structure for the core functionality and protocol support. The current focus is on implementing the core functionality and protocol support.

## Current Priorities

1. **Core Functionality**:
   - Implement the account module
   - Implement the signer module
   - Implement the RPC client module
   - Implement the transaction module
   - Implement the monitor module

2. **Protocol Support**:
   - Implement the Alkanes module
   - Implement the BRC20 module
   - Implement the Rune module
   - Implement the Collectible module

3. **CLI Tool**:
   - Implement the CLI module
   - Implement the command handlers

## Next Steps

1. **Account Module**:
   - Implement account creation from mnemonic
   - Implement account creation from extended private key
   - Implement address generation for all address types
   - Implement account serialization and deserialization

2. **Signer Module**:
   - Implement transaction signing for all address types
   - Implement message signing and verification
   - Implement PSBT handling

3. **RPC Client Module**:
   - Implement Bitcoin RPC client
   - Implement Esplora RPC client
   - Implement Metashrew RPC client
   - Implement Alkanes RPC client
   - Implement Ord RPC client

## Current Challenges

1. **RPC Integration**:
   - Integration with various RPC services may be complex
   - Different services may have different APIs and response formats
   - Error handling may be challenging

2. **Protocol Implementation**:
   - Implementing all protocols and features may be challenging
   - Different protocols may have different requirements and constraints
   - Testing may be challenging

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
