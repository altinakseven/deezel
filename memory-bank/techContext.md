# Deezel Technical Context

## Architecture

Deezel is designed as a modular Rust library with a focus on:

1. **Modularity**: Each component is designed to be used independently or as part of the whole system.
2. **Performance**: Rust's performance characteristics are leveraged for computationally intensive operations.
3. **Safety**: Rust's memory safety guarantees help prevent common bugs and security issues.
4. **Extensibility**: The architecture allows for easy addition of new protocols and features.

### Core Components

#### Account Module

The account module provides functionality for HD wallet management with support for multiple address types:

- Legacy (P2PKH)
- Nested SegWit (P2SH-P2WPKH)
- Native SegWit (P2WPKH)
- Taproot (P2TR)

It implements BIP32/39/44 for hierarchical deterministic wallet generation and management.

#### Signer Module

The signer module handles transaction signing for all address types, as well as message signing and verification. It works closely with the account module to derive private keys from mnemonics and sign transactions.

#### RPC Client Module

The RPC client module provides a unified interface for interacting with various Bitcoin RPC services:

- Bitcoin Core RPC
- Esplora API
- Metashrew API
- Alkanes API
- Ord API

#### Transaction Module

The transaction module handles transaction construction, PSBT creation, fee estimation, and UTXO selection. It works closely with the signer module to create and sign transactions.

#### Monitor Module

The monitor module provides functionality for monitoring the blockchain, tracking transactions, and handling confirmations and chain reorganizations.

#### Protocol Modules

The protocol modules implement support for various Bitcoin protocols:

- **Alkanes**: Contract deployment, token minting, and transfer
- **BRC20**: Token deployment, minting, and transfer
- **Rune**: Rune etching, minting, and transfer
- **Collectible**: NFT creation and transfer

#### CLI Module

The CLI module provides a command-line interface for all functionality, making it easy to use the library from the command line.

### Design Decisions

#### Rust vs. TypeScript

The decision to reimplement oyl-sdk in Rust was driven by several factors:

1. **Performance**: Rust's performance characteristics are better suited for computationally intensive operations like cryptography and transaction processing.
2. **Safety**: Rust's memory safety guarantees help prevent common bugs and security issues.
3. **Ecosystem**: The Rust ecosystem has excellent libraries for Bitcoin development, such as rust-bitcoin, BDK, and miniscript.
4. **Compilation**: Rust's compilation model allows for better optimization and error detection at compile time.

#### Modular Architecture

The modular architecture was chosen to allow for:

1. **Flexibility**: Users can use only the components they need.
2. **Testability**: Each component can be tested independently.
3. **Maintainability**: Changes to one component don't affect others.
4. **Extensibility**: New protocols and features can be added without modifying existing code.

#### BDK Integration

Bitcoin Development Kit (BDK) was chosen as the foundation for wallet functionality because:

1. **Maturity**: BDK is a mature and well-tested library for Bitcoin wallet development.
2. **Features**: BDK provides a rich set of features for wallet management, transaction construction, and signing.
3. **Community**: BDK has a strong community and is actively maintained.
4. **Compatibility**: BDK is compatible with other Bitcoin libraries in the Rust ecosystem.

#### Error Handling

The error handling strategy uses the `anyhow` and `thiserror` crates for:

1. **Context**: Errors include context about where they occurred.
2. **Propagation**: Errors can be easily propagated up the call stack.
3. **Custom Errors**: Domain-specific errors can be defined and handled appropriately.
4. **User-Friendly Messages**: Errors can be presented to users in a friendly way.

#### Async/Await

The async/await pattern is used for:

1. **Concurrency**: Multiple operations can be performed concurrently.
2. **I/O Efficiency**: I/O-bound operations don't block the thread.
3. **Readability**: Async code is more readable than callback-based code.
4. **Composability**: Async operations can be easily composed.

### Technical Considerations

#### Cross-Platform Compatibility

Deezel is designed to be cross-platform, with support for:

- Linux
- macOS
- Windows

This is achieved by:

1. Using platform-agnostic APIs
2. Avoiding platform-specific features
3. Using cross-platform libraries

#### JavaScript/TypeScript Bindings

To maintain compatibility with existing oyl-sdk users, JavaScript/TypeScript bindings will be provided using NAPI-RS. This will allow:

1. **Gradual Migration**: Existing users can migrate gradually from oyl-sdk to deezel.
2. **API Compatibility**: The JavaScript/TypeScript API will be compatible with oyl-sdk.
3. **Performance**: The Rust implementation will provide better performance than the TypeScript implementation.

#### Testing Strategy

The testing strategy includes:

1. **Unit Tests**: Each component is tested in isolation.
2. **Integration Tests**: Components are tested together.
3. **End-to-End Tests**: The entire system is tested as a whole.
4. **Property-Based Tests**: Randomized inputs are used to test edge cases.
5. **Fuzz Testing**: Random inputs are used to find bugs and security issues.

#### Documentation

The documentation strategy includes:

1. **API Documentation**: Each function and type is documented with examples.
2. **User Guide**: A comprehensive guide for users.
3. **Examples**: Example code for common use cases.
4. **Migration Guide**: A guide for migrating from oyl-sdk to deezel.

## Technical Debt

### Current Technical Debt

1. **Placeholder Implementations**: Many functions have placeholder implementations that need to be filled in.
2. **Missing Tests**: Most modules don't have tests yet.
3. **Incomplete Documentation**: Documentation is minimal at this point.
4. **RPC Client Implementation**: The RPC client implementation is incomplete.
5. **Transaction Construction**: Transaction construction is not fully implemented.

### Plan to Address Technical Debt

1. **Prioritize Core Functionality**: Focus on implementing core functionality first.
2. **Add Tests**: Add tests as functionality is implemented.
3. **Improve Documentation**: Improve documentation as functionality is implemented.
4. **Refactor as Needed**: Refactor code as patterns emerge.
5. **Regular Reviews**: Conduct regular code reviews to identify and address technical debt.

## Future Considerations

### Performance Optimization

1. **Profiling**: Profile the code to identify performance bottlenecks.
2. **Optimization**: Optimize critical paths.
3. **Parallelization**: Use parallelism for computationally intensive operations.
4. **Caching**: Cache frequently used data.

### Security

1. **Code Reviews**: Conduct regular code reviews with a focus on security.
2. **Dependency Audits**: Regularly audit dependencies for security issues.
3. **Fuzzing**: Use fuzz testing to find security issues.
4. **Security Best Practices**: Follow security best practices for cryptographic operations.

### Scalability

1. **Resource Usage**: Monitor and optimize resource usage.
2. **Connection Pooling**: Use connection pooling for RPC clients.
3. **Batching**: Batch operations where possible.
4. **Caching**: Cache frequently used data.

### Maintainability

1. **Code Style**: Follow Rust's code style guidelines.
2. **Documentation**: Keep documentation up to date.
3. **Tests**: Maintain high test coverage.
4. **Refactoring**: Refactor code as needed to maintain clarity and simplicity.
