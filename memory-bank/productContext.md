# Deezel Product Context

## Purpose

Deezel is a comprehensive Bitcoin wallet SDK and CLI tool designed to replace oyl-sdk with a more performant, safer, and more maintainable implementation in Rust. It provides functionality for Bitcoin wallet management, transaction construction, and support for various Bitcoin protocols including DIESEL tokens, BRC20, Runes, and Collectibles.

## Target Audience

### Primary Audience

1. **Developers**: Software developers building Bitcoin applications who need a reliable, performant, and feature-rich wallet SDK.
2. **Blockchain Projects**: Projects building on Bitcoin that need to integrate wallet functionality and support for various Bitcoin protocols.
3. **Current oyl-sdk Users**: Users of oyl-sdk who want to migrate to a more performant and safer implementation.

### Secondary Audience

1. **Power Users**: Advanced Bitcoin users who want to interact with various Bitcoin protocols through a CLI tool.
2. **System Administrators**: Administrators who need to automate Bitcoin-related tasks.
3. **Researchers**: Blockchain researchers who need tools to interact with Bitcoin and its protocols.

## Product Vision

Deezel aims to be the go-to SDK and CLI tool for Bitcoin wallet management and protocol interaction, providing a comprehensive, performant, and safe solution for developers and users. It will support all major Bitcoin protocols and provide a seamless migration path for oyl-sdk users.

### Key Differentiators

1. **Performance**: Rust's performance characteristics make Deezel significantly faster than oyl-sdk, especially for computationally intensive operations.
2. **Safety**: Rust's memory safety guarantees help prevent common bugs and security issues.
3. **Comprehensive Protocol Support**: Deezel supports all major Bitcoin protocols, including DIESEL, BRC20, Runes, and Collectibles.
4. **Modular Architecture**: Deezel's modular architecture allows users to use only the components they need.
5. **CLI Tool**: Deezel provides a comprehensive CLI tool for interacting with Bitcoin and its protocols.

## User Stories

### Developer Stories

1. As a developer, I want to create and manage Bitcoin wallets with support for multiple address types, so that I can build applications that support all types of Bitcoin addresses.
2. As a developer, I want to construct and sign Bitcoin transactions, so that I can build applications that send and receive Bitcoin.
3. As a developer, I want to interact with various Bitcoin protocols, so that I can build applications that support these protocols.
4. As a developer, I want to monitor the blockchain for transactions and confirmations, so that I can build applications that provide real-time updates to users.
5. As a developer, I want to use a modular SDK, so that I can use only the components I need.

### oyl-sdk User Stories

1. As an oyl-sdk user, I want to migrate to Deezel with minimal changes to my code, so that I can benefit from Deezel's performance and safety improvements without a major rewrite.
2. As an oyl-sdk user, I want to use Deezel's JavaScript/TypeScript bindings, so that I can continue to use my existing JavaScript/TypeScript codebase.
3. As an oyl-sdk user, I want to use Deezel's API, which is compatible with oyl-sdk, so that I can migrate gradually.

### Power User Stories

1. As a power user, I want to create and manage Bitcoin wallets from the command line, so that I can manage my Bitcoin without a GUI.
2. As a power user, I want to interact with various Bitcoin protocols from the command line, so that I can use these protocols without a GUI.
3. As a power user, I want to automate Bitcoin-related tasks, so that I can save time and reduce errors.

## Product Requirements

### Functional Requirements

1. **Wallet Management**:
   - Create and manage HD wallets with support for multiple address types (legacy, nested segwit, native segwit, taproot).
   - Import and export wallets using mnemonics and private keys.
   - Generate and manage addresses.
   - Track balances and transaction history.

2. **Transaction Construction**:
   - Construct and sign Bitcoin transactions.
   - Support for various output types (P2PKH, P2SH, P2WPKH, P2WSH, P2TR).
   - Fee estimation and UTXO selection.
   - Transaction broadcasting.

3. **Protocol Support**:
   - **DIESEL**: Mint and transfer DIESEL tokens.
   - **BRC20**: Deploy, mint, and transfer BRC20 tokens.
   - **Runes**: Etch, mint, and transfer Runes.
   - **Collectibles**: Create and transfer NFT collectibles.
   - **Alkanes**: Deploy and interact with Alkanes contracts.

4. **Blockchain Monitoring**:
   - Monitor the blockchain for transactions and confirmations.
   - Handle chain reorganizations.
   - Track transaction status.

5. **CLI Tool**:
   - Command-line interface for all functionality.
   - Configuration management.
   - Interactive mode.

6. **JavaScript/TypeScript Bindings**:
   - API compatible with oyl-sdk.
   - TypeScript type definitions.
   - Documentation and examples.

### Non-Functional Requirements

1. **Performance**:
   - Faster than oyl-sdk for all operations.
   - Efficient resource usage.
   - Minimal memory footprint.

2. **Safety**:
   - No memory safety issues.
   - Proper error handling.
   - Secure cryptographic operations.

3. **Maintainability**:
   - Modular architecture.
   - Comprehensive documentation.
   - High test coverage.
   - Clean code.

4. **Usability**:
   - Intuitive API.
   - Comprehensive documentation.
   - Helpful error messages.
   - Examples and tutorials.

5. **Compatibility**:
   - Compatible with all major Bitcoin implementations.
   - Compatible with oyl-sdk API.
   - Cross-platform support (Linux, macOS, Windows).

## Success Metrics

1. **Performance**: Deezel should be at least 2x faster than oyl-sdk for all operations.
2. **Safety**: Deezel should have no memory safety issues or security vulnerabilities.
3. **Adoption**: At least 50% of oyl-sdk users should migrate to Deezel within 6 months of release.
4. **Satisfaction**: User satisfaction should be at least 4.5/5 based on surveys and feedback.
5. **Contributions**: At least 10 external contributors should contribute to Deezel within 6 months of release.

## Roadmap

### Phase 1: Core Infrastructure (Weeks 1-4)

1. Project structure setup
2. Account module implementation
3. Signer module implementation
4. RPC client implementation
5. Transaction module implementation
6. Monitor module implementation

### Phase 2: Protocol Support (Weeks 5-8)

1. Alkanes protocol implementation
2. BRC20 protocol implementation
3. Rune protocol implementation
4. Collectible protocol implementation

### Phase 3: CLI and JavaScript/TypeScript Bindings (Weeks 9-12)

1. CLI implementation
2. JavaScript/TypeScript bindings
3. Documentation and examples
4. Testing and bug fixes

### Phase 4: Release and Maintenance (Ongoing)

1. Initial release
2. Bug fixes and improvements
3. New features and protocols
4. Community engagement and support

## Competitive Analysis

### oyl-sdk

**Strengths**:
- Established user base
- Comprehensive protocol support
- JavaScript/TypeScript native

**Weaknesses**:
- Performance issues
- Memory safety issues
- Limited modularity

### BDK

**Strengths**:
- Rust native
- Performance
- Safety
- Comprehensive wallet functionality

**Weaknesses**:
- Limited protocol support
- No CLI tool
- No JavaScript/TypeScript bindings

### bitcoinjs-lib

**Strengths**:
- Established user base
- JavaScript/TypeScript native
- Comprehensive Bitcoin functionality

**Weaknesses**:
- Performance issues
- Limited protocol support
- No CLI tool

## Market Opportunity

The Bitcoin ecosystem is growing rapidly, with new protocols and applications being developed every day. There is a need for a comprehensive, performant, and safe SDK and CLI tool that supports all major Bitcoin protocols and provides a seamless migration path for existing users.

Deezel addresses this need by providing:

1. **Comprehensive Protocol Support**: Support for all major Bitcoin protocols, including DIESEL, BRC20, Runes, and Collectibles.
2. **Performance and Safety**: Rust's performance characteristics and memory safety guarantees.
3. **Modular Architecture**: Users can use only the components they need.
4. **CLI Tool**: A comprehensive CLI tool for interacting with Bitcoin and its protocols.
5. **JavaScript/TypeScript Bindings**: API compatible with oyl-sdk for seamless migration.

## Go-to-Market Strategy

1. **Open Source**: Release Deezel as an open-source project to encourage adoption and contributions.
2. **Documentation and Examples**: Provide comprehensive documentation and examples to make it easy for users to get started.
3. **Community Engagement**: Engage with the Bitcoin and Rust communities to promote Deezel and gather feedback.
4. **Migration Guide**: Provide a comprehensive migration guide for oyl-sdk users.
5. **Tutorials and Workshops**: Conduct tutorials and workshops to help users get started with Deezel.
6. **Partnerships**: Partner with Bitcoin projects and companies to promote Deezel and gather feedback.

## Risks and Mitigation

1. **Adoption Risk**: Users may be reluctant to migrate from oyl-sdk to Deezel.
   - **Mitigation**: Provide a seamless migration path with JavaScript/TypeScript bindings and API compatibility.

2. **Technical Risk**: Implementing all protocols and features may be challenging.
   - **Mitigation**: Prioritize core functionality and protocols, and involve the community in development.

3. **Resource Risk**: Limited resources for development and maintenance.
   - **Mitigation**: Focus on core functionality and protocols, and involve the community in development.

4. **Market Risk**: The Bitcoin ecosystem may evolve in unexpected ways.
   - **Mitigation**: Design Deezel to be flexible and extensible, and stay engaged with the Bitcoin community.

5. **Competitive Risk**: Other projects may emerge with similar functionality.
   - **Mitigation**: Focus on Deezel's key differentiators and engage with the community to gather feedback and improve.
