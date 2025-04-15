# Active Context

## Current Work Focus

The project is currently in its implementation phase. The basic module structure has been established, and we have implemented the core functionality for Bitcoin and alkanes metaprotocol interactions. The primary goal is to create a comprehensive toolkit that can interact with Bitcoin and the alkanes metaprotocol using BDK with a custom JSON-RPC provider, replacing the need for esplora while adding metashrew_view RPC calls for rendering alkanes view functions.

We have created a comprehensive reference document (`oyl-sdk-alkanes-reference.md`) that details how deezel maps to the alkanes functionality in oyl-sdk and serves as a guide for our implementation.

### Active Development Areas

1. **Core Infrastructure Setup** ✅
   - Project structure and organization
   - Dependency configuration
   - Build system setup
   - Command-line argument parsing for RPC URLs
   - Library and binary structure

2. **Wallet Implementation** 🔄
   - BDK integration for Bitcoin wallet functionality ✅
   - Custom JSON-RPC provider replacing Esplora backend ✅
   - UTXO management with ordinal and rune constraints 🔄
   - Wallet state persistence 🔄

3. **Block Monitoring** 🔄
   - Bitcoin RPC integration for `getblockcount` ✅
   - Metashrew RPC integration for `metashrew_height` ✅
   - Block height verification (Metashrew height = Bitcoin height + 1) ✅
   - Rate limiting implementation 🔄

4. **Transaction Construction** 🔄
   - Runestone with Protostone creation ✅
   - Protocol-specific message encoding ✅
   - Output consolidation logic 🔄
   - UTXO selection using `spendablesbyaddress` via protobuf 🔄
   - Compatibility with alkanes metaprotocol functionality 🔄

5. **Alkanes Metaprotocol Integration** 🔄
   - Runestone decoding for all protostones (not just DIESEL) ✅
   - Metashrew view function rendering via RPC ✅
   - Protostone parsing and interpretation 🔄
   - Support for various alkanes operations 🔄

## Recent Changes

The project has been significantly advanced with the implementation of the basic module structure:

1. **Project Setup Completed**
   - Cargo.toml with all required dependencies
   - Main application with CLI argument parsing
   - Module structure for all core components

2. **Module Structure Implementation**
   - Wallet module with BDK integration structure
   - Block monitor with polling mechanism
   - Transaction constructor with Runestone/Protostone structure
   - RPC client for Bitcoin and Metashrew communication
   - Enhanced Runestone decoder for all protostones

3. **Documentation Updates**
   - Progress tracking updated
   - Active context updated to reflect current state
   - Added oyl-sdk alkanes reference documentation

## Next Steps

The following tasks are prioritized for immediate implementation:

1. **Wallet Module Implementation**
   - [x] Create basic BDK wallet integration structure
   - [x] Implement custom JSON-RPC provider replacing Esplora backend
   - [x] Map Sandshrew RPC calls to JSON-RPC API
   - [ ] Complete persistent wallet state management
   - [ ] Finalize UTXO tracking and management

2. **Block Monitor Implementation**
   - [x] Create block polling mechanism structure
   - [x] Implement block height verification
   - [ ] Complete rate limiting implementation
   - [ ] Finalize confirmation tracking
   - [ ] Implement comprehensive error handling and recovery

3. **Transaction Constructor Implementation**
   - [x] Create Runestone/Protostone structure
   - [x] Implement Runestone protocol for all protostones
   - [x] Create dust output and OP_RETURN output
   - [ ] Implement UTXO selection logic
   - [ ] Complete output consolidation mechanism
   - [ ] Finalize transaction signing and verification

4. **RPC Client Implementation**
   - [x] Create Sandshrew RPC client structure
   - [x] Implement metashrew_view RPC calls
   - [x] Implement basic API methods
   - [ ] Complete implementation of all required API methods
   - [ ] Finalize error handling and retries
   - [ ] Complete response parsing and validation

5. **Runestone/Protostone Decoding**
   - [x] Basic Runestone extraction from transactions
   - [x] Protocol tag and message parsing
   - [x] Enhanced Runestone decoder for all protostones
   - [ ] Complete Protostone decoding for all types
   - [ ] Implement cellpack structure interpretation
   - [ ] Support for various alkanes operations

6. **Integration and Testing**
   - [ ] Integrate all components
   - [ ] Complete unit tests for each module
   - [ ] Develop integration tests
   - [ ] Implement end-to-end testing

## Active Decisions and Considerations

### Technical Decisions Under Consideration

1. **Concurrency Model**
   - Evaluating between thread-based and async approaches
   - Considering Tokio for async runtime
   - Assessing performance implications for long-running processes

2. **Error Handling Strategy**
   - Determining appropriate error propagation
   - Considering retry policies for transient failures
   - Evaluating logging and monitoring requirements

3. **Persistence Strategy**
   - Evaluating file-based vs. database storage for wallet state
   - Considering encryption requirements for sensitive data
   - Assessing backup and recovery mechanisms

4. **Fee Estimation Approach**
   - Determining optimal fee estimation strategy
   - Considering dynamic fee adjustment based on confirmation time
   - Evaluating balance between cost efficiency and confirmation speed

### Open Questions

1. **Scaling Considerations**
   - How will the application handle increasing UTXO sets?
   - What are the performance implications of monitoring multiple wallets?
   - How can we optimize for long-term operation?

2. **Security Concerns**
   - What are the security implications of persistent key storage?
   - How should we handle potential chain reorganizations?
   - What measures are needed to protect against potential attacks?

3. **Operational Considerations**
   - What monitoring and alerting are required for production use?
   - How should the application handle network outages?
   - What recovery procedures are needed for various failure scenarios?

## Current Priorities

1. Implement core wallet functionality with BDK
2. Develop block monitoring with Sandshrew RPC
3. Create transaction construction with Runestone/Protostone
4. Enhance Runestone decoder for all protostones
5. Implement metashrew_view RPC calls
6. Integrate components for end-to-end operation
7. Implement comprehensive testing

## Alkanes Metaprotocol Integration

We have made significant progress in implementing deezel as a comprehensive toolkit for interacting with Bitcoin and the alkanes metaprotocol:

1. **Reference Documentation**
   - Created comprehensive reference documentation (`oyl-sdk-alkanes-reference.md`) that maps alkanes functionality to deezel components
   - Documented API endpoints, method mappings, and implementation differences

2. **CLI Implementation**
   - Created a new binary `deezel` that provides command-line tools for interacting with Bitcoin and the alkanes metaprotocol
   - Implemented read-only commands for alkanes functionality:
     - `deezel metashrew height`
     - `deezel bitcoind getblockcount`
     - `deezel alkanes getbytecode <block:tx>`
     - `deezel alkanes protorunesbyaddress <address>`
     - `deezel alkanes protorunesbyoutpoint <txid:vout>`
     - `deezel alkanes spendablesbyaddress <address>`
     - `deezel alkanes traceblock <blockheight>`
     - `deezel alkanes trace <txid:vout>`
     - `deezel alkanes simulate <block:tx:input1:input2...>`
     - `deezel alkanes meta <block:tx>`
   - Added new command for Runestone decoding:
     - `deezel runestone <txid_or_hex>`

3. **RPC Client Extensions**
   - Extended the RPC client with methods for all required alkanes operations
   - Implemented proper error handling and response parsing
   - Added support for metashrew_view RPC calls

4. **Runestone/Protostone Decoding**
   - Implemented enhanced Runestone decoder for all protostones
   - Added support for protocol tag and message parsing
   - Implemented cellpack structure interpretation

The next steps are to complete the implementation of the `deezel alkanes execute` command for transaction execution and enhance the Runestone decoder to support all types of protostones.

## Alkanes Metaprotocol Compatibility

As part of our development efforts, we are focusing on ensuring that deezel can serve as a comprehensive toolkit for interacting with Bitcoin and the alkanes metaprotocol. This involves:

1. **API Compatibility**
   - Implementing equivalent RPC methods to those used by alkanes
   - Ensuring consistent behavior for key operations like token minting and tracing

2. **Functionality Mapping**
   - Mapping alkanes functions to deezel components
   - Implementing core operations supported by the alkanes metaprotocol

3. **Command-Line Interface**
   - Providing a CLI that supports the key alkanes commands
   - Ensuring consistent parameter handling and output formatting

4. **Runestone/Protostone Support**
   - Implementing comprehensive Runestone decoding for all protostones
   - Supporting various cellpack structures and interpretations
   - Enabling interaction with the alkanes metaprotocol

The `oyl-sdk-alkanes-reference.md` document in the memory-bank provides a detailed mapping between alkanes functionality and deezel components, serving as a guide for our implementation.