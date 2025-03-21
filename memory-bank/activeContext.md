# Active Context

## Current Work Focus

The project is currently in its implementation phase. The basic module structure has been established, and we have implemented the core functionality for DIESEL token minting and management.

### Active Development Areas

1. **Core Infrastructure Setup** ✅
   - Project structure and organization
   - Dependency configuration
   - Build system setup
   - Command-line argument parsing for RPC URLs
   - Library and binary structure

2. **Wallet Implementation** 🔄
   - BDK integration for Bitcoin wallet functionality ✅
   - Custom Esplora backend for Sandshrew RPC ✅
   - UTXO management with ordinal and rune constraints 🔄
   - Wallet state persistence 🔄

3. **Block Monitoring** 🔄
   - Bitcoin RPC integration for `getblockcount`
   - Metashrew RPC integration for `metashrew_height`
   - Block height verification (Metashrew height = Bitcoin height + 1)
   - Rate limiting implementation

4. **Transaction Construction** 🔄
   - Runestone with Protostone creation
   - Protocol-specific message encoding
   - Output consolidation logic
   - UTXO selection using `spendablesbyaddress` via protobuf

## Recent Changes

The project has been significantly advanced with the implementation of the basic module structure:

1. **Project Setup Completed**
   - Cargo.toml with all required dependencies
   - Main application with CLI argument parsing
   - Module structure for all core components

2. **Module Structure Implementation**
   - Wallet module with BDK integration structure
   - Block monitor with polling mechanism
   - Transaction constructor with DIESEL token minting structure
   - RPC client for Bitcoin and Metashrew communication

3. **Documentation Updates**
   - Progress tracking updated
   - Active context updated to reflect current state

## Next Steps

The following tasks are prioritized for immediate implementation:

1. **Wallet Module Implementation**
   - [x] Create basic BDK wallet integration structure
   - [x] Implement custom Esplora backend for Sandshrew RPC
   - [x] Map Sandshrew RPC calls to Esplora REST API
   - [ ] Complete persistent wallet state management
   - [ ] Finalize UTXO tracking and management

2. **Block Monitor Implementation**
   - [x] Create block polling mechanism structure
   - [ ] Complete rate limiting implementation
   - [ ] Finalize confirmation tracking
   - [ ] Implement comprehensive error handling and recovery

3. **Transaction Constructor Implementation**
   - [x] Create Runestone/Protostone structure
   - [x] Implement Runestone protocol for DIESEL token minting
   - [x] Create dust output and OP_RETURN output
   - [ ] Implement UTXO selection logic
   - [ ] Complete output consolidation mechanism
   - [ ] Finalize transaction signing and verification

4. **RPC Client Implementation**
   - [x] Create Sandshrew RPC client structure
   - [ ] Complete implementation of required API methods
   - [ ] Finalize error handling and retries
   - [ ] Complete response parsing and validation

5. **Integration and Testing**
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
4. Integrate components for end-to-end operation
5. Implement comprehensive testing