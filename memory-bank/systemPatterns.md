# System Patterns

## System Architecture

The deezel application follows a modular architecture with several key components working together to achieve automated DIESEL token minting and management:

```
┌─────────────────────────────────────────────────────────────┐
│                       deezel CLI Tool                       │
├─────────────┬─────────────────┬────────────────┬────────────┤
│ Bitcoin     │ Block           │ Transaction    │ RPC        │
│ Wallet      │ Monitor         │ Constructor    │ Client     │
├─────────────┼─────────────────┼────────────────┼────────────┤
│ BDK         │ Sandshrew       │ Runestone      │ HTTP       │
│ Integration │ Integration     │ Protocol       │ Client     │
└─────────────┴─────────────────┴────────────────┴────────────┘
```

### Core Components

1. **Bitcoin Wallet Module**
   - Manages wallet state persistence
   - Handles key management and address generation
   - Tracks UTXOs and their states
   - Implements custom Esplora backend using Sandshrew RPC

2. **Block Monitor Module**
   - Polls Sandshrew RPC for new blocks
   - Implements rate limiting to avoid API restrictions
   - Triggers transaction construction on new blocks
   - Tracks transaction confirmations

3. **Transaction Constructor Module**
   - Creates Runestone with Protostones
   - Implements protocol-specific message encoding
   - Manages UTXO selection considering ordinal and rune constraints
   - Handles output consolidation logic

4. **RPC Client Module**
   - Manages communication with Sandshrew RPC endpoint
   - Implements required API methods
   - Handles serialization/deserialization of requests and responses
   - Manages error handling and retries

## Key Technical Decisions

### 1. BDK Integration

The project uses Bitcoin Development Kit (BDK) for wallet management, which provides:
- Secure key management
- Transaction construction and signing
- UTXO tracking
- Descriptor-based wallet architecture

This decision allows us to leverage a well-tested library for Bitcoin wallet functionality rather than implementing these complex components from scratch.

### 2. Custom Esplora Backend

Rather than using standard Esplora endpoints, deezel implements a custom Esplora backend that uses the Sandshrew RPC API. This decision:
- Reduces external dependencies
- Provides consistent API access
- Enables specialized queries for DIESEL token data

### 3. Runestone Protocol Implementation

The application implements the Runestone protocol for creating transactions with Protostones. This enables:
- DIESEL token minting through standardized protocol
- Compatibility with existing token infrastructure
- Future extensibility for additional token operations

### 4. Once-Per-Block Transaction Strategy

deezel attempts to mint DIESEL tokens once per block, which:
- Provides predictable operation
- Avoids excessive transaction fees
- Maintains a reasonable consolidation frequency
- Prevents API rate limit issues

## Design Patterns

### 1. Repository Pattern

Used for data access abstraction, particularly for:
- Wallet state persistence
- Transaction history tracking
- UTXO management

### 2. Service Pattern

Implemented for core business logic:
- Block monitoring service
- Transaction construction service
- RPC communication service

### 3. Factory Pattern

Used for creating complex objects:
- Transaction construction
- Runestone/Protostone creation
- RPC request formation

### 4. Observer Pattern

Implemented for event handling:
- New block notifications
- Transaction confirmation events
- Error events

## Component Relationships

1. **Block Monitor → Transaction Constructor**
   - Block monitor triggers transaction construction on new blocks

2. **Transaction Constructor → Bitcoin Wallet**
   - Constructor requests UTXOs and addresses from wallet
   - Constructor submits signed transactions back to wallet

3. **Bitcoin Wallet → RPC Client**
   - Wallet uses RPC client to query blockchain data
   - Wallet broadcasts transactions via RPC client

4. **Block Monitor → RPC Client**
   - Monitor polls for new blocks via RPC client

This architecture provides clear separation of concerns while maintaining efficient communication between components.