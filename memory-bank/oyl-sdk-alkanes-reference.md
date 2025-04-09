# OYL SDK Alkanes Reference

## Overview

This document provides a comprehensive reference for the alkanes functionality in oyl-sdk and how deezel can serve as a stand-in replacement. The deezel project is being developed to replace the alkanes command functionality from oyl-sdk, focusing on DIESEL token minting and management using BDK and Sandshrew RPC.

## OYL SDK Alkanes Architecture

The oyl-sdk provides a TypeScript-based implementation for interacting with the Alkanes protocol on Bitcoin. It consists of several key components:

### Core Components

1. **AlkanesRpc Client**
   - Handles communication with Metashrew/Sandshrew RPC endpoints
   - Provides methods for querying alkanes data, tracing transactions, and simulating operations
   - Key methods:
     - `getAlkanesByAddress`: Retrieves alkanes owned by an address
     - `getAlkanesByOutpoint`: Retrieves alkanes associated with a specific UTXO
     - `trace`: Traces a transaction to verify token operations
     - `simulate`: Simulates alkanes operations before execution

2. **Alkanes Module**
   - Implements core Alkanes protocol functionality
   - Handles Protostone creation and encoding
   - Manages transaction construction for alkanes operations
   - Key functions:
     - `encodeProtostone`: Encodes protocol tag, edicts, and calldata into a Protostone
     - `execute`: Creates and broadcasts transactions with Protostones
     - `findAlkaneUtxos`: Locates UTXOs containing specific alkanes tokens

3. **Token Module**
   - Implements token-specific operations
   - Handles token deployment, sending, and splitting
   - Key functions:
     - `tokenDeployment`: Deploys a new token using commit-reveal pattern
     - `send`: Transfers tokens between addresses
     - `split`: Splits token UTXOs for better management

4. **CLI Interface**
   - Provides command-line tools for alkanes operations
   - Key commands:
     - `alkanesTrace`: Traces a transaction to verify token operations
     - `alkaneTokenDeploy`: Deploys a new token
     - `alkaneExecute`: Executes a transaction with a Protostone
     - `alkaneSend`: Sends tokens to another address

## Deezel as a Replacement

Deezel is designed to replace the alkanes functionality of oyl-sdk, focusing specifically on DIESEL token minting and management. Here's how deezel maps to the oyl-sdk alkanes functionality:

### Architecture Mapping

| OYL SDK Component | Deezel Component | Description |
|-------------------|------------------|-------------|
| AlkanesRpc | RpcClient | Handles communication with Sandshrew RPC endpoints |
| Alkanes Module | Runestone Module | Implements Runestone protocol for DIESEL token minting |
| Token Module | Transaction Module | Handles transaction construction for DIESEL operations |
| CLI Interface | Main Binary | Provides command-line interface for DIESEL operations |

### RPC Method Mapping

| OYL SDK Method | Deezel Method | Description |
|----------------|---------------|-------------|
| `alkanes_trace` | `trace_transaction` | Traces a transaction to verify DIESEL token minting |
| `alkanes_protorunesbyaddress` | `get_protorunes_by_address` | Gets DIESEL token balance for an address |
| `metashrew_height` | `get_metashrew_height` | Gets the current block height from Metashrew |
| `metashrew_view` | Not directly implemented | General blockchain data access |
| `spendablesbyaddress` | Not directly implemented | UTXO selection via protobuf scheme |

### Key Functionality Comparison

#### 1. Protostone Creation

**OYL SDK:**
```typescript
const protostone = encodeProtostone({
  protocolTag: 1n,
  calldata: [2n, 0n, 77n]
});
```

**Deezel:**
```rust
let runestone = Runestone::new_diesel(); // Creates a Runestone with protocol tag 1 and message [2, 0, 77]
let runestone_script = runestone.encipher();
```

#### 2. Transaction Execution

**OYL SDK:**
```typescript
const result = await execute({
  gatheredUtxos,
  account,
  protostone,
  provider,
  feeRate: 5,
  signer
});
```

**Deezel:**
```rust
let tx = tx_constructor.create_minting_transaction().await?;
let txid = tx_constructor.broadcast_transaction(&tx).await?;
```

#### 3. Transaction Tracing

**OYL SDK:**
```typescript
const traceResult = await alkanesRpc.trace({
  txid: reversedTxid,
  vout: tx.output.length + 1
});
```

**Deezel:**
```rust
let trace_result = self.rpc_client.trace_transaction(&reversed_txid, vout).await?;
```

#### 4. Token Balance Checking

**OYL SDK:**
```typescript
const alkanes = await alkanesRpc.getAlkanesByAddress({
  address,
  protocolTag: "1"
});
```

**Deezel:**
```rust
let protorunes = self.rpc_client.get_protorunes_by_address(address).await?;
```

## Implementation Differences

While deezel aims to provide similar functionality to the alkanes component of oyl-sdk, there are some key differences in the implementation:

1. **Language**: deezel is implemented in Rust, while oyl-sdk is implemented in TypeScript
2. **Wallet Implementation**: deezel uses BDK for wallet management, while oyl-sdk uses bitcoinjs-lib
3. **Focus**: deezel focuses specifically on DIESEL token minting and management, while oyl-sdk's alkanes module supports a broader range of operations
4. **Transaction Construction**: deezel uses BDK's transaction building capabilities, while oyl-sdk uses custom transaction construction
5. **UTXO Management**: deezel implements custom UTXO tracking considering ordinal and rune constraints

## API Endpoints

Deezel interacts with the following Sandshrew RPC endpoints:

### Bitcoin RPC
- `btc_getblockcount`: Used to check current block height

### Metashrew RPC
- `metashrew_height`: To verify block height
- `spendablesbyaddress`: For UTXO selection via protobuf scheme

### Alkanes RPC
- `alkanes_trace`: For tracing transactions to verify DIESEL token minting
- `alkanes_protorunesbyaddress`: For checking DIESEL token balances

### Esplora RPC
- `esplora_tx::hex`: For getting transaction details
- `esplora_address::utxo`: For getting UTXOs for an address
- `esplora_address::txs`: For getting transaction history for an address
- `esplora_broadcast`: For broadcasting transactions

## DIESEL Token Minting Process

The DIESEL token minting process in deezel follows these steps:

1. **Monitor for new blocks**
   - Poll Sandshrew RPC for new blocks
   - Verify that Metashrew height is Bitcoin height + 1

2. **Check spendable outputs**
   - Get regular BTC outputs via esplora
   - Check ordinal safety via ord_address
   - Get DIESEL balance via alkanes_protorunesbyaddress

3. **Construct transaction**
   - Include all spendable DIESEL outputs for consolidation
   - Add dust output (546 sats)
   - Add Runestone with Protostone (Protocol tag: 1, Message cellpack: [2, 0, 77])

4. **Broadcast and monitor confirmation**
   - Broadcast transaction to the Bitcoin network
   - Monitor for confirmation

5. **Verify minting**
   - Call alkanes_trace with reversed txid and appropriate vout
   - Log trace results

## Conclusion

Deezel serves as a Rust-based replacement for the alkanes functionality in oyl-sdk, focusing specifically on DIESEL token minting and management. While it doesn't implement the full range of functionality provided by oyl-sdk's alkanes module, it provides the core functionality needed for DIESEL token operations using BDK and Sandshrew RPC.