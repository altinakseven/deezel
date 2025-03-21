# deezel

A Bitcoin wallet CLI tool for automated DIESEL token minting and management using BDK and Sandshrew RPC.

## Overview

This program provides a persistent Bitcoin wallet that automatically mints DIESEL tokens by constructing and broadcasting special transactions containing Protostones. It continuously monitors new blocks and attempts to mint DIESEL once per block while consolidating existing DIESEL holdings.

## Core Components

### Bitcoin Wallet
- Uses BDK for wallet management
- Custom Esplora backend implementation using Sandshrew RPC
- Persistent wallet state
- UTXO management considering ordinal and rune constraints

### Block Monitor
- Polls Sandshrew RPC for new blocks (btc_getblockcount)
- Implements reasonable rate limiting
- Tracks transaction confirmations

### Transaction Construction  
- Creates Runestone with Protostones only
- Protocol tag: 1
- Message cellpack: [2, 0, 77]
- Points to dust output (546 sats)
- Consolidates existing DIESEL outputs

### RPC Integration
- Sandshrew endpoint: https://mainnet.sandshrew.io/v2/lasereyes
- Content-Type: application/json
- Methods:
  - btc_getblockcount
  - alkanes_trace
  - ord_address
  - alkanes_protorunesbyaddress
  - esplora_* namespace

## Transaction Flow

1. Monitor for new blocks
2. Check spendable outputs:
   - Regular BTC outputs via esplora
   - Ordinal safety via ord_address
   - DIESEL balance via alkanes_protorunesbyaddress
3. Construct transaction:
   - Include all spendable DIESEL outputs
   - Add dust output (546 sats)
   - Add Runestone with Protostone
4. Broadcast and monitor confirmation
5. Call alkanes_trace with reversed txid and appropriate vout
6. Log trace results

## Implementation Notes

- One transaction attempt per block
- Transaction vout for tracing: tx.output.len() + 1
- Reversed txid bytes for trace calls
- Rate limit compliance for Sandshrew API
- Proper error handling and logging
- Output value preservation checks
