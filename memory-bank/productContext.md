# Product Context

## Purpose

The deezel project exists to automate the minting and management of DIESEL tokens on the Bitcoin blockchain. It provides a persistent Bitcoin wallet that continuously monitors the blockchain and automatically mints DIESEL tokens by constructing and broadcasting special transactions containing Protostones.

## Problems Solved

1. **Manual Token Minting Complexity**: Creating the specialized transactions required for DIESEL token minting is complex and error-prone when done manually. deezel automates this process.

2. **UTXO Management Challenges**: Managing UTXOs while considering ordinal and rune constraints requires specialized knowledge. deezel handles this complexity automatically.

3. **Continuous Monitoring Requirements**: Effective token minting requires continuous monitoring of the blockchain for new blocks. deezel provides automated monitoring with appropriate rate limiting.

4. **Token Consolidation Needs**: Without automation, DIESEL token outputs can become scattered across many UTXOs, making them difficult to manage. deezel automatically consolidates existing DIESEL holdings.

## How It Works

1. **Continuous Block Monitoring**: The application polls the Sandshrew RPC endpoint for new blocks, implementing appropriate rate limiting to avoid API restrictions.

2. **UTXO Analysis**: For each new block, deezel analyzes available UTXOs to determine which are spendable, considering:
   - Regular BTC outputs via esplora API
   - Ordinal safety via ord_address API
   - Existing DIESEL balance via alkanes_protorunesbyaddress API

3. **Transaction Construction**: Once per block, deezel constructs a transaction that:
   - Includes all spendable DIESEL outputs for consolidation
   - Adds a dust output (546 sats)
   - Adds a Runestone with Protostone (Protocol tag: 1, Message cellpack: [2, 0, 77])

4. **Transaction Broadcasting**: The constructed transaction is broadcast to the Bitcoin network.

5. **Confirmation Monitoring**: deezel tracks the confirmation status of broadcast transactions.

6. **Token Verification**: After confirmation, deezel calls alkanes_trace with the reversed txid and appropriate vout to verify successful minting.

## User Experience Goals

1. **Zero-Maintenance Operation**: Once configured, deezel should run continuously without requiring user intervention.

2. **Reliable Token Minting**: The application should reliably mint DIESEL tokens once per block when possible.

3. **Efficient UTXO Management**: deezel should maintain an efficient UTXO set, consolidating DIESEL tokens to minimize transaction fees and complexity.

4. **Transparent Operation**: The application should provide clear logging and status information about its operations, including successful mints, errors, and current token balances.

5. **Resource Efficiency**: deezel should operate with minimal resource usage, making it suitable for running on modest hardware over extended periods.