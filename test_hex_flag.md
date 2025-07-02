# Testing the --hex Flag Implementation

This document demonstrates the new `--hex` flag functionality added to all deezel view commands.

## Overview

The `--hex` flag has been added to all `deezel view *` commands to output the raw hex value returned by `metashrew_view` instead of the processed/decoded response.

## Commands with --hex Flag

All the following view commands now support the `--hex` flag:

1. `deezel view getbytecode --hex`
2. `deezel view getblock --hex`
3. `deezel view protorunesbyaddress --hex`
4. `deezel view transactionbyid --hex`
5. `deezel view spendablesbyaddress --hex`
6. `deezel view protorunesbyheight --hex`
7. `deezel view protorunesbyoutpoint --hex`
8. `deezel view trace --hex`
9. `deezel view simulate --hex`

## Usage Examples

### Without --hex flag (processed output):
```bash
./target/release/deezel view getbytecode 2:0
```
This returns the processed bytecode response.

### With --hex flag (raw hex output):
```bash
./target/release/deezel view getbytecode 2:0 --hex
```
This returns the raw hex value from metashrew_view.

### For protorunes by address:
```bash
# Processed output
./target/release/deezel view protorunesbyaddress bc1qaddress

# Raw hex output
./target/release/deezel view protorunesbyaddress bc1qaddress --hex
```

### For trace command (has both --raw and --hex):
```bash
# Pretty formatted trace
./target/release/deezel view trace txid:0

# JSON formatted trace
./target/release/deezel view trace txid:0 --raw

# Raw hex from metashrew_view
./target/release/deezel view trace txid:0 --hex
```

## Implementation Details

- The `--hex` flag is implemented for all view commands
- When `--hex` is used, the command calls `rpc_client.get_metashrew_view_hex()` instead of the processed methods
- The raw hex response from `metashrew_view` is output directly to stdout
- For commands that require protobuf encoding (like getbytecode, protorunesbyaddress, etc.), the appropriate protobuf message is constructed and hex-encoded before being sent to metashrew_view
- The trace command supports both `--raw` (JSON) and `--hex` (raw hex) flags

## Technical Implementation

The implementation adds:
1. `--hex` flag to all ViewCommands enum variants
2. `get_metashrew_view_hex()` method in RpcClient
3. Conditional logic in each view command handler to use raw hex output when `--hex` flag is present
4. Proper protobuf message construction for commands that require it

## Testing

All commands compile successfully and the help documentation shows the `--hex` flag is properly documented for each command.