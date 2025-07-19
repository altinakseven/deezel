#!/bin/bash

# Enhanced alkanes execute script with commit/reveal pattern support
# Usage: ./run-alkanes-execute.sh [--raw] [--trace] [additional-args...]

export RUST_LOG=debug

# Parse command line arguments
RAW_FLAG=""
TRACE_FLAG=""
ADDITIONAL_ARGS=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --raw)
            RAW_FLAG="--raw"
            shift
            ;;
        --trace)
            TRACE_FLAG="--trace"
            shift
            ;;
        *)
            ADDITIONAL_ARGS="$ADDITIONAL_ARGS $1"
            shift
            ;;
    esac
done

# Define wallet file and passphrase
WALLET_FILE="$HOME/.deezel/regtest.json.asc"
PASSPHRASE="testtesttest"

# Create wallet if it doesn't exist
if [ ! -f "$WALLET_FILE" ]; then
    echo "Wallet not found. Creating a new one..."
    /data/metashrew/deezel/target/release/deezel \
        -p regtest \
        --wallet-file "$WALLET_FILE" \
        --passphrase "$PASSPHRASE" \
        wallet create
    
    echo "Funding the new wallet..."
    # Get a new address from the wallet
    ADDRESS=$(/data/metashrew/deezel/target/release/deezel -p regtest --wallet-file "$WALLET_FILE" --passphrase "$PASSPHRASE" wallet addresses --limit 1 | jq -r '.[0].address')
    
    # Mine 101 blocks to the new address to make the coinbase output spendable
    /data/metashrew/deezel/target/release/deezel \
        -p regtest \
        rpc generatetoaddress 101 "$ADDRESS"
fi

# Execute the alkanes command with commit/reveal pattern
/data/metashrew/deezel/target/release/deezel \
    --sandshrew-rpc-url http://localhost:18888 \
    -p regtest \
    --wallet-file "$WALLET_FILE" \
    --passphrase "$PASSPHRASE" \
    alkanes execute \
    --input-requirements B:1000 \
    --change-address [self:p2tr:2] \
    --to-addresses [self:p2tr:1],[self:p2tr:2],[self:p2tr:3] \
    --envelope /data/metashrew/deezel/examples/free_mint.wasm.gz \
    --mine \
    --fee-rate 1 \
    -y \
    --trace \
    --protostones '[3,797,101]:v0:v0'

