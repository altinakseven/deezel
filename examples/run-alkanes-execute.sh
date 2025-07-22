#!/bin/bash

# Enhanced alkanes execute script with commit/reveal pattern support
# Usage: ./run-alkanes-execute.sh [--raw] [--trace] [additional-args...]

export RUST_LOG=info

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
cd /data/deezel
cargo build --release -p deezel
cargo build -p deezel
# Execute the alkanes command with commit/reveal pattern

/data/deezel/target/release/deezel \
    --sandshrew-rpc-url http://localhost:18888 \
    -p regtest \
    --wallet-file ~/.deezel/wallet.json \
    --passphrase testtesttest \
    alkanes execute \
    --inputs B:1000 \
    --change p2tr:1 \
    --to p2tr:0 \
    --mine \
    --fee-rate 1 \
    -y \
    --trace \
	    '[2,0,77]:v0:v0'
