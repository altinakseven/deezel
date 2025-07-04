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

# Execute the alkanes command with commit/reveal pattern
/data/deezel/target/debug/deezel \
    --sandshrew-rpc-url http://localhost:18888 \
    -p regtest \
    --wallet-file ~/.deezel/regtest.json.asc \
    --passphrase testtesttest \
    alkanes execute \
    --envelope ~/free_mint.wasm.gz \
    --inputs B:1000 \
    --change [self:p2tr:2] \
    --to [self:p2tr:1] \
    --fee-rate 1 \
    --yes \
    $RAW_FLAG \
    $TRACE_FLAG \
    $ADDITIONAL_ARGS \
	    '[3,797,101]:v0:v0'
