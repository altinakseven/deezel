#!/bin/bash

# Reproduces the HTTP call for the `alkanes trace` subcommand.
#
# This script takes an outpoint (<txid>:<vout>) as input, constructs a
# protobuf message, and sends it to the metashrew server's `metashrew_view`
# RPC method to get a transaction trace.
#
# Usage:
# ./trace_alkanes.sh <txid>:<vout>
#
# Example:
# ./trace_alkanes.sh 1a91e3dace36e2be3bf0300542635b77828a6a967f05350462b7184d6ab230d1:0

set -e

# --- Validation ---
if [ -z "$1" ]; then
    echo "Usage: $0 <txid>:<vout>"
    exit 1
fi

if ! command -v jq &> /dev/null; then
    echo "Error: jq is not installed. Please install it to run this script."
    exit 1
fi

if ! command -v xxd &> /dev/null; then
    echo "Error: xxd is not installed. Please install it to run this script."
    exit 1
fi

# --- Configuration ---
METASHREW_URL="http://localhost:8080"
OUTPOINT=$1

# --- 1. Parse Input ---
TXID=$(echo "$OUTPOINT" | cut -d: -f1)
VOUT=$(echo "$OUTPOINT" | cut -d: -f2)

echo "🔍 Tracing outpoint: $TXID:$VOUT"
echo "📡 Using Metashrew URL: $METASHREW_URL"

# --- 2. Prepare Protobuf Payload ---
# The `bitcoin::Txid` struct stores bytes in reverse order of the displayed hex.
# `to_raw_hash()` returns these internal (little-endian) bytes.
# So, we must reverse the byte order from the input TXID string.
REVERSED_TXID_HEX=$(echo "$TXID" | grep -o .. | tac | tr -d '\n')

# Build the payload as a hex string.
# Field 1 (txid): tag 0x0a, length 32 (0x20)
HEX_STRING="0a20${REVERSED_TXID_HEX}"

# Field 2 (vout): tag 0x10
HEX_STRING+="10"

# Varint encode VOUT and append to hex string
N=$VOUT
if (( N == 0 )); then
  VOUT_HEX="00"
else
  VOUT_HEX=""
  while (( N > 0 )); do
    BYTE=$(( N & 127 ))
    N=$(( N >> 7 ))
    if (( N > 0 )); then
      BYTE=$(( BYTE | 128 ))
    fi
    VOUT_HEX+=$(printf "%02x" "$BYTE")
  done
fi
HEX_STRING+=$VOUT_HEX

# The final hex payload for the JSON-RPC request
HEX_PAYLOAD="0x${HEX_STRING}"

echo "📦 Protobuf Hex Payload: $HEX_PAYLOAD"

# --- 3. Construct JSON-RPC Request ---
JSON_RPC_PAYLOAD=$(jq -n \
    --arg method "metashrew_view" \
    --argjson params "[\"trace\", \"$HEX_PAYLOAD\", \"latest\"]" \
    '{jsonrpc: "2.0", method: $method, params: $params, id: 1}')

echo "📋 JSON-RPC Request Body:"
echo "$JSON_RPC_PAYLOAD" | jq .

# --- 4. Execute curl Command ---
echo -e "\n🚀 Sending request to Metashrew server..."
RESPONSE=$(curl -s -X POST \
    -H "Content-Type: application/json" \
    -d "$JSON_RPC_PAYLOAD" \
    "$METASHREW_URL")

echo "📝 Raw Server Response:"
echo "$RESPONSE" | jq .

# --- 5. Parse and Decode Response ---
# The actual trace is in the 'result' field, hex-encoded.
HEX_TRACE=$(echo "$RESPONSE" | jq -r '.result')

if [ -z "$HEX_TRACE" ] || [ "$HEX_TRACE" == "null" ]; then
    echo -e "\n❌ Error: Received null or empty trace from server."
    exit 1
fi

# The trace itself is a JSON string, so we decode the hex and then parse the resulting JSON.
DECODED_TRACE=$(echo "$HEX_TRACE" | sed 's/0x//' | xxd -r -p)

echo -e "\n✅ Trace received and decoded successfully!"
echo "--- TRACE START ---"
echo "$DECODED_TRACE" | jq .
echo "--- TRACE END ---"
