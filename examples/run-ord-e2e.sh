#!/bin/bash
set -e # Exit on error
set -x # Print commands

export RUST_LOG=info
DEEZEL=/data/deezel/target/debug/deezel

echo "Running ord e2e tests..."

echo "Getting block count..."
$DEEZEL --sandshrew-rpc-url http://localhost:18888 ord block-count

echo "Getting latest blocks..."
$DEEZEL --sandshrew-rpc-url http://localhost:18888 ord blocks

echo "Getting all inscriptions..."
$DEEZEL --sandshrew-rpc-url http://localhost:18888 ord inscriptions

echo "Getting all runes..."
$DEEZEL --sandshrew-rpc-url http://localhost:18888 ord runes

echo "Getting info for sat 0..."
$DEEZEL --sandshrew-rpc-url http://localhost:18888 ord sat 0

echo "Ord e2e tests complete."