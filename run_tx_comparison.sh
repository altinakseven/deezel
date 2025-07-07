#!/bin/bash

# Transaction Comparison Test Runner
# Compares deezel-built reveal tx with working integration test reveal tx

echo "=== Deezel Transaction Comparison Test ==="
echo "Comparing ./examples/tx.hex vs ./examples/working-tx.hex"
echo ""

# Check if hex files exist
if [ ! -f "./examples/tx.hex" ]; then
    echo "❌ Error: ./examples/tx.hex not found"
    exit 1
fi

if [ ! -f "./examples/working-tx.hex" ]; then
    echo "❌ Error: ./examples/working-tx.hex not found"
    exit 1
fi

echo "✅ Both hex files found"
echo "📊 File sizes:"
echo "   tx.hex: $(wc -c < ./examples/tx.hex) characters"
echo "   working-tx.hex: $(wc -c < ./examples/working-tx.hex) characters"
echo ""

# Run the comparison test
echo "🔍 Running transaction comparison test..."
echo ""

cargo test test_compare_reveal_transactions -- --nocapture

echo ""
echo "📋 For detailed analysis, see: src/tests/README_tx_comparison.md"
echo "🔧 To run again: ./run_tx_comparison.sh"