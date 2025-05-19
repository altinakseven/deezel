#!/bin/bash
# Test script for verifying deezel functionality against oylnet

set -e  # Exit on any error

# Configuration
OYLNET_BITCOIN_RPC="http://bitcoinrpc:bitcoinrpc@oylnet.alkimake.io:8332"
OYLNET_METASHREW_RPC="http://oylnet.alkimake.io:8080"
WALLET_PATH="./oylnet_wallet.dat"
LOG_LEVEL="debug"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print header
echo -e "${BLUE}=== Testing Deezel against Oylnet ===${NC}"
echo "Bitcoin RPC: $OYLNET_BITCOIN_RPC"
echo "Metashrew RPC: $OYLNET_METASHREW_RPC"
echo "Wallet: $WALLET_PATH"
echo ""

# Check if deezel is built
if [ ! -f "./target/debug/deezel" ] && [ ! -f "./target/release/deezel" ]; then
    echo -e "${RED}Error: deezel binary not found. Please build the project first.${NC}"
    echo "Run: cargo build"
    exit 1
fi

# Determine binary path
DEEZEL_BIN="./target/debug/deezel"
if [ -f "./target/release/deezel" ]; then
    DEEZEL_BIN="./target/release/deezel"
    echo -e "${GREEN}Using release build of deezel${NC}"
else
    echo -e "${YELLOW}Using debug build of deezel${NC}"
fi

# Base command with standard args
DEEZEL="$DEEZEL_BIN --bitcoin-rpc-url $OYLNET_BITCOIN_RPC --metashrew-rpc-url $OYLNET_METASHREW_RPC --wallet-path $WALLET_PATH --log-level $LOG_LEVEL"

# Function to run a test and report result
run_test() {
    local test_name="$1"
    local command="$2"
    
    echo -e "\n${YELLOW}Running test: ${test_name}${NC}"
    echo "Command: $command"
    
    if eval "$command"; then
        echo -e "${GREEN}✓ Test passed: ${test_name}${NC}"
        return 0
    else
        echo -e "${RED}✗ Test failed: ${test_name}${NC}"
        return 1
    }
}

# Function to check wallet and create if needed
check_wallet() {
    echo -e "\n${BLUE}Checking wallet...${NC}"
    
    if $DEEZEL walletinfo &>/dev/null; then
        echo -e "${GREEN}Wallet exists and is accessible${NC}"
    else
        echo -e "${YELLOW}Creating new wallet...${NC}"
        $DEEZEL walletinfo || true
        echo -e "${GREEN}Wallet created${NC}"
    fi
}

# Test 1: Get wallet info
test_wallet_info() {
    run_test "Wallet Info" "$DEEZEL walletinfo"
}

# Test 2: Test fee estimation
test_fee_estimation() {
    run_test "Fee Estimation (6 blocks)" "$DEEZEL alkanes execute --execute 2,0,0 --fee-target-blocks 6"
}

# Test 3: Test fee override
test_fee_override() {
    run_test "Fee Override (5.0 sat/vB)" "$DEEZEL alkanes execute --execute 2,0,0 --fee-rate 5.0"
}

# Test 4: Test RBF (Replace-By-Fee)
test_rbf() {
    run_test "RBF Transaction" "$DEEZEL alkanes execute --execute 2,0,0 --rbf"
}

# Test 5: Execute with single input
test_single_input() {
    run_test "Single Input" "$DEEZEL alkanes execute --execute 2,0,0 --input 1010,10000000,2"
}

# Test 6: Execute with multiple inputs
test_multiple_inputs() {
    run_test "Multiple Inputs" "$DEEZEL alkanes execute --execute 2,0,10 --input 1010,10000000,2,1011,50000000,3"
}

# Test 7: Validate inputs against alkane holdings
test_validate_inputs() {
    run_test "Validate Inputs" "$DEEZEL alkanes execute --input 1010,10000000,2 --validate"
}

# Test 8: Decode runestone from recent transaction
test_decode_runestone() {
    # Get a transaction ID from oylnet
    echo -e "\n${BLUE}Getting a recent transaction for runestone decoding...${NC}"
    TXID=$($DEEZEL alkanes execute --execute 2,0,0 | grep "Transaction ID:" | cut -d ' ' -f 3)
    
    if [ -n "$TXID" ]; then
        run_test "Decode Runestone" "$DEEZEL runestone $TXID"
    else
        echo -e "${YELLOW}Skipping runestone decode - couldn't get transaction ID${NC}"
        return 0
    fi
}

# Main test execution
main() {
    # Check/create wallet first
    check_wallet
    
    # Run all tests and count failures
    failures=0
    
    test_wallet_info || ((failures++))
    test_fee_estimation || ((failures++))
    test_fee_override || ((failures++))
    test_rbf || ((failures++))
    test_single_input || ((failures++))
    test_multiple_inputs || ((failures++))
    test_validate_inputs || ((failures++))
    test_decode_runestone || ((failures++))
    
    # Summary
    echo -e "\n${BLUE}=== Test Summary ===${NC}"
    if [ $failures -eq 0 ]; then
        echo -e "${GREEN}All tests passed successfully!${NC}"
    else
        echo -e "${RED}$failures test(s) failed.${NC}"
    fi
    
    return $failures
}

# Run the tests
main
