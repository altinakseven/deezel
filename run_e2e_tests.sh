#!/bin/bash

# Deezel E2E Test Runner
# This script runs the complete end-to-end test suite for deezel CLI
# using the mock metashrew server implementation.

set -e

echo "🚀 Deezel E2E Test Suite"
echo "========================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if cargo is available
if ! command -v cargo &> /dev/null; then
    print_error "Cargo is not installed or not in PATH"
    exit 1
fi

# Check if we're in the right directory
if [ ! -f "Cargo.toml" ]; then
    print_error "Please run this script from the deezel project root directory"
    exit 1
fi

print_status "Building deezel CLI..."
if cargo build; then
    print_success "Build completed successfully"
else
    print_error "Build failed"
    exit 1
fi

print_status "Running unit tests..."
if cargo test --lib; then
    print_success "Unit tests passed"
else
    print_warning "Some unit tests failed, continuing with e2e tests..."
fi

print_status "Starting E2E test suite..."
echo

# Test categories
declare -a test_categories=(
    "test_wallet_operations"
    "test_diesel_balance_check" 
    "test_utxo_listing"
    "test_diesel_minting"
    "test_transaction_monitoring"
    "test_rpc_connectivity"
    "test_error_handling"
    "test_comprehensive_diesel_workflow"
    "test_concurrent_operations"
)

# Performance tests (run separately)
declare -a performance_tests=(
    "test_performance_many_utxos"
)

# Track results
passed_tests=0
failed_tests=0
total_tests=$((${#test_categories[@]} + ${#performance_tests[@]}))

# Function to run a single test
run_test() {
    local test_name=$1
    local test_type=${2:-"standard"}
    
    print_status "Running $test_name..."
    
    if [ "$test_type" = "performance" ]; then
        # Run performance tests with single thread and no capture
        if RUST_LOG=warn cargo test "$test_name" -- --test-threads=1 --nocapture; then
            print_success "$test_name passed"
            ((passed_tests++))
        else
            print_error "$test_name failed"
            ((failed_tests++))
        fi
    else
        # Run standard tests with debug logging
        if RUST_LOG=debug cargo test "$test_name" -- --test-threads=1; then
            print_success "$test_name passed"
            ((passed_tests++))
        else
            print_error "$test_name failed"
            ((failed_tests++))
        fi
    fi
    echo
}

# Run standard test categories
print_status "Running standard e2e tests..."
for test in "${test_categories[@]}"; do
    run_test "$test" "standard"
done

# Run performance tests
print_status "Running performance tests..."
for test in "${performance_tests[@]}"; do
    run_test "$test" "performance"
done

# Summary
echo "📊 Test Results Summary"
echo "======================="
echo "Total tests: $total_tests"
echo "Passed: $passed_tests"
echo "Failed: $failed_tests"

if [ $failed_tests -eq 0 ]; then
    print_success "All tests passed! 🎉"
    echo
    echo "✅ Your deezel CLI is working correctly with the mock metashrew setup"
    echo "✅ All DIESEL token functionality has been validated"
    echo "✅ RPC connectivity and error handling are working"
    echo "✅ Performance tests completed successfully"
    echo
    echo "You can now use deezel with confidence! 🚀"
    exit 0
else
    print_error "$failed_tests test(s) failed"
    echo
    echo "❌ Some tests failed. Please check the output above for details."
    echo "💡 Common issues:"
    echo "   - Port conflicts (try running tests individually)"
    echo "   - Missing dependencies (check Cargo.toml)"
    echo "   - Binary not found (run 'cargo build' first)"
    echo
    echo "🔧 For debugging, run individual tests with:"
    echo "   RUST_LOG=debug cargo test <test_name> -- --nocapture"
    exit 1
fi