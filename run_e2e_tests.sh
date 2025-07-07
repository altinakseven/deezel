#!/bin/bash

# Deezel Alkanes E2E Test Runner
# This script runs the comprehensive end-to-end test suite for deezel alkanes
# envelope and cellpack functionality.

set -e

echo "🚀 Deezel Alkanes E2E Test Suite"
echo "================================="

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

print_status "Running alkanes envelope and cellpack tests..."
echo

# Alkanes E2E test categories
declare -a alkanes_tests=(
    "test_contract_deployment_envelope_cellpack"
    "test_contract_execution_cellpack_only"
    "test_cellpack_compositions"
    "test_input_requirement_parsing"
    "test_validation_error_cases"
    "test_complex_protostone_parsing"
    "test_cellpack_roundtrip"
    "test_working_deployment_command"
    "test_output_target_formats"
)

# Integration tests
declare -a integration_tests=(
    "test_alkanes_e2e"
    "integration_tests"
)

# Track results
passed_tests=0
failed_tests=0
total_tests=$((${#alkanes_tests[@]} + ${#integration_tests[@]}))

# Function to run a single test
run_test() {
    local test_name=$1
    local test_type=${2:-"standard"}
    
    print_status "Running $test_name..."
    
    if [ "$test_type" = "integration" ]; then
        # Run integration tests with more verbose output
        if RUST_LOG=info cargo test "$test_name" -- --test-threads=1 --nocapture; then
            print_success "$test_name passed"
            ((passed_tests++))
        else
            print_error "$test_name failed"
            ((failed_tests++))
        fi
    else
        # Run standard unit tests
        if RUST_LOG=warn cargo test "$test_name" -- --test-threads=1; then
            print_success "$test_name passed"
            ((passed_tests++))
        else
            print_error "$test_name failed"
            ((failed_tests++))
        fi
    fi
    echo
}

# Run alkanes e2e tests
print_status "Running alkanes envelope and cellpack tests..."
for test in "${alkanes_tests[@]}"; do
    run_test "$test" "standard"
done

# Run integration tests
print_status "Running integration tests..."
for test in "${integration_tests[@]}"; do
    run_test "$test" "integration"
done

# Summary
echo "📊 Alkanes E2E Test Results"
echo "==========================="
echo "Total tests: $total_tests"
echo "Passed: $passed_tests"
echo "Failed: $failed_tests"

if [ $failed_tests -eq 0 ]; then
    print_success "All alkanes tests passed! 🎉"
    echo
    echo "✅ Alkanes envelope and cellpack functionality validated"
    echo "✅ Contract deployment (envelope + cellpack) working correctly"
    echo "✅ Contract execution (cellpack only) working correctly"
    echo "✅ Complex protostone parsing and validation working"
    echo "✅ Input requirement parsing working correctly"
    echo "✅ Error handling and validation working properly"
    echo
    echo "🚀 Your alkanes implementation is ready for production!"
    echo
    echo "📝 Working deployment command:"
    echo "   deezel alkanes execute --envelope ./examples/free_mint.wasm.gz --to [addr] '[3,1000,101]:v0:v0'"
    echo
    echo "📝 Working execution command:"
    echo "   deezel alkanes execute --to [addr] '[3,1000,101]:v0:v0'"
    exit 0
else
    print_error "$failed_tests test(s) failed"
    echo
    echo "❌ Some alkanes tests failed. Please check the output above for details."
    echo "💡 Common issues:"
    echo "   - Validation logic errors"
    echo "   - Cellpack parsing issues"
    echo "   - Envelope handling problems"
    echo "   - Protostone construction errors"
    echo
    echo "🔧 For debugging, run individual tests with:"
    echo "   RUST_LOG=debug cargo test <test_name> -- --nocapture"
    echo
    echo "📚 See src/tests/README.md for detailed test documentation"
    exit 1
fi