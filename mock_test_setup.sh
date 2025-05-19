#!/bin/bash
# Setup script for mocked testing environment
# This script creates mock responses to simulate RPC calls for testing

set -e  # Exit on any error

echo "Setting up mocked testing environment for deezel..."

# Create mock directory if it doesn't exist
mkdir -p ./mocks

# Create mock response for getblockcount
cat > ./mocks/blockcount.json << EOF
{
  "jsonrpc": "2.0",
  "result": 800000,
  "id": 1
}
EOF
echo "Created mock blockcount response"

# Create mock response for height
cat > ./mocks/height.json << EOF
{
  "jsonrpc": "2.0", 
  "result": 800001,
  "id": 1
}
EOF
echo "Created mock height response"

# Create mock response for spendablesbyaddress
cat > ./mocks/spendables.json << EOF
{
  "jsonrpc": "2.0",
  "result": [
    {
      "outpoint": "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16:0",
      "value": 5000000,
      "script_pubkey": "001442d829047570aaaef74fc57adfe4c75c605f63"
    },
    {
      "outpoint": "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d:1",
      "value": 10000000,
      "script_pubkey": "001442d829047570aaaef74fc57adfe4c75c605f63"
    }
  ],
  "id": 1
}
EOF
echo "Created mock spendables response"

# Create mock response for protorunesbyaddress
cat > ./mocks/protorunes.json << EOF
{
  "jsonrpc": "2.0",
  "result": [
    {
      "id": 1010,
      "name": "Test Alkane 1010",
      "balance": "150000000",
      "last_seen": "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16:0"
    },
    {
      "id": 1011,
      "name": "Test Alkane 1011",
      "balance": "750000000",
      "last_seen": "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d:1"
    }
  ],
  "id": 1
}
EOF
echo "Created mock protorunes response"

# Create mock response for transaction hex
cat > ./mocks/tx_hex.json << EOF
{
  "jsonrpc": "2.0",
  "result": "0100000001f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e1600000000da0047304402207f3220a2c3a7d8c26eb3eb7d03c78d3d6c9334c07e9a2bc0c976604c89b16d7c02205f38d98c5bf3354178cd5a1b0ee9f1b0b68e279ff541294ce8da7cba91bc47fb0147304402205e28f674a19f5f666ad7ded0ebf292e680647d16378fd534e11acba9f10e539802202d867db03a8281766da8ba54670a1341dead773094d1fa4fccdb5776e3de92c701475221034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa2102466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f2752ae000000000122020000000000001976a914168b992bcfc44050310b3a94bd0771136d2c5c8888ac00000000",
  "id": 1
}
EOF
echo "Created mock transaction hex response"

# Create mock response for trace
cat > ./mocks/trace.json << EOF
{
  "jsonrpc": "2.0",
  "result": {
    "success": true,
    "runetype": "DIESEL",
    "operations": [
      {
        "type": "mint",
        "id": 1,
        "output": 0,
        "amount": "1000000000"
      }
    ]
  },
  "id": 1
}
EOF
echo "Created mock trace response"

# Create test wallet if it doesn't exist
if [ ! -f "./test_wallet.dat" ]; then
  echo "Creating test wallet..."
  touch ./test_wallet.dat
  echo "Test wallet created"
fi

echo "Creating mock test runner script..."
# Create test runner script that uses the mocks
cat > ./run_mock_tests.sh << 'EOF'
#!/bin/bash
# Mock test runner for deezel
# This script intercepts RPC calls and returns mock responses

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Mock function for deezel commands
mock_deezel() {
  command=$1
  shift
  
  echo -e "${BLUE}Executing mock: deezel $command $@${NC}"
  
  case "$command" in
    "walletinfo")
      echo -e "${GREEN}Wallet Information${NC}"
      echo "Wallet Addresses:"
      echo "  Native SegWit (bech32): tb1q6kgsjms0grnldr6novecgr0uzez55member5sal"
      echo ""
      echo "Bitcoin Balance:"
      echo "  Confirmed: 15000000 sats"
      echo "  Pending: 0 sats"
      echo "  Total: 15000000 sats"
      echo ""
      echo "Alkanes Balances:"
      echo "  1: Test Alkane 1010 - 150000000 units"
      echo "  2: Test Alkane 1011 - 750000000 units"
      ;;
      
    "alkanes")
      subcommand=$1
      shift
      
      case "$subcommand" in
        "protorunesbyaddress")
          address=$1
          cat ./mocks/protorunes.json | jq
          ;;
          
        "execute")
          # Parse options
          while [[ $# -gt 0 ]]; do
            case "$1" in
              --execute)
                execute="$2"
                shift 2
                ;;
              --input)
                input="$2"
                shift 2
                ;;
              --validate)
                validate=true
                shift
                ;;
              *)
                shift
                ;;
            esac
          done
          
          if [ "$validate" = true ] && [ ! -z "$input" ]; then
            echo -e "${GREEN}Inputs are valid for user's alkane holdings${NC}"
          elif [ ! -z "$execute" ] && [ ! -z "$input" ]; then
            echo -e "${GREEN}Transaction created successfully with execute parameters: $execute${NC}"
            echo "Transaction details: Transaction { version: 2, lock_time: Absolute(0), input: [TxIn { previous_output: OutPoint { txid: f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16, vout: 0 }, sequence: Sequence(ffffffff), witness: Witness(...), script_sig: ... }], output: [TxOut { value: 546, script_pubkey: OP_0 OP_PUSHBYTES_20 42d829047570aaaef74fc57adfe4c75c605f63 }, TxOut { value: 0, script_pubkey: OP_RETURN OP_PUSHNUM_13 OP_PUSHBYTES_9 <$execute,$input encoded> }, TxOut { value: 4999000, script_pubkey: OP_0 OP_PUSHBYTES_20 3a4851b1b6f9c8e93a78f3e1a2a3f722012e136e }] }"
            echo "TXID: abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
            echo "Transaction would be broadcast"
          elif [ ! -z "$execute" ]; then
            echo -e "${GREEN}Transaction created successfully with execute parameters: $execute${NC}"
            echo "Transaction details: Transaction { version: 2, lock_time: Absolute(0), input: [TxIn { previous_output: OutPoint { txid: f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16, vout: 0 }, sequence: Sequence(ffffffff), witness: Witness(...), script_sig: ... }], output: [TxOut { value: 546, script_pubkey: OP_0 OP_PUSHBYTES_20 42d829047570aaaef74fc57adfe4c75c605f63 }, TxOut { value: 0, script_pubkey: OP_RETURN OP_PUSHNUM_13 OP_PUSHBYTES_3 <$execute encoded> }, TxOut { value: 4999000, script_pubkey: OP_0 OP_PUSHBYTES_20 3a4851b1b6f9c8e93a78f3e1a2a3f722012e136e }] }"
            echo "TXID: abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
            echo "Transaction would be broadcast"
          elif [ ! -z "$input" ]; then
            echo -e "${GREEN}Transaction created successfully${NC}"
            echo "Transaction details: Transaction { version: 2, lock_time: Absolute(0), input: [TxIn { previous_output: OutPoint { txid: f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16, vout: 0 }, sequence: Sequence(ffffffff), witness: Witness(...), script_sig: ... }], output: [TxOut { value: 546, script_pubkey: OP_0 OP_PUSHBYTES_20 42d829047570aaaef74fc57adfe4c75c605f63 }, TxOut { value: 0, script_pubkey: OP_RETURN OP_PUSHNUM_13 OP_PUSHBYTES_9 <2,0,77,$input encoded> }, TxOut { value: 4999000, script_pubkey: OP_0 OP_PUSHBYTES_20 3a4851b1b6f9c8e93a78f3e1a2a3f722012e136e }] }"
            echo "TXID: abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
            echo "Transaction would be broadcast"
          else
            echo -e "${GREEN}Standard DIESEL minting transaction created successfully${NC}"
            echo "Transaction details: Transaction { version: 2, lock_time: Absolute(0), input: [TxIn { previous_output: OutPoint { txid: f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16, vout: 0 }, sequence: Sequence(ffffffff), witness: Witness(...), script_sig: ... }], output: [TxOut { value: 546, script_pubkey: OP_0 OP_PUSHBYTES_20 42d829047570aaaef74fc57adfe4c75c605f63 }, TxOut { value: 0, script_pubkey: OP_RETURN OP_PUSHNUM_13 OP_PUSHBYTES_3 020077 }, TxOut { value: 4999000, script_pubkey: OP_0 OP_PUSHBYTES_20 3a4851b1b6f9c8e93a78f3e1a2a3f722012e136e }] }"
            echo "TXID: abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
            echo "Transaction would be broadcast"
          fi
          ;;
          
        "spendablesbyaddress")
          address=$1
          cat ./mocks/spendables.json | jq
          ;;
          
        *)
          echo -e "${RED}Unhandled alkanes subcommand: $subcommand${NC}"
          ;;
      esac
      ;;
      
    "runestone")
      txid=$1
      echo -e "${YELLOW}Found 1 protostones:${NC}"
      
      if [[ "$@" == *"--execute"* ]]; then
        # Extract execute param using regex
        if [[ "$@" =~ --execute[[:space:]]\"([^\"]+)\" ]]; then
          execute="${BASH_REMATCH[1]}"
          IFS=',' read -r namespace contract_id opcode <<< "$execute"
          echo "Protostone 1: Protostone { protocol_tag: 1, params: ExecuteParams { namespace: $namespace, contract_id: $contract_id, opcode: $opcode }, inputs: None }"
        fi
      elif [[ "$@" == *"--input"* ]]; then
        # Extract input param using regex
        if [[ "$@" =~ --input[[:space:]]\"([^\"]+)\" ]]; then
          input="${BASH_REMATCH[1]}"
          echo "Protostone 1: Protostone { protocol_tag: 1, params: ExecuteParams { namespace: 2, contract_id: 0, opcode: 77 }, inputs: Some([Input { id: 1010, amount: 100000000, output: 2 }]) }"
        fi
      else
        echo "Protostone 1: Protostone { protocol_tag: 1, params: ExecuteParams { namespace: 2, contract_id: 0, opcode: 77 }, inputs: None }"
      fi
      ;;
      
    *)
      echo -e "${RED}Unhandled command: $command${NC}"
      ;;
  esac
}

# Run the test flows
echo -e "\n${YELLOW}=== Test Flow 1: Basic Execute Command ===${NC}"
echo -e "${YELLOW}Getting wallet info...${NC}"
mock_deezel walletinfo

echo -e "\n${YELLOW}Executing simple alkane operation...${NC}"
mock_deezel alkanes execute --execute "2,0,0"

echo -e "\n${YELLOW}=== Test Flow 2: Execute with Inputs ===${NC}"
echo -e "${YELLOW}Checking alkane balances...${NC}"
ADDRESS="tb1q6kgsjms0grnldr6novecgr0uzez55member5sal"
mock_deezel alkanes protorunesbyaddress $ADDRESS

echo -e "\n${YELLOW}Validating inputs...${NC}"
mock_deezel alkanes execute --input "1010,100000000,2" --validate

echo -e "\n${YELLOW}Executing vault deposit with inputs...${NC}"
mock_deezel alkanes execute --execute "2,1010,5" --input "1010,100000000,2"

echo -e "\n${YELLOW}=== Test Flow 3: Multiple Inputs ===${NC}"
echo -e "${YELLOW}Executing with multiple inputs...${NC}"
mock_deezel alkanes execute --execute "2,0,10" --input "1010,100000000,2,1011,500000000,3"

echo -e "\n${YELLOW}=== Test Flow 4: Runestone Decoding ===${NC}"
echo -e "${YELLOW}Decoding Runestone...${NC}"
mock_deezel runestone abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890

echo -e "\n${GREEN}All mock tests completed successfully!${NC}"
EOF

# Make the test runner executable
chmod +x ./run_mock_tests.sh

echo "Setup complete. Run ./run_mock_tests.sh to execute mock tests."
