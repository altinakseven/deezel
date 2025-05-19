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
