#!/usr/bin/env python3
"""
Script to retrieve transaction bytes using Sandshrew API
Supports both esplora and Bitcoin RPC methods
"""

import requests
import json
import sys
import argparse
from typing import Optional, Dict, Any

class SandshrewClient:
    """Client for interacting with Sandshrew API"""
    
    def __init__(self, api_key: str, base_url: str = "https://mainnet.sandshrew.io/v1"):
        self.api_key = api_key
        self.base_url = base_url
        self.headers = {
            'Content-Type': 'application/json'
        }
    
    def _make_request(self, method: str, params: list) -> Dict[Any, Any]:
        """Make a JSON-RPC request to Sandshrew API"""
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params
        }
        
        url = f"{self.base_url}/{self.api_key}"
        
        try:
            response = requests.post(url, headers=self.headers, data=json.dumps(payload))
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error making request: {e}")
            sys.exit(1)
    
    def get_transaction_hex_esplora(self, txid: str) -> str:
        """Get transaction hex using esplora API"""
        print(f"Fetching transaction hex using esplora method for txid: {txid}")
        
        result = self._make_request("esplora_tx::hex", [txid])
        
        if "error" in result:
            print(f"Error: {result['error']}")
            sys.exit(1)
        
        return result["result"]
    
    def get_transaction_raw_esplora(self, txid: str) -> str:
        """Get raw transaction bytes using esplora API"""
        print(f"Fetching raw transaction bytes using esplora method for txid: {txid}")
        
        result = self._make_request("esplora_tx::raw", [txid])
        
        if "error" in result:
            print(f"Error: {result['error']}")
            sys.exit(1)
        
        return result["result"]
    
    def get_transaction_btc_rpc(self, txid: str, verbose: bool = False) -> str:
        """Get transaction using Bitcoin RPC method"""
        print(f"Fetching transaction using Bitcoin RPC method for txid: {txid}")
        
        result = self._make_request("btc_getrawtransaction", [txid, verbose])
        
        if "error" in result:
            print(f"Error: {result['error']}")
            sys.exit(1)
        
        return result["result"]
    
    def get_transaction_info_esplora(self, txid: str) -> Dict[Any, Any]:
        """Get transaction information using esplora API"""
        print(f"Fetching transaction info using esplora method for txid: {txid}")
        
        result = self._make_request("esplora_tx", [txid])
        
        if "error" in result:
            print(f"Error: {result['error']}")
            sys.exit(1)
        
        return result["result"]

def main():
    parser = argparse.ArgumentParser(description="Retrieve transaction bytes using Sandshrew API")
    parser.add_argument("--api-key", required=True, help="Sandshrew API key")
    parser.add_argument("--txid", default="a353ad401adb753affd68dbab9e4c61306c45ed68d00353157b72906bf0cb1d2", 
                       help="Transaction ID (default: the one from ordiscan.com)")
    parser.add_argument("--method", choices=["esplora_hex", "esplora_raw", "btc_rpc", "all"], 
                       default="all", help="Method to use for fetching transaction")
    parser.add_argument("--output", help="Output file to save the transaction bytes")
    parser.add_argument("--info", action="store_true", help="Also fetch transaction info")
    
    args = parser.parse_args()
    
    client = SandshrewClient(args.api_key)
    
    print(f"Retrieving transaction bytes for: {args.txid}")
    print("=" * 60)
    
    results = {}
    
    try:
        if args.method in ["esplora_hex", "all"]:
            print("\n1. Using esplora_tx::hex method:")
            hex_result = client.get_transaction_hex_esplora(args.txid)
            results["esplora_hex"] = hex_result
            print(f"Transaction hex: {hex_result}")
            print(f"Length: {len(hex_result)} characters ({len(hex_result)//2} bytes)")
        
        if args.method in ["esplora_raw", "all"]:
            print("\n2. Using esplora_tx::raw method:")
            raw_result = client.get_transaction_raw_esplora(args.txid)
            results["esplora_raw"] = raw_result
            print(f"Raw transaction: {raw_result}")
            if isinstance(raw_result, str):
                print(f"Length: {len(raw_result)} characters")
        
        if args.method in ["btc_rpc", "all"]:
            print("\n3. Using btc_getrawtransaction method:")
            btc_result = client.get_transaction_btc_rpc(args.txid, verbose=False)
            results["btc_rpc"] = btc_result
            print(f"Transaction hex: {btc_result}")
            print(f"Length: {len(btc_result)} characters ({len(btc_result)//2} bytes)")
        
        if args.info:
            print("\n4. Transaction Information:")
            info_result = client.get_transaction_info_esplora(args.txid)
            results["info"] = info_result
            print(json.dumps(info_result, indent=2))
        
        # Save to file if requested
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"\nResults saved to: {args.output}")
        
        print("\n" + "=" * 60)
        print("Transaction retrieval completed successfully!")
        
        # Verify all hex results are the same
        hex_results = [v for k, v in results.items() if k in ["esplora_hex", "btc_rpc"] and isinstance(v, str)]
        if len(hex_results) > 1:
            if all(h == hex_results[0] for h in hex_results):
                print("✓ All hex methods returned identical results")
            else:
                print("⚠ Warning: Different methods returned different hex values")
    
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()