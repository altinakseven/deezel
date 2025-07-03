#!/bin/bash
curl http://localhost:18888 -X POST -H 'Content-Type: application/json' -d '{"method": "esplora_address::utxo", "params": ["bcrt1p6ms0frn6tl7rdyuf3fte8gtpy5umcejjuqsrcheas897gfa03trqvyvpj4"], "id": 0, "jsonrpc": "2.0"}'
