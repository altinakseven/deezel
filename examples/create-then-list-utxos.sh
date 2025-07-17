#!/bin/bash
./target/release/deezel --sandshrew-rpc-url http://localhost:18888 --wallet-file ~/.deezel/wallet.json --passphrase testtesttest wallet create
./target/release/deezel --sandshrew-rpc-url http://localhost:18888 --wallet-file ~/.deezel/wallet.json bitcoind generatetoaddress 201 [self:p2tr:100]
./target/release/deezel --sandshrew-rpc-url http://localhost:18888 wallet sync
./target/release/deezel --sandshrew-rpc-url http://localhost:18888 --wallet-file ~/.deezel/wallet.json --passphrase testtesttest wallet utxos --addresses p2tr:100
