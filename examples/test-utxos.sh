#!/bin/bash
export RUST_LOG=debug
./target/release/deezel --wallet-file ~/.deezel/wallet.json --passphrase testtesttest wallet create
./target/release/deezel --wallet-file ~/.deezel/wallet.json bitcoind generatetoaddress 201 p2tr:0
./target/release/deezel --wallet-file ~/.deezel/wallet.json wallet sync
./target/release/deezel --wallet-file ~/.deezel/wallet.json wallet utxos p2tr:0
