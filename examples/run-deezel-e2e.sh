#!/bin/bash
export RUST_LOG=info
DEEZEL=/data/deezel/target/release/deezel

PWD=$(pwd)
cd /data/alkanes
echo "restarting alkanes"
docker-compose down -v
docker-compose up -d
sleep 3

# Remove existing wallet to ensure clean state
rm -f ~/.deezel/wallet.json

echo "🔐 Creating GPG-encrypted wallet (non-interactive mode)..."
$DEEZEL --wallet-file ~/.deezel/wallet.json -p regtest --sandshrew-rpc-url http://localhost:18888 --passphrase testtesttest wallet create

echo "🔍 Initial UTXO check..."
$DEEZEL --wallet-file ~/.deezel/wallet.json -p regtest --sandshrew-rpc-url http://localhost:18888 --passphrase testtesttest wallet utxos --addresses p2tr:0

echo "⛏️  Generating 400 blocks to P2TR address..."
$DEEZEL --wallet-file ~/.deezel/wallet.json -p regtest --sandshrew-rpc-url http://localhost:18888 --passphrase testtesttest bitcoind generatetoaddress 201 [self:p2tr:0]

echo "Waiting for blockchain sync..."
sleep 6

echo "Checking UTXOs after block generation..."
$DEEZEL --wallet-file ~/.deezel/wallet.json -p regtest --sandshrew-rpc-url http://localhost:18888 --passphrase testtesttest wallet utxos --addresses p2tr:0

echo "Attempting to send transaction..."
$DEEZEL --wallet-file ~/.deezel/wallet.json -p regtest --sandshrew-rpc-url http://localhost:18888 --passphrase testtesttest wallet send -y --from p2tr:0 [self:p2tr:0] 10000 --fee-rate 1


bash /data/deezel/examples/run-alkanes-execute.sh
