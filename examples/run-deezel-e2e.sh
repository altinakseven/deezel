#!/bin/bash
export RUST_LOG=debug
DEEZEL=/data/metashrew/deezel/target/release/deezel

PWD=$(pwd)
cd /data/alkanes
echo "restarting alkanes"
docker-compose down -v
docker-compose up -d
sleep 3

# Remove existing wallet to ensure clean state
rm -f ~/.deezel/regtest.json.asc

echo "🔐 Creating GPG-encrypted wallet (non-interactive mode)..."
$DEEZEL --wallet-file ~/.deezel/regtest.json.asc -p regtest --sandshrew-rpc-url http://localhost:18888 --passphrase testtesttest wallet create
$DEEZEL --wallet-file ~/.deezel/regtest.json.asc -p regtest --sandshrew-rpc-url http://localhost:18888 --passphrase testtesttest wallet addresses p2tr:0-100 > /dev/null

echo "🔍 Initial UTXO check..."
$DEEZEL --wallet-file ~/.deezel/regtest.json.asc -p regtest --sandshrew-rpc-url http://localhost:18888 --passphrase testtesttest wallet utxos

echo "⛏️  Generating 201 blocks to P2TR address..."
echo "Deriving address for block generation..."
echo "Generating blocks to address [self:p2tr:0]..."
$DEEZEL --wallet-file ~/.deezel/regtest.json.asc -p regtest --sandshrew-rpc-url http://localhost:18888 --passphrase testtesttest bitcoind generatetoaddress 201 [self:p2tr:0]

echo "Wallet is now funded. UTXOs will be synced on demand by the next command."

echo "Checking for matured UTXOs..."
for i in {1..30}; do
    UTXOS=$($DEEZEL --wallet-file ~/.deezel/regtest.json.asc -p regtest --sandshrew-rpc-url http://localhost:18888 --passphrase testtesttest wallet utxos --addresses [self:p2tr:0] | grep "No UTXOs found")
    if [ -z "$UTXOS" ]; then
        echo "✅ UTXOs found!"
        break
    fi
    echo "⏳ No UTXOs found, waiting... (Attempt $i/30)"
    sleep 2
done

if [ -n "$UTXOS" ]; then
    echo "❌ Timed out waiting for UTXOs."
    exit 1
fi

echo "Attempting to send transaction..."
$DEEZEL --wallet-file ~/.deezel/regtest.json.asc -p regtest --sandshrew-rpc-url http://localhost:18888 --passphrase testtesttest wallet send -y --from "[self:p2tr:0]" "[self:p2tr:1]" 10000 --fee-rate 1


bash /data/metashrew/deezel/examples/run-alkanes-execute.sh
