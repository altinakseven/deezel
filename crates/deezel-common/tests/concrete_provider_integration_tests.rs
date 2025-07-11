use deezel_common::provider::ConcreteProvider;
use deezel_common::traits::*;
use std::path::PathBuf;

async fn create_provider() -> ConcreteProvider {
    ConcreteProvider::new(
        "http://bitcoinrpc:bitcoinrpc@localhost:8332".to_string(),
        "http://localhost:8080".to_string(),
        "http://localhost:30002".to_string(), // blockstream.info testnet
        Some(PathBuf::from("/tmp/deezel-test-wallet.keystore")),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn test_bitcoin_rpc_provider() {
    let provider = create_provider().await;
    let block_count = provider.get_block_count().await;
    assert!(block_count.is_ok());
    assert!(block_count.unwrap() > 0);
}

#[tokio::test]
#[ignore]
async fn test_metashrew_rpc_provider() {
    let provider = create_provider().await;
    let height = provider.get_metashrew_height().await;
    assert!(height.is_ok());
    assert!(height.unwrap() > 0);
}

#[tokio::test]
#[ignore]
async fn test_esplora_provider() {
    let provider = create_provider().await;
    let tip_hash = provider.get_blocks_tip_hash().await;
    assert!(tip_hash.is_ok());
    assert_eq!(tip_hash.unwrap().len(), 64);
}

#[tokio::test]
async fn test_runestone_provider() {
    let provider = create_provider().await;
    // This requires a transaction with a runestone.
    // For now, we just check that the method doesn't panic.
    // A more comprehensive test would create such a transaction.
    let txid = "0000000000000000000000000000000000000000000000000000000000000000";
    let result = provider.analyze_runestone(txid).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_alkanes_provider() {
    let provider = create_provider().await;
    // This requires a deployed alkane.
    // For now, we just check that the method doesn't panic.
    let alkane_id = "0:0";
    let result = provider.get_token_info(alkane_id).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_wallet_address_derivation() {
    use deezel_common::keystore::create_keystore;
    use std::fs::File;
    use std::io::Write;

    // 1. Create a new keystore
    let passphrase = "test_password";
    let keystore = create_keystore(passphrase).unwrap();
    let keystore_json = serde_json::to_string(&keystore).unwrap();

    // 2. Save the keystore to a temporary file
    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join("test-wallet.keystore");
    let mut file = File::create(&file_path).unwrap();
    file.write_all(keystore_json.as_bytes()).unwrap();

    // 3. Create a ConcreteProvider with the path to the temporary keystore
    let mut provider = ConcreteProvider::new(
        "http://bitcoinrpc:bitcoinrpc@localhost:8332".to_string(),
        "http://localhost:8080".to_string(),
        "regtest".to_string(),
        Some(file_path),
    )
    .await
    .unwrap();

    // 4. Set the passphrase and call get_address and get_addresses
    provider.set_passphrase(Some(passphrase.to_string()));
    let address = WalletProvider::get_address(&provider).await.unwrap();
    assert!(!address.is_empty());

    let addresses = provider.get_addresses(5).await.unwrap();
    assert_eq!(addresses.len(), 5);
    assert_eq!(addresses[0].address, address);
}