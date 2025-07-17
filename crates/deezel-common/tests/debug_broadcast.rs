use deezel_common::provider::ConcreteProvider;
use deezel_common::traits::BitcoinRpcProvider;

#[tokio::test]
#[ignore]
async fn test_broadcast_failing_tx() {
    let provider = ConcreteProvider::new(
        "http://localhost:18888".to_string(), // bitcoin rpc
        "http://localhost:18888".to_string(), // metashrew rpc
        "http://localhost:18888".to_string(), // sandshrew rpc
        Some("http://localhost:18888".to_string()), // esplora url
        "regtest".to_string(),
        None,
    ).await.unwrap();

    let failing_tx_hex = "020000000001017393d74046cd3c7151dae1e40404d92fbc0e8f4b65a0fe8d2cfad9d72aea4a200000000000fdffffff0210270000000000002251209f702b68b426cd1c9dc3129e1fbf5b33d9038040a616b899fb1693bddbea6c1381ca052a0100000022512073d9efe6ea4d9affff65603d426ea2fa9b0949fa0b8803fe5a4b75ec0c331e490140e627f16c841ce5c506abc7f67f1808255a150ef86448644071df7f7951550390a25675bd04e396724b254aae01ac1256e007b6f0a45f4af28660318376f2f35600000000";

    let result = provider.send_raw_transaction(failing_tx_hex).await;

    println!("Broadcast result: {:?}", result);
    assert!(result.is_err(), "Expected the transaction to fail, but it succeeded.");
}