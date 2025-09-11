//! Integration tests for alkanes view functionality

use deezel_common::provider::ConcreteProvider;
use deezel_common::traits::AlkanesProvider;

// This is the frBTC alkane ID from the frontend
const FRBTC_ALKANE_ID: &str = "32:0";

#[tokio::test]
async fn test_alkanes_view_get_premium() -> anyhow::Result<()> {
    // 1. Setup ConcreteProvider to connect to local nodes
    let provider = ConcreteProvider::new(
        Some("http://bitcoinrpc:bitcoinrpc@localhost:18443".to_string()), // bitcoind rpc
        "http://localhost:8080".to_string(),      // metashrew rpc
        None,
        None,
        "regtest".to_string(),
        None,
    )
    .await?;

    // 2. Call the view function
    let result = provider
        .view(FRBTC_ALKANE_ID, "get_premium", None)
        .await;

    // 3. Assertions
    println!("Result from view call: {result:?}");
    assert!(result.is_ok());

    let premium = result.unwrap();
    assert!(premium.is_u64());
    assert_eq!(premium.as_u64().unwrap(), 1000); // Expecting 1000 from contract source

    Ok(())
}