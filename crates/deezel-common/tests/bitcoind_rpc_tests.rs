//! # Bitcoind RPC Tests
//!
//! This module contains tests for the `BitcoindProvider` implementation.

use deezel_common::provider::ConcreteProvider;
use deezel_common::traits::BitcoindProvider;
use wiremock::matchers::{method, body_json};
use wiremock::{Mock, MockServer, ResponseTemplate};
use serde_json::json;

async fn setup() -> (MockServer, ConcreteProvider) {
    let server = MockServer::start().await;
    let provider = ConcreteProvider::new(
        server.uri(),
        server.uri(),
        None,
        "regtest".to_string(),
        None,
    ).await.unwrap();
    (server, provider)
}

#[tokio::test]
async fn test_get_blockchain_info() {
    // Arrange
    let (server, provider) = setup().await;
    let mock_info = json!({
        "chain": "regtest",
        "blocks": 101,
        "headers": 101,
        "bestblockhash": "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
        "difficulty": 4.656542373906925e-10,
        "mediantime": 1296688602,
        "verificationprogress": 1.0,
        "initialblockdownload": false,
        "chainwork": "000000000000000000000000000000000000000000000000000000c900c900c9",
        "size_on_disk": 0,
        "pruned": false,
        "softforks": {},
        "warnings": ""
    });

    let rpc_response = json!({
        "jsonrpc": "2.0",
        "result": mock_info,
        "id": 1
    });

    Mock::given(method("POST"))
        .and(body_json(json!({
            "jsonrpc": "2.0",
            "method": "getblockchaininfo",
            "params": serde_json::Value::Null,
            "id": 1
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(rpc_response))
        .mount(&server)
        .await;

    // Act
    let result = provider.get_blockchain_info().await;

    // Assert
    assert!(result.is_ok());
    let info = result.unwrap();
    assert_eq!(info.chain, bitcoin::Network::Regtest);
    assert_eq!(info.blocks, 101);
}