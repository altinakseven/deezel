use anyhow::Result;
use bdk::bitcoin::Network;
use deezel::alkanes::{AlkanesContract, AlkanesManager, AlkanesOutpoint, AlkanesPayload, ContractId};
use deezel::rpc::RpcClient;
use mockall::predicate::*;
use mockall::mock;
use std::collections::HashMap;
use tokio::test;

// Mock RPC client for testing
mock! {
    RpcClient {
        fn _call(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value>;
    }
}

#[test]
async fn test_get_tokens_by_address() -> Result<()> {
    // Create mock RPC client
    let mut mock_rpc = MockRpcClient::new();
    
    // Set up expectations
    mock_rpc
        .expect__call()
        .with(
            eq("alkanes_protorunesbyaddress"),
            always(),
        )
        .times(1)
        .returning(|_, _| {
            Ok(serde_json::json!({
                "outpoints": [
                    {
                        "outpoint": {
                            "txid": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                            "vout": 0
                        },
                        "output": {
                            "value": "0x00000000000001f4", // 500 satoshis
                            "script": "76a914000000000000000000000000000000000000000088ac"
                        },
                        "txindex": 1,
                        "height": 100,
                        "runes": [
                            {
                                "balance": "0x0000000000000064", // 100 tokens
                                "rune": {
                                    "id": {
                                        "block": "0x00000064", // Block 100
                                        "tx": "0x00000001" // TX 1
                                    },
                                    "name": "Test Token",
                                    "symbol": "TEST",
                                    "divisibility": 8,
                                    "spacers": 0
                                }
                            }
                        ]
                    }
                ]
            }))
        });
    
    // Create AlkanesManager with mock RPC client
    let manager = AlkanesManager::new(mock_rpc, Network::Regtest);
    
    // Call the method under test
    let outpoints = manager.get_tokens_by_address("bc1qtest", "1").await?;
    
    // Verify results
    assert_eq!(outpoints.len(), 1);
    
    let outpoint = &outpoints[0];
    assert_eq!(outpoint.txid, "efcdab8967452301efcdab8967452301efcdab8967452301efcdab8967452301"); // Reversed txid
    assert_eq!(outpoint.vout, 0);
    assert_eq!(outpoint.value, 500);
    assert_eq!(outpoint.script, "76a914000000000000000000000000000000000000000088ac");
    assert_eq!(outpoint.tx_index, 1);
    assert_eq!(outpoint.height, 100);
    
    assert_eq!(outpoint.tokens.len(), 1);
    let token = &outpoint.tokens[0];
    assert_eq!(token.id.block, "100");
    assert_eq!(token.id.tx, "1");
    assert_eq!(token.name, "Test Token");
    assert_eq!(token.symbol, "TEST");
    assert_eq!(token.balance, "100");
    assert_eq!(token.divisibility, 8);
    assert_eq!(token.spacers, 0);
    
    Ok(())
}

#[test]
async fn test_get_contract_by_id() -> Result<()> {
    // Create mock RPC client
    let mut mock_rpc = MockRpcClient::new();
    
    // Set up expectations for each property query
    // Name (opcode 99)
    mock_rpc
        .expect__call()
        .with(
            eq("alkanes_simulate"),
            always(),
        )
        .times(1)
        .returning(|_, params| {
            let params_obj = params.as_array().unwrap()[0].as_object().unwrap();
            let inputs = params_obj.get("inputs").unwrap().as_array().unwrap();
            
            if inputs[0].as_str().unwrap() == "99" {
                Ok(serde_json::json!({
                    "status": 0,
                    "execution": {
                        "data": "0x54657374546f6b656e" // "TestToken" in hex
                    }
                }))
            } else {
                Ok(serde_json::json!({
                    "status": 1
                }))
            }
        });
    
    // Symbol (opcode 100)
    mock_rpc
        .expect__call()
        .with(
            eq("alkanes_simulate"),
            always(),
        )
        .times(1)
        .returning(|_, params| {
            let params_obj = params.as_array().unwrap()[0].as_object().unwrap();
            let inputs = params_obj.get("inputs").unwrap().as_array().unwrap();
            
            if inputs[0].as_str().unwrap() == "100" {
                Ok(serde_json::json!({
                    "status": 0,
                    "execution": {
                        "data": "0x54455354" // "TEST" in hex
                    }
                }))
            } else {
                Ok(serde_json::json!({
                    "status": 1
                }))
            }
        });
    
    // Total Supply (opcode 101)
    mock_rpc
        .expect__call()
        .with(
            eq("alkanes_simulate"),
            always(),
        )
        .times(1)
        .returning(|_, params| {
            let params_obj = params.as_array().unwrap()[0].as_object().unwrap();
            let inputs = params_obj.get("inputs").unwrap().as_array().unwrap();
            
            if inputs[0].as_str().unwrap() == "101" {
                Ok(serde_json::json!({
                    "status": 0,
                    "execution": {
                        "data": "0x000000000000000000000000000000000000000000000000000000000000000a" // 10 in hex
                    }
                }))
            } else {
                Ok(serde_json::json!({
                    "status": 1
                }))
            }
        });
    
    // Cap (opcode 102)
    mock_rpc
        .expect__call()
        .with(
            eq("alkanes_simulate"),
            always(),
        )
        .times(1)
        .returning(|_, params| {
            let params_obj = params.as_array().unwrap()[0].as_object().unwrap();
            let inputs = params_obj.get("inputs").unwrap().as_array().unwrap();
            
            if inputs[0].as_str().unwrap() == "102" {
                Ok(serde_json::json!({
                    "status": 0,
                    "execution": {
                        "data": "0x0000000000000064" // 100 in hex
                    }
                }))
            } else {
                Ok(serde_json::json!({
                    "status": 1
                }))
            }
        });
    
    // Minted (opcode 103)
    mock_rpc
        .expect__call()
        .with(
            eq("alkanes_simulate"),
            always(),
        )
        .times(1)
        .returning(|_, params| {
            let params_obj = params.as_array().unwrap()[0].as_object().unwrap();
            let inputs = params_obj.get("inputs").unwrap().as_array().unwrap();
            
            if inputs[0].as_str().unwrap() == "103" {
                Ok(serde_json::json!({
                    "status": 0,
                    "execution": {
                        "data": "0x000000000000000a" // 10 in hex
                    }
                }))
            } else {
                Ok(serde_json::json!({
                    "status": 1
                }))
            }
        });
    
    // Mint Amount (opcode 104)
    mock_rpc
        .expect__call()
        .with(
            eq("alkanes_simulate"),
            always(),
        )
        .times(1)
        .returning(|_, params| {
            let params_obj = params.as_array().unwrap()[0].as_object().unwrap();
            let inputs = params_obj.get("inputs").unwrap().as_array().unwrap();
            
            if inputs[0].as_str().unwrap() == "104" {
                Ok(serde_json::json!({
                    "status": 0,
                    "execution": {
                        "data": "0x0000000000000005" // 5 in hex
                    }
                }))
            } else {
                Ok(serde_json::json!({
                    "status": 1
                }))
            }
        });
    
    // Create AlkanesManager with mock RPC client
    let manager = AlkanesManager::new(mock_rpc, Network::Regtest);
    
    // Call the method under test
    let contract_id = ContractId {
        block: "100".to_string(),
        tx: "1".to_string(),
    };
    
    let contract = manager.get_contract_by_id(&contract_id).await?;
    
    // Verify results
    assert_eq!(contract.id.block, "100");
    assert_eq!(contract.id.tx, "1");
    assert_eq!(contract.name, "TestToken");
    assert_eq!(contract.symbol, "TEST");
    assert_eq!(contract.total_supply, 10);
    assert_eq!(contract.cap, 100);
    assert_eq!(contract.minted, 10);
    assert_eq!(contract.mint_amount, 5);
    assert_eq!(contract.mint_active, true);
    assert_eq!(contract.percentage_minted, 10); // 10%
    
    Ok(())
}

#[test]
async fn test_find_tokens_by_id() -> Result<()> {
    // Create mock RPC client
    let mut mock_rpc = MockRpcClient::new();
    
    // Set up expectations
    mock_rpc
        .expect__call()
        .with(
            eq("alkanes_protorunesbyaddress"),
            always(),
        )
        .times(1)
        .returning(|_, _| {
            Ok(serde_json::json!({
                "outpoints": [
                    {
                        "outpoint": {
                            "txid": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                            "vout": 0
                        },
                        "output": {
                            "value": "0x00000000000001f4", // 500 satoshis
                            "script": "76a914000000000000000000000000000000000000000088ac"
                        },
                        "txindex": 1,
                        "height": 100,
                        "runes": [
                            {
                                "balance": "0x0000000000000064", // 100 tokens
                                "rune": {
                                    "id": {
                                        "block": "0x00000064", // Block 100
                                        "tx": "0x00000001" // TX 1
                                    },
                                    "name": "Test Token",
                                    "symbol": "TEST",
                                    "divisibility": 8,
                                    "spacers": 0
                                }
                            }
                        ]
                    },
                    {
                        "outpoint": {
                            "txid": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
                            "vout": 1
                        },
                        "output": {
                            "value": "0x00000000000001f4", // 500 satoshis
                            "script": "76a914000000000000000000000000000000000000000088ac"
                        },
                        "txindex": 2,
                        "height": 101,
                        "runes": [
                            {
                                "balance": "0x0000000000000032", // 50 tokens
                                "rune": {
                                    "id": {
                                        "block": "0x00000064", // Block 100
                                        "tx": "0x00000001" // TX 1
                                    },
                                    "name": "Test Token",
                                    "symbol": "TEST",
                                    "divisibility": 8,
                                    "spacers": 0
                                }
                            }
                        ]
                    }
                ]
            }))
        });
    
    // Create AlkanesManager with mock RPC client
    let manager = AlkanesManager::new(mock_rpc, Network::Regtest);
    
    // Call the method under test
    let contract_id = ContractId {
        block: "100".to_string(),
        tx: "1".to_string(),
    };
    
    let (outpoints, total) = manager.find_tokens_by_id("bc1qtest", &contract_id, 120, true).await?;
    
    // Verify results
    assert_eq!(outpoints.len(), 2);
    assert_eq!(total, 150); // 100 + 50
    
    // First outpoint should have 100 tokens (greatest first)
    assert_eq!(outpoints[0].tokens[0].balance, "100");
    
    // Second outpoint should have 50 tokens
    assert_eq!(outpoints[1].tokens[0].balance, "50");
    
    // Test with smallest first
    let (outpoints, total) = manager.find_tokens_by_id("bc1qtest", &contract_id, 120, false).await?;
    
    // Verify results
    assert_eq!(outpoints.len(), 2);
    assert_eq!(total, 150); // 50 + 100
    
    // First outpoint should have 50 tokens (smallest first)
    assert_eq!(outpoints[0].tokens[0].balance, "50");
    
    // Second outpoint should have 100 tokens
    assert_eq!(outpoints[1].tokens[0].balance, "100");
    
    Ok(())
}
