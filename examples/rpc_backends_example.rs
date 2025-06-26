//! Comprehensive example demonstrating all RPC backend configurations
//! 
//! This example shows how to configure and use deezel with different backends:
//! - Sandshrew unified JSON-RPC
//! - Direct ord server REST API
//! - Direct esplora REST API  
//! - Bitcoin Core RPC
//! - Legacy configuration for backward compatibility

use anyhow::Result;
use serde_json::Value;
use std::time::Duration;
use tokio;

// Mock types for the example since the actual RPC implementation is in legacy code
#[derive(Clone)]
pub struct EnhancedRpcClient;

#[derive(Clone)]
pub enum RpcBackend {
    Sandshrew { url: String, timeout: Duration },
    Ord { url: String, timeout: Duration },
    Esplora { url: String, timeout: Duration },
    BitcoinCore { url: String, username: String, password: String, timeout: Duration },
}

#[derive(Clone)]
pub struct EnhancedRpcConfig {
    pub backend: RpcBackend,
    pub fallbacks: Vec<RpcBackend>,
    pub enable_cache: bool,
    pub cache_ttl: u64,
    pub rate_limit: Option<u64>,
}

impl EnhancedRpcClient {
    pub fn new(_config: EnhancedRpcConfig) -> Self {
        Self
    }
    
    pub async fn health_check(&self) -> Result<bool> {
        println!("  [Mock] Health check performed");
        Ok(true)
    }
    
    pub async fn get_inscription(&self, id: &str) -> Result<Value> {
        println!("  [Mock] Getting inscription: {}", id);
        Ok(serde_json::json!({"id": id, "content_type": "text/plain"}))
    }
    
    pub async fn get_sat_info(&self, sat: u64) -> Result<Value> {
        println!("  [Mock] Getting sat info: {}", sat);
        Ok(serde_json::json!({"sat": sat, "rarity": "common"}))
    }
    
    pub async fn get_address_info(&self, address: &str) -> Result<Value> {
        println!("  [Mock] Getting address info: {}", address);
        Ok(serde_json::json!({"address": address, "balance": 0}))
    }
    
    pub async fn get_mempool_info(&self) -> Result<Value> {
        println!("  [Mock] Getting mempool info");
        Ok(serde_json::json!({"size": 1000, "bytes": 500000}))
    }
    
    pub async fn get_inscription_content(&self, id: &str) -> Result<Vec<u8>> {
        println!("  [Mock] Getting inscription content: {}", id);
        Ok(b"Hello, World!".to_vec())
    }
    
    pub async fn get_address_utxos(&self, address: &str) -> Result<Vec<Value>> {
        println!("  [Mock] Getting UTXOs for address: {}", address);
        Ok(vec![serde_json::json!({"txid": "abc123", "vout": 0, "value": 1000})])
    }
    
    pub async fn get_fee_estimates(&self) -> Result<FeeEstimates> {
        println!("  [Mock] Getting fee estimates");
        Ok(FeeEstimates {
            estimates: vec![(1, 10.0), (6, 5.0), (144, 1.0)].into_iter().collect()
        })
    }
    
    pub async fn get_block_height(&self) -> Result<u64> {
        println!("  [Mock] Getting block height");
        Ok(800000)
    }
    
    pub async fn get_transaction(&self, txid: &str) -> Result<TransactionInfo> {
        println!("  [Mock] Getting transaction: {}", txid);
        Ok(TransactionInfo { txid: txid.to_string() })
    }
}

pub struct FeeEstimates {
    pub estimates: std::collections::HashMap<u32, f64>,
}

pub struct TransactionInfo {
    pub txid: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    
    println!("=== Deezel RPC Backends Example ===\n");
    
    // Example 1: Sandshrew unified interface (recommended)
    println!("1. Sandshrew Unified Interface");
    let sandshrew_config = EnhancedRpcConfig {
        backend: RpcBackend::Sandshrew {
            url: "http://localhost:8080".to_string(),
            timeout: Duration::from_secs(30),
        },
        fallbacks: vec![],
        enable_cache: true,
        cache_ttl: 300,
        rate_limit: Some(100),
    };
    
    let sandshrew_client = EnhancedRpcClient::new(sandshrew_config);
    demonstrate_sandshrew_capabilities(&sandshrew_client).await?;
    
    // Example 2: Direct ord server
    println!("\n2. Direct Ord Server");
    let ord_config = EnhancedRpcConfig {
        backend: RpcBackend::Ord {
            url: "http://localhost:80".to_string(), // Default ord server port
            timeout: Duration::from_secs(30),
        },
        fallbacks: vec![],
        enable_cache: true,
        cache_ttl: 300,
        rate_limit: Some(50),
    };
    
    let ord_client = EnhancedRpcClient::new(ord_config);
    demonstrate_ord_capabilities(&ord_client).await?;
    
    // Example 3: Direct esplora server
    println!("\n3. Direct Esplora Server");
    let esplora_config = EnhancedRpcConfig {
        backend: RpcBackend::Esplora {
            url: "https://blockstream.info/api".to_string(), // Public esplora instance
            timeout: Duration::from_secs(30),
        },
        fallbacks: vec![],
        enable_cache: true,
        cache_ttl: 600, // Longer cache for public API
        rate_limit: Some(10), // Conservative rate limit for public API
    };
    
    let esplora_client = EnhancedRpcClient::new(esplora_config);
    demonstrate_esplora_capabilities(&esplora_client).await?;
    
    // Example 4: Bitcoin Core RPC
    println!("\n4. Bitcoin Core RPC");
    let bitcoin_config = EnhancedRpcConfig {
        backend: RpcBackend::BitcoinCore {
            url: "http://localhost:8332".to_string(),
            username: "bitcoinrpc".to_string(),
            password: "bitcoinrpc".to_string(),
            timeout: Duration::from_secs(30),
        },
        fallbacks: vec![],
        enable_cache: true,
        cache_ttl: 60, // Shorter cache for local node
        rate_limit: None, // No rate limit for local node
    };
    
    let bitcoin_client = EnhancedRpcClient::new(bitcoin_config);
    demonstrate_bitcoin_core_capabilities(&bitcoin_client).await?;
    
    // Example 5: Multi-backend with fallbacks
    println!("\n5. Multi-Backend Configuration with Fallbacks");
    let multi_config = EnhancedRpcConfig {
        backend: RpcBackend::Sandshrew {
            url: "http://localhost:8080".to_string(),
            timeout: Duration::from_secs(10),
        },
        fallbacks: vec![
            RpcBackend::Esplora {
                url: "https://blockstream.info/api".to_string(),
                timeout: Duration::from_secs(15),
            },
            RpcBackend::BitcoinCore {
                url: "http://localhost:8332".to_string(),
                username: "bitcoinrpc".to_string(),
                password: "bitcoinrpc".to_string(),
                timeout: Duration::from_secs(20),
            },
        ],
        enable_cache: true,
        cache_ttl: 300,
        rate_limit: Some(50),
    };
    
    let multi_client = EnhancedRpcClient::new(multi_config);
    demonstrate_unified_interface(&multi_client).await?;
    
    println!("\n=== Example Complete ===");
    Ok(())
}

/// Demonstrate Sandshrew unified interface capabilities
async fn demonstrate_sandshrew_capabilities(client: &EnhancedRpcClient) -> Result<()> {
    println!("Testing Sandshrew unified interface...");
    
    // Health check
    match client.health_check().await {
        Ok(true) => println!("✓ Sandshrew server is healthy"),
        Ok(false) => println!("⚠ Sandshrew server health check failed"),
        Err(e) => println!("✗ Sandshrew server unreachable: {}", e),
    }
    
    // Test ord namespace via Sandshrew
    println!("Testing ord namespace through Sandshrew:");
    
    // Get inscription (example inscription ID)
    let inscription_id = "e3e24e2b90c6e4e1b8e8e4e1b8e8e4e1b8e8e4e1b8e8e4e1b8e8e4e1b8e8e4e1i0";
    match client.get_inscription(inscription_id).await {
        Ok(inscription) => println!("✓ Retrieved inscription: {}", serde_json::to_string_pretty(&inscription)?),
        Err(e) => println!("⚠ Could not retrieve inscription: {}", e),
    }
    
    // Get sat information
    let sat_number = 1000000000; // Example sat number
    match client.get_sat_info(sat_number).await {
        Ok(sat_info) => println!("✓ Retrieved sat info: {}", serde_json::to_string_pretty(&sat_info)?),
        Err(e) => println!("⚠ Could not retrieve sat info: {}", e),
    }
    
    // Test esplora namespace via Sandshrew
    println!("Testing esplora namespace through Sandshrew:");
    
    // Get address info (example address)
    let address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    match client.get_address_info(address).await {
        Ok(addr_info) => println!("✓ Retrieved address info: {}", serde_json::to_string_pretty(&addr_info)?),
        Err(e) => println!("⚠ Could not retrieve address info: {}", e),
    }
    
    // Get mempool info
    match client.get_mempool_info().await {
        Ok(mempool) => println!("✓ Retrieved mempool info: {}", serde_json::to_string_pretty(&mempool)?),
        Err(e) => println!("⚠ Could not retrieve mempool info: {}", e),
    }
    
    Ok(())
}

/// Demonstrate direct ord server capabilities
async fn demonstrate_ord_capabilities(client: &EnhancedRpcClient) -> Result<()> {
    println!("Testing direct ord server...");
    
    // Health check
    match client.health_check().await {
        Ok(true) => println!("✓ Ord server is healthy"),
        Ok(false) => println!("⚠ Ord server health check failed"),
        Err(e) => println!("✗ Ord server unreachable: {}", e),
    }
    
    // Test ord-specific endpoints
    let inscription_id = "e3e24e2b90c6e4e1b8e8e4e1b8e8e4e1b8e8e4e1b8e8e4e1b8e8e4e1b8e8e4e1i0";
    
    // Get inscription content
    match client.get_inscription_content(inscription_id).await {
        Ok(content) => println!("✓ Retrieved inscription content (length: {} bytes)", content.len()),
        Err(e) => println!("⚠ Could not retrieve inscription content: {}", e),
    }
    
    // Get sat information
    let sat_number = 1000000000;
    match client.get_sat_info(sat_number).await {
        Ok(sat_info) => println!("✓ Retrieved sat info: {}", serde_json::to_string_pretty(&sat_info)?),
        Err(e) => println!("⚠ Could not retrieve sat info: {}", e),
    }
    
    Ok(())
}

/// Demonstrate direct esplora server capabilities
async fn demonstrate_esplora_capabilities(client: &EnhancedRpcClient) -> Result<()> {
    println!("Testing direct esplora server...");
    
    // Health check
    match client.health_check().await {
        Ok(true) => println!("✓ Esplora server is healthy"),
        Ok(false) => println!("⚠ Esplora server health check failed"),
        Err(e) => println!("✗ Esplora server unreachable: {}", e),
    }
    
    // Test esplora-specific endpoints
    let address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    
    // Get address UTXOs
    match client.get_address_utxos(address).await {
        Ok(utxos) => println!("✓ Retrieved {} UTXOs for address", utxos.len()),
        Err(e) => println!("⚠ Could not retrieve UTXOs: {}", e),
    }
    
    // Get fee estimates
    match client.get_fee_estimates().await {
        Ok(fees) => {
            println!("✓ Retrieved fee estimates:");
            for (target, rate) in fees.estimates.iter().take(5) {
                println!("  {} blocks: {:.1} sat/vB", target, rate);
            }
        },
        Err(e) => println!("⚠ Could not retrieve fee estimates: {}", e),
    }
    
    // Get latest block height
    match client.get_block_height().await {
        Ok(height) => println!("✓ Current block height: {}", height),
        Err(e) => println!("⚠ Could not retrieve block height: {}", e),
    }
    
    Ok(())
}

/// Demonstrate Bitcoin Core RPC capabilities
async fn demonstrate_bitcoin_core_capabilities(client: &EnhancedRpcClient) -> Result<()> {
    println!("Testing Bitcoin Core RPC...");
    
    // Health check
    match client.health_check().await {
        Ok(true) => println!("✓ Bitcoin Core is healthy"),
        Ok(false) => println!("⚠ Bitcoin Core health check failed"),
        Err(e) => println!("✗ Bitcoin Core unreachable: {}", e),
    }
    
    // Test Bitcoin Core specific methods
    match client.get_block_height().await {
        Ok(height) => println!("✓ Current block height: {}", height),
        Err(e) => println!("⚠ Could not retrieve block height: {}", e),
    }
    
    // Get mempool info
    match client.get_mempool_info().await {
        Ok(mempool) => println!("✓ Retrieved mempool info: {}", serde_json::to_string_pretty(&mempool)?),
        Err(e) => println!("⚠ Could not retrieve mempool info: {}", e),
    }
    
    Ok(())
}

/// Demonstrate unified interface across all backends
async fn demonstrate_unified_interface(client: &EnhancedRpcClient) -> Result<()> {
    println!("Testing unified BlockchainClient interface...");
    
    // All these methods work regardless of backend
    match client.health_check().await {
        Ok(true) => println!("✓ Primary backend is healthy"),
        Ok(false) => println!("⚠ Primary backend health check failed"),
        Err(e) => println!("✗ Primary backend unreachable, trying fallbacks: {}", e),
    }
    
    match client.get_block_height().await {
        Ok(height) => println!("✓ Current block height: {}", height),
        Err(e) => println!("⚠ Could not retrieve block height: {}", e),
    }
    
    match client.get_fee_estimates().await {
        Ok(fees) => {
            println!("✓ Retrieved fee estimates:");
            for (target, rate) in fees.estimates.iter().take(3) {
                println!("  {} blocks: {:.1} sat/vB", target, rate);
            }
        },
        Err(e) => println!("⚠ Could not retrieve fee estimates: {}", e),
    }
    
    // Example transaction ID (this would be a real txid in practice)
    let example_txid = "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16";
    match client.get_transaction(example_txid).await {
        Ok(tx) => println!("✓ Retrieved transaction: {}", tx.txid),
        Err(e) => println!("⚠ Could not retrieve transaction: {}", e),
    }
    
    Ok(())
}

/// Example of how to configure for different deployment scenarios
#[allow(dead_code)]
fn deployment_examples() -> Vec<EnhancedRpcConfig> {
    vec![
        // Development: Local sandshrew instance
        EnhancedRpcConfig {
            backend: RpcBackend::Sandshrew {
                url: "http://localhost:8080".to_string(),
                timeout: Duration::from_secs(30),
            },
            fallbacks: vec![],
            enable_cache: true,
            cache_ttl: 60,
            rate_limit: None,
        },
        
        // Production: Sandshrew with esplora fallback
        EnhancedRpcConfig {
            backend: RpcBackend::Sandshrew {
                url: "https://api.sandshrew.io".to_string(),
                timeout: Duration::from_secs(10),
            },
            fallbacks: vec![
                RpcBackend::Esplora {
                    url: "https://blockstream.info/api".to_string(),
                    timeout: Duration::from_secs(15),
                },
            ],
            enable_cache: true,
            cache_ttl: 300,
            rate_limit: Some(100),
        },
        
        // Self-hosted: Local Bitcoin Core + ord + esplora
        EnhancedRpcConfig {
            backend: RpcBackend::BitcoinCore {
                url: "http://localhost:8332".to_string(),
                username: "bitcoinrpc".to_string(),
                password: "your_rpc_password".to_string(),
                timeout: Duration::from_secs(30),
            },
            fallbacks: vec![
                RpcBackend::Ord {
                    url: "http://localhost:80".to_string(),
                    timeout: Duration::from_secs(30),
                },
                RpcBackend::Esplora {
                    url: "http://localhost:3000".to_string(),
                    timeout: Duration::from_secs(30),
                },
            ],
            enable_cache: true,
            cache_ttl: 60,
            rate_limit: None,
        },
        
        // Hybrid: Mix of local and remote services
        EnhancedRpcConfig {
            backend: RpcBackend::Ord {
                url: "http://localhost:80".to_string(), // Local ord for inscriptions
                timeout: Duration::from_secs(30),
            },
            fallbacks: vec![
                RpcBackend::Esplora {
                    url: "https://blockstream.info/api".to_string(), // Remote esplora for blockchain data
                    timeout: Duration::from_secs(15),
                },
            ],
            enable_cache: true,
            cache_ttl: 300,
            rate_limit: Some(50),
        },
    ]
}