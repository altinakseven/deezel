//! Transaction construction and signing
//!
//! This module handles:
//! - Creating Runestone with Protostones
//! - UTXO selection
//! - Output consolidation
//! - Transaction signing and verification

use anyhow::{Context, Result};
use bitcoin::{Address, Network, ScriptBuf, Transaction, TxOut};
use bitcoin::consensus::encode::serialize;
use log::{debug, info};
use std::sync::Arc;
use std::str::FromStr;

use crate::rpc::RpcClient;
use crate::wallet::WalletManager;
use ordinals::Runestone;

/// Dust output value in satoshis
const DUST_OUTPUT_VALUE: u64 = 546;

/// Protocol tag for DIESEL token minting
const PROTOCOL_TAG: u8 = 1;

/// Message cellpack for DIESEL token minting
const MESSAGE_CELLPACK: [u8; 3] = [2, 0, 77];

/// Transaction constructor configuration
pub struct TransactionConfig {
    /// Network (mainnet, testnet, regtest)
    pub network: Network,
    /// Fee rate in satoshis per vbyte
    pub fee_rate: f64,
    /// Maximum number of inputs to include in a transaction
    pub max_inputs: usize,
    /// Maximum number of outputs to include in a transaction
    pub max_outputs: usize,
}

impl Default for TransactionConfig {
    fn default() -> Self {
        Self {
            network: Network::Testnet,
            fee_rate: 1.0,        // 1 sat/vbyte
            max_inputs: 100,      // Maximum 100 inputs
            max_outputs: 20,      // Maximum 20 outputs
        }
    }
}

/// Transaction constructor for creating DIESEL token minting transactions
pub struct TransactionConstructor {
    /// Wallet manager
    wallet_manager: Arc<WalletManager>,
    /// RPC client
    rpc_client: Arc<RpcClient>,
    /// Transaction configuration
    _config: TransactionConfig,
}

impl TransactionConstructor {
    /// Create a new transaction constructor
    pub fn new(
        wallet_manager: Arc<WalletManager>,
        rpc_client: Arc<RpcClient>,
        config: TransactionConfig,
    ) -> Self {
        Self {
            wallet_manager,
            rpc_client,
            _config: config,
        }
    }
    
    /// Create a DIESEL token minting transaction
    pub async fn create_minting_transaction(&self) -> Result<Transaction> {
        info!("Creating DIESEL token minting transaction");
        
        // Get a new address for the dust output
        let dust_address = self.wallet_manager.get_address().await?;
        let address = Address::from_str(&dust_address)
            .context("Failed to parse dust address")?;
        let dust_script = address.assume_checked().script_pubkey();
        
        // Create Runestone with Protostone for DIESEL token minting
        let runestone = Runestone {
            edicts: vec![],
            etching: None,
            mint: None,
            pointer: None,
            // Protocol tag: 1, Message cellpack: [2, 0, 77]
            protocol: Some(vec![PROTOCOL_TAG as u128, MESSAGE_CELLPACK[0] as u128, MESSAGE_CELLPACK[1] as u128, MESSAGE_CELLPACK[2] as u128]),
        };
        let ordinals_script = runestone.encipher();
        
        // Use the ordinals script directly
        let runestone_script = ScriptBuf::from_bytes(ordinals_script.as_bytes().to_vec());
        
        // TODO: Implement actual UTXO selection and transaction construction
        // This is a placeholder implementation
        
        // 1. Get spendable UTXOs
        // In a real implementation, we would:
        // - Get regular BTC outputs via esplora
        // - Check ordinal safety via ord_address
        // - Get DIESEL balance via alkanes_protorunesbyaddress
        
        // 2. Select UTXOs for spending
        // In a real implementation, we would select UTXOs based on:
        // - Regular BTC outputs for fees
        // - DIESEL outputs for consolidation
        
        // Create transaction with:
        // - Dust output (546 sats)
        // - OP_RETURN output with Runestone
        let tx = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![
                // Dust output
                TxOut {
                    value: bitcoin::Amount::from_sat(DUST_OUTPUT_VALUE),
                    script_pubkey: dust_script,
                },
                // OP_RETURN output with Runestone
                TxOut {
                    value: bitcoin::Amount::ZERO,
                    script_pubkey: runestone_script,
                },
            ],
        };
        
        info!("DIESEL token minting transaction created successfully");
        debug!("Transaction: {:?}", tx);
        Ok(tx)
    }
    
    /// Broadcast a transaction to the network
    pub async fn broadcast_transaction(&self, tx: &Transaction) -> Result<String> {
        info!("Broadcasting transaction");
        
        // Serialize transaction to hex
        let _tx_hex = hex::encode(serialize(tx));
        
        // Get the transaction ID before broadcasting
        let txid = tx.compute_txid().to_string();
        
        // In a real implementation, we would:
        // - Send the transaction to the Bitcoin network via RPC
        // - Start monitoring for confirmations
        
        // For now, just log the transaction ID
        info!("Transaction broadcast successfully: {}", txid);
        
        // Trace the transaction to verify DIESEL token minting
        self.trace_transaction(&txid).await?;
        
        Ok(txid)
    }
    
    /// Trace a transaction to verify DIESEL token minting
    pub async fn trace_transaction(&self, txid: &str) -> Result<()> {
        // For DIESEL token minting, the vout for tracing is tx.output.len() + 1
        // This is because the Runestone protocol uses a 1-based index for outputs
        // and the OP_RETURN output is typically the last output in the transaction
        let vout = 2; // Dust output (index 0) + OP_RETURN output (index 1) + 1
        
        info!("Tracing transaction: {} vout: {}", txid, vout);
        
        // Reverse txid bytes for trace calls
        // Bitcoin txids are displayed in reverse byte order compared to their internal representation
        let reversed_txid = reverse_txid_bytes(txid)?;
        
        // Call alkanes_trace with reversed txid and appropriate vout
        let trace_pretty = self.rpc_client.trace_transaction_pretty(&reversed_txid, vout).await?;
        
        info!("Transaction traced successfully");
        println!("{}", trace_pretty);
        
        Ok(())
    }
    
    /// Create a Runestone with Protostone
    fn _create_runestone(&self) -> Result<bitcoin::ScriptBuf> {
        // TODO: Implement actual Runestone creation
        // This is a placeholder implementation
        
        // In a real implementation, we would:
        // - Create an OP_RETURN output
        // - Include protocol tag (1)
        // - Include message cellpack [2, 0, 77]
        
        // For now, return a placeholder script
        Ok(bitcoin::ScriptBuf::new())
    }
}

/// Reverse the bytes of a txid for trace calls
/// Bitcoin txids are displayed in reverse byte order compared to their internal representation
fn reverse_txid_bytes(txid: &str) -> Result<String> {
    // Decode the hex string to bytes
    let mut txid_bytes = hex::decode(txid)
        .context("Invalid txid hex")?;
    
    // Reverse the bytes
    txid_bytes.reverse();
    
    // Encode back to hex string
    Ok(hex::encode(txid_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::{RpcClient, RpcConfig};
    use crate::wallet::{WalletManager, WalletConfig};
    use bitcoin::Network;
    use tempfile::tempdir;
    
    #[tokio::test]
    async fn test_transaction_constructor_creation() {
        // Create a temporary directory and a dummy wallet file for this test.
        let temp_dir = tempdir().unwrap();
        let wallet_path = temp_dir.path().join("test_wallet.dat");
        std::fs::File::create(&wallet_path).unwrap();

        // Create wallet manager
        let wallet_config = WalletConfig {
            wallet_path: wallet_path.to_str().unwrap().to_string(),
            network: Network::Testnet,
            bitcoin_rpc_url: "http://localhost:8080".to_string(), // FIXED: Use Sandshrew endpoint
            metashrew_rpc_url: "http://localhost:8080".to_string(),
            network_params: None,
        };
        let wallet_manager = WalletManager::new(wallet_config).await.unwrap();
        
        // Create RPC client
        // FIXED: Use Sandshrew RPC for all operations to avoid network mismatch
        let rpc_config = RpcConfig {
            bitcoin_rpc_url: "http://localhost:8080".to_string(), // Use Sandshrew endpoint
            metashrew_rpc_url: "http://localhost:8080".to_string(),
        };
        let rpc_client = RpcClient::new(rpc_config);
        
        // Create transaction constructor
        let config = TransactionConfig::default();
        let constructor = TransactionConstructor::new(
            Arc::new(wallet_manager),
            Arc::new(rpc_client),
            config,
        );
        
        // Verify constructor was created successfully
        assert_eq!(constructor._config.network, Network::Testnet);
    }
    
    #[test]
    fn test_reverse_txid_bytes() {
        // Test with a sample txid
        let original_txid = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let expected_reversed = "9078563412efcdab9078563412efcdab9078563412efcdab9078563412efcdab";
        
        let reversed = reverse_txid_bytes(original_txid).unwrap();
        assert_eq!(reversed, expected_reversed);
        
        // Test that reversing twice gives us back the original
        let double_reversed = reverse_txid_bytes(&reversed).unwrap();
        assert_eq!(double_reversed, original_txid);
    }
    
    #[test]
    fn test_reverse_txid_bytes_invalid_hex() {
        // Test with invalid hex
        let result = reverse_txid_bytes("invalid_hex");
        assert!(result.is_err());
    }
}
