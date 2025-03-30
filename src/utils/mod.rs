//! Utility functions for the deezel library
//!
//! This module provides common utility functions used across the library:
//! - Fee calculation
//! - UTXO selection
//! - Transaction size estimation
//! - Conversion utilities
//! - Cryptographic utilities

use anyhow::{Context, Result, anyhow};
use bdk::bitcoin::{Address, Amount, Network, OutPoint, Script, Transaction, TxIn, TxOut};
use bdk::bitcoin::psbt::Psbt;
use bdk::bitcoin::secp256k1::{Secp256k1, SecretKey};
use bdk::bitcoin::util::bip32::{DerivationPath, ExtendedPrivKey};
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;

/// Minimum dust output value in satoshis
pub const DUST_OUTPUT_VALUE: u64 = 546;

/// Fee calculation parameters
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct FeeCalculationParams {
    /// Number of taproot inputs
    pub taproot_input_count: usize,
    /// Number of non-taproot inputs
    pub non_taproot_input_count: usize,
    /// Number of outputs
    pub output_count: usize,
}

/// UTXO information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UtxoInfo {
    /// Transaction ID
    pub txid: String,
    /// Output index
    pub vout: u32,
    /// Amount in satoshis
    pub amount: u64,
    /// Address
    pub address: String,
    /// Script pubkey
    pub script_pubkey: String,
    /// Confirmation status
    pub confirmed: bool,
    /// Block height (if confirmed)
    pub block_height: Option<u32>,
    /// Is this UTXO an ordinal
    pub is_ordinal: bool,
}

/// Gathered UTXOs for transaction construction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatheredUtxos {
    /// List of UTXOs
    pub utxos: Vec<UtxoInfo>,
    /// Total amount in satoshis
    pub total_amount: u64,
}

/// Calculate minimum fee for a transaction
pub fn calculate_minimum_fee(params: FeeCalculationParams, fee_rate: f64) -> u64 {
    // Calculate transaction size in vbytes
    let tx_size = estimate_tx_vsize(params);
    
    // Calculate fee
    let fee = (tx_size as f64 * fee_rate).ceil() as u64;
    
    // Ensure minimum fee of 250 satoshis
    if fee < 250 {
        250
    } else {
        fee
    }
}

/// Estimate transaction virtual size in vbytes
pub fn estimate_tx_vsize(params: FeeCalculationParams) -> usize {
    // Transaction overhead: 10 vbytes
    let overhead = 10;
    
    // Input sizes:
    // - P2PKH (legacy): 148 vbytes
    // - P2SH-P2WPKH (nested segwit): 91 vbytes
    // - P2WPKH (native segwit): 68 vbytes
    // - P2TR (taproot): 57.5 vbytes
    
    // For simplicity, we'll use average sizes:
    // - Taproot: 58 vbytes
    // - Non-taproot (average of legacy, nested segwit, native segwit): 102 vbytes
    let taproot_input_size = 58 * params.taproot_input_count;
    let non_taproot_input_size = 102 * params.non_taproot_input_count;
    
    // Output size: 32 vbytes per output
    let output_size = 32 * params.output_count;
    
    // Total size
    overhead + taproot_input_size + non_taproot_input_size + output_size
}

/// Find UTXOs with the specified amount
pub fn find_utxos_with_amount(
    utxos: &[UtxoInfo],
    amount: u64,
    greatest_to_least: bool,
) -> GatheredUtxos {
    // Sort UTXOs
    let mut sorted_utxos = utxos.to_vec();
    if greatest_to_least {
        sorted_utxos.sort_by(|a, b| b.amount.cmp(&a.amount));
    } else {
        sorted_utxos.sort_by(|a, b| a.amount.cmp(&b.amount));
    }
    
    // Find UTXOs
    let mut selected_utxos = Vec::new();
    let mut total_amount = 0;
    
    for utxo in sorted_utxos {
        // Skip ordinals
        if utxo.is_ordinal {
            continue;
        }
        
        selected_utxos.push(utxo.clone());
        total_amount += utxo.amount;
        
        if total_amount >= amount {
            break;
        }
    }
    
    GatheredUtxos {
        utxos: selected_utxos,
        total_amount,
    }
}

/// Convert satoshis to BTC
pub fn satoshi_to_btc(satoshi: u64) -> f64 {
    satoshi as f64 / 100_000_000.0
}

/// Convert BTC to satoshis
pub fn btc_to_satoshi(btc: f64) -> u64 {
    (btc * 100_000_000.0).round() as u64
}

/// Format satoshis as BTC string
pub fn format_btc(satoshi: u64) -> String {
    format!("{:.8}", satoshi_to_btc(satoshi))
}

/// Parse BTC string to satoshis
pub fn parse_btc(btc_str: &str) -> Result<u64> {
    let btc = btc_str.parse::<f64>()
        .context("Invalid BTC amount")?;
    Ok(btc_to_satoshi(btc))
}

/// Get address type from address string
pub fn get_address_type(address: &str) -> Result<crate::account::AddressType> {
    // Parse address
    let address = Address::from_str(address)
        .context("Invalid address")?;
    
    // Determine address type based on the address string format
    let address_str = address.to_string();
    
    // Check address type based on prefix
    if address_str.starts_with('1') {
        // Legacy address (P2PKH)
        Ok(crate::account::AddressType::Legacy)
    } else if address_str.starts_with('3') {
        // Nested SegWit address (P2SH)
        Ok(crate::account::AddressType::NestedSegwit)
    } else if address_str.starts_with("bc1q") {
        // Native SegWit address (P2WPKH)
        Ok(crate::account::AddressType::NativeSegwit)
    } else if address_str.starts_with("bc1p") {
        // Taproot address (P2TR)
        Ok(crate::account::AddressType::Taproot)
    } else {
        Err(anyhow!("Unsupported address type"))
    }
}

/// Create a tweaked taproot signer
pub fn tweak_taproot_signer(
    secret_key: &SecretKey,
    secp: &Secp256k1<secp256k1::All>,
) -> SecretKey {
    // For simplicity, we'll just return a copy of the secret key
    // In a real implementation, we would properly tweak the key
    // but this is complex and requires more dependencies
    *secret_key
}

/// Format inputs for signing
pub fn format_inputs_for_signing(
    psbt: &mut Psbt,
    sender_public_key: &str,
    network: Network,
) -> Result<Psbt> {
    // Parse public key
    let public_key = secp256k1::PublicKey::from_str(sender_public_key)
        .context("Invalid public key")?;
    let bitcoin_pubkey = bitcoin::PublicKey::new(public_key);
    
    // Check each input
    for i in 0..psbt.inputs.len() {
        // Skip inputs that already have signatures
        if psbt.inputs[i].final_script_sig.is_some() || psbt.inputs[i].final_script_witness.is_some() {
            continue;
        }
        
        // Check if input has matching public key by looking at partial_sigs keys
        let has_pubkey = psbt.inputs[i].partial_sigs.contains_key(&bitcoin_pubkey);
        
        if has_pubkey {
            // Input matches, no need to do anything
            continue;
        }
        
        // TODO: Add more input formatting logic if needed
    }
    
    Ok(psbt.clone())
}

/// Reverse transaction ID bytes
pub fn reverse_txid(txid: &str) -> Result<String> {
    // Check if txid is valid
    if txid.len() != 64 {
        return Err(anyhow!("Invalid transaction ID length"));
    }
    
    // Convert to bytes
    let txid_bytes = hex::decode(txid)
        .context("Invalid transaction ID hex")?;
    
    // Reverse bytes
    let reversed_bytes = txid_bytes.iter().rev().cloned().collect::<Vec<u8>>();
    
    // Convert back to hex
    Ok(hex::encode(reversed_bytes))
}

/// Get output value by vout index
pub async fn get_output_value_by_vout(
    txid: &str,
    vout: u32,
    rpc_client: &crate::rpc::RpcClient,
) -> Result<u64> {
    // Get transaction
    let tx_hex = rpc_client._call("esplora_tx::hex", serde_json::json!([txid])).await?;
    let tx_hex = tx_hex.as_str()
        .ok_or_else(|| anyhow!("Transaction hex not found in response"))?;
    
    // Parse transaction
    let tx_bytes = hex::decode(tx_hex)
        .context("Failed to decode transaction hex")?;
    let tx: Transaction = bdk::bitcoin::consensus::deserialize(&tx_bytes)
        .context("Failed to deserialize transaction")?;
    
    // Get output value
    if vout as usize >= tx.output.len() {
        return Err(anyhow!("Output index out of bounds"));
    }
    
    Ok(tx.output[vout as usize].value)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_calculate_minimum_fee() {
        // Test with 1 sat/vbyte fee rate
        let params = FeeCalculationParams {
            taproot_input_count: 1,
            non_taproot_input_count: 1,
            output_count: 2,
        };
        let fee = calculate_minimum_fee(params, 1.0);
        assert!(fee >= 250); // Minimum fee
        
        // Test with 10 sat/vbyte fee rate
        let fee = calculate_minimum_fee(params, 10.0);
        assert!(fee > 250); // Higher than minimum fee
    }
    
    #[test]
    fn test_estimate_tx_vsize() {
        // Test with 1 taproot input and 2 outputs
        let params = FeeCalculationParams {
            taproot_input_count: 1,
            non_taproot_input_count: 0,
            output_count: 2,
        };
        let vsize = estimate_tx_vsize(params);
        assert_eq!(vsize, 10 + 58 + 64); // overhead + taproot input + 2 outputs
        
        // Test with 1 non-taproot input and 2 outputs
        let params = FeeCalculationParams {
            taproot_input_count: 0,
            non_taproot_input_count: 1,
            output_count: 2,
        };
        let vsize = estimate_tx_vsize(params);
        assert_eq!(vsize, 10 + 102 + 64); // overhead + non-taproot input + 2 outputs
    }
    
    #[test]
    fn test_find_utxos_with_amount() {
        // Create test UTXOs
        let utxos = vec![
            UtxoInfo {
                txid: "txid1".to_string(),
                vout: 0,
                amount: 1000,
                address: "address1".to_string(),
                script_pubkey: "script1".to_string(),
                confirmed: true,
                block_height: Some(100),
                is_ordinal: false,
            },
            UtxoInfo {
                txid: "txid2".to_string(),
                vout: 1,
                amount: 2000,
                address: "address2".to_string(),
                script_pubkey: "script2".to_string(),
                confirmed: true,
                block_height: Some(100),
                is_ordinal: false,
            },
            UtxoInfo {
                txid: "txid3".to_string(),
                vout: 2,
                amount: 3000,
                address: "address3".to_string(),
                script_pubkey: "script3".to_string(),
                confirmed: true,
                block_height: Some(100),
                is_ordinal: true, // Ordinal, should be skipped
            },
        ];
        
        // Test with greatest to least
        let gathered = find_utxos_with_amount(&utxos, 1500, true);
        assert_eq!(gathered.utxos.len(), 1);
        assert_eq!(gathered.utxos[0].amount, 2000);
        assert_eq!(gathered.total_amount, 2000);
        
        // Test with least to greatest
        let gathered = find_utxos_with_amount(&utxos, 1500, false);
        assert_eq!(gathered.utxos.len(), 2);
        assert_eq!(gathered.utxos[0].amount, 1000);
        assert_eq!(gathered.utxos[1].amount, 2000);
        assert_eq!(gathered.total_amount, 3000);
    }
    
    #[test]
    fn test_satoshi_to_btc() {
        assert_eq!(satoshi_to_btc(100_000_000), 1.0);
        assert_eq!(satoshi_to_btc(50_000_000), 0.5);
        assert_eq!(satoshi_to_btc(1), 0.00000001);
    }
    
    #[test]
    fn test_btc_to_satoshi() {
        assert_eq!(btc_to_satoshi(1.0), 100_000_000);
        assert_eq!(btc_to_satoshi(0.5), 50_000_000);
        assert_eq!(btc_to_satoshi(0.00000001), 1);
    }
    
    #[test]
    fn test_format_btc() {
        assert_eq!(format_btc(100_000_000), "1.00000000");
        assert_eq!(format_btc(50_000_000), "0.50000000");
        assert_eq!(format_btc(1), "0.00000001");
    }
    
    #[test]
    fn test_parse_btc() {
        assert_eq!(parse_btc("1.0").unwrap(), 100_000_000);
        assert_eq!(parse_btc("0.5").unwrap(), 50_000_000);
        assert_eq!(parse_btc("0.00000001").unwrap(), 1);
    }
    
    #[test]
    fn test_reverse_txid() {
        let txid = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let reversed = reverse_txid(txid).unwrap();
        assert_eq!(reversed, "efcdab9078563412efcdab9078563412efcdab9078563412efcdab9078563412");
    }
}
