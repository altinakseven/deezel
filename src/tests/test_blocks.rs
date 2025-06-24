//! Test block generation utilities
//!
//! This module provides utilities for generating test Bitcoin blocks
//! with DIESEL token transactions for e2e testing.

use anyhow::{Result, anyhow};
use bitcoin::{
    Block, Transaction, TxIn, TxOut, OutPoint, Witness, ScriptBuf,
    Amount, Sequence, Txid, absolute::LockTime, blockdata::transaction::Version,
    hashes::Hash, CompactTarget,
};
use bitcoin::blockdata::block::Header as BlockHeader;
use ordinals::{Runestone, Etching, Rune};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use super::{TestState, get_test_state, MockUtxo};

/// Test block builder for creating mock Bitcoin blocks
pub struct TestBlockBuilder {
    /// Block height
    pub height: u32,
    /// Previous block hash
    pub prev_blockhash: bitcoin::BlockHash,
    /// Block timestamp
    pub time: u32,
    /// Block transactions
    pub transactions: Vec<Transaction>,
}

impl TestBlockBuilder {
    /// Create a new test block builder
    pub fn new(height: u32) -> Self {
        let prev_blockhash = if height == 0 {
            bitcoin::BlockHash::all_zeros()
        } else {
            // Generate a deterministic previous block hash based on height
            let mut hash_bytes = [0u8; 32];
            hash_bytes[0..4].copy_from_slice(&(height - 1).to_le_bytes());
            bitcoin::BlockHash::from_byte_array(hash_bytes)
        };

        Self {
            height,
            prev_blockhash,
            time: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as u32,
            transactions: Vec::new(),
        }
    }

    /// Add a coinbase transaction
    pub fn with_coinbase(mut self, reward: u64) -> Self {
        let coinbase_tx = self.create_coinbase_transaction(reward);
        self.transactions.insert(0, coinbase_tx);
        self
    }

    /// Add a DIESEL minting transaction
    pub fn with_diesel_mint(mut self, 
        input_txid: Txid, 
        input_vout: u32, 
        output_address: &str,
        amount: u64
    ) -> Result<Self> {
        let diesel_tx = self.create_diesel_mint_transaction(
            input_txid, 
            input_vout, 
            output_address, 
            amount
        )?;
        self.transactions.push(diesel_tx);
        Ok(self)
    }

    /// Add a regular Bitcoin transaction
    pub fn with_transaction(mut self, tx: Transaction) -> Self {
        self.transactions.push(tx);
        self
    }

    /// Build the final block
    pub fn build(self) -> Result<Block> {
        if self.transactions.is_empty() {
            return Err(anyhow!("Block must have at least a coinbase transaction"));
        }

        let header = BlockHeader {
            version: bitcoin::blockdata::block::Version::ONE,
            prev_blockhash: self.prev_blockhash,
            merkle_root: self.calculate_merkle_root()?,
            time: self.time,
            bits: CompactTarget::from_consensus(0x207fffff), // Regtest difficulty
            nonce: 0,
        };

        Ok(Block {
            header,
            txdata: self.transactions,
        })
    }

    /// Create a coinbase transaction
    fn create_coinbase_transaction(&self, reward: u64) -> Transaction {
        let coinbase_input = TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from(vec![self.height.to_le_bytes().to_vec()].concat()),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        };

        let coinbase_output = TxOut {
            value: Amount::from_sat(reward),
            script_pubkey: ScriptBuf::from_hex("76a914000000000000000000000000000000000000000088ac")
                .expect("Valid script"),
        };

        Transaction {
            version: Version::ONE,
            lock_time: LockTime::ZERO,
            input: vec![coinbase_input],
            output: vec![coinbase_output],
        }
    }

    /// Create a DIESEL minting transaction
    fn create_diesel_mint_transaction(
        &self,
        input_txid: Txid,
        input_vout: u32,
        output_address: &str,
        amount: u64,
    ) -> Result<Transaction> {
        // Create input from previous UTXO
        let input = TxIn {
            previous_output: OutPoint {
                txid: input_txid,
                vout: input_vout,
            },
            script_sig: ScriptBuf::new(), // Will be filled by wallet
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        };

        // Create main output to the address
        let main_output = TxOut {
            value: Amount::from_sat(amount),
            script_pubkey: self.address_to_script_pubkey(output_address)?,
        };

        // Create DIESEL minting OP_RETURN output
        let diesel_runestone = Runestone {
            etching: None,
            pointer: Some(0), // Points to main output
            edicts: Vec::new(),
            mint: None,
            protocol: Some(vec![
                // DIESEL protocol message: [protocol_tag=1, message=[2, 0, 77]]
                1u128, // Protocol tag for DIESEL
                2u128, 0u128, 77u128, // DIESEL mint cellpack
            ]),
        };

        let op_return_output = TxOut {
            value: Amount::from_sat(0),
            script_pubkey: diesel_runestone.encipher(),
        };

        // Create dust output for DIESEL tracking
        let dust_output = TxOut {
            value: Amount::from_sat(546), // Dust limit
            script_pubkey: self.address_to_script_pubkey(output_address)?,
        };

        Ok(Transaction {
            version: Version::ONE,
            lock_time: LockTime::ZERO,
            input: vec![input],
            output: vec![main_output, op_return_output, dust_output],
        })
    }

    /// Convert address string to script pubkey
    fn address_to_script_pubkey(&self, address: &str) -> Result<ScriptBuf> {
        // For testing, create a simple P2PKH script
        // In a real implementation, this would parse the actual address
        if address.starts_with("bc1") || address.starts_with("tb1") || address.starts_with("bcrt1") {
            // Bech32 address - create P2WPKH script
            Ok(ScriptBuf::from_hex("0014000000000000000000000000000000000000")
                .expect("Valid script"))
        } else {
            // Legacy address - create P2PKH script
            Ok(ScriptBuf::from_hex("76a914000000000000000000000000000000000000000088ac")
                .expect("Valid script"))
        }
    }

    /// Calculate merkle root for the block
    fn calculate_merkle_root(&self) -> Result<bitcoin::TxMerkleNode> {
        if self.transactions.is_empty() {
            return Err(anyhow!("Cannot calculate merkle root for empty transaction list"));
        }

        let txids: Vec<bitcoin::Txid> = self.transactions
            .iter()
            .map(|tx| tx.compute_txid())
            .collect();

        // Simple merkle root calculation for testing
        // In production, use proper merkle tree implementation
        if txids.len() == 1 {
            Ok(bitcoin::TxMerkleNode::from_byte_array(txids[0].to_byte_array()))
        } else {
            // For simplicity, just use the first txid as merkle root
            // Real implementation would build proper merkle tree
            Ok(bitcoin::TxMerkleNode::from_byte_array(txids[0].to_byte_array()))
        }
    }
}

/// Create a test block with DIESEL minting transaction
pub fn create_diesel_mint_block(
    height: u32,
    input_txid: Txid,
    input_vout: u32,
    output_address: &str,
    amount: u64,
) -> Result<Block> {
    TestBlockBuilder::new(height)
        .with_coinbase(5000000000) // 50 BTC coinbase reward
        .with_diesel_mint(input_txid, input_vout, output_address, amount)?
        .build()
}

/// Create a simple test block with just coinbase
pub fn create_simple_test_block(height: u32) -> Result<Block> {
    TestBlockBuilder::new(height)
        .with_coinbase(5000000000) // 50 BTC coinbase reward
        .build()
}

/// Create test UTXOs for an address
pub fn create_test_utxos(address: &str, count: usize, amount_per_utxo: u64) -> Vec<MockUtxo> {
    (0..count)
        .map(|i| MockUtxo {
            txid: format!("{:064x}", i + 1),
            vout: 0,
            amount: amount_per_utxo,
            script_pubkey: "76a914000000000000000000000000000000000000000088ac".to_string(),
            confirmations: 6,
        })
        .collect()
}

/// Setup test blockchain state with some blocks and UTXOs
pub fn setup_test_blockchain(start_height: u32, num_blocks: u32) -> Result<()> {
    let state = get_test_state()?;
    let mut state_guard = state.lock().unwrap();

    // Generate test blocks
    for i in 0..num_blocks {
        let height = start_height + i;
        let block = create_simple_test_block(height)?;
        let block_bytes = bitcoin::consensus::serialize(&block);
        state_guard.blocks.insert(height, block_bytes);
    }

    // Update current height
    state_guard.height = start_height + num_blocks - 1;

    Ok(())
}

/// Create a test transaction with DIESEL minting
pub fn create_test_diesel_transaction(
    input_txid: &str,
    input_vout: u32,
    output_address: &str,
    amount: u64,
) -> Result<Transaction> {
    let txid = Txid::from_str(input_txid)
        .map_err(|e| anyhow!("Invalid txid: {}", e))?;

    let builder = TestBlockBuilder::new(0);
    builder.create_diesel_mint_transaction(txid, input_vout, output_address, amount)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{init_test_state, TestConfig};

    #[test]
    fn test_create_simple_block() {
        let block = create_simple_test_block(840000).unwrap();
        assert_eq!(block.txdata.len(), 1); // Just coinbase
        assert!(block.txdata[0].is_coinbase());
    }

    #[test]
    fn test_create_diesel_mint_block() {
        let input_txid = Txid::from_str("0000000000000000000000000000000000000000000000000000000000000001").unwrap();
        let block = create_diesel_mint_block(
            840001,
            input_txid,
            0,
            "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080",
            100000000,
        ).unwrap();
        
        assert_eq!(block.txdata.len(), 2); // Coinbase + DIESEL mint
        assert!(block.txdata[0].is_coinbase());
        assert!(!block.txdata[1].is_coinbase());
        
        // Check DIESEL transaction has OP_RETURN output
        let diesel_tx = &block.txdata[1];
        assert_eq!(diesel_tx.output.len(), 3); // Main output + OP_RETURN + dust
        assert_eq!(diesel_tx.output[1].value, Amount::from_sat(0)); // OP_RETURN has 0 value
    }

    #[test]
    fn test_setup_test_blockchain() {
        let _state = init_test_state(TestConfig::default()).unwrap();
        setup_test_blockchain(840000, 5).unwrap();
        
        let state = get_test_state().unwrap();
        let state_guard = state.lock().unwrap();
        assert_eq!(state_guard.height, 840004);
        assert_eq!(state_guard.blocks.len(), 5);
    }
}