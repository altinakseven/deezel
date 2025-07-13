//! # Bitcoind System Implementation
//!
//! This module implements the `SystemBitcoind` trait, providing handlers for
//! the `bitcoind` subcommands. It uses the underlying `BitcoindProvider` to
//! interact with the Bitcoin Core RPC.

use async_trait::async_trait;
use bitcoin::address::NetworkUnchecked;
use deezel_common::{
    bitcoind::*,
    commands::BitcoindCommands,
    traits::{BitcoindProvider, SystemBitcoind, WalletProvider},
    Result, Address,
};
use crate::SystemDeezel;

#[async_trait(?Send)]
impl SystemBitcoind for SystemDeezel {
    async fn execute_bitcoind_command(&self, command: BitcoindCommands) -> Result<()> {
        match command {
            BitcoindCommands::GetBlockchainInfo => {
                let info = self.provider.get_blockchain_info().await?;
                println!("{:#?}", info);
            }
            BitcoindCommands::GetBlockCount => {
                let count = self.provider.get_block_count().await?;
                println!("{}", count);
            }
            BitcoindCommands::GetBlockHash { height } => {
                let hash = self.provider.get_block_hash(height).await?;
                println!("{}", hash);
            }
            BitcoindCommands::GetBlockHeader { hash } => {
                let block_hash = hash.parse()?;
                let header = self.provider.get_block_header(&block_hash).await?;
                println!("{:#?}", header);
            }
            BitcoindCommands::GetBlockVerbose { hash } => {
                let block_hash = hash.parse()?;
                let block = self.provider.get_block_verbose(&block_hash).await?;
                println!("{:#?}", block);
            }
            BitcoindCommands::GetBlockTxids { hash } => {
                let block_hash = hash.parse()?;
                let txids = self.provider.get_block_txids(&block_hash).await?;
                println!("{:#?}", txids);
            }
            BitcoindCommands::GetBlockFilter { hash } => {
                let block_hash = hash.parse()?;
                let filter = self.provider.get_block_filter(&block_hash).await?;
                println!("{:#?}", filter);
            }
            BitcoindCommands::GetBlockStats { height } => {
                let stats = self.provider.get_block_stats(height).await?;
                println!("{:#?}", stats);
            }
            BitcoindCommands::GetChainTips => {
                let tips = self.provider.get_chain_tips().await?;
                println!("{:#?}", tips);
            }
            BitcoindCommands::GetChainTxStats {
                n_blocks,
                block_hash,
            } => {
                let b_hash = block_hash.map(|s| s.parse()).transpose()?;
                let stats = self
                    .provider
                    .get_chain_tx_stats(n_blocks, b_hash)
                    .await?;
                println!("{:#?}", stats);
            }
            BitcoindCommands::GetMempoolInfo => {
                let info = self.provider.get_mempool_info().await?;
                println!("{:#?}", info);
            }
            BitcoindCommands::GetRawMempool => {
                let mempool = self.provider.get_raw_mempool().await?;
                println!("{:#?}", mempool);
            }
            BitcoindCommands::GetTxOut {
                txid,
                vout,
                include_mempool,
            } => {
                let txid = txid.parse()?;
                let tx_out = self
                    .provider
                    .get_tx_out(&txid, vout, Some(include_mempool))
                    .await?;
                println!("{:#?}", tx_out);
            }
            BitcoindCommands::GetMiningInfo => {
                let info = self.provider.get_mining_info().await?;
                println!("{:#?}", info);
            }
            BitcoindCommands::GetNetworkInfo => {
                let info = self.provider.get_network_info().await?;
                println!("{:#?}", info);
            }
            BitcoindCommands::ListBanned => {
                let banned = self.provider.list_banned().await?;
                println!("{:#?}", banned);
            }
            BitcoindCommands::ScanTxOutSet { requests } => {
                let reqs: Vec<ScanTxOutRequest> = requests
                    .iter()
                    .map(|s| {
                        // Assuming the string format is "descriptor"
                        ScanTxOutRequest::Single(s.to_string())
                    })
                    .collect();
                let result = self.provider.scan_tx_out_set(&reqs).await?;
                println!("{:#?}", result);
            }
            BitcoindCommands::GenerateToAddress { n_blocks, address } => {
                let addr: Address<NetworkUnchecked> = address.parse()?;
                let addr = addr.require_network(self.provider.get_network())?;
                let block_hashes = self.provider.generate_to_address(n_blocks, &addr).await?;
                println!("Generated {} blocks:", block_hashes.len());
                for hash in block_hashes {
                    println!("  {}", hash);
                }
            }
            BitcoindCommands::SendRawTransaction { tx_hex } => {
                let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&hex::decode(tx_hex)?)?;
                let txid = self.provider.send_raw_transaction(&tx).await?;
                println!("Transaction sent: {}", txid);
            }
        }
        Ok(())
    }
}