//! # Deezel Bitcoind Provider
//!
//! This module provides an implementation of the `BitcoindProvider` trait,
//! which offers a comprehensive interface to a Bitcoin Core node's JSON-RPC API.
//! It uses the `bitcoincore-rpc` crate for data structures and leverages the
//! existing `JsonRpcProvider` for the actual RPC calls.

use crate::{
    traits::{BitcoindProvider, JsonRpcProvider},
    Result,
};
use async_trait::async_trait;
use bitcoin::{
    consensus::deserialize,
    Block, BlockHash, Txid,
};
use bitcoincore_rpc_json::{
    GetBlockHeaderResult, GetBlockResult, GetBlockStatsResult, GetBlockchainInfoResult,
    GetChainTipsResult, GetMempoolInfoResult, GetNetworkInfoResult, GetRawTransactionResult,
    GetTxOutResult,
};
use serde_json::json;

#[async_trait(?Send)]
impl<T: JsonRpcProvider> BitcoindProvider for T {
    async fn get_blockchain_info(&self) -> Result<GetBlockchainInfoResult> {
        let result = self.call("", "getblockchaininfo", json!([]), 1).await?;
        let info: GetBlockchainInfoResult = serde_json::from_value(result)?;
        Ok(info)
    }

    async fn get_network_info(&self) -> Result<GetNetworkInfoResult> {
        let result = self.call("", "getnetworkinfo", json!([]), 1).await?;
        let info: GetNetworkInfoResult = serde_json::from_value(result)?;
        Ok(info)
    }

    async fn get_raw_transaction(
        &self,
        txid: &Txid,
        block_hash: Option<&BlockHash>,
    ) -> Result<bitcoin::Transaction> {
        let params = json!([txid, false, block_hash]);
        let result = self.call("", "getrawtransaction", params, 1).await?;
        let hex: String = serde_json::from_value(result)?;
        let bytes = hex::decode(hex)?;
        Ok(deserialize(&bytes)?)
    }

    async fn get_raw_transaction_info(
        &self,
        txid: &Txid,
        block_hash: Option<&BlockHash>,
    ) -> Result<GetRawTransactionResult> {
        let params = json!([txid, true, block_hash]);
        let result = self.call("", "getrawtransaction", params, 1).await?;
        let info: GetRawTransactionResult = serde_json::from_value(result)?;
        Ok(info)
    }

    async fn get_block(&self, hash: &BlockHash) -> Result<Block> {
        let params = json!([hash, 0]);
        let result = self.call("", "getblock", params, 1).await?;
        let hex: String = serde_json::from_value(result)?;
        let bytes = hex::decode(hex)?;
        Ok(deserialize(&bytes)?)
    }

    async fn get_block_info(&self, hash: &BlockHash) -> Result<GetBlockResult> {
        let params = json!([hash, 1]);
        let result = self.call("", "getblock", params, 1).await?;
        let info: GetBlockResult = serde_json::from_value(result)?;
        Ok(info)
    }

    async fn get_block_hash(&self, height: u64) -> Result<BlockHash> {
        let params = json!([height]);
        let result = self.call("", "getblockhash", params, 1).await?;
        let hash: BlockHash = serde_json::from_value(result)?;
        Ok(hash)
    }

    async fn get_block_header(&self, hash: &BlockHash) -> Result<bitcoin::block::Header> {
        let params = json!([hash, false]);
        let result = self.call("", "getblockheader", params, 1).await?;
        let hex: String = serde_json::from_value(result)?;
        let bytes = hex::decode(hex)?;
        Ok(deserialize(&bytes)?)
    }

    async fn get_block_header_info(&self, hash: &BlockHash) -> Result<GetBlockHeaderResult> {
        let params = json!([hash, true]);
        let result = self.call("", "getblockheader", params, 1).await?;
        let info: GetBlockHeaderResult = serde_json::from_value(result)?;
        Ok(info)
    }

    async fn get_block_stats(&self, hash: &BlockHash) -> Result<GetBlockStatsResult> {
        let params = json!([hash]);
        let result = self.call("", "getblockstats", params, 1).await?;
        let info: GetBlockStatsResult = serde_json::from_value(result)?;
        Ok(info)
    }

    async fn get_chain_tips(&self) -> Result<GetChainTipsResult> {
        let result = self.call("", "getchaintips", json!([]), 1).await?;
        let info: GetChainTipsResult = serde_json::from_value(result)?;
        Ok(info)
    }

    async fn get_mempool_info(&self) -> Result<GetMempoolInfoResult> {
        let result = self.call("", "getmempoolinfo", json!([]), 1).await?;
        let info: GetMempoolInfoResult = serde_json::from_value(result)?;
        Ok(info)
    }

    async fn get_raw_mempool(&self) -> Result<Vec<Txid>> {
        let result = self.call("", "getrawmempool", json!([false]), 1).await?;
        let info: Vec<Txid> = serde_json::from_value(result)?;
        Ok(info)
    }

    async fn get_tx_out(
        &self,
        txid: &Txid,
        vout: u32,
        include_mempool: bool,
    ) -> Result<Option<GetTxOutResult>> {
        let params = json!([txid, vout, include_mempool]);
        let result = self.call("", "gettxout", params, 1).await?;
        let info: Option<GetTxOutResult> = serde_json::from_value(result)?;
        Ok(info)
    }

    async fn send_raw_transaction(&self, tx: &bitcoin::Transaction) -> Result<Txid> {
        let tx_hex = bitcoin::consensus::encode::serialize_hex(tx);
        let params = json!([tx_hex]);
        let result = self.call("", "sendrawtransaction", params, 1).await?;
        let txid: Txid = serde_json::from_value(result)?;
        Ok(txid)
    }

    async fn get_block_count(&self) -> Result<u64> {
        let result = self.call("", "getblockcount", json!([]), 1).await?;
        let count: u64 = serde_json::from_value(result)?;
        Ok(count)
    }

    async fn generate_to_address(
        &self,
        nblocks: u32,
        address: &str,
    ) -> Result<serde_json::Value> {
        let params = json!([nblocks, address]);
        let result = self.call("", "generatetoaddress", params, 1).await?;
        Ok(result)
    }
}