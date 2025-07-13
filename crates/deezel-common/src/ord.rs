// Copyright (c) 2023-2024 Deezel Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//
//
// Chadson's Documentation of ord.rs:
//
// Purpose:
// This file defines the data structures that represent the JSON responses from the `ord` server API.
// These structs are used to deserialize the JSON responses into strongly-typed Rust objects,
// which can then be used for processing, and pretty-printing in the `deezel` CLI.
//
// The structs defined here are based on the `api.rs` file from the `ord` reference implementation.
//
// Key Structs:
// - `Block`: Represents a Bitcoin block, including its hash, height, and associated inscriptions and runes.
// - `Inscription`: Represents an Ordinal inscription, including its ID, content type, and other metadata.
// - `Rune`: Represents a Rune, a fungible token on Bitcoin.
// - `Output`: Represents a transaction output (UTXO), including its value, script pubkey, and any associated inscriptions or runes.
// - `Sat`: Represents a single satoshi, including its rarity, charms, and associated inscriptions.
//
// Implementation Notes:
// - All structs derive `serde::{Deserialize, Serialize}` to allow for deserialization from JSON and serialization for the `--raw` flag.
// - Other common traits like `Debug`, `PartialEq`, and `Clone` are also derived for convenience.
// - This module uses types from the `ordinals` and `bitcoin` crates, which are dependencies of `deezel-common`.
// - Some types like `SpacedRune`, `Pile`, and `Charm` are defined locally as they are not available in the `ordinals` crate version used, or to avoid pulling in too many dependencies.
//
//

use bitcoin::{
    block::Header as BlockHeader, BlockHash, OutPoint,
    ScriptBuf, TxMerkleNode, Txid,
};
use ord::InscriptionId;
use ordinals::{Rarity, Rune, Sat, SatPoint};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt::{self, Display, Formatter};
#[cfg(feature = "native-deps")]
use tabled::Tabled;

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct Block {
    pub hash: BlockHash,
    pub header: BlockHeader,
    pub info: Option<BlockInfo>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "native-deps", derive(Tabled))]
pub struct BlockInfo {
    pub hash: BlockHash,
    pub confirmations: i32,
    pub height: i32,
    pub version: i32,
    #[serde(rename = "versionHex")]
    pub version_hex: String,
    #[serde(rename = "merkleroot")]
    pub merkle_root: TxMerkleNode,
    pub time: u32,
    #[serde(rename = "mediantime")]
    pub median_time: u32,
    pub nonce: u32,
    pub bits: String,
    pub difficulty: f64,
    #[serde(rename = "chainwork")]
    pub chain_work: String,
    #[serde(rename = "nTx")]
    pub n_tx: u32,
    #[serde(rename = "previousblockhash")]
    #[cfg_attr(feature = "native-deps", tabled(display_with = "display_option"))]
    pub previous_block_hash: Option<BlockHash>,
    #[serde(rename = "nextblockhash")]
    #[cfg_attr(feature = "native-deps", tabled(display_with = "display_option"))]
    pub next_block_hash: Option<BlockHash>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct Blocks {
    pub last: u64,
    pub blocks: Vec<BlockHash>,
    pub featured_blocks: BTreeMap<BlockHash, Vec<InscriptionId>>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct Children {
    pub ids: Vec<InscriptionId>,
    pub more: bool,
    pub page: usize,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct ChildInscriptions {
    pub children: Vec<RelativeInscriptionRecursive>,
    pub more: bool,
    pub page: usize,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct ParentInscriptions {
    pub parents: Vec<RelativeInscriptionRecursive>,
    pub more: bool,
    pub page: usize,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "native-deps", derive(Tabled))]
pub struct Inscription {
    #[cfg_attr(feature = "native-deps", tabled(display_with = "display_option"))]
    pub address: Option<String>,
    #[cfg_attr(feature = "native-deps", tabled(display_with = "display_vec"))]
    pub charms: Vec<Charm>,
    pub child_count: u64,
    #[cfg_attr(feature = "native-deps", tabled(skip))]
    pub children: Vec<InscriptionId>,
    #[cfg_attr(feature = "native-deps", tabled(display_with = "display_option"))]
    pub content_length: Option<usize>,
    #[cfg_attr(feature = "native-deps", tabled(display_with = "display_option"))]
    pub content_type: Option<String>,
    #[cfg_attr(feature = "native-deps", tabled(display_with = "display_option"))]
    pub effective_content_type: Option<String>,
    pub fee: u64,
    pub height: u32,
    pub id: InscriptionId,
    #[cfg_attr(feature = "native-deps", tabled(display_with = "display_option"))]
    pub next: Option<InscriptionId>,
    pub number: i32,
    #[cfg_attr(feature = "native-deps", tabled(skip))]
    pub parents: Vec<InscriptionId>,
    #[cfg_attr(feature = "native-deps", tabled(display_with = "display_option"))]
    pub previous: Option<InscriptionId>,
    #[cfg_attr(feature = "native-deps", tabled(display_with = "display_option"))]
    pub rune: Option<SpacedRune>,
    #[cfg_attr(feature = "native-deps", tabled(display_with = "display_option"))]
    pub sat: Option<Sat>,
    pub satpoint: SatPoint,
    pub timestamp: i64,
    #[cfg_attr(feature = "native-deps", tabled(display_with = "display_option"))]
    pub value: Option<u64>,
    #[cfg_attr(feature = "native-deps", tabled(display_with = "display_option"))]
    pub metaprotocol: Option<String>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct InscriptionRecursive {
    pub charms: Vec<Charm>,
    pub content_type: Option<String>,
    pub content_length: Option<usize>,
    pub delegate: Option<InscriptionId>,
    pub fee: u64,
    pub height: u32,
    pub id: InscriptionId,
    pub number: i32,
    pub output: OutPoint,
    pub sat: Option<Sat>,
    pub satpoint: SatPoint,
    pub timestamp: i64,
    pub value: Option<u64>,
    pub address: Option<String>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "native-deps", derive(Tabled))]
pub struct RelativeInscriptionRecursive {
    #[cfg_attr(feature = "native-deps", tabled(display_with = "display_vec"))]
    pub charms: Vec<Charm>,
    pub fee: u64,
    pub height: u32,
    pub id: InscriptionId,
    pub number: i32,
    pub output: OutPoint,
    #[cfg_attr(feature = "native-deps", tabled(display_with = "display_option"))]
    pub sat: Option<Sat>,
    pub satpoint: SatPoint,
    pub timestamp: i64,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct Inscriptions {
    pub ids: Vec<InscriptionId>,
    pub more: bool,
    pub page_index: u32,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct UtxoRecursive {
    pub inscriptions: Option<Vec<InscriptionId>>,
    pub runes: Option<BTreeMap<SpacedRune, Pile>>,
    pub sat_ranges: Option<Vec<(u64, u64)>>,
    pub value: u64,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "native-deps", derive(Tabled))]
pub struct Output {
    #[cfg_attr(feature = "native-deps", tabled(display_with = "display_option"))]
    pub address: Option<String>,
    pub confirmations: u32,
    pub indexed: bool,
    #[cfg_attr(feature = "native-deps", tabled(display_with = "display_option_vec"))]
    pub inscriptions: Option<Vec<InscriptionId>>,
    pub outpoint: OutPoint,
    #[cfg_attr(feature = "native-deps", tabled(skip))]
    pub runes: Option<BTreeMap<SpacedRune, Pile>>,
    #[cfg_attr(feature = "native-deps", tabled(skip))]
    pub sat_ranges: Option<Vec<(u64, u64)>>,
    pub script_pubkey: ScriptBuf,
    pub spent: bool,
    pub transaction: Txid,
    pub value: u64,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "native-deps", derive(Tabled))]
pub struct SatResponse {
    #[cfg_attr(feature = "native-deps", tabled(display_with = "display_option"))]
    pub address: Option<String>,
    pub block: u32,
    #[cfg_attr(feature = "native-deps", tabled(display_with = "display_vec"))]
    pub charms: Vec<Charm>,
    pub cycle: u32,
    pub decimal: String,
    pub degree: String,
    pub epoch: u32,
    #[cfg_attr(feature = "native-deps", tabled(display_with = "display_vec"))]
    pub inscriptions: Vec<InscriptionId>,
    pub name: String,
    pub number: u64,
    pub offset: u64,
    pub percentile: String,
    pub period: u32,
    pub rarity: Rarity,
    #[cfg_attr(feature = "native-deps", tabled(display_with = "display_option"))]
    pub satpoint: Option<SatPoint>,
    pub timestamp: i64,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct SatInscription {
    pub id: Option<InscriptionId>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct SatInscriptions {
    pub ids: Vec<InscriptionId>,
    pub more: bool,
    pub page: u64,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "native-deps", derive(Tabled))]
pub struct AddressInfo {
    #[cfg_attr(feature = "native-deps", tabled(display_with = "display_vec"))]
    pub outputs: Vec<OutPoint>,
    #[cfg_attr(feature = "native-deps", tabled(display_with = "display_option_vec"))]
    pub inscriptions: Option<Vec<InscriptionId>>,
    pub sat_balance: u64,
    #[cfg_attr(feature = "native-deps", tabled(skip))]
    pub runes_balances: Option<Vec<(SpacedRune, String, Option<char>)>>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "native-deps", derive(Tabled))]
pub struct RuneInfo {
    pub burned: String,
    pub divisibility: u8,
    pub etching: Txid,
    pub height: u32,
    pub id: String,
    pub index: u64,
    pub mints: String,
    pub number: u64,
    pub rune: SpacedRune,
    pub supply: String,
    #[cfg_attr(feature = "native-deps", tabled(display_with = "display_option"))]
    pub symbol: Option<char>,
    pub timestamp: i64,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct Runes {
    pub runes: BTreeMap<String, RuneInfo>,
    pub next_page_number: Option<u32>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "native-deps", derive(Tabled))]
pub struct TxInfo {
    pub chain: String,
    #[cfg_attr(feature = "native-deps", tabled(display_with = "display_option"))]
    pub etching: Option<SpacedRune>,
    #[cfg_attr(feature = "native-deps", tabled(display_with = "display_vec"))]
    pub inscriptions: Vec<InscriptionId>,
    #[cfg_attr(feature = "native-deps", tabled(skip))]
    pub transaction: bitcoin::Transaction,
    pub txid: Txid,
}

impl Display for Charm {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(
    Copy, Clone, Debug, PartialEq, Eq, Ord, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum Charm {
    Coin,
    Cursed,
    Epic,
    Legendary,
    Lost,
    Nineball,
    Rare,
    Reinscription,
    Unbound,
    Uncommon,
    Vindicated,
    Mythic,
    Burned,
    Palindrome,
}

#[derive(
    Copy, Clone, Debug, PartialEq, Ord, PartialOrd, Eq, Default, Serialize, Deserialize,
)]
pub struct SpacedRune {
    pub rune: Rune,
    pub spacers: u32,
}

impl Display for SpacedRune {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let rune = self.rune.to_string();
        for (i, c) in rune.chars().enumerate() {
            write!(f, "{c}")?;
            if i < rune.len() - 1 && self.spacers & (1 << i) != 0 {
                write!(f, "•")?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Clone, Copy)]
pub struct Pile {
    pub amount: u128,
    pub divisibility: u8,
    pub symbol: Option<char>,
}

#[cfg(feature = "native-deps")]
fn display_option<T: Display>(option: &Option<T>) -> String {
    match option {
        Some(value) => value.to_string(),
        None => String::new(),
    }
}

#[cfg(feature = "native-deps")]
fn display_vec<T: Display>(vec: &Vec<T>) -> String {
    vec.iter()
        .map(|item| item.to_string())
        .collect::<Vec<String>>()
        .join(", ")
}

#[cfg(feature = "native-deps")]
fn display_option_vec<T: Display>(option: &Option<Vec<T>>) -> String {
    match option {
        Some(vec) => display_vec(vec),
        None => String::new(),
    }
}

