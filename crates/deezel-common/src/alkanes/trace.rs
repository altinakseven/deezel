// This file is part of the deezel project.
// Copyright (c) 2023, Casey Rodarmor, all rights reserved.
// Copyright (c) 2024, The Deezel Developers, all rights reserved.
// Deezel is licensed under the MIT license.
// See LICENSE file in the project root for full license information.

//! This module defines the structures for representing and displaying alkanes transaction traces.
//! It provides a native Rust representation of the trace data returned by the indexer,
//! along with implementations for serialization, deserialization, and pretty-printing.

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
#[cfg(not(feature = "std"))]
use alloc::{vec::Vec, string::{String, ToString}, format};
#[cfg(feature = "std")]
use std::vec::Vec;
use core::fmt;

/// Represents a complete execution trace of a transaction, containing multiple calls.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Trace {
    #[serde(rename = "trace")]
    pub calls: Vec<Call>,
}

/// Represents a single call within a transaction trace.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Call {
    #[serde(with = "hex_serde")]
    pub caller: Vec<u8>,
    #[serde(rename = "id")]
    pub contract_id: Option<ContractId>,
    #[serde(rename = "inputData", with = "hex_serde")]
    pub input_data: Vec<u8>,
    #[serde(rename = "value")]
    pub value: Option<U128>,
    pub events: Vec<Event>,
}

/// Represents a contract identifier (block and transaction index).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ContractId {
    pub block: Option<U64>,
    pub tx: Option<U64>,
}

/// Represents an event emitted during a call.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Event {
    #[serde(with = "hex_serde")]
    pub data: Vec<u8>,
}

/// Represents a 64-bit unsigned integer, used for block and tx numbers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct U64 {
    pub lo: u64,
}

/// Represents a 128-bit unsigned integer, used for token values.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct U128 {
    pub lo: u64,
    pub hi: u64,
}

impl fmt::Display for Trace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Trace:")?;
        for (i, call) in self.calls.iter().enumerate() {
            writeln!(f, "  Call {}:", i)?;
            writeln!(f, "    Caller: {}", hex::encode(&call.caller))?;
            if let Some(id) = &call.contract_id {
                writeln!(f, "    Contract: {}:{}", id.block.as_ref().map_or(0, |b| b.lo), id.tx.as_ref().map_or(0, |t| t.lo))?;
            }
            writeln!(f, "    Input Data: {}", hex::encode(&call.input_data))?;
            if let Some(value) = &call.value {
                 writeln!(f, "    Value: {}", value.lo)?;
            }
            writeln!(f, "    Events:")?;
            for (j, event) in call.events.iter().enumerate() {
                writeln!(f, "      Event {}:", j)?;
                writeln!(f, "        Data: {}", hex::encode(&event.data))?;
            }
        }
        Ok(())
    }
}

/// Converts a Trace object to a raw JSON value.
pub fn to_raw_json(trace: &Trace) -> JsonValue {
    serde_json::to_value(trace).unwrap_or_else(|_| serde_json::json!({ "error": "Failed to serialize trace" }))
}

mod hex_serde {
    use serde::{Serializer, Deserializer, de::Error, Deserialize};
    #[cfg(not(feature = "std"))]
    use alloc::{string::String, vec::Vec};
    #[cfg(feature = "std")]
    use std::{string::String, vec::Vec};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        hex::decode(s).map_err(Error::custom)
    }
}