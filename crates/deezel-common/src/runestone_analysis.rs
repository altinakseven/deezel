//! Comprehensive Transaction and Runestone Analysis
//!
//! This module provides functions to perform a detailed analysis of a Bitcoin
//! transaction, extracting information about its inputs, outputs, and any
//! embedded protostones or runestones. It also includes a pretty-printer
//! to format the analysis into a human-readable string, consistent with
//! the reference implementation's output.

use crate::alkanes::analyze::analyze_runestone;
use crate::Result;
use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};
use bitcoin::{Address, Network, Script, Transaction};
use serde_json::{json, Value as JsonValue};

/// Analyzes a transaction and any embedded runestone, producing a detailed JSON object.
///
/// This function inspects the transaction's inputs, outputs, and decodes any
/// protostone data found in an OP_RETURN output. The structure of the returned
/// JSON value is designed to match the output of the `--raw` flag from the
/// reference implementation.
///
/// # Arguments
///
/// * `tx` - A reference to the `bitcoin::Transaction` to be analyzed.
/// * `network` - The `bitcoin::Network` context (e.g., Mainnet, Testnet) for address generation.
///
/// # Returns
///
/// A `Result` containing a `serde_json::Value` with the detailed analysis.
pub fn analyze_transaction_with_runestone(
    tx: &Transaction,
    network: Network,
) -> Result<JsonValue> {
    let txid = tx.compute_txid();

    // Analyze inputs
    let inputs: Vec<JsonValue> = tx
        .input
        .iter()
        .enumerate()
        .map(|(i, tx_in)| {
            json!({
                "index": i,
                "previous_output": {
                    "txid": tx_in.previous_output.txid.to_string(),
                    "vout": tx_in.previous_output.vout,
                },
                "script_sig_size": tx_in.script_sig.len(),
                "sequence": tx_in.sequence.0,
                "witness_items": tx_in.witness.len(),
            })
        })
        .collect();

    // Analyze outputs
    let outputs: Vec<JsonValue> = tx
        .output
        .iter()
        .enumerate()
        .map(|(i, tx_out)| {
            let mut output_json = serde_json::Map::new();
            output_json.insert("index".to_string(), json!(i));
            output_json.insert("value".to_string(), json!(tx_out.value.to_sat()));
            output_json.insert(
                "script_pubkey_size".to_string(),
                json!(tx_out.script_pubkey.len()),
            );

            if tx_out.script_pubkey.is_op_return() {
                output_json.insert("script_type".to_string(), json!("OP_RETURN"));
                if let Some(op_return_data) = tx_out.script_pubkey.as_bytes().get(2..) {
                    output_json.insert(
                        "op_return_data".to_string(),
                        json!(hex::encode(op_return_data)),
                    );
                    output_json.insert("op_return_size".to_string(), json!(op_return_data.len()));
                }
            } else {
                let script_type = get_script_type(&tx_out.script_pubkey);
                output_json.insert("script_type".to_string(), json!(script_type));
                if let Ok(address) = Address::from_script(&tx_out.script_pubkey, network) {
                    output_json.insert("address".to_string(), json!(address.to_string()));
                }
            }
            JsonValue::Object(output_json)
        })
        .collect();

    // Analyze protostones/runestones
    let protostones = match analyze_runestone(tx) {
        Ok(runestone_analysis) => {
            // The `analyze_runestone` function returns a JSON object.
            // We need to check if it represents a valid runestone or protostone.
            // The reference output shows a "protostones" array.
            if let Some(_edicts) = runestone_analysis.get("edicts") {
                 vec![runestone_analysis]
            } else {
                vec![]
            }
        }
        Err(_) => vec![],
    };

    // Assemble the final JSON object
    let result = json!({
        "transaction_id": txid.to_string(),
        "version": tx.version,
        "lock_time": tx.lock_time.to_consensus_u32(),
        "input_count": tx.input.len(),
        "output_count": tx.output.len(),
        "inputs": inputs,
        "outputs": outputs,
        "protostones": protostones,
    });

    Ok(result)
}

/// Formats the detailed transaction analysis into a human-readable string.
///
/// This function takes the JSON object produced by `analyze_transaction_with_runestone`
/// and formats it with headers, emojis, and structured sections for readability.
///
/// # Arguments
///
/// * `analysis` - A `serde_json::Value` containing the detailed transaction analysis.
///
/// # Returns
///
/// A `Result` containing the formatted `String`.
pub fn pretty_print_transaction_analysis(analysis: &JsonValue) -> Result<String> {
    let mut output = String::new();

    output.push_str("🔍 Transaction Analysis\n");
    output.push_str("═══════════════════════\n");

    if let Some(txid) = analysis.get("transaction_id").and_then(|v| v.as_str()) {
        output.push_str(&format!("📋 Transaction ID: {}\n", txid));
    }
    if let Some(version) = analysis.get("version").and_then(|v| v.as_i64()) {
        output.push_str(&format!("🔢 Version: {}\n", version));
    }
    if let Some(lock_time) = analysis.get("lock_time").and_then(|v| v.as_u64()) {
        output.push_str(&format!("🔒 Lock Time: {}\n", lock_time));
    }

    // Inputs
    if let Some(inputs) = analysis.get("inputs").and_then(|v| v.as_array()) {
        output.push_str(&format!("\n📥 Inputs ({}):\n", inputs.len()));
        for (i, input) in inputs.iter().enumerate() {
            let txid = input["previous_output"]["txid"].as_str().unwrap_or("?");
            let vout = input["previous_output"]["vout"].as_u64().unwrap_or(0);
            let witness_items = input["witness_items"].as_u64().unwrap_or(0);
            output.push_str(&format!("  {}. 🔗 {}:{}\n", i + 1, txid, vout));
            output.push_str(&format!("     📝 Witness: {} items\n", witness_items));
        }
    }

    // Outputs
    if let Some(outputs) = analysis.get("outputs").and_then(|v| v.as_array()) {
        output.push_str(&format!("\n📤 Outputs ({}):\n", outputs.len()));
        for output_value in outputs {
            let index = output_value["index"].as_u64().unwrap_or(0);
            let value_sat = output_value["value"].as_u64().unwrap_or(0);
            let value_btc = value_sat as f64 / 100_000_000.0;
            let script_type = output_value["script_type"].as_str().unwrap_or("?");

            output.push_str(&format!("  {}. 💰 {:.8} BTC ({} sats)\n", index, value_btc, value_sat));

            if script_type == "OP_RETURN" {
                let data_len = output_value["op_return_size"].as_u64().unwrap_or(0);
                let data_hex = output_value["op_return_data"].as_str().unwrap_or("");
                output.push_str(&format!("     📜 OP_RETURN script ({} bytes)\n", data_len));
                output.push_str(&format!("     📄 Data: {}\n", data_hex));
            } else {
                let address = output_value["address"].as_str().unwrap_or("?");
                output.push_str(&format!("     🏠 {}: {}\n", script_type, address));
            }
        }
    }

    // Protostones
    if let Some(protostones) = analysis.get("protostones").and_then(|v| v.as_array()) {
        if !protostones.is_empty() {
            output.push_str(&format!("\n🪨 Protostones Found: {}\n", protostones.len()));
            output.push_str("═══════════════════════\n");

            for (i, stone) in protostones.iter().enumerate() {
                output.push_str(&format!("\n🪨 Protostone #{}\n", i + 1));
                output.push_str("───────────────────\n");

                // This part needs to be adapted based on the actual structure
                // of the protostone JSON from `analyze_runestone`.
                // For now, we'll just pretty-print the JSON.
                let pretty_stone = serde_json::to_string_pretty(stone)?;
                output.push_str(&pretty_stone);
                output.push_str("\n");
            }
        }
    }

    output.push_str("\n✅ Analysis complete!\n");

    Ok(output)
}

/// Helper to determine the script type string from a script pubkey.
fn get_script_type(script: &Script) -> &str {
    if script.is_p2pk() {
        "P2PK"
    } else if script.is_p2pkh() {
        "P2PKH"
    } else if script.is_p2sh() {
        "P2SH"
    } else if script.is_p2wpkh() {
        "P2WPKH"
    } else if script.is_p2wsh() {
        "P2WSH"
    } else if script.is_p2tr() {
        "P2TR"
    } else if script.is_op_return() {
        "OP_RETURN"
    } else {
        "Non-standard"
    }
}
