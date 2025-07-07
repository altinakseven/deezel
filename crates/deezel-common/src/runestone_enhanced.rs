//! Enhanced runestone formatting and analysis
//!
//! This module provides enhanced formatting capabilities for runestone analysis
//! with emoji styling and detailed output formatting.

use crate::Result;
use serde_json::Value as JsonValue;

/// Format runestone with enhanced styling
pub fn format_runestone_with_decoded_messages(runestone_data: &JsonValue) -> Result<String> {
    format_runestone_enhanced(runestone_data)
}

/// Print human readable runestone (alias for compatibility)
pub fn print_human_readable_runestone(runestone_data: &JsonValue) -> Result<String> {
    format_runestone_enhanced(runestone_data)
}

/// Format runestone with enhanced styling (internal implementation)
fn format_runestone_enhanced(runestone_data: &JsonValue) -> Result<String> {
    let mut output = String::new();
    
    output.push_str("🪨 Enhanced Runestone Analysis\n");
    output.push_str("═══════════════════════════════\n\n");
    
    if let Some(etching) = runestone_data.get("etching") {
        output.push_str("🎯 Etching Details:\n");
        
        if let Some(rune) = etching.get("rune").and_then(|v| v.as_str()) {
            output.push_str(&format!("  📛 Rune Name: {}\n", rune));
        }
        
        if let Some(divisibility) = etching.get("divisibility").and_then(|v| v.as_u64()) {
            output.push_str(&format!("  🔢 Divisibility: {}\n", divisibility));
        }
        
        if let Some(premine) = etching.get("premine").and_then(|v| v.as_u64()) {
            output.push_str(&format!("  ⛏️  Premine: {}\n", premine));
        }
        
        if let Some(symbol) = etching.get("symbol").and_then(|v| v.as_str()) {
            output.push_str(&format!("  🔤 Symbol: {}\n", symbol));
        }
        
        if let Some(terms) = etching.get("terms") {
            output.push_str("  📋 Minting Terms:\n");
            
            if let Some(amount) = terms.get("amount").and_then(|v| v.as_u64()) {
                output.push_str(&format!("    💰 Amount per mint: {}\n", amount));
            }
            
            if let Some(cap) = terms.get("cap").and_then(|v| v.as_u64()) {
                output.push_str(&format!("    🧢 Total cap: {}\n", cap));
            }
            
            if let Some(height) = terms.get("height") {
                if let (Some(start), Some(end)) = (
                    height.get("start").and_then(|v| v.as_u64()),
                    height.get("end").and_then(|v| v.as_u64())
                ) {
                    output.push_str(&format!("    📏 Height range: {} - {}\n", start, end));
                }
            }
            
            if let Some(offset) = terms.get("offset") {
                if let (Some(start), Some(end)) = (
                    offset.get("start").and_then(|v| v.as_u64()),
                    offset.get("end").and_then(|v| v.as_u64())
                ) {
                    output.push_str(&format!("    📍 Offset range: {} - {}\n", start, end));
                }
            }
        }
        
        output.push('\n');
    }
    
    if let Some(edicts) = runestone_data.get("edicts").and_then(|v| v.as_array()) {
        if !edicts.is_empty() {
            output.push_str("📜 Transfer Edicts:\n");
            
            for (i, edict) in edicts.iter().enumerate() {
                output.push_str(&format!("  {}. ", i + 1));
                
                if let Some(id) = edict.get("id").and_then(|v| v.as_str()) {
                    output.push_str(&format!("ID: {} ", id));
                }
                
                if let Some(amount) = edict.get("amount").and_then(|v| v.as_u64()) {
                    output.push_str(&format!("Amount: {} ", amount));
                }
                
                if let Some(output_idx) = edict.get("output").and_then(|v| v.as_u64()) {
                    output.push_str(&format!("→ Output: {}", output_idx));
                }
                
                output.push('\n');
            }
            
            output.push('\n');
        }
    }
    
    if let Some(mint) = runestone_data.get("mint").and_then(|v| v.as_str()) {
        output.push_str(&format!("🏭 Mint Operation: {}\n\n", mint));
    }
    
    if let Some(pointer) = runestone_data.get("pointer").and_then(|v| v.as_u64()) {
        output.push_str(&format!("👉 Change Pointer: Output {}\n\n", pointer));
    }
    
    if let Some(cenotaph) = runestone_data.get("cenotaph").and_then(|v| v.as_array()) {
        if !cenotaph.is_empty() {
            output.push_str("⚠️  Cenotaph Errors:\n");
            
            for error in cenotaph {
                if let Some(error_str) = error.as_str() {
                    output.push_str(&format!("  • {}\n", error_str));
                }
            }
            
            output.push('\n');
        }
    }
    
    // Add decoded message information if available
    if let Some(decoded_messages) = runestone_data.get("decoded_messages") {
        output.push_str("📝 Decoded Messages:\n");
        
        if let Some(messages) = decoded_messages.as_array() {
            for (i, message) in messages.iter().enumerate() {
                output.push_str(&format!("  {}. ", i + 1));
                
                if let Some(msg_str) = message.as_str() {
                    output.push_str(&format!("{}\n", msg_str));
                } else {
                    output.push_str(&format!("{}\n", message));
                }
            }
        } else {
            output.push_str(&format!("  {}\n", decoded_messages));
        }
        
        output.push('\n');
    }
    
    // Add raw data section if requested
    if let Some(raw_data) = runestone_data.get("raw_data") {
        output.push_str("🔍 Raw Data:\n");
        output.push_str(&format!("  {}\n\n", raw_data));
    }
    
    Ok(output)
}

/// Format runestone with basic styling (no emojis)
pub fn format_runestone_basic(runestone_data: &JsonValue) -> Result<String> {
    let mut output = String::new();
    
    output.push_str("Runestone Analysis\n");
    output.push_str("==================\n\n");
    
    if let Some(etching) = runestone_data.get("etching") {
        output.push_str("Etching:\n");
        
        if let Some(rune) = etching.get("rune").and_then(|v| v.as_str()) {
            output.push_str(&format!("  Rune: {}\n", rune));
        }
        
        if let Some(divisibility) = etching.get("divisibility").and_then(|v| v.as_u64()) {
            output.push_str(&format!("  Divisibility: {}\n", divisibility));
        }
        
        if let Some(premine) = etching.get("premine").and_then(|v| v.as_u64()) {
            output.push_str(&format!("  Premine: {}\n", premine));
        }
        
        if let Some(symbol) = etching.get("symbol").and_then(|v| v.as_str()) {
            output.push_str(&format!("  Symbol: {}\n", symbol));
        }
        
        output.push('\n');
    }
    
    if let Some(edicts) = runestone_data.get("edicts").and_then(|v| v.as_array()) {
        if !edicts.is_empty() {
            output.push_str("Edicts:\n");
            
            for (i, edict) in edicts.iter().enumerate() {
                output.push_str(&format!("  {}. ", i + 1));
                
                if let Some(id) = edict.get("id").and_then(|v| v.as_str()) {
                    output.push_str(&format!("ID: {} ", id));
                }
                
                if let Some(amount) = edict.get("amount").and_then(|v| v.as_u64()) {
                    output.push_str(&format!("Amount: {} ", amount));
                }
                
                if let Some(output_idx) = edict.get("output").and_then(|v| v.as_u64()) {
                    output.push_str(&format!("Output: {}", output_idx));
                }
                
                output.push('\n');
            }
            
            output.push('\n');
        }
    }
    
    if let Some(mint) = runestone_data.get("mint").and_then(|v| v.as_str()) {
        output.push_str(&format!("Mint: {}\n\n", mint));
    }
    
    if let Some(pointer) = runestone_data.get("pointer").and_then(|v| v.as_u64()) {
        output.push_str(&format!("Pointer: {}\n\n", pointer));
    }
    
    Ok(output)
}

/// Analyze runestone and provide detailed breakdown
pub fn analyze_runestone_detailed(runestone_data: &JsonValue) -> Result<JsonValue> {
    let mut analysis = serde_json::Map::new();
    
    // Basic statistics
    let mut stats = serde_json::Map::new();
    stats.insert("has_etching".to_string(), JsonValue::Bool(runestone_data.get("etching").is_some()));
    stats.insert("has_mint".to_string(), JsonValue::Bool(runestone_data.get("mint").is_some()));
    stats.insert("has_pointer".to_string(), JsonValue::Bool(runestone_data.get("pointer").is_some()));
    
    if let Some(edicts) = runestone_data.get("edicts").and_then(|v| v.as_array()) {
        stats.insert("edict_count".to_string(), JsonValue::Number(edicts.len().into()));
    } else {
        stats.insert("edict_count".to_string(), JsonValue::Number(0.into()));
    }
    
    if let Some(cenotaph) = runestone_data.get("cenotaph").and_then(|v| v.as_array()) {
        stats.insert("has_errors".to_string(), JsonValue::Bool(!cenotaph.is_empty()));
        stats.insert("error_count".to_string(), JsonValue::Number(cenotaph.len().into()));
    } else {
        stats.insert("has_errors".to_string(), JsonValue::Bool(false));
        stats.insert("error_count".to_string(), JsonValue::Number(0.into()));
    }
    
    analysis.insert("statistics".to_string(), JsonValue::Object(stats));
    
    // Operation type classification
    let mut operation_type = "unknown";
    if runestone_data.get("etching").is_some() {
        operation_type = "etching";
    } else if runestone_data.get("mint").is_some() {
        operation_type = "mint";
    } else if runestone_data.get("edicts").and_then(|v| v.as_array()).map_or(false, |arr| !arr.is_empty()) {
        operation_type = "transfer";
    }
    
    analysis.insert("operation_type".to_string(), JsonValue::String(operation_type.to_string()));
    
    // Add original data
    analysis.insert("runestone_data".to_string(), runestone_data.clone());
    
    Ok(JsonValue::Object(analysis))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    
    #[test]
    fn test_format_runestone_enhanced() {
        let runestone_data = json!({
            "etching": {
                "rune": "BITCOIN",
                "divisibility": 8,
                "premine": 1000000,
                "symbol": "₿"
            },
            "edicts": [
                {
                    "id": "123:456",
                    "amount": 1000,
                    "output": 1
                }
            ],
            "mint": "789:012",
            "pointer": 2
        });
        
        let formatted = format_runestone_with_decoded_messages(&runestone_data).unwrap();
        assert!(formatted.contains("🪨 Enhanced Runestone Analysis"));
        assert!(formatted.contains("📛 Rune Name: BITCOIN"));
        assert!(formatted.contains("🔢 Divisibility: 8"));
        assert!(formatted.contains("📜 Transfer Edicts:"));
        assert!(formatted.contains("🏭 Mint Operation: 789:012"));
        assert!(formatted.contains("👉 Change Pointer: Output 2"));
    }
    
    #[test]
    fn test_format_runestone_basic() {
        let runestone_data = json!({
            "etching": {
                "rune": "TEST",
                "divisibility": 2
            }
        });
        
        let formatted = format_runestone_basic(&runestone_data).unwrap();
        assert!(formatted.contains("Runestone Analysis"));
        assert!(formatted.contains("Rune: TEST"));
        assert!(formatted.contains("Divisibility: 2"));
        assert!(!formatted.contains("🪨")); // No emojis in basic format
    }
    
    #[test]
    fn test_analyze_runestone_detailed() {
        let runestone_data = json!({
            "etching": {
                "rune": "TEST"
            },
            "edicts": [
                {"id": "1:2", "amount": 100, "output": 1}
            ]
        });
        
        let analysis = analyze_runestone_detailed(&runestone_data).unwrap();
        
        let stats = analysis.get("statistics").unwrap();
        assert_eq!(stats.get("has_etching").unwrap(), &JsonValue::Bool(true));
        assert_eq!(stats.get("edict_count").unwrap(), &JsonValue::Number(1.into()));
        assert_eq!(stats.get("has_errors").unwrap(), &JsonValue::Bool(false));
        
        assert_eq!(analysis.get("operation_type").unwrap(), &JsonValue::String("etching".to_string()));
    }
}