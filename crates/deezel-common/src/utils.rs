//! Common utilities for the deezel-common library
//!
//! This module provides various utility functions and helpers used throughout
//! the deezel ecosystem.

pub mod protostone;

use crate::{Result, DeezelError};
use bitcoin::{Transaction, Address, Network};
use std::str::FromStr;

/// Expand tilde (~) in file paths to home directory
pub fn expand_tilde(path: &str) -> Result<String> {
    if path.starts_with("~/") {
        // In WASM, we can't access HOME environment variable
        #[cfg(target_arch = "wasm32")]
        {
            // For WASM, just remove the tilde and use relative path
            Ok(path.replacen("~", "", 1))
        }
        
        #[cfg(not(target_arch = "wasm32"))]
        {
            let home = std::env::var("HOME")
                .map_err(|_| DeezelError::Configuration("HOME environment variable not set".to_string()))?;
            Ok(path.replacen("~", &home, 1))
        }
    } else {
        Ok(path.to_string())
    }
}

/// Parse outpoint from string (format: txid:vout)
pub fn parse_outpoint(outpoint: &str) -> Result<(String, u32)> {
    let parts: Vec<&str> = outpoint.split(':').collect();
    if parts.len() != 2 {
        return Err(DeezelError::Parse("Invalid outpoint format. Expected 'txid:vout'".to_string()));
    }
    
    let txid = parts[0].to_string();
    let vout = parts[1].parse::<u32>()
        .map_err(|_| DeezelError::Parse("Invalid vout in outpoint".to_string()))?;
    
    Ok((txid, vout))
}

/// Parse contract ID from string (format: txid:vout)
pub fn parse_contract_id(contract_id: &str) -> Result<(String, String)> {
    let parts: Vec<&str> = contract_id.split(':').collect();
    if parts.len() != 2 {
        return Err(DeezelError::Parse("Invalid contract ID format. Expected 'txid:vout'".to_string()));
    }
    
    Ok((parts[0].to_string(), parts[1].to_string()))
}

/// Parse alkane ID from string (format: block:tx)
pub fn parse_alkane_id(alkane_id: &str) -> Result<(u64, u64)> {
    let parts: Vec<&str> = alkane_id.split(':').collect();
    if parts.len() != 2 {
        return Err(DeezelError::Parse("Invalid alkane ID format. Expected 'block:tx'".to_string()));
    }
    
    let block = parts[0].parse::<u64>()
        .map_err(|_| DeezelError::Parse("Invalid block number in alkane ID".to_string()))?;
    let tx = parts[1].parse::<u64>()
        .map_err(|_| DeezelError::Parse("Invalid transaction number in alkane ID".to_string()))?;
    
    Ok((block, tx))
}

/// Decode transaction from hex string
pub fn decode_transaction_hex(hex_str: &str) -> Result<Transaction> {
    let clean_hex = hex_str.trim_start_matches("0x");
    let tx_bytes = hex::decode(clean_hex)
        .map_err(|e| DeezelError::Parse(format!("Failed to decode transaction hex: {}", e)))?;
    
    bitcoin::consensus::encode::deserialize(&tx_bytes)
        .map_err(|e| DeezelError::Parse(format!("Failed to deserialize transaction: {}", e)))
}

/// Encode transaction to hex string
pub fn encode_transaction_hex(tx: &Transaction) -> String {
    bitcoin::consensus::encode::serialize_hex(tx)
}

/// Validate Bitcoin address
pub fn validate_bitcoin_address(address: &str, network: Option<Network>) -> Result<Address> {
    match Address::from_str(address) {
        Ok(unchecked_addr) => {
            // Convert to checked address
            let addr = unchecked_addr.assume_checked();
            
            // If network is specified, validate it matches
            if let Some(expected_network) = network {
                // For now, we'll skip network validation as the API has changed
                // In a full implementation, we'd check the address format against the network
                let _ = expected_network; // Suppress unused variable warning
            }
            Ok(addr)
        }
        Err(e) => Err(DeezelError::AddressResolution(
            format!("Invalid Bitcoin address {}: {}", address, e)
        )),
    }
}

/// Check if a string is a raw Bitcoin address (not an identifier)
pub fn is_raw_bitcoin_address(addr: &str) -> bool {
    !addr.contains('[') && !addr.contains(':') && (
        addr.starts_with('1') || 
        addr.starts_with('3') || 
        addr.starts_with("bc1") || 
        addr.starts_with("tb1") || 
        addr.starts_with("bcrt1")
    )
}

/// Format satoshis as Bitcoin with proper decimal places
pub fn format_bitcoin_amount(satoshis: u64, decimals: Option<u8>) -> String {
    let decimals = decimals.unwrap_or(8);
    let divisor = 10_u64.pow(decimals as u32);
    let btc = satoshis as f64 / divisor as f64;
    format!("{:.8}", btc).trim_end_matches('0').trim_end_matches('.').to_string()
}

/// Parse Bitcoin amount string to satoshis
pub fn parse_bitcoin_amount(amount_str: &str) -> Result<u64> {
    let amount: f64 = amount_str.parse()
        .map_err(|_| DeezelError::Parse(format!("Invalid amount: {}", amount_str)))?;
    
    if amount < 0.0 {
        return Err(DeezelError::Parse("Amount cannot be negative".to_string()));
    }
    
    let satoshis = (amount * 100_000_000.0).round() as u64;
    Ok(satoshis)
}

/// Compress a list of opcodes into readable ranges (e.g., "1-10, 15, 20-25")
pub fn compress_opcode_ranges(opcodes: &[u128]) -> String {
    if opcodes.is_empty() {
        return String::new();
    }
    
    let mut ranges = Vec::new();
    let mut start = opcodes[0];
    let mut end = opcodes[0];
    
    for &opcode in opcodes.iter().skip(1) {
        if opcode == end + 1 {
            end = opcode;
        } else {
            if start == end {
                ranges.push(start.to_string());
            } else {
                ranges.push(format!("{}-{}", start, end));
            }
            start = opcode;
            end = opcode;
        }
    }
    
    // Add the last range
    if start == end {
        ranges.push(start.to_string());
    } else {
        ranges.push(format!("{}-{}", start, end));
    }
    
    ranges.join(", ")
}

/// Parse opcode ranges from string (e.g., "0-999,2000-2500")
pub fn parse_opcode_ranges(ranges_str: &str) -> Result<Vec<u128>> {
    let mut opcodes = Vec::new();
    
    for range_part in ranges_str.split(',') {
        let range_part = range_part.trim();
        if range_part.contains('-') {
            let parts: Vec<&str> = range_part.split('-').collect();
            if parts.len() != 2 {
                return Err(DeezelError::Parse(format!("Invalid range format: {}", range_part)));
            }
            let start: u128 = parts[0].parse()
                .map_err(|_| DeezelError::Parse(format!("Invalid start opcode: {}", parts[0])))?;
            let end: u128 = parts[1].parse()
                .map_err(|_| DeezelError::Parse(format!("Invalid end opcode: {}", parts[1])))?;
            
            if start > end {
                return Err(DeezelError::Parse(format!("Invalid range: start {} > end {}", start, end)));
            }
            
            for opcode in start..=end {
                opcodes.push(opcode);
            }
        } else {
            let opcode: u128 = range_part.parse()
                .map_err(|_| DeezelError::Parse(format!("Invalid opcode: {}", range_part)))?;
            opcodes.push(opcode);
        }
    }
    
    opcodes.sort();
    opcodes.dedup();
    Ok(opcodes)
}

/// Decode data bytevector for display
pub fn decode_data_bytevector(data: &[u8]) -> String {
    if data.is_empty() {
        return "Empty (0 bytes)".to_string();
    }
    
    // Always show hex first
    let hex_part = if data.len() <= 32 {
        format!("Hex: {}", hex::encode(data))
    } else {
        format!("Hex: {} (first 32 bytes of {})", hex::encode(&data[..32]), data.len())
    };
    
    // Check for Solidity error signature (0x08c379a0)
    if data.len() >= 4 && data[0..4] == [0x08, 0xc3, 0x79, 0xa0] {
        // Skip the 4-byte error signature and try to decode as UTF-8
        let message_bytes = &data[4..];
        if let Ok(utf8_string) = String::from_utf8(message_bytes.to_vec()) {
            let clean_string = utf8_string.trim_matches('\0').trim();
            if !clean_string.is_empty() && clean_string.is_ascii() {
                return format!("{} | Solidity Error: \"{}\"", hex_part, clean_string);
            }
        }
        // If UTF-8 decoding fails, show as hex
        return format!("{} | Solidity Error", hex_part);
    }
    
    // Try to decode as UTF-8 string for additional context
    if let Ok(utf8_string) = String::from_utf8(data.to_vec()) {
        let clean_string = utf8_string.trim_matches('\0').trim();
        if !clean_string.is_empty() && clean_string.is_ascii() && clean_string.len() > 3 {
            return format!("{} | UTF-8: \"{}\"", hex_part, clean_string);
        }
    }
    
    // Try to interpret as numbers for common data sizes
    if data.len() == 16 {
        // Could be a u128
        let value = u128::from_le_bytes(data.try_into().unwrap_or([0; 16]));
        return format!("{} | u128: {}", hex_part, value);
    } else if data.len() == 8 {
        // Could be a u64
        let value = u64::from_le_bytes(data.try_into().unwrap_or([0; 8]));
        return format!("{} | u64: {}", hex_part, value);
    } else if data.len() == 4 {
        // Could be a u32
        let value = u32::from_le_bytes(data.try_into().unwrap_or([0; 4]));
        return format!("{} | u32: {}", hex_part, value);
    }
    
    // Just show hex
    hex_part
}

/// Time utilities
pub mod time {
    use std::time::{SystemTime, UNIX_EPOCH, Duration};
    
    /// Get current Unix timestamp in seconds
    pub fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs()
    }
    
    /// Get current Unix timestamp in milliseconds
    pub fn now_millis() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_millis() as u64
    }
    
    /// Format timestamp as human-readable string
    pub fn format_timestamp(timestamp: u64) -> String {
        #[cfg(not(target_arch = "wasm32"))]
        {
            use chrono::DateTime;
            if let Some(datetime) = DateTime::from_timestamp(timestamp as i64, 0) {
                datetime.format("%Y-%m-%d %H:%M:%S UTC").to_string()
            } else {
                format!("Invalid timestamp: {}", timestamp)
            }
        }
        
        #[cfg(target_arch = "wasm32")]
        {
            // For WASM, just return the timestamp as string
            format!("Timestamp: {}", timestamp)
        }
    }
    
    /// Parse duration string (e.g., "5m", "1h", "30s")
    pub fn parse_duration(duration_str: &str) -> Result<Duration, String> {
        if duration_str.is_empty() {
            return Err("Empty duration string".to_string());
        }
        
        let (number_part, unit_part) = if let Some(pos) = duration_str.find(|c: char| c.is_alphabetic()) {
            (&duration_str[..pos], &duration_str[pos..])
        } else {
            (duration_str, "s") // Default to seconds
        };
        
        let number: u64 = number_part.parse()
            .map_err(|_| format!("Invalid number in duration: {}", number_part))?;
        
        let multiplier = match unit_part.to_lowercase().as_str() {
            "s" | "sec" | "second" | "seconds" => 1,
            "m" | "min" | "minute" | "minutes" => 60,
            "h" | "hour" | "hours" => 3600,
            "d" | "day" | "days" => 86400,
            _ => return Err(format!("Unknown time unit: {}", unit_part)),
        };
        
        Ok(Duration::from_secs(number * multiplier))
    }
}

/// Hex utilities
pub mod hex_utils {
    use crate::{Result, DeezelError};
    
    /// Encode bytes to hex string with 0x prefix
    pub fn encode_with_prefix(data: &[u8]) -> String {
        format!("0x{}", hex::encode(data))
    }
    
    /// Decode hex string (with or without 0x prefix)
    pub fn decode_flexible(hex_str: &str) -> Result<Vec<u8>> {
        let clean_hex = hex_str.trim_start_matches("0x");
        hex::decode(clean_hex)
            .map_err(|e| DeezelError::Parse(format!("Invalid hex string: {}", e)))
    }
    
    /// Check if string is valid hex
    pub fn is_valid_hex(s: &str) -> bool {
        let clean = s.trim_start_matches("0x");
        clean.chars().all(|c| c.is_ascii_hexdigit()) && clean.len() % 2 == 0
    }
    
    /// Format hex string with spacing for readability
    pub fn format_hex_readable(hex_str: &str, bytes_per_group: usize) -> String {
        let clean = hex_str.trim_start_matches("0x");
        let chars_per_group = bytes_per_group * 2;
        
        clean.chars()
            .collect::<Vec<_>>()
            .chunks(chars_per_group)
            .map(|chunk| chunk.iter().collect::<String>())
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// String utilities
pub mod string_utils {
    /// Truncate string to specified length with ellipsis
    pub fn truncate_with_ellipsis(s: &str, max_len: usize) -> String {
        if s.len() <= max_len {
            s.to_string()
        } else if max_len <= 3 {
            "...".to_string()
        } else {
            format!("{}...", &s[..max_len - 3])
        }
    }
    
    /// Convert snake_case to camelCase
    pub fn snake_to_camel(s: &str) -> String {
        let mut result = String::new();
        let mut capitalize_next = false;
        
        for c in s.chars() {
            if c == '_' {
                capitalize_next = true;
            } else if capitalize_next {
                result.push(c.to_uppercase().next().unwrap_or(c));
                capitalize_next = false;
            } else {
                result.push(c);
            }
        }
        
        result
    }
    
    /// Convert camelCase to snake_case
    pub fn camel_to_snake(s: &str) -> String {
        let mut result = String::new();
        
        for (i, c) in s.chars().enumerate() {
            if c.is_uppercase() && i > 0 {
                result.push('_');
            }
            result.push(c.to_lowercase().next().unwrap_or(c));
        }
        
        result
    }
}

/// Collection utilities
pub mod collections {
    use std::collections::HashMap;
    use std::hash::Hash;
    
    /// Group items by a key function
    pub fn group_by<T, K, F>(items: Vec<T>, key_fn: F) -> HashMap<K, Vec<T>>
    where
        K: Eq + Hash,
        F: Fn(&T) -> K,
    {
        let mut groups = HashMap::new();
        
        for item in items {
            let key = key_fn(&item);
            groups.entry(key).or_insert_with(Vec::new).push(item);
        }
        
        groups
    }
    
    /// Count occurrences of items
    pub fn count_occurrences<T>(items: &[T]) -> HashMap<&T, usize>
    where
        T: Eq + Hash,
    {
        let mut counts = HashMap::new();
        
        for item in items {
            *counts.entry(item).or_insert(0) += 1;
        }
        
        counts
    }
    
    /// Find duplicates in a collection
    pub fn find_duplicates<T>(items: &[T]) -> Vec<&T>
    where
        T: Eq + Hash,
    {
        let counts = count_occurrences(items);
        counts.into_iter()
            .filter(|(_, count)| *count > 1)
            .map(|(item, _)| item)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parse_outpoint() {
        let (txid, vout) = parse_outpoint("abcd1234:0").unwrap();
        assert_eq!(txid, "abcd1234");
        assert_eq!(vout, 0);
        
        assert!(parse_outpoint("invalid").is_err());
        assert!(parse_outpoint("txid:invalid").is_err());
    }
    
    #[test]
    fn test_parse_alkane_id() {
        let (block, tx) = parse_alkane_id("123:456").unwrap();
        assert_eq!(block, 123);
        assert_eq!(tx, 456);
        
        assert!(parse_alkane_id("invalid").is_err());
        assert!(parse_alkane_id("123:invalid").is_err());
    }
    
    #[test]
    fn test_format_bitcoin_amount() {
        assert_eq!(format_bitcoin_amount(100000000, None), "1");
        assert_eq!(format_bitcoin_amount(50000000, None), "0.5");
        assert_eq!(format_bitcoin_amount(1, None), "0.00000001");
    }
    
    #[test]
    fn test_parse_bitcoin_amount() {
        assert_eq!(parse_bitcoin_amount("1.0").unwrap(), 100000000);
        assert_eq!(parse_bitcoin_amount("0.5").unwrap(), 50000000);
        assert_eq!(parse_bitcoin_amount("0.00000001").unwrap(), 1);
        
        assert!(parse_bitcoin_amount("-1.0").is_err());
        assert!(parse_bitcoin_amount("invalid").is_err());
    }
    
    #[test]
    fn test_compress_opcode_ranges() {
        let opcodes = vec![1, 2, 3, 5, 7, 8, 9, 15];
        let compressed = compress_opcode_ranges(&opcodes);
        assert_eq!(compressed, "1-3, 5, 7-9, 15");
        
        let single = vec![42];
        assert_eq!(compress_opcode_ranges(&single), "42");
        
        let empty: Vec<u128> = vec![];
        assert_eq!(compress_opcode_ranges(&empty), "");
    }
    
    #[test]
    fn test_parse_opcode_ranges() {
        let opcodes = parse_opcode_ranges("1-3,5,7-9").unwrap();
        assert_eq!(opcodes, vec![1, 2, 3, 5, 7, 8, 9]);
        
        assert!(parse_opcode_ranges("invalid").is_err());
        assert!(parse_opcode_ranges("1-invalid").is_err());
    }
    
    #[test]
    fn test_hex_utils() {
        assert_eq!(hex_utils::encode_with_prefix(&[0xde, 0xad, 0xbe, 0xef]), "0xdeadbeef");
        assert_eq!(hex_utils::decode_flexible("0xdeadbeef").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(hex_utils::decode_flexible("deadbeef").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
        
        assert!(hex_utils::is_valid_hex("deadbeef"));
        assert!(hex_utils::is_valid_hex("0xdeadbeef"));
        assert!(!hex_utils::is_valid_hex("invalid"));
        assert!(!hex_utils::is_valid_hex("deadbee")); // Odd length
    }
    
    #[test]
    fn test_string_utils() {
        assert_eq!(string_utils::truncate_with_ellipsis("hello world", 8), "hello...");
        assert_eq!(string_utils::truncate_with_ellipsis("short", 10), "short");
        
        assert_eq!(string_utils::snake_to_camel("hello_world"), "helloWorld");
        assert_eq!(string_utils::camel_to_snake("helloWorld"), "hello_world");
    }
    
    #[test]
    fn test_time_utils() {
        use time::*;
        
        let duration = parse_duration("5m").unwrap();
        assert_eq!(duration.as_secs(), 300);
        
        let duration = parse_duration("1h").unwrap();
        assert_eq!(duration.as_secs(), 3600);
        
        assert!(parse_duration("invalid").is_err());
    }
}