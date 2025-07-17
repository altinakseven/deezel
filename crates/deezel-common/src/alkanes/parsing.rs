//! Parsing logic for alkanes commands
#[cfg(not(feature = "std"))]
use alloc::{string::{String, ToString}, vec::Vec, format};
#[cfg(feature = "std")]
use std::{string::{String, ToString}, vec::Vec, format};
use anyhow::{anyhow, Context, Result};
use super::types::{InputRequirement, OutputTarget, ProtostoneEdict, ProtostoneSpec, BitcoinTransfer};
use alkanes_support::cellpack::Cellpack;

/// Parse input requirements from string format
pub fn parse_input_requirements(input_str: &str) -> Result<Vec<InputRequirement>> {
    let mut requirements = Vec::new();
    
    for part in input_str.split(',') {
        let trimmed = part.trim();
        
        if trimmed.starts_with("B:") {
            // Bitcoin requirement: B:amount
            let amount_str = &trimmed[2..];
            let amount = amount_str.parse::<u64>()
                .context("Invalid Bitcoin amount in input requirement")?;
            requirements.push(InputRequirement::Bitcoin { amount });
        } else {
            // Alkanes requirement: block:tx:amount
            let parts: Vec<&str> = trimmed.split(':').collect();
            if parts.len() != 3 {
                return Err(anyhow!("Invalid alkanes input requirement format. Expected 'block:tx:amount'"));
            }
            
            let block = parts[0].parse::<u64>()
                .context("Invalid block number in alkanes requirement")?;
            let tx = parts[1].parse::<u64>()
                .context("Invalid tx number in alkanes requirement")?;
            let amount = parts[2].parse::<u64>()
                .context("Invalid amount in alkanes requirement")?;
            
            requirements.push(InputRequirement::Alkanes { block, tx, amount });
        }
    }
    
    Ok(requirements)
}

/// Parse protostone specifications from complex string format
pub fn parse_protostones(protostones_str: &str) -> Result<Vec<ProtostoneSpec>> {
    // Split by comma, but ignore commas inside [] brackets (cellpacks)
    let protostone_parts = split_respecting_brackets(protostones_str, ',')?;
    
    let mut protostones = Vec::new();
    
    for part in &protostone_parts {
        let spec = parse_single_protostone(part)?;
        protostones.push(spec);
    }
    
    Ok(protostones)
}

/// Parse a single protostone specification
fn parse_single_protostone(spec_str: &str) -> Result<ProtostoneSpec> {
    let mut cellpack = None;
    let mut edicts = Vec::new();
    let mut bitcoin_transfer = None;
    
    // Use a more sophisticated parsing approach
    let parts = split_complex_protostone(spec_str)?;
    
    for part in parts.iter() {
        let trimmed = part.trim();
        
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            let content = &trimmed[1..trimmed.len()-1];
            
            // Check if this is a cellpack (contains commas) or an edict (contains colons)
            if content.contains(',') && !content.contains(':') {
                // This is a cellpack: [3,797,101]
                cellpack = Some(parse_cellpack(content)?);
            } else if content.contains(':') {
                // This is a bracketed edict: [4:797:1:p1]
                let edict = parse_edict(trimmed)?;
                edicts.push(edict);
            } else {
                // Ambiguous - try cellpack first, then edict
                if let Ok(cp) = parse_cellpack(content) {
                    cellpack = Some(cp);
                } else {
                    let edict = parse_edict(trimmed)?;
                    edicts.push(edict);
                }
            }
        } else if trimmed.starts_with("B:") {
            // This is a Bitcoin transfer
            bitcoin_transfer = Some(parse_bitcoin_transfer(trimmed)?);
        } else if !trimmed.is_empty() {
            // This might be a simple edict: block:tx:amount:target
            if let Ok(edict) = parse_edict(trimmed) {
                edicts.push(edict);
            } else {
                log::warn!("Could not parse protostone part: {}", trimmed);
            }
        }
    }
    
    Ok(ProtostoneSpec {
        cellpack,
        edicts,
        bitcoin_transfer,
    })
}

/// Parse cellpack from string format
fn parse_cellpack(cellpack_str: &str) -> Result<Cellpack> {
    // Parse comma-separated numbers into Vec<u128>
    let mut values = Vec::new();
    
    for part in cellpack_str.split(',') {
        let trimmed = part.trim();
        let value = trimmed.parse::<u128>()
            .with_context(|| format!("Invalid u128 value in cellpack: {}", trimmed))?;
        values.push(value);
    }
    
    // Convert Vec<u128> to Cellpack using TryFrom
    // The first two values become target (block, tx), remaining values become inputs
    Cellpack::try_from(values)
        .with_context(|| "Failed to create Cellpack from values (need at least 2 values for target)")
}

/// Parse Bitcoin transfer specification
fn parse_bitcoin_transfer(transfer_str: &str) -> Result<BitcoinTransfer> {
    // Format: B:amount:target
    let parts: Vec<&str> = transfer_str.split(':').collect();
    if parts.len() != 3 {
        return Err(anyhow!("Invalid Bitcoin transfer format. Expected 'B:amount:target'"));
    }
    
    let amount = parts[1].parse::<u64>()
        .context("Invalid amount in Bitcoin transfer")?;
    let target = parse_output_target(parts[2])?;
    
    Ok(BitcoinTransfer { amount, target })
}

/// Parse edict specification
fn parse_edict(edict_str: &str) -> Result<ProtostoneEdict> {
    // Handle both formats:
    // 1. Simple format: block:tx:amount:target
    // 2. Bracketed format: [block:tx:amount:output] (where output becomes target)
    
    let trimmed = edict_str.trim();
    
    if trimmed.starts_with('[') && trimmed.ends_with(']') {
        // Bracketed format: [block:tx:amount:output]
        let content = &trimmed[1..trimmed.len()-1];
        let parts: Vec<&str> = content.split(':').collect();
        if parts.len() != 4 {
            return Err(anyhow!("Invalid bracketed edict format. Expected '[block:tx:amount:output]'"));
        }
        
        let block = parts[0].parse::<u64>()
            .context("Invalid block number in bracketed edict")?;
        let tx = parts[1].parse::<u64>()
            .context("Invalid tx number in bracketed edict")?;
        let amount = parts[2].parse::<u64>()
            .context("Invalid amount in bracketed edict")?;
        let target = parse_output_target(parts[3])?;
        
        Ok(ProtostoneEdict {
            alkane_id: super::types::AlkaneId { block, tx },
            amount,
            target,
        })
    } else {
        // Simple format: block:tx:amount:target
        let parts: Vec<&str> = trimmed.split(':').collect();
        if parts.len() < 4 {
            return Err(anyhow!("Invalid edict format. Expected 'block:tx:amount:target' or '[block:tx:amount:output]'"));
        }
        
        let block = parts[0].parse::<u64>()
            .context("Invalid block number in edict")?;
        let tx = parts[1].parse::<u64>()
            .context("Invalid tx number in edict")?;
        let amount = parts[2].parse::<u64>()
            .context("Invalid amount in edict")?;
        let target = parse_output_target(parts[3])?;
        
        Ok(ProtostoneEdict {
            alkane_id: super::types::AlkaneId { block, tx },
            amount,
            target,
        })
    }
}

/// Parse output target (vN, pN, or split)
fn parse_output_target(target_str: &str) -> Result<OutputTarget> {
    let trimmed = target_str.trim();
    
    if trimmed == "split" {
        Ok(OutputTarget::Split)
    } else if trimmed.starts_with('v') {
        let index_str = &trimmed[1..];
        let index = index_str.parse::<u32>()
            .context("Invalid output index in target")?;
        Ok(OutputTarget::Output(index))
    } else if trimmed.starts_with('p') {
        let index_str = &trimmed[1..];
        let index = index_str.parse::<u32>()
            .context("Invalid protostone index in target")?;
        Ok(OutputTarget::Protostone(index))
    } else {
        Err(anyhow!("Invalid output target format. Expected 'vN', 'pN', or 'split'"))
    }
}

/// Split string by delimiter while respecting bracket nesting
fn split_respecting_brackets(input: &str, delimiter: char) -> Result<Vec<String>> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut bracket_depth = 0;
    
    for ch in input.chars() {
        match ch {
            '[' => {
                bracket_depth += 1;
                current.push(ch);
            },
            ']' => {
                bracket_depth -= 1;
                current.push(ch);
                if bracket_depth < 0 {
                    return Err(anyhow!("Unmatched closing bracket"));
                }
            },
            c if c == delimiter && bracket_depth == 0 => {
                if !current.trim().is_empty() {
                    parts.push(current.trim().to_string());
                }
                current.clear();
            },
            _ => {
                current.push(ch);
            }
        }
    }
    
    if bracket_depth != 0 {
        return Err(anyhow!("Unmatched opening bracket"));
    }
    
    if !current.trim().is_empty() {
        parts.push(current.trim().to_string());
    }
    
    Ok(parts)
}

/// Split complex protostone specification while respecting nested brackets
fn split_complex_protostone(input: &str) -> Result<Vec<String>> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut bracket_depth = 0;
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        match ch {
            '[' => {
                if bracket_depth == 0 && !current.is_empty() {
                    parts.push(current.trim().to_string());
                    current.clear();
                }
                bracket_depth += 1;
                current.push(ch);
            },
            ']' => {
                bracket_depth -= 1;
                current.push(ch);
                if bracket_depth < 0 {
                    return Err(anyhow!("Unmatched closing bracket"));
                }
                if bracket_depth == 0 {
                    parts.push(current.trim().to_string());
                    current.clear();
                }
            },
            ':' if bracket_depth == 0 => {
                if !current.is_empty() {
                    parts.push(current.trim().to_string());
                }
                current.clear();
                // The colon itself is a separator, not part of a token
            },
            ',' if bracket_depth == 0 => {
                if !current.is_empty() {
                    parts.push(current.trim().to_string());
                }
                current.clear();
            },
            _ => {
                current.push(ch);
            }
        }
    }

    if bracket_depth != 0 {
        return Err(anyhow!("Unmatched opening bracket"));
    }

    if !current.trim().is_empty() {
        parts.push(current.trim().to_string());
    }

    // Filter out empty strings that might result from separators
    Ok(parts.into_iter().filter(|s| !s.is_empty()).collect())
}