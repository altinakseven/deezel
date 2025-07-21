//! Utility modules for deezel-common
//!
//! This module contains various utility functions and types used throughout the deezel-common crate.

pub mod protostone;
pub mod hex;

pub use protostone::*;

// Re-export alkane utilities for backward compatibility
pub use crate::alkanes::parsing::parse_input_requirements as parse_alkane_id;

/// Converts a slice of bytes to a u128.
///
/// # Panics
///
/// Panics if the slice is not 16 bytes long.
pub fn u128_from_slice(slice: &[u8]) -> u128 {
    let mut array = [0u8; 16];
    array.copy_from_slice(slice);
    u128::from_le_bytes(array)
}