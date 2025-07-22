//! Utility modules for deezel-common
//!
//! This module contains various utility functions and types used throughout the deezel-common crate.

pub mod protostone;
pub mod hex;

pub use protostone::*;

// Re-export alkane utilities for backward compatibility
pub use crate::alkanes::parsing::parse_input_requirements as parse_alkane_id;
use protorune_support::proto::protorune as protorune_pb;

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

/// Converts a u128 to a protobuf uint128.
pub fn to_uint128(value: u128) -> protorune_pb::Uint128 {
    let mut u = protorune_pb::Uint128::new();
    u.lo = value as u64;
    u.hi = (value >> 64) as u64;
    u
}