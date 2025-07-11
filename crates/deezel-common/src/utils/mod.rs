//! Utility modules for deezel-common
//!
//! This module contains various utility functions and types used throughout the deezel-common crate.

pub mod protostone;
pub mod hex;

pub use protostone::*;

// Re-export alkane utilities for backward compatibility
pub use crate::alkanes::utils::parse_alkane_id;