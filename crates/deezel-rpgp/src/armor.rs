//! # Armor module
//!
//! Armor module provides implementation of ASCII Armor as specified in RFC 9580.
//! <https://www.rfc-editor.org/rfc/rfc9580.html#name-forming-ascii-armor>
extern crate alloc;
use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::format;

mod reader;
mod writer;

pub use self::{reader::*, writer::*};
