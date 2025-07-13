//! Hex encoding utility trait.

use alloc::string::String;
use bitcoin::ScriptBuf;
use hex;

pub trait ToHexString {
    fn to_hex_string(&self) -> String;
}

impl ToHexString for ScriptBuf {
    fn to_hex_string(&self) -> String {
        hex::encode(self.as_bytes())
    }
}