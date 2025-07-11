//! Hex encoding utility trait.

use bitcoin::ScriptBuf;

pub trait ToHexString {
    fn to_hex_string(&self) -> String;
}

impl ToHexString for ScriptBuf {
    fn to_hex_string(&self) -> String {
        hex::encode(self.as_bytes())
    }
}