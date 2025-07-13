extern crate alloc;
use num_enum::{FromPrimitive, IntoPrimitive};

/// Available compression algorithms.
/// Ref: <https://www.rfc-editor.org/rfc/rfc9580.html#name-compression-algorithms>
#[derive(Debug, PartialEq, Eq, Clone, Copy, FromPrimitive, IntoPrimitive)]
#[repr(u8)]
#[non_exhaustive]
pub enum CompressionAlgorithm {
    Uncompressed = 0,
    ZIP = 1,
    ZLIB = 2,
    BZip2 = 3,
    /// Do not use, just for compatibility with GnuPG.
    Private10 = 110,

    #[num_enum(catch_all)]
    Other(u8),
}
