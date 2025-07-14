extern crate alloc;
use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::format;
use core::num::TryFromIntError;

use ed25519_dalek::SignatureError;
use snafu::Snafu;
#[cfg(feature = "std")]
use snafu::Backtrace;

pub type Result<T, E = Error> = core::result::Result<T, E>;

// custom nom error types
pub const MPI_TOO_LONG: u32 = 1000;

pub use crate::parsing::{Error as ParsingError, RemainingError};

/// Error types
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
#[non_exhaustive]
pub enum Error {
    #[snafu(display("invalid input"))]
    InvalidInput {
        #[cfg(feature = "std")]
        #[snafu(backtrace)]
        backtrace: Backtrace,
    },
    #[snafu(display("invalid armor wrappers"))]
    InvalidArmorWrappers,
    #[snafu(display("invalid crc24 checksum"))]
    InvalidChecksum,
    #[snafu(transparent)]
    Base64Decode {
        source: base64::DecodeError,
        #[cfg(feature = "std")]
        #[snafu(backtrace)]
        backtrace: Backtrace,
    },
    #[snafu(display("requested data size is larger than the packet body"))]
    RequestedSizeTooLarge,
    #[snafu(display("no matching packet found"))]
    NoMatchingPacket {
        #[cfg(feature = "std")]
        #[snafu(backtrace)]
        backtrace: Backtrace,
    },
    #[snafu(display("more than one matching packet was found"))]
    TooManyPackets,
    #[snafu(display("packet contained more data than was parsable (trailing bytes {size})"))]
    PacketTooLarge { size: u64 },
    #[snafu(transparent)]
    RSAError {
        #[snafu(source(from(rsa::errors::Error, Box::new)))]
        source: Box<rsa::errors::Error>,
        #[cfg(feature = "std")]
        #[snafu(backtrace)]
        backtrace: Backtrace,
    },
    #[snafu(transparent)]
    EllipticCurve {
        source: elliptic_curve::Error,
        #[cfg(feature = "std")]
        #[snafu(backtrace)]
        backtrace: Backtrace,
    },
    #[snafu(display("IO error: {}", source), context(false))]
    IO {
        source: crate::io::Error,
        #[cfg(feature = "std")]
        #[snafu(backtrace)]
        backtrace: Backtrace,
    },
    #[snafu(display("invalid key length"))]
    InvalidKeyLength,
    #[snafu(display("block mode error"))]
    BlockMode,
    #[snafu(display("missing key"))]
    MissingKey,
    #[snafu(display("cfb: invalid key iv length"))]
    CfbInvalidKeyIvLength,
    #[snafu(display("Not yet implemented: {message}"))]
    Unimplemented {
        message: String,
        #[cfg(feature = "std")]
        #[snafu(backtrace)]
        backtrace: Backtrace,
    },
    /// Signals packet versions and parameters we don't support, but can safely ignore
    #[snafu(display("Unsupported: {message}"))]
    Unsupported {
        message: String,
        #[cfg(feature = "std")]
        #[snafu(backtrace)]
        backtrace: Backtrace,
    },
    #[snafu(display("{message}"))]
    Message {
        message: String,
        #[cfg(feature = "std")]
        #[snafu(backtrace)]
        backtrace: Backtrace,
    },
    #[snafu(display("Invalid Packet {kind:?}"))]
    PacketError { kind: nom::error::ErrorKind },
    #[snafu(display("Unpadding failed"))]
    UnpadError,
    #[snafu(display("Padding failed"))]
    PadError,
    #[snafu(transparent)]
    Utf8Error {
        source: core::str::Utf8Error,
        #[cfg(feature = "std")]
        #[snafu(backtrace)]
        backtrace: Backtrace,
    },
    #[snafu(transparent)]
    ParseIntError {
        source: core::num::ParseIntError,
        #[cfg(feature = "std")]
        #[snafu(backtrace)]
        backtrace: Backtrace,
    },
    #[snafu(display("Invalid Packet Content {source:?}"))]
    InvalidPacketContent { source: Box<Error> },
    #[snafu(transparent)]
    SignatureError { source: SignatureError },
    #[snafu(display("Modification Detection Code error"))]
    MdcError,
    #[snafu(transparent)]
    TryFromInt {
        source: TryFromIntError,
        #[cfg(feature = "std")]
        #[snafu(backtrace)]
        backtrace: Backtrace,
    },
    #[snafu(display("AEAD {:?}", source), context(false))]
    Aead { source: crate::crypto::aead::Error },
    #[snafu(display("AES key wrap {:?}", source), context(false))]
    AesKw {
        source: crate::crypto::aes_kw::Error,
    },
    #[snafu(transparent)]
    ChecksumMissmatch {
        source: crate::crypto::checksum::ChecksumMismatch,
    },
    #[snafu(transparent)]
    Sha1HashCollision {
        source: crate::crypto::checksum::Sha1HashCollision,
    },
    #[snafu(display("AES KEK error: {}", msg))]
    AesKek {
        msg: String,
    },
    #[snafu(transparent)]
    PacketParsing {
        source: ParsingError,
        #[cfg(feature = "std")]
        #[snafu(backtrace)]
        backtrace: Backtrace,
    },
    #[snafu(display("packet is incomplete"))]
    PacketIncomplete {
        source: ParsingError,
        #[cfg(feature = "std")]
        #[snafu(backtrace)]
        backtrace: Backtrace,
    },
    #[snafu(display("Argon2 error: {}", msg))]
    Argon2 {
        msg: String,
        #[cfg(feature = "std")]
        #[snafu(backtrace)]
        backtrace: Backtrace,
    },
    #[snafu(transparent)]
    SigningError { source: cx448::SigningError },
}

impl From<crate::crypto::hash::Error> for Error {
    fn from(err: crate::crypto::hash::Error) -> Self {
        match err {
            crate::crypto::hash::Error::Unsupported { alg } => UnsupportedSnafu {
                message: format!("hash algorithm: {:?}", alg),
            }
            .build(),
            crate::crypto::hash::Error::Sha1HashCollision { source } => source.into(),
        }
    }
}

impl<T> From<nom::error::Error<T>> for Error {
    fn from(err: nom::error::Error<T>) -> Self {
        Self::PacketError { kind: err.code }
    }
}

impl From<cipher::InvalidLength> for Error {
    fn from(_: cipher::InvalidLength) -> Error {
        Error::CfbInvalidKeyIvLength
    }
}

impl From<block_padding::UnpadError> for Error {
    fn from(_: block_padding::UnpadError) -> Error {
        Error::UnpadError
    }
}

impl From<String> for Error {
    fn from(err: String) -> Error {
        Error::Message {
            message: err,
            #[cfg(feature = "std")]
            backtrace: snafu::GenerateImplicitData::generate(),
        }
    }
}

impl From<derive_builder::UninitializedFieldError> for Error {
    fn from(err: derive_builder::UninitializedFieldError) -> Error {
        Error::Message {
            message: err.to_string(),
            #[cfg(feature = "std")]
            backtrace: snafu::GenerateImplicitData::generate(),
        }
    }
}

#[cfg(feature = "std")]
impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Self::IO {
            source: err.into(),
        }
    }
}

macro_rules! unimplemented_err {
    ($e:expr) => {
        return Err($crate::errors::UnimplementedSnafu { message: $e.to_string() }.build())
    };
    ($fmt:expr, $($arg:tt)+) => {
        return Err($crate::errors::UnimplementedSnafu { message: format!($fmt, $($arg)+)}.build())
    };
}

macro_rules! unsupported_err {
    ($e:expr) => {
        return Err($crate::errors::UnsupportedSnafu {
            message: $e.to_string(),
        }.build())
    };
    ($fmt:expr, $($arg:tt)+) => {
        return Err($crate::errors::UnsupportedSnafu {
            message: format!($fmt, $($arg)+),
        }.build())
    };
}

macro_rules! bail {
    ($e:expr) => {
        return Err($crate::errors::Error::Message {
            message: $e.to_string(),
            #[cfg(feature = "std")]
            backtrace: ::snafu::GenerateImplicitData::generate(),
        })
    };
    ($fmt:expr, $($arg:tt)+) => {
        return Err($crate::errors::Error::Message {
            message: format!($fmt, $($arg)+),
            #[cfg(feature = "std")]
            backtrace: ::snafu::GenerateImplicitData::generate(),
        })
    };
}

macro_rules! format_err {
    ($e:expr) => {
        $crate::errors::Error::Message {
            message: $e.to_string(),
            #[cfg(feature = "std")]
            backtrace: ::snafu::GenerateImplicitData::generate(),
        }
    };
    ($fmt:expr, $($arg:tt)+) => {
        $crate::errors::Error::Message {
            message: format!($fmt, $($arg)+),
            #[cfg(feature = "std")]
            backtrace: ::snafu::GenerateImplicitData::generate(),
        }
    };
}

macro_rules! ensure {
    ($cond:expr, $e:expr) => {
        if !($cond) {
            $crate::errors::bail!($e);
        }
    };
    ($cond:expr, $fmt:expr, $($arg:tt)+) => {
        if !($cond) {
            $crate::errors::bail!($fmt, $($arg)+);
        }
    };
}

macro_rules! ensure_eq {
    ($left:expr, $right:expr) => ({
        match (&$left, &$right) {
            (left_val, right_val) => {
                if !(*left_val == *right_val) {
                    $crate::errors::bail!(r#"assertion failed: `(left == right)`
  left: `{:?}`,
 right: `{:?}`"#, left_val, right_val)
                }
            }
        }
    });
    ($left:expr, $right:expr,) => ({
        $crate::errors::ensure_eq!($left, $right)
    });
    ($left:expr, $right:expr, $($arg:tt)+) => ({
        match (&($left), &($right)) {
            (left_val, right_val) => {
                if !(*left_val == *right_val) {
                    $crate::errors::bail!(r#"assertion failed: `(left == right)`
  left: `{:?}`,
 right: `{:?}`: {}"#, left_val, right_val,
                           format_args!($($arg)+))
                }
            }
        }
    });
}

macro_rules! err_opt {
    ($e:expr) => {
        match $e {
            Ok(v) => v,
            Err(err) => return Some(Err(err)),
        }
    };
}

pub(crate) use bail;
pub(crate) use ensure;
pub(crate) use ensure_eq;
pub(crate) use err_opt;
pub(crate) use format_err;
pub(crate) use unimplemented_err;
pub(crate) use unsupported_err;

#[cfg(test)]
mod tests {
    /// Check the size of the error enum
    ///
    /// Because clippy will start throwing warning if an enum gets above 128, we'd like to keep the
    /// size of the `Error` enum lower than that limit with some headroom to be wrapped by a
    /// downstream crate.
    ///
    /// If this test triggers, you should consider Box'ing the offending member.
    ///
    /// See: <https://rust-lang.github.io/rust-clippy/master/index.html#result_large_err>
    #[cfg(target_pointer_width = "64")]
    #[test]
    fn size_of_error() {
        assert_eq!(core::mem::size_of::<super::Error>(), 80);
    }
}
