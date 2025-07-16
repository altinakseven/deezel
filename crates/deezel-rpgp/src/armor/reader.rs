extern crate alloc;
use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec::Vec,
};
use core::{fmt, str};
use crate::ser::Serialize;

use crate::io::BufReader;
use nom::{
    branch::alt,
    bytes::streaming::{tag, take_until1},
    character::streaming::{digit1, line_ending, not_line_ending},
    combinator::{complete, map, map_res, opt, value},
    multi::many0,
    sequence::{delimited, pair, preceded, terminated},
    AsChar, IResult, Input, Parser,
};

use crate::{
    base64::Base64Reader,
    errors::Result,
    io::{Cursor, Read},
};

/// Armor block types.
///
/// Both OpenPGP (RFC 9580) and OpenSSL PEM armor types are included.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum BlockType {
    /// PGP public key
    PublicKey,
    /// PEM encoded PKCS#1 public key
    PublicKeyPKCS1(PKCS1Type),
    /// PEM encoded PKCS#8 public key
    PublicKeyPKCS8,
    /// Public key OpenSSH
    PublicKeyOpenssh,
    /// PGP private key
    PrivateKey,
    /// PEM encoded PKCS#1 private key
    PrivateKeyPKCS1(PKCS1Type),
    /// PEM encoded PKCS#8 private key
    PrivateKeyPKCS8,
    /// OpenSSH private key
    PrivateKeyOpenssh,
    Message,
    MultiPartMessage(usize, usize),
    Signature,
    // gnupgp extension
    File,
    /// Cleartext Framework message
    CleartextMessage,
}

impl fmt::Display for BlockType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlockType::PublicKey => f.write_str("PGP PUBLIC KEY BLOCK"),
            BlockType::PrivateKey => f.write_str("PGP PRIVATE KEY BLOCK"),
            BlockType::MultiPartMessage(x, y) => write!(f, "PGP MESSAGE, PART {x}/{y}"),
            BlockType::Message => f.write_str("PGP MESSAGE"),
            BlockType::Signature => f.write_str("PGP SIGNATURE"),
            BlockType::File => f.write_str("PGP ARMORED FILE"),
            BlockType::PublicKeyPKCS1(typ) => write!(f, "{typ} PUBLIC KEY"),
            BlockType::PublicKeyPKCS8 => f.write_str("PUBLIC KEY"),
            BlockType::PublicKeyOpenssh => f.write_str("OPENSSH PUBLIC KEY"),
            BlockType::PrivateKeyPKCS1(typ) => write!(f, "{typ} PRIVATE KEY"),
            BlockType::PrivateKeyPKCS8 => f.write_str("PRIVATE KEY"),
            BlockType::PrivateKeyOpenssh => f.write_str("OPENSSH PRIVATE KEY"),
            BlockType::CleartextMessage => f.write_str("PGP SIGNED MESSAGE"),
        }
    }
}

impl Serialize for BlockType {
    fn to_writer<W: crate::io::Write>(&self, w: &mut W) -> Result<()> {
        w.write_all(self.to_string().as_bytes())?;

        Ok(())
    }

    fn write_len(&self) -> usize {
        // allocates, but this is tiny, should be fine
        let x = self.to_string();
        x.len()
    }
}

/// OpenSSL PKCS#1 PEM armor types
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum PKCS1Type {
    RSA,
    DSA,
    EC,
}

impl fmt::Display for PKCS1Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PKCS1Type::RSA => write!(f, "RSA"),
            PKCS1Type::DSA => write!(f, "DSA"),
            PKCS1Type::EC => write!(f, "EC"),
        }
    }
}

/// Armor Headers.
pub type Headers = BTreeMap<String, Vec<String>>;

/// Parses a single ascii armor header separator.
fn armor_header_sep(i: &[u8]) -> IResult<&[u8], &[u8]> {
    tag(&b"-----"[..])(i)
}

#[inline]
fn parse_digit(x: &[u8]) -> Result<usize> {
    let s = str::from_utf8(x)?;
    let digit: usize = s.parse()?;
    Ok(digit)
}

/// Parses the type inside of an ascii armor header.
fn armor_header_type(i: &[u8]) -> IResult<&[u8], BlockType> {
    alt((
        value(BlockType::PublicKey, tag("PGP PUBLIC KEY BLOCK")),
        value(BlockType::PrivateKey, tag("PGP PRIVATE KEY BLOCK")),
        map(
            preceded(
                tag("PGP MESSAGE, PART "),
                pair(
                    map_res(digit1, parse_digit),
                    opt(preceded(tag("/"), map_res(digit1, parse_digit))),
                ),
            ),
            |(x, y)| BlockType::MultiPartMessage(x, y.unwrap_or(0)),
        ),
        value(BlockType::Message, tag("PGP MESSAGE")),
        value(BlockType::Signature, tag("PGP SIGNATURE")),
        value(BlockType::File, tag("PGP ARMORED FILE")),
        value(BlockType::CleartextMessage, tag("PGP SIGNED MESSAGE")),
        // OpenSSL formats
        // Public Key File PKCS#1
        value(
            BlockType::PublicKeyPKCS1(PKCS1Type::RSA),
            tag("RSA PUBLIC KEY"),
        ),
        // Public Key File PKCS#1
        value(
            BlockType::PublicKeyPKCS1(PKCS1Type::DSA),
            tag("DSA PUBLIC KEY"),
        ),
        // Public Key File PKCS#1
        value(
            BlockType::PublicKeyPKCS1(PKCS1Type::EC),
            tag("EC PUBLIC KEY"),
        ),
        // Public Key File PKCS#8
        value(BlockType::PublicKeyPKCS8, tag("PUBLIC KEY")),
        // OpenSSH Public Key File
        value(BlockType::PublicKeyOpenssh, tag("OPENSSH PUBLIC KEY")),
        // Private Key File PKCS#1
        value(
            BlockType::PrivateKeyPKCS1(PKCS1Type::RSA),
            tag("RSA PRIVATE KEY"),
        ),
        // Private Key File PKCS#1
        value(
            BlockType::PrivateKeyPKCS1(PKCS1Type::DSA),
            tag("DSA PRIVATE KEY"),
        ),
        // Private Key File PKCS#1
        value(
            BlockType::PrivateKeyPKCS1(PKCS1Type::EC),
            tag("EC PRIVATE KEY"),
        ),
        // Private Key File PKCS#8
        value(BlockType::PrivateKeyPKCS8, tag("PRIVATE KEY")),
        // OpenSSH Private Key File
        value(BlockType::PrivateKeyOpenssh, tag("OPENSSH PRIVATE KEY")),
    ))
    .parse(i)
}

/// Parses a single armor header line.
fn armor_header_line(i: &[u8]) -> IResult<&[u8], BlockType> {
    delimited(
        pair(armor_header_sep, tag(&b"BEGIN "[..])),
        armor_header_type,
        armor_header_sep,
    )
    .parse(i)
}

/// Parses a single key value pair, for the header.
fn key_value_pair(i: &[u8]) -> IResult<&[u8], (&str, &str)> {
    let (i, key) = map_res(
        alt((
            complete(take_until1(":\r\n")),
            complete(take_until1(":\n")),
            complete(take_until1(": ")),
        )),
        str::from_utf8,
    )
    .parse(i)?;

    // consume the ":"
    let (i, _) = tag(":")(i)?;
    let (i, t) = alt((tag(" "), line_ending)).parse(i)?;

    let (i, value) = if t == b" " {
        let (i, value) = map_res(not_line_ending, str::from_utf8).parse(i)?;
        let (i, _) = line_ending(i)?;
        (i, value)
    } else {
        // empty value
        (i, "")
    };

    Ok((i, (key, value)))
}

/// Parses a list of key value pairs.
fn key_value_pairs(i: &[u8]) -> IResult<&[u8], Vec<(&str, &str)>> {
    many0(complete(key_value_pair)).parse(i)
}

/// Parses the full armor header.
fn armor_headers(i: &[u8]) -> IResult<&[u8], Headers> {
    map(key_value_pairs, |pairs| {
        // merge multiple values with the same name
        let mut out = BTreeMap::<String, Vec<String>>::new();
        for (k, v) in pairs {
            let e = out.entry(k.to_string()).or_default();
            e.push(v.to_string());
        }
        out
    })
    .parse(i)
}

/// Armor Header
pub fn armor_header(i: &[u8]) -> IResult<&[u8], (BlockType, Headers)> {
    let (i, typ) = armor_header_line(i)?;
    let (i, headers) = match typ {
        BlockType::CleartextMessage => armor_headers_hash(i)?,
        _ => armor_headers(i)?,
    };

    Ok((i, (typ, headers)))
}

fn armor_headers_hash(i: &[u8]) -> IResult<&[u8], Headers> {
    let (i, headers) = many0(complete(hash_header_line)).parse(i)?;

    let mut res = BTreeMap::new();
    let headers = headers.into_iter().flatten().collect();
    res.insert("Hash".to_string(), headers);

    Ok((i, res))
}

pub fn alphanumeric1_or_dash<T, E: nom::error::ParseError<T>>(input: T) -> IResult<T, T, E>
where
    T: Input,
    <T as Input>::Item: AsChar,
{
    input.split_at_position1(
        |item| {
            let i = item.as_char();

            !(i.is_alphanum() || i == '-')
        },
        nom::error::ErrorKind::AlphaNumeric,
    )
}

fn hash_header_line(i: &[u8]) -> IResult<&[u8], Vec<String>> {
    let (i, _) = tag("Hash: ")(i)?;
    let (i, mut values) = many0(map_res(terminated(alphanumeric1_or_dash, tag(",")), |s| {
        str::from_utf8(s).map(|s| s.to_string())
    }))
    .parse(i)?;

    let (i, last_value) = terminated(
        map_res(alphanumeric1_or_dash, |s| {
            str::from_utf8(s).map(|s| s.to_string())
        }),
        line_ending,
    )
    .parse(i)?;
    values.push(last_value);

    Ok((i, values))
}

pub fn decode(i: &[u8]) -> Result<(BlockType, Headers, Vec<u8>)> {
    let (remaining, (typ, headers)) = armor_header(i).map_err(|e: nom::Err<nom::error::Error<_>>| {
        crate::errors::Error::from(e.to_string())
    })?;

    // Skip the blank line after headers
    let remaining = if remaining.starts_with(b"\r\n") {
        &remaining[2..]
    } else if remaining.starts_with(b"\n") {
        &remaining[1..]
    } else {
        remaining
    };

    // Find the footer and extract the base64 content
    let footer = format!("-----END {}-----", typ);
    let footer_start = remaining
        .windows(footer.len())
        .position(|w| w == footer.as_bytes());

    let base64_content = if let Some(footer_start) = footer_start {
        &remaining[..footer_start]
    } else {
        return Err(crate::errors::Error::from("armor footer not found".to_string()));
    };

    let (base64_data, _checksum) = if let Some(pos) = memchr::memrchr(b'\n', base64_content) {
        if base64_content.get(pos + 1) == Some(&b'=') {
            // Found checksum
            (&base64_content[..pos], Some(&base64_content[pos + 1..]))
        } else {
            (base64_content, None)
        }
    } else {
        (base64_content, None)
    };

    let cleaned_base64: Vec<u8> = base64_data
        .iter()
        .filter(|&&b| !matches!(b, b'\r' | b'\n'))
        .copied()
        .collect();

    let mut reader = Base64Reader::new(BufReader::new(Cursor::new(&cleaned_base64)));
    let mut decoded = Vec::new();
    reader.read_to_end(&mut decoded)?;

    Ok((typ, headers, decoded))
}
