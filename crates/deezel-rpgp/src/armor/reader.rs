extern crate alloc;
use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec::Vec,
    format,
};
use core::{fmt, str};
use crate::ser::Serialize;

#[cfg(feature = "std")]
use std::io::{self, BufRead, Cursor, Read};

#[cfg(not(feature = "std"))]
use crate::io::{self, BufRead, Cursor, Read};

use base64::Engine;
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
    base64::{Base64Decoder, Base64Reader},
    errors::Result,
};

use crate::errors::bail;
use crate::io::BufReader;

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
    fn to_writer<W: io::Write>(&self, w: &mut W) -> Result<()> {
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
        pair(armor_header_sep, line_ending),
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

use byteorder::{BigEndian, ByteOrder};
use crc24::Crc24Hasher;
#[cfg(feature = "std")]
use std::hash::Hasher;

#[cfg(not(feature = "std"))]
use core::hash::Hasher;

/// Read the checksum from an base64 encoded buffer.
fn read_checksum(input: &[u8]) -> io::Result<u64> {
    let checksum = base64::engine::general_purpose::STANDARD
        .decode(input)
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
    let mut buf = [0; 4];
    let mut i = checksum.len();
    for a in checksum.iter().rev() {
        buf[i] = *a;
        i -= 1;
    }
    Ok(u64::from(BigEndian::read_u32(&buf)))
}
pub fn header_parser(i: &[u8]) -> IResult<&[u8], (BlockType, Headers, bool)> {
    // https://www.rfc-editor.org/rfc/rfc9580.html#name-forming-ascii-armor
    let (i, prefix) = nom::bytes::streaming::take_until("-----")(i)?;
    let has_leading_data = !prefix.is_empty();
    // "An Armor Header Line, appropriate for the type of data" (returned as 'typ')
    // "Armor Headers" ('headers')
    let (i, (typ, headers)) = armor_header(i)?;
    // "A blank (zero length or containing only whitespace) line"
    let (i, _) = pair(nom::character::streaming::space0, line_ending).parse(i)?;
    Ok((i, (typ, headers, has_leading_data)))
}
fn footer_parser(i: &[u8]) -> IResult<&[u8], (Option<u64>, BlockType)> {
    let (i, checksum) = opt(map_res(
        preceded(tag("="), nom::bytes::streaming::take(4u8)),
        |v: &[u8]| read_checksum(v).map_err(|_| nom::error::ErrorKind::Verify),
    ))
    .parse(i)?;
    let (i, _) = opt(line_ending).parse(i)?; // consume optional newline after checksum or before footer
    let (i, typ) = armor_footer_line(i)?;
    Ok((i, (checksum, typ)))
}

/// Parses a single armor footer line
fn armor_footer_line(i: &[u8]) -> IResult<&[u8], BlockType> {
    delimited(
        pair(armor_header_sep, tag(&b"END "[..])),
        armor_header_type,
        pair(armor_header_sep, opt(complete(line_ending))),
    )
    .parse(i)
}
/// Streaming based ascii armor parsing.
#[derive(derive_more::Debug)]
pub struct Dearmor<R: BufRead> {
    /// The ascii armor parsed block type.
    pub typ: Option<BlockType>,
    /// The headers found in the armored file.
    pub headers: Headers,
    /// Optional crc checksum
    pub checksum: Option<u64>,
    /// Current state
    current_part: Part<R>,
    #[debug("Crc24Hasher")]
    crc: Crc24Hasher,
    /// Maximum buffer limit
    max_buffer_limit: usize,
}
/// Internal indicator, where in the parsing phase we are
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
enum Part<R: BufRead> {
    Header(R),
    Body(Base64Decoder<Base64Reader<R>>),
    Footer(crate::io::BufReader<R>),
    Done(crate::io::BufReader<R>),
    Temp,
}
impl<R: BufRead> Dearmor<R> {
    /// Creates a new `Dearmor`, with the default limit of 1GiB.
    pub fn new(input: R) -> Self {
        Self::with_limit(input, 1024 * 1024 * 1024)
    }
    /// Creates a new `Dearmor` with the provided maximum buffer size.
    pub fn with_limit(input: R, limit: usize) -> Self {
        Dearmor {
            typ: None,
            headers: BTreeMap::new(),
            checksum: None,
            current_part: Part::Header(input),
            crc: Default::default(),
            max_buffer_limit: limit,
        }
    }
    pub fn into_parts(self) -> (Option<BlockType>, Headers, Option<u64>, BufReader<R>) {
        let Self {
            typ,
            headers,
            checksum,
            current_part,
            ..
        } = self;
        let Part::Done(b) = current_part else {
            panic!("can only be called when done");
        };
        (typ, headers, checksum, b)
    }
    /// The current maximum buffer limit.
    pub fn max_buffer_limit(&self) -> usize {
        self.max_buffer_limit
    }
    pub fn read_only_header(mut self) -> Result<(BlockType, Headers, bool, R)> {
        let header = core::mem::replace(&mut self.current_part, Part::Temp);
        if let Part::Header(mut b) = header {
            let (typ, headers, leading) =
                Self::read_header_internal(&mut b, self.max_buffer_limit)?;
            return Ok((typ, headers, leading, b));
        }
        bail!("invalid state, cannot read header");
    }
    pub fn after_header(typ: BlockType, headers: Headers, input: R, limit: usize) -> Self {
        Self {
            typ: Some(typ),
            headers,
            checksum: None,
            current_part: Part::Body(Base64Decoder::new(Base64Reader::new(input))),
            crc: Default::default(),
            max_buffer_limit: limit,
        }
    }
    pub fn read_header(&mut self) -> Result<()> {
        let header = core::mem::replace(&mut self.current_part, Part::Temp);
        if let Part::Header(mut b) = header {
            let (typ, headers, _has_leading_data) =
                Self::read_header_internal(&mut b, self.max_buffer_limit)?;
            self.typ = Some(typ);
            self.headers = headers;
            self.current_part = Part::Body(Base64Decoder::new(Base64Reader::new(b)));
            return Ok(());
        }
        bail!("invalid state, cannot read header");
    }
    fn read_header_internal(b: &mut R, limit: usize) -> Result<(BlockType, Headers, bool)> {
        let (typ, headers, leading) = read_from_buf(b, "armor header", limit, header_parser)?;
        Ok((typ, headers, leading))
    }
    fn read_footer(&mut self, mut b: crate::io::BufReader<R>) -> Result<()> {
        let (checksum, footer_typ) =
            read_from_buf(&mut b, "armor footer", self.max_buffer_limit, footer_parser)?;
        if let Some(ref header_typ) = self.typ {
            if header_typ != &footer_typ {
                self.current_part = Part::Done(b);
                bail!(
                    "armor ascii footer does not match header: {:?} != {:?}",
                    self.typ,
                    footer_typ
                );
            }
        }
        self.checksum = checksum;
        self.current_part = Part::Done(b);
        // check checksum if there is one
        if let Some(expected) = self.checksum {
            let actual = self.crc.finish();
            if expected != actual {
                bail!("invalid crc24 checksum");
            }
        }
        Ok(())
    }
}
impl<R: BufRead> Read for Dearmor<R> {
    fn read(&mut self, into: &mut [u8]) -> io::Result<usize> {
        let mut read = 0;
        loop {
            let current_part = core::mem::replace(&mut self.current_part, Part::Temp);
            match current_part {
                Part::Header(mut b) => {
                    let (typ, headers, _leading) =
                        Self::read_header_internal(&mut b, self.max_buffer_limit).map_err(|e| {
                            io::Error::new(io::ErrorKind::Other, "failed to read header")
                        })?;
                    self.typ = Some(typ);
                    self.headers = headers;
                    self.current_part = Part::Body(Base64Decoder::new(Base64Reader::new(b)));
                }
                Part::Body(mut b) => {
                    let last_read = b.read(&mut into[read..])?;
                    if last_read > 0 {
                        self.crc.write(&into[read..read + last_read]);
                    }
                    if last_read == 0 && read < into.len() {
                        // we are done with the body
                        let b = b.into_inner().into_inner();
                        self.current_part = Part::Footer(BufReader::new(b));
                    } else {
                        self.current_part = Part::Body(b);
                    }
                    read += last_read;
                    if read == into.len() {
                        return Ok(read);
                    }
                }
                Part::Footer(mut b) => {
                    self.read_footer(b)
                        .map_err(|e| io::Error::new(io::ErrorKind::Other, "failed to read footer"))?;
                }
                Part::Done(b) => {
                    self.current_part = Part::Done(b);
                    return Ok(read);
                }
                Part::Temp => panic!("invalid state"),
            }
        }
    }
}
pub(crate) fn read_from_buf<B: BufRead, T, P>(
    b: &mut B,
    ctx: &str,
    limit: usize,
    parser: P,
) -> Result<T>
where
    P: Fn(&[u8]) -> IResult<&[u8], T>,
{
    // Zero copy, single buffer
    let buf = b.fill_buf()?;
    if buf.is_empty() {
        bail!("not enough bytes in buffer: {}", ctx);
    }
    match parser(buf) {
        Ok((remaining, res)) => {
            let consumed = buf.len() - remaining.len();
            b.consume(consumed);
            return Ok(res);
        }
        Err(nom::Err::Incomplete(_)) => {}
        Err(err) => {
            bail!("failed reading: {} {:?}", ctx, err);
        }
    };
    // incomplete
    let mut back_buffer = buf.to_vec();
    let len = back_buffer.len();
    b.consume(len);
    let mut last_buffer_len;
    loop {
        // Safety check to not consume too much
        if back_buffer.len() >= limit {
            bail!("input too large");
        }
        let buf = b.fill_buf()?;
        if buf.is_empty() {
            bail!("not enough bytes in buffer: {}", ctx);
        }
        last_buffer_len = buf.len();
        back_buffer.extend_from_slice(buf);
        match parser(&back_buffer) {
            Ok((remaining, res)) => {
                let consumed = last_buffer_len - remaining.len();
                b.consume(consumed);
                return Ok(res);
            }
            Err(nom::Err::Incomplete(_)) => {
                b.consume(last_buffer_len);
                continue;
            }
            Err(err) => {
                bail!("failed reading: {} {:?}", ctx, err);
            }
        };
    }
}

pub fn decode(i: &[u8]) -> Result<(BlockType, Headers, Vec<u8>)> {
    let mut dearmor = Dearmor::new(BufReader::new(i));
    let mut bytes = Vec::new();
    dearmor.read_to_end(&mut bytes)?;
    Ok((dearmor.typ.unwrap(), dearmor.headers, bytes))
}
