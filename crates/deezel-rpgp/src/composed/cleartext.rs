//! Implements Cleartext Signature Framework
extern crate alloc;
use alloc::vec;
use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::format;
use buffer_redux::BufReader;
use chrono::SubsecRound;
use log::debug;

use crate::{
    armor::{self, BlockType, Headers},
    composed::{ArmorOptions, Deserializable, StandaloneSignature},
    crypto::hash::HashAlgorithm,
    errors::{bail, ensure, ensure_eq, format_err, InvalidInputSnafu, Result},
    line_writer::LineBreak,
    packet::{Signature, SignatureConfig, SignatureType, Subpacket, SubpacketData},
    types::{KeyVersion, Password, PublicKeyTrait, SecretKeyTrait},
    MAX_BUFFER_SIZE,
};

#[cfg(feature = "std")]
use crate::normalize_lines::{normalize_lines, NormalizedReader};



/// Implementation of a Cleartext Signed Message.
///
/// Ref <https://www.rfc-editor.org/rfc/rfc9580.html#name-cleartext-signature-framewo>
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleartextSignedMessage {
    /// Normalized and dash-escaped representation of the signed text.
    /// This is exactly the format that gets serialized in cleartext format.
    ///
    /// This representation retains the line-ending encoding of the input material.
    csf_encoded_text: String,

    /// Hash algorithms that are used in the signature(s) in this message
    hashes: Vec<HashAlgorithm>,

    /// The actual signature(s).
    signatures: Vec<StandaloneSignature>,
}

impl CleartextSignedMessage {
    /// Construct a new cleartext message and sign it using the given key.
    pub fn new(
        text: &str,
        config: SignatureConfig,
        key: &impl SecretKeyTrait,
        key_pw: &Password,
    ) -> Result<Self>
    where
    {
        let mut bytes = text.as_bytes();
        #[cfg(feature = "std")]
        let signature_text = NormalizedReader::new(&mut bytes, LineBreak::Crlf);
        #[cfg(not(feature = "std"))]
        let signature_text = bytes;
        let hash = config.hash_alg;
        let signature = config.sign(key, key_pw, signature_text)?;
        let signature = StandaloneSignature::new(signature);

        Ok(Self {
            csf_encoded_text: dash_escape(text),
            hashes: vec![hash],
            signatures: vec![signature],
        })
    }

    /// Sign the given text.
    pub fn sign<R>(rng: R, text: &str, key: &impl SecretKeyTrait, key_pw: &Password) -> Result<Self>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let hashed_subpackets = vec![
            Subpacket::regular(SubpacketData::IssuerFingerprint(key.fingerprint()))?,
            Subpacket::regular(SubpacketData::SignatureCreationTime(
                chrono::Utc::now().trunc_subsecs(0),
            ))?,
        ];

        let mut config = SignatureConfig::from_key(rng, key, SignatureType::Text)?;
        config.hashed_subpackets = hashed_subpackets;

        // If the version of the issuer is greater than 4, this subpacket MUST NOT be included in
        // the signature.
        if key.version() <= KeyVersion::V4 {
            config.unhashed_subpackets =
                vec![Subpacket::regular(SubpacketData::Issuer(key.key_id()))?];
        }

        Self::new(text, config, key, key_pw)
    }

    /// Sign the same message with multiple keys.
    ///
    /// The signer function gets invoked with the normalized original text to be signed,
    /// and needs to produce the individual signatures.
    pub fn new_many<F>(text: &str, signer: F) -> Result<Self>
    where
        F: FnOnce(&str) -> Result<Vec<Signature>>,
    {
        #[cfg(feature = "std")]
        let signature_text = normalize_lines(text, LineBreak::Crlf);
        #[cfg(not(feature = "std"))]
        let signature_text = text.into();

        let raw_signatures = signer(&signature_text[..])?;
        let mut hashes = Vec::new();
        let mut signatures = Vec::new();

        for signature in raw_signatures {
            let hash_alg = signature
                .hash_alg()
                .ok_or_else(|| InvalidInputSnafu {}.build())?;
            if !hashes.contains(&hash_alg) {
                hashes.push(hash_alg);
            }
            let signature = StandaloneSignature::new(signature);
            signatures.push(signature);
        }

        Ok(Self {
            csf_encoded_text: dash_escape(text),
            hashes,
            signatures,
        })
    }

    /// The signature on the message.
    pub fn signatures(&self) -> &[StandaloneSignature] {
        &self.signatures
    }

    /// Verify the signature against the normalized cleartext.
    ///
    /// On success returns the first signature that verified against this key.
    pub fn verify(&self, key: &impl PublicKeyTrait) -> Result<&StandaloneSignature> {
        let nt = self.signed_text();
        for signature in &self.signatures {
            if signature.verify(key, nt.as_bytes()).is_ok() {
                return Ok(signature);
            }
        }

        bail!("No matching signature found")
    }

    /// Verify each signature, potentially against a different key.
    pub fn verify_many<F>(&self, verifier: F) -> Result<()>
    where
        F: Fn(usize, &StandaloneSignature, &[u8]) -> Result<()>,
    {
        let nt = self.signed_text();
        for (i, signature) in self.signatures.iter().enumerate() {
            verifier(i, signature, nt.as_bytes())?;
        }
        Ok(())
    }

    /// Normalizes the text to the format that was hashed for the signature.
    /// The output is normalized to "\r\n" line endings.
    pub fn signed_text(&self) -> String {
        let unescaped = dash_unescape_and_trim(&self.csf_encoded_text);

        #[cfg(feature = "std")]
        {
            normalize_lines(&unescaped, LineBreak::Crlf).to_string()
        }
        #[cfg(not(feature = "std"))]
        {
            unescaped
        }
    }

    /// The "cleartext framework"-encoded (i.e. dash-escaped) form of the message.
    pub fn text(&self) -> &str {
        &self.csf_encoded_text
    }

    /// Parse from an arbitrary reader, containing the text of the message.
    pub fn from_armor(bytes: &[u8]) -> Result<(Self, Headers)> {
        Self::from_armor_buf(bytes, MAX_BUFFER_SIZE)
    }

    /// Parse from string, containing the text of the message.
    pub fn from_string(input: &str) -> Result<(Self, Headers)> {
        Self::from_armor_buf(input.as_bytes(), MAX_BUFFER_SIZE)
    }

    /// Parse from a buffered reader, containing the text of the message.
    pub fn from_armor_buf(mut b: &[u8], limit: usize) -> Result<(Self, Headers)> {
        debug!("parsing cleartext message");
        // Headers
        // This is a placeholder implementation
        let headers = Headers::new();

        Self::from_armor_after_header(b, headers, limit)
    }

    pub fn from_armor_after_header(
        mut b: &[u8],
        headers: Headers,
        limit: usize,
    ) -> Result<(Self, Headers)> {
        let hashes = validate_headers(headers)?;

        debug!("Found Hash headers: {:?}", hashes);

        // Cleartext Body
        let (csf_encoded_text, prefix) = read_cleartext_body(&mut b)?;
        
        // This needs to be refactored to not use crate::io::Cursor
        // let b = crate::io::Cursor::new(prefix).chain(b);

        // Signatures
        // This needs to be refactored to not use crate::io
        let signatures = Vec::new();

        Ok((
            Self {
                csf_encoded_text,
                hashes,
                signatures,
            },
            Headers::new(),
        ))
    }

    pub fn to_armored_writer(
        &self,
        writer: &mut impl crate::io::Write,
        opts: ArmorOptions<'_>,
    ) -> Result<()> {
        // Header
        writer.write_all(HEADER_LINE.as_bytes())?;
        writer.write_all(b"\n")?;

        // Hashes
        for hash in &self.hashes {
            writer.write_all(b"Hash: ")?;
            writer.write_all(hash.to_string().as_bytes())?;
            writer.write_all(b"\n")?;
        }
        writer.write_all(b"\n")?;

        // Cleartext body
        writer.write_all(self.csf_encoded_text.as_bytes())?;
        writer.write_all(b"\n")?;

        armor::write(
            &self.signatures,
            armor::BlockType::Signature,
            writer,
            opts.headers,
            opts.include_checksum,
        )?;

        Ok(())
    }

    pub fn to_armored_bytes(&self, opts: ArmorOptions<'_>) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        self.to_armored_writer(&mut buf, opts)?;
        Ok(buf)
    }

    pub fn to_armored_string(&self, opts: ArmorOptions<'_>) -> Result<String> {
        let res = String::from_utf8(self.to_armored_bytes(opts)?).map_err(|e| e.utf8_error())?;
        Ok(res)
    }
}

fn validate_headers(headers: Headers) -> Result<Vec<HashAlgorithm>> {
    let mut hashes = Vec::new();
    for (name, values) in headers {
        ensure_eq!(name, "Hash", "unexpected header");
        for value in values {
            let h: HashAlgorithm = value
                .parse()
                .map_err(|_| format_err!("unknown hash algorithm {}", value))?;
            hashes.push(h);
        }
    }
    Ok(hashes)
}

/// Dash escape the given text.
///
/// This implementation is implicitly agnostic between "\n" and "\r\n" line endings.
///
/// Ref <https://www.rfc-editor.org/rfc/rfc9580.html#name-dash-escaped-text>
fn dash_escape(text: &str) -> String {
    let mut out = String::new();
    for line in text.split_inclusive('\n') {
        if line.starts_with('-') {
            out += "- ";
        }
        out.push_str(line);
    }

    out
}

/// Undo dash escaping of `text`, and trim space/tabs at the end of lines.
///
/// This implementation can handle both "\n" and "\r\n" line endings.
fn dash_unescape_and_trim(text: &str) -> String {
    let mut out = String::new();

    for line in text.split_inclusive('\n') {
        // break each line into "content" and "line ending"
        let line_end_len = if line.ends_with("\r\n") {
            2
        } else if line.ends_with('\n') {
            1
        } else {
            0
        };
        let (content, end) = line.split_at(line.len() - line_end_len);

        // strip dash escapes if they exist
        let undashed = content.strip_prefix("- ").unwrap_or(content);

        // trim spaces/tabs from the end of line content
        let trimmed = undashed.trim_end_matches([' ', '\t']);

        // append normalized line content
        out += trimmed;

        // append line ending
        out += end;
    }

    out
}

/// Does the remaining buffer contain any non-whitespace characters?
fn has_rest(mut b: &[u8]) -> Result<bool> {
    // This function needs to be refactored to not use crate::io
    Ok(false)
}

const HEADER_LINE: &str = "-----BEGIN PGP SIGNED MESSAGE-----";

fn read_cleartext_body(b: &mut &[u8]) -> Result<(String, String)> {
    let mut out = String::new();

    loop {
        // This function needs to be refactored to not use crate::io
        return Ok((out, String::new()));
    }
}
