//! Decoded Chrome/Chromium storage value types.
//!
//! Reference: `cclgroupltd/ccl_chromium_reader` `ccl_chromium_localstorage.py`
//! (`decode_string`). A **type-prefixed string** is a one-byte prefix followed
//! by the encoded body: prefix `0x00` = UTF-16-LE, `0x01` = `iso-8859-1`
//! (Latin-1); any other prefix is malformed and surfaced raw with `lossy` set.
//! Decoding never fails — a lone surrogate or dangling byte becomes U+FFFD and
//! sets `lossy`, and the raw bytes are always retained.

/// How a [`StorageValue`] was decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Encoding {
    /// UTF-16 little-endian (type prefix `0x00`).
    Utf16Le,
    /// 8-bit `iso-8859-1` / Latin-1 (type prefix `0x01`).
    Latin1,
    /// The value had no bytes at all.
    Empty,
    /// An unrecognised type-prefix byte (carried verbatim).
    Unknown(u8),
}

/// A decoded storage value. The `raw` bytes are always retained; `lossy` is set
/// whenever decoding had to substitute a replacement character or the prefix was
/// unrecognised, so a caller cannot mistake a lossy decode for a clean one
/// (secure-by-design).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StorageValue {
    /// Best-effort decoded text (U+FFFD substituted for undecodable units).
    pub text: String,
    /// The raw value bytes, verbatim.
    pub raw: Vec<u8>,
    /// Which decoder produced `text`.
    pub encoding: Encoding,
    /// `true` if decoding was lossy or the prefix was unrecognised.
    pub lossy: bool,
}

impl StorageValue {
    /// The empty value (e.g. a deletion tombstone carries no value bytes).
    pub(crate) fn empty() -> Self {
        StorageValue {
            text: String::new(),
            raw: Vec::new(),
            encoding: Encoding::Empty,
            lossy: false,
        }
    }
}

/// Decode a UTF-16-LE body. A trailing odd byte or a lone surrogate marks the
/// result lossy but never panics.
pub(crate) fn decode_utf16le(body: &[u8], raw: &[u8]) -> StorageValue {
    let mut lossy = false;
    let mut chunks = body.chunks_exact(2);
    let units: Vec<u16> = chunks
        .by_ref()
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    if !chunks.remainder().is_empty() {
        lossy = true; // dangling half code unit
    }
    let mut text = String::new();
    for unit in char::decode_utf16(units) {
        if let Ok(ch) = unit {
            text.push(ch);
        } else {
            text.push('\u{FFFD}');
            lossy = true;
        }
    }
    StorageValue {
        text,
        raw: raw.to_vec(),
        encoding: Encoding::Utf16Le,
        lossy,
    }
}

/// Decode an `iso-8859-1` body. Every byte maps to U+00xx, so this is total and
/// never lossy.
pub(crate) fn decode_latin1(body: &[u8], raw: &[u8]) -> StorageValue {
    let text: String = body.iter().map(|&b| b as char).collect();
    StorageValue {
        text,
        raw: raw.to_vec(),
        encoding: Encoding::Latin1,
        lossy: false,
    }
}

/// Decode a type-prefixed string (Local Storage script keys and values): prefix
/// `0x00` = UTF-16-LE, `0x01` = Latin-1, anything else = malformed (surfaced raw
/// with `lossy = true`).
pub(crate) fn decode_type_prefixed(raw: &[u8]) -> StorageValue {
    match raw.first() {
        None => StorageValue::empty(),
        Some(0) => decode_utf16le(&raw[1..], raw),
        Some(1) => decode_latin1(&raw[1..], raw),
        Some(&other) => StorageValue {
            // Surface the raw bytes; a best-effort lossy view helps a human triage.
            text: String::from_utf8_lossy(raw).into_owned(),
            raw: raw.to_vec(),
            encoding: Encoding::Unknown(other),
            lossy: true,
        },
    }
}

/// Decode a Session Storage value. These are UTF-16-LE, but a leading `0x00`
/// (UTF-16-LE) or `0x01` (Latin-1) type prefix is handled defensively when
/// present — matching the observed on-disk variation.
pub(crate) fn decode_session_value(raw: &[u8]) -> StorageValue {
    match raw.first() {
        None => StorageValue::empty(),
        Some(0) => decode_utf16le(&raw[1..], raw),
        Some(1) => decode_latin1(&raw[1..], raw),
        Some(_) => decode_utf16le(raw, raw),
    }
}
