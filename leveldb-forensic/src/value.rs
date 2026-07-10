//! Decoded Chrome/Chromium storage value types.
//!
//! Reference: cclgroupltd/ccl_chromium_reader `ccl_chromium_localstorage.py`
//! (`decode_string`). The decoders themselves land in the GREEN step; this
//! module defines the value type they produce.

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
