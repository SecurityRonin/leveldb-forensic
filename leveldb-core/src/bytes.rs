//! Bounds-checked cursor over a byte slice.
//!
//! Every read is length-checked before it happens: a truncated or lying length
//! yields an [`Error`], never a panic or an out-of-bounds index. Length-prefixed
//! reads additionally cap the claimed length at the bytes actually remaining, so
//! a hostile varint cannot drive an over-allocation.

use crate::error::Error;
use integer_encoding::VarInt;

pub(crate) struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub(crate) fn pos(&self) -> usize {
        self.pos
    }

    pub(crate) fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Take exactly `n` bytes, advancing the cursor. Errors if fewer remain.
    pub(crate) fn take(&mut self, n: usize, what: &'static str) -> Result<&'a [u8], Error> {
        let end = self.pos.checked_add(n).ok_or(Error::UnexpectedEof {
            what,
            offset: self.pos,
        })?;
        let slice = self.buf.get(self.pos..end).ok_or(Error::UnexpectedEof {
            what,
            offset: self.pos,
        })?;
        self.pos = end;
        Ok(slice)
    }

    pub(crate) fn read_u8(&mut self, what: &'static str) -> Result<u8, Error> {
        Ok(self.take(1, what)?[0])
    }

    pub(crate) fn read_u32_le(&mut self, what: &'static str) -> Result<u32, Error> {
        let b = self.take(4, what)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub(crate) fn read_u64_le(&mut self, what: &'static str) -> Result<u64, Error> {
        let b = self.take(8, what)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    /// Decode a LEB128 varint (LevelDB's integer encoding). Truncated or
    /// overlong encodings error rather than panic.
    pub(crate) fn read_varint_u64(&mut self) -> Result<u64, Error> {
        let rest = self.buf.get(self.pos..).unwrap_or(&[]);
        let (value, consumed) =
            u64::decode_var(rest).ok_or(Error::BadVarint { offset: self.pos })?;
        // `decode_var` never reports more bytes than it read from `rest`.
        self.pos = self.pos.saturating_add(consumed);
        Ok(value)
    }

    pub(crate) fn read_varint_u32(&mut self) -> Result<u32, Error> {
        let offset = self.pos;
        let v = self.read_varint_u64()?;
        u32::try_from(v).map_err(|_| Error::BadVarint { offset })
    }

    /// Read a length-prefixed slice: a varint32 length followed by that many
    /// bytes. The length is capped at the bytes remaining, so an oversized or
    /// lying length errors instead of allocating.
    pub(crate) fn read_length_prefixed(&mut self, what: &'static str) -> Result<&'a [u8], Error> {
        let offset = self.pos;
        let len = self.read_varint_u64()?;
        let available = self.remaining() as u64;
        if len > available {
            return Err(Error::LengthOutOfRange {
                what,
                value: len,
                available,
                offset,
            });
        }
        // `len <= available`, and `available` is `remaining()` (a `usize`) widened
        // to `u64`, so `len` always fits back into `usize` — the cast cannot lose
        // bits on any pointer width. (An infallible cast, not a fallible convert,
        // so there is no dead error arm to test.)
        let len = len as usize;
        self.take(len, what)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_varint_u32_overflows_on_a_too_large_value() {
        // A varint encoding a value > u32::MAX must error (the map_err arm),
        // not truncate silently.
        let mut cur = Cursor::new(&[0xff, 0xff, 0xff, 0xff, 0x1f]); // 0x1_ffff_ffff
        assert!(matches!(
            cur.read_varint_u32(),
            Err(Error::BadVarint { offset: 0 })
        ));
    }

    #[test]
    fn read_varint_u32_accepts_an_in_range_value() {
        let mut cur = Cursor::new(&[0xac, 0x02]); // 300
        assert_eq!(cur.read_varint_u32().unwrap(), 300);
    }

    #[test]
    fn read_length_prefixed_rejects_a_lying_length() {
        // Length prefix (varint) 200 but only a few bytes remain.
        let mut cur = Cursor::new(&[0xc8, 0x01, 0xaa, 0xbb]); // len=200, 2 body bytes
        assert!(matches!(
            cur.read_length_prefixed("x"),
            Err(Error::LengthOutOfRange {
                value: 200,
                available: 2,
                ..
            })
        ));
    }

    #[test]
    fn read_length_prefixed_reads_the_exact_body() {
        let mut cur = Cursor::new(&[0x03, b'a', b'b', b'c', b'z']);
        assert_eq!(cur.read_length_prefixed("x").unwrap(), b"abc");
        assert_eq!(cur.remaining(), 1);
    }
}
