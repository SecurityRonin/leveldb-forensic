//! LevelDB SSTable (`.ldb`) reader.
//!
//! Format: <https://github.com/google/leveldb/blob/main/doc/table_format.md>
//!
//! Layout (tail of file): a fixed 48-byte Footer = metaindex `BlockHandle` ‖
//! index `BlockHandle` ‖ zero-pad to 40 ‖ 8-byte magic `0xdb4775248b80fb57`
//! (little-endian). A `BlockHandle` is two varints (offset, size). The index
//! block's entry values are `BlockHandle`s pointing at the data blocks. A data
//! block is prefix-compressed entries followed by a restart array; each entry is
//! `shared_len`,`non_shared_len`,`value_len` (varints), the non-shared key
//! bytes, then the value bytes. A block's 5-byte trailer (at `handle.size`) is a
//! 1-byte compression type (0 = none, 1 = Snappy) plus a masked crc32c (u32 LE).
//! The last 8 bytes of a data-block internal key are `(seq << 8) | value_type`
//! (value_type 0 = deletion, 1 = value).

use std::path::{Path, PathBuf};

use crate::bytes::Cursor;
use crate::error::Error;
use crate::record::Record;

const FOOTER_LEN: usize = 48;
const MAGIC_OFFSET: usize = 40;
const TABLE_MAGIC: u64 = 0xdb47_7524_8b80_fb57;
const BLOCK_TRAILER_LEN: usize = 5;
const COMPRESSION_NONE: u8 = 0;
const COMPRESSION_SNAPPY: u8 = 1;
const TYPE_DELETION: u8 = 0;
const INTERNAL_KEY_TRAILER: usize = 8;

/// Cap on a single decompressed block. A LevelDB block is normally a few KiB
/// (large values inflate it), so this generous ceiling rejects an allocation
/// bomb without refusing legitimate data.
const MAX_DECOMPRESSED_BLOCK: usize = 256 * 1024 * 1024;

#[derive(Clone, Copy)]
struct BlockHandle {
    offset: u64,
    size: u64,
}

/// A decoded block entry: reconstructed key and its raw value bytes.
type Entry = (Vec<u8>, Vec<u8>);

/// crc32c mask used by LevelDB (a rotate plus a constant) so the crc of the crc
/// is never trivially zero.
const CRC_MASK_DELTA: u32 = 0xa282_ead8;

fn mask_crc(crc: u32) -> u32 {
    crc.rotate_left(17).wrapping_add(CRC_MASK_DELTA)
}

fn read_block_handle(cur: &mut Cursor) -> Result<BlockHandle, Error> {
    let offset = cur.read_varint_u64()?;
    let size = cur.read_varint_u64()?;
    Ok(BlockHandle { offset, size })
}

fn parse_footer(buf: &[u8]) -> Result<BlockHandle, Error> {
    if buf.len() < FOOTER_LEN {
        return Err(Error::UnexpectedEof {
            what: "SSTable footer",
            offset: 0,
        });
    }
    let foot_off = buf.len() - FOOTER_LEN;
    let footer = &buf[foot_off..];
    // `footer` is exactly `FOOTER_LEN` bytes, so `[40..48]` is always eight bytes
    // and the conversion cannot fail; the guard arm stays as a defensive backstop
    // (a match, not a closure, so it is a line rather than a counted function).
    let magic_bytes: [u8; 8] = match footer[MAGIC_OFFSET..MAGIC_OFFSET + 8].try_into() {
        Ok(b) => b,
        Err(_) => {
            return Err(Error::UnexpectedEof {
                what: "SSTable footer magic",
                offset: foot_off + MAGIC_OFFSET,
            })
        }
    };
    if u64::from_le_bytes(magic_bytes) != TABLE_MAGIC {
        return Err(Error::BadTableMagic {
            found: magic_bytes,
            offset: foot_off + MAGIC_OFFSET,
        });
    }
    let mut cur = Cursor::new(&footer[..MAGIC_OFFSET]);
    let _metaindex = read_block_handle(&mut cur)?;
    let index = read_block_handle(&mut cur)?;
    Ok(index)
}

/// Read and decompress the block named by `handle` (trailer stripped), verifying
/// the masked crc32c over the block data plus its compression-type byte.
fn read_block(buf: &[u8], handle: BlockHandle) -> Result<Vec<u8>, Error> {
    // On a 64-bit target `usize == u64` so these conversions never fail; on a
    // 32-bit target a `> u32::MAX` handle is genuinely out of range. The guard
    // arms stay as defensive backstops for the 32-bit case (a match, not a
    // closure, so each is a line rather than a counted function).
    let offset = match usize::try_from(handle.offset) {
        Ok(v) => v,
        Err(_) => {
            return Err(Error::LengthOutOfRange {
                what: "block offset",
                value: handle.offset,
                available: buf.len() as u64,
                offset: 0,
            })
        }
    };
    let size = match usize::try_from(handle.size) {
        Ok(v) => v,
        Err(_) => {
            return Err(Error::LengthOutOfRange {
                what: "block size",
                value: handle.size,
                available: buf.len() as u64,
                offset,
            })
        }
    };
    let end = offset
        .checked_add(size)
        .and_then(|e| e.checked_add(BLOCK_TRAILER_LEN))
        .ok_or(Error::LengthOutOfRange {
            what: "block extent",
            value: handle.size,
            available: buf.len() as u64,
            offset,
        })?;
    let region = buf.get(offset..end).ok_or(Error::LengthOutOfRange {
        what: "block",
        value: handle.size,
        available: buf.len().saturating_sub(offset) as u64,
        offset,
    })?;

    let data = &region[..size];
    let type_byte = region[size];
    let stored_crc = u32::from_le_bytes([
        region[size + 1],
        region[size + 2],
        region[size + 3],
        region[size + 4],
    ]);
    // crc covers the block data followed by the 1-byte compression type.
    let computed = mask_crc(crc32c::crc32c(&region[..=size]));
    if computed != stored_crc {
        return Err(Error::BadBlockCrc {
            stored: stored_crc,
            computed,
            offset,
        });
    }

    match type_byte {
        COMPRESSION_NONE => Ok(data.to_vec()),
        COMPRESSION_SNAPPY => {
            let out_len = snap::raw::decompress_len(data).map_err(|_| Error::LengthOutOfRange {
                what: "snappy block",
                value: 0,
                available: MAX_DECOMPRESSED_BLOCK as u64,
                offset,
            })?;
            if out_len > MAX_DECOMPRESSED_BLOCK {
                return Err(Error::LengthOutOfRange {
                    what: "snappy decompressed block",
                    value: out_len as u64,
                    available: MAX_DECOMPRESSED_BLOCK as u64,
                    offset,
                });
            }
            snap::raw::Decoder::new()
                .decompress_vec(data)
                .map_err(|_| Error::LengthOutOfRange {
                    what: "snappy block",
                    value: out_len as u64,
                    available: MAX_DECOMPRESSED_BLOCK as u64,
                    offset,
                })
        }
        other => Err(Error::UnknownCompression {
            kind: other,
            offset: offset + size,
        }),
    }
}

/// Parse a block body (entries + restart array) into `(key, value)` pairs. The
/// same routine serves index blocks (values are encoded `BlockHandle`s) and data
/// blocks (keys are internal keys). Restart points are an iteration optimisation
/// only; a straight prefix-decode over every entry reconstructs each key.
fn parse_block_entries(block: &[u8]) -> Result<Vec<Entry>, Error> {
    if block.len() < 4 {
        return Err(Error::UnexpectedEof {
            what: "block restart count",
            offset: 0,
        });
    }
    let n_off = block.len() - 4;
    let num_restarts = u32::from_le_bytes([
        block[n_off],
        block[n_off + 1],
        block[n_off + 2],
        block[n_off + 3],
    ]) as usize;
    let restart_bytes = num_restarts.checked_mul(4).ok_or(Error::LengthOutOfRange {
        what: "restart array",
        value: num_restarts as u64,
        available: n_off as u64,
        offset: n_off,
    })?;
    let entries_end = n_off
        .checked_sub(restart_bytes)
        .ok_or(Error::LengthOutOfRange {
            what: "restart array",
            value: restart_bytes as u64,
            available: n_off as u64,
            offset: n_off,
        })?;

    let mut cur = Cursor::new(&block[..entries_end]);
    let mut prev_key: Vec<u8> = Vec::new();
    let mut out = Vec::new();
    while !cur.is_empty() {
        let pos = cur.pos();
        let shared = cur.read_varint_u32()? as usize;
        let non_shared = cur.read_varint_u32()? as usize;
        let value_len = cur.read_varint_u32()? as usize;
        if shared > prev_key.len() {
            return Err(Error::LengthOutOfRange {
                what: "shared key prefix",
                value: shared as u64,
                available: prev_key.len() as u64,
                offset: pos,
            });
        }
        let key_delta = cur.take(non_shared, "entry key delta")?;
        let value = cur.take(value_len, "entry value")?;
        let mut key = Vec::with_capacity(shared + non_shared);
        key.extend_from_slice(&prev_key[..shared]);
        key.extend_from_slice(key_delta);
        prev_key.clone_from(&key);
        out.push((key, value.to_vec()));
    }
    Ok(out)
}

/// Split an internal key into `(user_key, seq, is_deletion)`. Returns `None` if
/// the key is shorter than its mandatory 8-byte trailer (never true for a valid
/// data-block key).
fn split_internal_key(internal: &[u8]) -> Option<(&[u8], u64, bool)> {
    if internal.len() < INTERNAL_KEY_TRAILER {
        return None;
    }
    let n = internal.len() - INTERNAL_KEY_TRAILER;
    let trailer_bytes: [u8; 8] = internal[n..].try_into().ok()?;
    let trailer = u64::from_le_bytes(trailer_bytes);
    let seq = trailer >> 8;
    let value_type = (trailer & 0xff) as u8;
    Some((&internal[..n], seq, value_type == TYPE_DELETION))
}

/// Parse a whole SSTable buffer into records.
pub(crate) fn parse_table(buf: &[u8], origin: &Path) -> Result<Vec<Record>, Error> {
    let index_handle = parse_footer(buf)?;
    let index_block = read_block(buf, index_handle)?;
    let index_entries = parse_block_entries(&index_block)?;

    let origin_path: PathBuf = origin.to_path_buf();
    let mut records = Vec::new();
    for (_index_key, handle_bytes) in index_entries {
        let mut cur = Cursor::new(&handle_bytes);
        let data_handle = read_block_handle(&mut cur)?;
        let data_block = read_block(buf, data_handle)?;
        for (internal_key, value) in parse_block_entries(&data_block)? {
            if let Some((user_key, seq, deleted)) = split_internal_key(&internal_key) {
                records.push(Record {
                    key: user_key.to_vec(),
                    value,
                    seq,
                    deleted,
                    origin_file: origin_path.clone(),
                });
            }
        }
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Wrap `data` as a Snappy-typed block with a *valid* trailer crc, so the
    /// crc check passes and the Snappy decode path (not the crc guard) is what
    /// runs on the crafted, undecodable payload.
    fn snappy_block(data: &[u8]) -> Vec<u8> {
        let mut region = data.to_vec();
        region.push(COMPRESSION_SNAPPY);
        let crc = mask_crc(crc32c::crc32c(&region));
        region.extend_from_slice(&crc.to_le_bytes());
        region
    }

    #[test]
    fn read_block_errors_on_undecodable_snappy_length() {
        // An incomplete Snappy varint length: `decompress_len` fails.
        let data = [0xffu8, 0xff];
        let buf = snappy_block(&data);
        let handle = BlockHandle {
            offset: 0,
            size: data.len() as u64,
        };
        assert!(read_block(&buf, handle).is_err());
    }

    #[test]
    fn read_block_errors_on_truncated_snappy_body() {
        // A valid length prefix (5) but no compressed body: `decompress_vec` fails.
        let data = [0x05u8];
        let buf = snappy_block(&data);
        let handle = BlockHandle {
            offset: 0,
            size: data.len() as u64,
        };
        assert!(read_block(&buf, handle).is_err());
    }

    #[test]
    fn read_block_rejects_an_unknown_compression_type() {
        // Type byte 2 is neither none (0) nor Snappy (1).
        let data = [0x01u8, 0x02, 0x03];
        let mut region = data.to_vec();
        region.push(2); // unknown compression type
        let crc = mask_crc(crc32c::crc32c(&region));
        region.extend_from_slice(&crc.to_le_bytes());
        let handle = BlockHandle {
            offset: 0,
            size: data.len() as u64,
        };
        assert!(matches!(
            read_block(&region, handle),
            Err(Error::UnknownCompression { kind: 2, .. })
        ));
    }
}
