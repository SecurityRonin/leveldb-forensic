//! LevelDB write-ahead log (`.log`) reader.
//!
//! Format: <https://github.com/google/leveldb/blob/main/doc/log_format.md>
//!
//! The file is a sequence of 32 KiB blocks. Each physical record has a 7-byte
//! header: masked crc32c (u32 LE) ‖ length (u16 LE) ‖ type (u8), followed by
//! `length` data bytes. A record is `FULL` (1), or split across `FIRST` (2) /
//! `MIDDLE` (3) / `LAST` (4) fragments. Fewer than 7 bytes at the tail of a
//! block are zero padding and skipped. A reassembled logical record is a
//! `WriteBatch`: seq (u64 LE) ‖ count (u32 LE), then `count` ops, each a type
//! byte (1 = Put, 0 = Delete), a length-prefixed key, and — for Put — a
//! length-prefixed value. Op `i` in the batch has sequence `seq + i`.

use std::path::{Path, PathBuf};

use crate::bytes::Cursor;
use crate::record::Record;

const BLOCK_SIZE: usize = 32 * 1024;
const HEADER_SIZE: usize = 7;
const REC_FULL: u8 = 1;
const REC_FIRST: u8 = 2;
const REC_MIDDLE: u8 = 3;
const REC_LAST: u8 = 4;
const OP_DELETE: u8 = 0;
const OP_VALUE: u8 = 1;
const BATCH_HEADER_LEN: usize = 12; // 8-byte seq + 4-byte count

const CRC_MASK_DELTA: u32 = 0xa282_ead8;

fn mask_crc(crc: u32) -> u32 {
    crc.rotate_left(17).wrapping_add(CRC_MASK_DELTA)
}

/// Masked crc32c over the type byte followed by the fragment data — the exact
/// value LevelDB's log writer stores.
fn record_crc(record_type: u8, data: &[u8]) -> u32 {
    let type_crc = crc32c::crc32c(&[record_type]);
    mask_crc(crc32c::crc32c_append(type_crc, data))
}

/// Parse a reassembled `WriteBatch` best-effort: emit every op it can decode,
/// stop quietly at the first structural inconsistency (a partially corrupt batch
/// still yields its readable prefix — never a panic).
fn parse_write_batch(batch: &[u8], origin: &Path, out: &mut Vec<Record>) {
    if batch.len() < BATCH_HEADER_LEN {
        return;
    }
    let mut cur = Cursor::new(batch);
    let base_seq = match cur.read_u64_le("batch seq") {
        Ok(s) => s,
        Err(_) => return,
    };
    let count = match cur.read_u32_le("batch count") {
        Ok(c) => c,
        Err(_) => return,
    };
    for i in 0..count {
        let op = match cur.read_u8("op type") {
            Ok(t) => t,
            Err(_) => return,
        };
        let seq = base_seq.saturating_add(u64::from(i));
        match op {
            OP_VALUE => {
                let key = match cur.read_length_prefixed("op key") {
                    Ok(k) => k.to_vec(),
                    Err(_) => return,
                };
                let value = match cur.read_length_prefixed("op value") {
                    Ok(v) => v.to_vec(),
                    Err(_) => return,
                };
                out.push(Record {
                    key,
                    value,
                    seq,
                    deleted: false,
                    origin_file: origin.to_path_buf(),
                });
            }
            OP_DELETE => {
                let key = match cur.read_length_prefixed("op key") {
                    Ok(k) => k.to_vec(),
                    Err(_) => return,
                };
                out.push(Record {
                    key,
                    value: Vec::new(),
                    seq,
                    deleted: true,
                    origin_file: origin.to_path_buf(),
                });
            }
            _ => return,
        }
    }
}

/// Parse a whole log file. CRC-failed or truncated physical records are skipped
/// (forensic leniency: recover as much of a partly-damaged log as possible)
/// while every well-formed batch is emitted. Never panics on any input.
pub(crate) fn parse_log(buf: &[u8], origin: &Path) -> Vec<Record> {
    let origin_path: PathBuf = origin.to_path_buf();
    let mut records = Vec::new();
    let mut fragment: Vec<u8> = Vec::new();
    let mut in_record = false;

    let mut block_start = 0usize;
    while block_start < buf.len() {
        let block_end = block_start.saturating_add(BLOCK_SIZE).min(buf.len());
        let block = &buf[block_start..block_end];
        let mut pos = 0usize;

        while pos + HEADER_SIZE <= block.len() {
            let header = &block[pos..pos + HEADER_SIZE];
            let stored_crc = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
            let length = u16::from_le_bytes([header[4], header[5]]) as usize;
            let record_type = header[6];

            // A zero header is trailing padding (preallocated file space).
            if record_type == 0 && length == 0 && stored_crc == 0 {
                break;
            }

            let data_start = pos + HEADER_SIZE;
            let data_end = match data_start.checked_add(length) {
                Some(e) if e <= block.len() => e,
                // Truncated / lying length — abandon the rest of this block.
                _ => break,
            };
            let data = &block[data_start..data_end];
            pos = data_end;

            let crc_ok = record_crc(record_type, data) == stored_crc;

            match record_type {
                REC_FULL => {
                    fragment.clear();
                    in_record = false;
                    if crc_ok {
                        parse_write_batch(data, &origin_path, &mut records);
                    }
                }
                REC_FIRST => {
                    fragment.clear();
                    if crc_ok {
                        fragment.extend_from_slice(data);
                        in_record = true;
                    } else {
                        in_record = false;
                    }
                }
                REC_MIDDLE => {
                    if in_record && crc_ok {
                        fragment.extend_from_slice(data);
                    } else {
                        in_record = false;
                        fragment.clear();
                    }
                }
                REC_LAST => {
                    if in_record && crc_ok {
                        fragment.extend_from_slice(data);
                        parse_write_batch(&fragment, &origin_path, &mut records);
                    }
                    fragment.clear();
                    in_record = false;
                }
                _ => {
                    // Unknown fragment type — reset reassembly, keep scanning.
                    in_record = false;
                    fragment.clear();
                }
            }
        }

        block_start = block_end;
    }

    records
}
