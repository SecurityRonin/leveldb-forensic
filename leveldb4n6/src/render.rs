//! Rendering of records to the three output formats.
//!
//! `text` is a human view (control characters flattened so a record stays on one
//! line); `jsonl` and `csv` are machine views — faithful and round-trippable
//! (arbitrary bytes as hex, strings JSON- or CSV-escaped, nothing truncated).

use std::fmt::Write as _;
use std::io::{self, Write};

use leveldb_core::Record;
use leveldb_forensic::{Encoding, LocalStorageRecord, SessionStorageRecord};

use crate::Format;

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// JSON-quote and escape a string (control characters as `\u00xx`).
fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Quote a CSV field if it contains a delimiter, quote, or newline.
fn csv_field(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// Flatten control characters so a value stays on a single text line.
fn oneline(s: &str) -> String {
    s.chars()
        .map(|c| {
            if matches!(c, '\n' | '\r' | '\t') {
                ' '
            } else {
                c
            }
        })
        .collect()
}

fn encoding_str(e: Encoding) -> String {
    match e {
        Encoding::Utf16Le => "utf-16-le".to_string(),
        Encoding::Latin1 => "latin-1".to_string(),
        Encoding::Empty => "empty".to_string(),
        Encoding::Unknown(b) => format!("unknown(0x{b:02x})"),
    }
}

/// Render raw LevelDB records. Key and value are arbitrary bytes, so every format
/// shows them as hex.
pub(crate) fn render_raw(
    records: &[Record],
    format: Format,
    out: &mut dyn Write,
) -> io::Result<()> {
    match format {
        Format::Text => {
            for r in records {
                writeln!(
                    out,
                    "seq={} deleted={} file={} key={} value={}",
                    r.seq,
                    r.deleted,
                    r.origin_file.display(),
                    hex(&r.key),
                    hex(&r.value),
                )?;
            }
        }
        Format::Jsonl => {
            for r in records {
                writeln!(
                    out,
                    "{{\"origin_file\":{},\"seq\":{},\"deleted\":{},\"key_hex\":{},\"value_hex\":{}}}",
                    json_string(&r.origin_file.display().to_string()),
                    r.seq,
                    r.deleted,
                    json_string(&hex(&r.key)),
                    json_string(&hex(&r.value)),
                )?;
            }
        }
        Format::Csv => {
            writeln!(out, "origin_file,seq,deleted,key_hex,value_hex")?;
            for r in records {
                writeln!(
                    out,
                    "{},{},{},{},{}",
                    csv_field(&r.origin_file.display().to_string()),
                    r.seq,
                    r.deleted,
                    hex(&r.key),
                    hex(&r.value),
                )?;
            }
        }
    }
    Ok(())
}

/// Render decoded Local Storage records.
pub(crate) fn render_local(
    records: &[LocalStorageRecord],
    format: Format,
    out: &mut dyn Write,
) -> io::Result<()> {
    match format {
        Format::Text => {
            for r in records {
                match r {
                    LocalStorageRecord::Meta {
                        origin,
                        timestamp_webkit_micros,
                        size,
                        seq,
                        deleted,
                    } => {
                        writeln!(
                            out,
                            "meta origin={origin} ts_webkit_micros={timestamp_webkit_micros} size={} seq={seq} deleted={deleted}",
                            size.map_or_else(|| "-".to_string(), |s| s.to_string()),
                        )?;
                    }
                    LocalStorageRecord::Data {
                        origin,
                        script_key,
                        value,
                        seq,
                        deleted,
                    } => {
                        writeln!(
                            out,
                            "data origin={origin} key={} value={} enc={} lossy={} seq={seq} deleted={deleted}",
                            oneline(&script_key.text),
                            oneline(&value.text),
                            encoding_str(value.encoding),
                            value.lossy,
                        )?;
                    }
                    LocalStorageRecord::Other { key, seq, deleted } => {
                        writeln!(out, "other key={} seq={seq} deleted={deleted}", hex(key))?;
                    }
                }
            }
        }
        Format::Jsonl => {
            for r in records {
                match r {
                    LocalStorageRecord::Meta {
                        origin,
                        timestamp_webkit_micros,
                        size,
                        seq,
                        deleted,
                    } => {
                        writeln!(
                            out,
                            "{{\"kind\":\"meta\",\"origin\":{},\"timestamp_webkit_micros\":{timestamp_webkit_micros},\"size\":{},\"seq\":{seq},\"deleted\":{deleted}}}",
                            json_string(origin),
                            size.map_or_else(|| "null".to_string(), |s| s.to_string()),
                        )?;
                    }
                    LocalStorageRecord::Data {
                        origin,
                        script_key,
                        value,
                        seq,
                        deleted,
                    } => {
                        writeln!(
                            out,
                            "{{\"kind\":\"data\",\"origin\":{},\"key\":{},\"value\":{},\"value_encoding\":{},\"lossy\":{},\"value_raw_hex\":{},\"seq\":{seq},\"deleted\":{deleted}}}",
                            json_string(origin),
                            json_string(&script_key.text),
                            json_string(&value.text),
                            json_string(&encoding_str(value.encoding)),
                            value.lossy,
                            json_string(&hex(&value.raw)),
                        )?;
                    }
                    LocalStorageRecord::Other { key, seq, deleted } => {
                        writeln!(
                            out,
                            "{{\"kind\":\"other\",\"key_hex\":{},\"seq\":{seq},\"deleted\":{deleted}}}",
                            json_string(&hex(key)),
                        )?;
                    }
                }
            }
        }
        Format::Csv => {
            writeln!(out, "kind,origin,key,value,value_encoding,lossy,timestamp_webkit_micros,size,seq,deleted")?;
            for r in records {
                match r {
                    LocalStorageRecord::Meta {
                        origin,
                        timestamp_webkit_micros,
                        size,
                        seq,
                        deleted,
                    } => {
                        writeln!(
                            out,
                            "meta,{},,,,,{timestamp_webkit_micros},{},{seq},{deleted}",
                            csv_field(origin),
                            size.map_or_else(String::new, |s| s.to_string()),
                        )?;
                    }
                    LocalStorageRecord::Data {
                        origin,
                        script_key,
                        value,
                        seq,
                        deleted,
                    } => {
                        writeln!(
                            out,
                            "data,{},{},{},{},{},,,{seq},{deleted}",
                            csv_field(origin),
                            csv_field(&script_key.text),
                            csv_field(&value.text),
                            encoding_str(value.encoding),
                            value.lossy,
                        )?;
                    }
                    LocalStorageRecord::Other { key, seq, deleted } => {
                        writeln!(out, "other,,{},,,,,,{seq},{deleted}", hex(key))?;
                    }
                }
            }
        }
    }
    Ok(())
}

/// Render decoded Session Storage records.
pub(crate) fn render_session(
    records: &[SessionStorageRecord],
    format: Format,
    out: &mut dyn Write,
) -> io::Result<()> {
    match format {
        Format::Text => {
            for r in records {
                match r {
                    SessionStorageRecord::Namespace {
                        guid,
                        host,
                        map_id,
                        seq,
                        deleted,
                    } => {
                        writeln!(
                            out,
                            "namespace guid={guid} host={host} map_id={map_id} seq={seq} deleted={deleted}"
                        )?;
                    }
                    SessionStorageRecord::Map {
                        map_id,
                        host,
                        script_key,
                        value,
                        seq,
                        deleted,
                    } => {
                        writeln!(
                            out,
                            "map map_id={map_id} host={} key={} value={} enc={} lossy={} seq={seq} deleted={deleted}",
                            host.as_deref().unwrap_or("-"),
                            oneline(script_key),
                            oneline(&value.text),
                            encoding_str(value.encoding),
                            value.lossy,
                        )?;
                    }
                    SessionStorageRecord::Other { key, seq, deleted } => {
                        writeln!(out, "other key={} seq={seq} deleted={deleted}", hex(key))?;
                    }
                }
            }
        }
        Format::Jsonl => {
            for r in records {
                match r {
                    SessionStorageRecord::Namespace {
                        guid,
                        host,
                        map_id,
                        seq,
                        deleted,
                    } => {
                        writeln!(
                            out,
                            "{{\"kind\":\"namespace\",\"guid\":{},\"host\":{},\"map_id\":{},\"seq\":{seq},\"deleted\":{deleted}}}",
                            json_string(guid),
                            json_string(host),
                            json_string(map_id),
                        )?;
                    }
                    SessionStorageRecord::Map {
                        map_id,
                        host,
                        script_key,
                        value,
                        seq,
                        deleted,
                    } => {
                        writeln!(
                            out,
                            "{{\"kind\":\"map\",\"map_id\":{},\"host\":{},\"key\":{},\"value\":{},\"value_encoding\":{},\"lossy\":{},\"seq\":{seq},\"deleted\":{deleted}}}",
                            json_string(map_id),
                            host.as_deref().map_or_else(|| "null".to_string(), json_string),
                            json_string(script_key),
                            json_string(&value.text),
                            json_string(&encoding_str(value.encoding)),
                            value.lossy,
                        )?;
                    }
                    SessionStorageRecord::Other { key, seq, deleted } => {
                        writeln!(
                            out,
                            "{{\"kind\":\"other\",\"key_hex\":{},\"seq\":{seq},\"deleted\":{deleted}}}",
                            json_string(&hex(key)),
                        )?;
                    }
                }
            }
        }
        Format::Csv => {
            writeln!(
                out,
                "kind,guid,host,map_id,key,value,value_encoding,lossy,seq,deleted"
            )?;
            for r in records {
                match r {
                    SessionStorageRecord::Namespace {
                        guid,
                        host,
                        map_id,
                        seq,
                        deleted,
                    } => {
                        writeln!(
                            out,
                            "namespace,{},{},{},,,,,{seq},{deleted}",
                            csv_field(guid),
                            csv_field(host),
                            csv_field(map_id),
                        )?;
                    }
                    SessionStorageRecord::Map {
                        map_id,
                        host,
                        script_key,
                        value,
                        seq,
                        deleted,
                    } => {
                        writeln!(
                            out,
                            "map,,{},{},{},{},{},{},{seq},{deleted}",
                            csv_field(host.as_deref().unwrap_or("")),
                            csv_field(map_id),
                            csv_field(script_key),
                            csv_field(&value.text),
                            encoding_str(value.encoding),
                            value.lossy,
                        )?;
                    }
                    SessionStorageRecord::Other { key, seq, deleted } => {
                        writeln!(out, "other,,,,{},,,,{seq},{deleted}", hex(key))?;
                    }
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use leveldb_forensic::StorageValue;
    use std::path::PathBuf;

    const FORMATS: [Format; 3] = [Format::Text, Format::Jsonl, Format::Csv];

    fn sv(text: &str) -> StorageValue {
        StorageValue {
            text: text.to_string(),
            raw: text.as_bytes().to_vec(),
            encoding: Encoding::Utf16Le,
            lossy: false,
        }
    }

    fn to_string<F: FnOnce(&mut dyn Write) -> io::Result<()>>(f: F) -> String {
        let mut buf: Vec<u8> = Vec::new();
        f(&mut buf).unwrap();
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn render_raw_every_format() {
        let recs = vec![Record {
            key: b"k".to_vec(),
            value: b"v".to_vec(),
            seq: 1,
            deleted: true,
            origin_file: PathBuf::from("000005.ldb"),
        }];
        for fmt in FORMATS {
            let out = to_string(|w| render_raw(&recs, fmt, w));
            assert!(out.contains("6b"), "{fmt:?} key hex: {out}"); // 'k'
            assert!(out.contains("76"), "{fmt:?} value hex: {out}"); // 'v'
        }
    }

    #[test]
    fn render_local_every_variant_and_format() {
        // Meta with and without a declared size (covers the size map_or_else
        // arms), a Data record, and an Other record — across all three formats.
        let recs = vec![
            LocalStorageRecord::Meta {
                origin: "https://o".into(),
                timestamp_webkit_micros: 42,
                size: Some(4096),
                seq: 1,
                deleted: false,
            },
            LocalStorageRecord::Meta {
                origin: "https://o2".into(),
                timestamp_webkit_micros: 7,
                size: None,
                seq: 2,
                deleted: true,
            },
            LocalStorageRecord::Data {
                origin: "https://o".into(),
                script_key: sv("the\tme"), // tab exercises the oneline flattening
                value: sv("dark"),
                seq: 3,
                deleted: false,
            },
            LocalStorageRecord::Other {
                key: b"VERSION".to_vec(),
                seq: 4,
                deleted: false,
            },
        ];
        for fmt in FORMATS {
            let out = to_string(|w| render_local(&recs, fmt, w));
            assert!(out.contains("dark"), "{fmt:?} data value: {out}");
            assert!(out.contains("4096"), "{fmt:?} meta size: {out}");
            assert!(
                out.contains("56455253494f4e"),
                "{fmt:?} other key hex: {out}"
            );
        }
    }

    #[test]
    fn render_session_every_variant_and_format() {
        let recs = vec![
            SessionStorageRecord::Namespace {
                guid: "g".into(),
                host: "https://h".into(),
                map_id: "7".into(),
                seq: 1,
                deleted: false,
            },
            SessionStorageRecord::Map {
                map_id: "7".into(),
                host: Some("https://h".into()),
                script_key: "greet".into(),
                value: sv("hi"),
                seq: 2,
                deleted: false,
            },
            SessionStorageRecord::Map {
                map_id: "9".into(),
                host: None, // orphan map: covers the host-None rendering arms
                script_key: "orphan".into(),
                value: sv("x"),
                seq: 3,
                deleted: false,
            },
            SessionStorageRecord::Other {
                key: b"weird".to_vec(),
                seq: 4,
                deleted: false,
            },
        ];
        for fmt in FORMATS {
            let out = to_string(|w| render_session(&recs, fmt, w));
            assert!(out.contains("greet"), "{fmt:?} map key: {out}");
            assert!(out.contains("orphan"), "{fmt:?} orphan map: {out}");
            assert!(out.contains("77656972"), "{fmt:?} other key hex: {out}"); // 'weir'
        }
    }
}
