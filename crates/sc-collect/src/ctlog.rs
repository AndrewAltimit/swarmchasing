//! Certificate Transparency logs read directly (RFC 6962 `get-sth` and
//! `get-entries`), as an alternative to crt.sh for watching names. A pull
//! reads the newest `scan` entries of one log and keeps certificates whose
//! DNS names match the query, so it is a bounded sample of a fast-growing
//! log, not a full monitor; crt.sh stays the per-name lookup.
//!
//! Certificates are parsed only as far as their subjectAltName dNSNames, by
//! a small DER walker: no certificate is validated or fetched from anywhere
//! but the log.
//!
//! Terms: CT logs exist to be read by anyone (RFC 6962 section 5 and
//! RFC 9162; the Chrome and Apple CT policies require logs to serve
//! `get-entries` publicly). Operators publish no use restrictions beyond
//! fair request rates, so requests are paced and the scan is small.

use crate::pager::{Cursor, Page};
use crate::{CdxQuery, Client, Kind, Needles, Source};
use anyhow::{Context, Result};
use base64::Engine as _;
use sc_core::{Observation, TsKind, redact_observation};
use serde_json::Value;
use std::cell::Cell;

/// Entries one pull reads unless `query.scan` says otherwise.
const DEFAULT_SCAN: usize = 256;
/// Entries asked for per request; logs may return fewer.
const BATCH: u64 = 256;

/// One CT log as a [`Source`]. `query.endpoint` is the log's base URL (from
/// a log list, e.g. `https://ct.googleapis.com/logs/us1/argon2026h2/`);
/// `query.pattern` `|`-separated substrings matched against DNS names.
pub struct CtLog {
    pub query: CdxQuery,
    base: String,
    end: Cell<u64>,
}

impl CtLog {
    pub fn new(query: CdxQuery) -> Result<Self> {
        let ep = query
            .endpoint
            .as_deref()
            .context("ctlog needs `endpoint`, the log's base URL")?;
        let u = url::Url::parse(ep).with_context(|| format!("ctlog endpoint `{ep}`"))?;
        if u.scheme() != "https" || u.query().is_some() {
            anyhow::bail!("ctlog endpoint must be an https base URL: {ep}");
        }
        let base = format!("{}/", ep.trim_end_matches('/'));
        Ok(Self {
            query,
            base,
            end: Cell::new(0),
        })
    }

    fn log_id(&self) -> String {
        self.base
            .trim_start_matches("https://")
            .trim_end_matches('/')
            .to_string()
    }
}

impl Source for CtLog {
    fn kind(&self) -> Kind {
        Kind::CtLog
    }

    fn query(&self) -> &CdxQuery {
        &self.query
    }

    fn page_size(&self) -> usize {
        usize::MAX
    }

    fn page(
        &self,
        client: &Client,
        _since: Option<i64>,
        cursor: Option<&Cursor>,
        size: usize,
    ) -> Result<Page> {
        let start = match cursor {
            Some(Cursor::Offset(i)) => *i as u64,
            Some(c) => anyhow::bail!("ctlog pages by entry index, not {c:?}"),
            None => {
                let sth: Value =
                    serde_json::from_str(&client.get(&format!("{}ct/v1/get-sth", self.base))?)
                        .context("get-sth: not JSON")?;
                let size = sth
                    .get("tree_size")
                    .and_then(Value::as_u64)
                    .context("get-sth: no tree_size")?;
                self.end.set(size);
                let scan = self.query.scan.unwrap_or(DEFAULT_SCAN).clamp(1, 100_000) as u64;
                size.saturating_sub(scan)
            }
        };
        let end = self.end.get();
        if start >= end {
            return Ok(Page::default());
        }
        let last = (start + BATCH).min(end) - 1;
        let body = client.get(&format!(
            "{}ct/v1/get-entries?start={start}&end={last}",
            self.base
        ))?;
        let entries = parse_entries(&body)?;
        let got = entries.len() as u64;
        let needles = Needles::new(&self.query.pattern);
        let mut records = Vec::new();
        for (i, (ts_ms, names)) in entries.into_iter().enumerate() {
            let Some(name) = names.iter().find(|n| needles.matches(n)) else {
                continue;
            };
            let idx = start + i as u64;
            let mut o = Observation {
                id: format!("ctlog:{}:{idx}", self.log_id()),
                source: "ctlog".into(),
                ts: (ts_ms / 1000) as i64,
                // The log accepting the (pre)certificate submission.
                ts_kind: TsKind::Request,
                url: format!("https://{}/", name.trim_start_matches("*.")),
                reference: Some(format!(
                    "{}ct/v1/get-entries?start={idx}&end={idx}",
                    self.base
                )),
                ..Default::default()
            };
            redact_observation(&mut o);
            records.push(o);
        }
        let truncated = records.len() > size;
        records.truncate(size);
        let next = (got > 0 && start + got < end).then(|| Cursor::Offset((start + got) as usize));
        Ok(Page {
            records,
            next,
            truncated,
        })
    }
}

/// Parse a `get-entries` response: each entry's log timestamp (ms) and the
/// DNS names of its certificate or precertificate.
pub fn parse_entries(body: &str) -> Result<Vec<(u64, Vec<String>)>> {
    let v: Value = serde_json::from_str(body).context("get-entries: not JSON")?;
    let entries = v
        .get("entries")
        .and_then(Value::as_array)
        .context("get-entries: no `entries` array")?;
    let b64 = base64::engine::general_purpose::STANDARD;
    Ok(entries
        .iter()
        .map(|e| {
            e.get("leaf_input")
                .and_then(Value::as_str)
                .and_then(|s| b64.decode(s).ok())
                .and_then(|leaf| leaf_names(&leaf))
                .unwrap_or_default()
        })
        .collect())
}

/// The timestamp and DNS names of a MerkleTreeLeaf (RFC 6962 section 3.4).
fn leaf_names(leaf: &[u8]) -> Option<(u64, Vec<String>)> {
    if leaf.len() < 15 || leaf[0] != 0 || leaf[1] != 0 {
        return None;
    }
    let ts = u64::from_be_bytes(leaf[2..10].try_into().ok()?);
    let entry_type = u16::from_be_bytes([leaf[10], leaf[11]]);
    let at = match entry_type {
        0 => 12,
        // precert_entry: issuer_key_hash[32], then the TBSCertificate.
        1 => 44,
        _ => return None,
    };
    let len_bytes = leaf.get(at..at + 3)?;
    let len = u32::from_be_bytes([0, len_bytes[0], len_bytes[1], len_bytes[2]]) as usize;
    let der = leaf.get(at + 3..at + 3 + len)?;
    Some((ts, san_dns_names(der)))
}

/// The subjectAltName dNSNames in a DER certificate or TBSCertificate,
/// lowercased. Finds the extension by its OID (2.5.29.17); anything
/// malformed yields no names.
pub fn san_dns_names(der: &[u8]) -> Vec<String> {
    const SAN_OID: [u8; 5] = [0x06, 0x03, 0x55, 0x1d, 0x11];
    let mut out = Vec::new();
    let Some(p) = der.windows(5).position(|w| w == SAN_OID) else {
        return out;
    };
    let mut p = p + 5;
    // Optional `critical BOOLEAN`.
    if der.get(p) == Some(&0x01) {
        p += 3;
    }
    let Some((0x04, octets)) = tlv(der, p).map(|(t, v, _)| (t, v)) else {
        return out;
    };
    let Some((0x30, names)) = tlv(octets, 0).map(|(t, v, _)| (t, v)) else {
        return out;
    };
    let mut q = 0;
    while let Some((tag, value, next)) = tlv(names, q) {
        if tag == 0x82
            && let Ok(s) = std::str::from_utf8(value)
            && s.is_ascii()
        {
            out.push(s.to_ascii_lowercase());
        }
        q = next;
    }
    out
}

/// The DER element at `p`: (tag, contents, offset after it).
fn tlv(b: &[u8], p: usize) -> Option<(u8, &[u8], usize)> {
    let tag = *b.get(p)?;
    let first = *b.get(p + 1)?;
    let (len, hdr) = if first < 0x80 {
        (first as usize, 2)
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 {
            return None;
        }
        let mut l = 0usize;
        for i in 0..n {
            l = (l << 8) | *b.get(p + 2 + i)? as usize;
        }
        (l, 2 + n)
    };
    let start = p + hdr;
    let v = b.get(start..start.checked_add(len)?)?;
    Some((tag, v, start + len))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A synthetic SAN extension inside some surrounding DER.
    fn san_ext(names: &[&str]) -> Vec<u8> {
        let mut gn = Vec::new();
        for n in names {
            gn.push(0x82);
            gn.push(n.len() as u8);
            gn.extend_from_slice(n.as_bytes());
        }
        let mut seq = vec![0x30, gn.len() as u8];
        seq.extend(gn);
        let mut ext = vec![0x06, 0x03, 0x55, 0x1d, 0x11, 0x04, seq.len() as u8];
        ext.extend(seq);
        let mut der = vec![0x30, 0x82, 0x00, 0x00, 0xa0, 0x03, 0x02, 0x01, 0x02];
        der.extend(ext);
        der
    }

    #[test]
    fn san_names_from_der() {
        let der = san_ext(&["Run-7.Sandbox.example", "*.sandbox.example"]);
        assert_eq!(
            san_dns_names(&der),
            ["run-7.sandbox.example", "*.sandbox.example"]
        );
        assert!(san_dns_names(&[0x30, 0x00]).is_empty());
        // Truncated input yields nothing rather than panicking.
        assert!(san_dns_names(&der[..der.len() - 4]).is_empty());
    }

    #[test]
    fn leaves_and_entries() {
        let cert = san_ext(&["a.example"]);
        let mut leaf = vec![0u8, 0];
        leaf.extend(1_791_662_234_057u64.to_be_bytes());
        leaf.extend([0, 0]);
        let l = cert.len() as u32;
        leaf.extend(&l.to_be_bytes()[1..]);
        leaf.extend(&cert);
        let mut pre = vec![0u8, 0];
        pre.extend(1_791_662_234_999u64.to_be_bytes());
        pre.extend([0, 1]);
        pre.extend([7u8; 32]);
        pre.extend(&l.to_be_bytes()[1..]);
        pre.extend(&cert);
        let b64 = base64::engine::general_purpose::STANDARD;
        let body = format!(
            r#"{{"entries":[{{"leaf_input":"{}","extra_data":""}},{{"leaf_input":"{}"}},{{"leaf_input":"!!"}}]}}"#,
            b64.encode(&leaf),
            b64.encode(&pre)
        );
        let e = parse_entries(&body).unwrap();
        assert_eq!(e.len(), 3);
        assert_eq!(e[0], (1_791_662_234_057, vec!["a.example".to_string()]));
        assert_eq!(e[1].1, ["a.example"]);
        assert!(e[2].1.is_empty());
        assert!(parse_entries("{}").is_err());
    }

    #[test]
    fn endpoint_is_required_and_https() {
        let q = |e: Option<&str>| CdxQuery {
            endpoint: e.map(str::to_string),
            ..Default::default()
        };
        assert!(CtLog::new(q(None)).is_err());
        assert!(CtLog::new(q(Some("http://log.example/"))).is_err());
        let l = CtLog::new(q(Some("https://log.example/2026h2"))).unwrap();
        assert_eq!(l.base, "https://log.example/2026h2/");
        assert_eq!(l.log_id(), "log.example/2026h2");
    }
}
