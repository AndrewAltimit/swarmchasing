//! OSV malicious-package records (`osv`): reference data, not events. The
//! OSV database publishes, per ecosystem, a `modified_id.csv` listing every
//! record id with its last-modified time, newest first. A pull reads it
//! from the top down to its checkpoint (the newest modified time read, in
//! ms), keeps the `MAL-` ids (the OpenSSF malicious-packages records), and
//! fetches those records oldest first, at most `scan` a pull, from the
//! same bucket. Each package a record names becomes a [`TargetLabel`]
//! (`osv-malicious`) on that ecosystem's platform, which the watch joins to
//! platform candidates whose members published that package: a flood whose
//! packages were later confirmed malicious says what the flood was for.
//!
//! `endpoint` is the OSV ecosystem name: `npm` (default), `PyPI`, `Go`,
//! `crates.io`, `NuGet`, `Packagist` or `RubyGems`.
//!
//! Without a checkpoint a pull reads [`FRESH_MS`] back; a checkpoint
//! older than [`MAX_BACKLOG_MS`] is skipped to there and the gap counted.
//! The CSV is streamed and read only down to the checkpoint, so a pull
//! reads a few kilobytes of it, not the whole file. Package code is never
//! fetched, nor any URL a record references.
//!
//! Terms: the OSV data dumps (<https://google.github.io/osv.dev/data/>)
//! are public in a Google Cloud Storage bucket, for bulk use; OSV's own
//! data is CC-BY 4.0, and the OpenSSF malicious-packages records
//! (<https://github.com/ossf/malicious-packages>) are published under
//! Apache 2.0. We keep the record id, the package name and the times.

use crate::pager::Coverage;
use crate::platform::{PlatformPull, TargetLabel, label_key};
use crate::{CdxQuery, Client, parse_date};
use anyhow::{Context, Result, bail};
use sc_core::platform::Platform;
use serde_json::Value;
use std::io::{BufRead, BufReader, Read};

const BUCKET: &str = "https://osv-vulnerabilities.storage.googleapis.com/";
/// Without a checkpoint, a pull reads this far back (ms).
pub const FRESH_MS: i64 = 24 * 3_600_000;
/// A checkpoint further back than this is skipped to [`FRESH_MS`] (ms).
pub const MAX_BACKLOG_MS: i64 = 7 * 24 * 3_600_000;
/// Records one pull fetches unless `scan` says otherwise.
const DEFAULT_RECORDS: usize = 50;
/// Most of the CSV one pull streams.
const MAX_CSV: u64 = 64 << 20;

/// The platform an OSV ecosystem's packages are published on.
pub fn ecosystem_platform(eco: &str) -> Option<Platform> {
    Some(match eco {
        "npm" => Platform::Npm,
        "PyPI" => Platform::Pypi,
        "Go" => Platform::Go,
        "crates.io" => Platform::Crates,
        "NuGet" => Platform::Nuget,
        "Packagist" => Platform::Packagist,
        "RubyGems" => Platform::Rubygems,
        _ => return None,
    })
}

/// `MAL-` ids modified after `after` (ms) from a `modified_id.csv`
/// (newest first), oldest first as (ms, id), and the lines read. Reading
/// stops at the first line at or before `after`.
pub fn modified_mal_ids(r: impl Read, after: i64) -> std::io::Result<(Vec<(i64, String)>, usize)> {
    let mut out = Vec::new();
    let mut lines = 0;
    for line in BufReader::new(r).lines() {
        let line = line?;
        let Some((ts, id)) = line.split_once(',') else {
            continue;
        };
        let Some(ms) = chrono::DateTime::parse_from_rfc3339(ts.trim())
            .ok()
            .map(|d| d.timestamp_millis())
        else {
            continue;
        };
        lines += 1;
        if ms <= after {
            break;
        }
        let id = id.trim();
        if id.starts_with("MAL-") && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            out.push((ms, id.to_string()));
        }
    }
    out.reverse();
    Ok((out, lines))
}

/// Labels from one OSV record: one per affected package in `eco`.
pub fn record_labels(body: &str, eco: &str) -> Result<Vec<TargetLabel>> {
    let v: Value = serde_json::from_str(body).context("OSV record: not JSON")?;
    let id = v
        .get("id")
        .and_then(Value::as_str)
        .context("OSV record: no id")?;
    let ts = v
        .get("published")
        .or_else(|| v.get("modified"))
        .and_then(Value::as_str)
        .and_then(parse_date)
        .unwrap_or(0);
    if v.get("withdrawn").and_then(Value::as_str).is_some() {
        return Ok(Vec::new());
    }
    let Some(platform) = ecosystem_platform(eco) else {
        bail!("unknown OSV ecosystem `{eco}`");
    };
    let mut out = Vec::new();
    for a in v
        .get("affected")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let s = |p: &str| a.pointer(p).and_then(Value::as_str);
        let (Some(name), Some(e)) = (s("/package/name"), s("/package/ecosystem")) else {
            continue;
        };
        if e != eco {
            continue;
        }
        out.push(TargetLabel {
            platform,
            target: label_key(platform, name),
            kind: "osv-malicious".into(),
            source_id: id.to_string(),
            link: format!("https://osv.dev/vulnerability/{id}"),
            ts,
        });
    }
    out.sort();
    out.dedup();
    Ok(out)
}

/// Pull the malicious-package labels of one ecosystem since `mark` (ms).
pub fn pull_labels(client: &Client, q: &CdxQuery, mark: Option<u64>) -> Result<PlatformPull> {
    let eco = q.endpoint.as_deref().unwrap_or("npm");
    if ecosystem_platform(eco).is_none() {
        bail!(
            "unknown OSV ecosystem `{eco}` (expected npm, PyPI, Go, crates.io, NuGet, Packagist or RubyGems)"
        );
    }
    let now_ms = crate::client::now_secs() * 1000;
    let fresh = now_ms - FRESH_MS;
    let (start, skipped) = match mark.map(|m| m as i64) {
        Some(m) if m >= now_ms - MAX_BACKLOG_MS => (m, 0),
        Some(m) => (fresh, (fresh - m).max(0)),
        None => (fresh, 0),
    };
    let csv = client.get_stream(&format!("{BUCKET}{eco}/modified_id.csv"), MAX_CSV)?;
    let (ids, lines) = modified_mal_ids(csv, start)?;
    let budget = q.scan.unwrap_or(DEFAULT_RECORDS).clamp(1, 500);
    let mut out = PlatformPull::default();
    let (mut next, mut fetched) = (start, 0u64);
    for (i, (ms, id)) in ids.iter().enumerate() {
        if i >= budget {
            break;
        }
        let body = match client.get(&format!("{BUCKET}{eco}/{id}.json")) {
            Ok(b) => b,
            Err(e) if i == 0 => return Err(e),
            Err(_) => break,
        };
        fetched += 1;
        next = *ms;
        out.labels.extend(record_labels(&body, eco)?);
    }
    if ids.is_empty() {
        next = start;
    }
    out.coverage = Coverage {
        unit: "records",
        read: fetched,
        available: ids.len() as u64 + u64::from(skipped > 0),
        skipped: u64::from(skipped > 0),
        next: Some(next.max(0) as u64),
        canary: Some(lines > 0),
    };
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Every package and id below is invented.

    #[test]
    fn the_csv_is_read_down_to_the_checkpoint() {
        let csv = "2026-10-13T17:45:05.995525682Z,MAL-2026-90003\n\
                   2026-10-13T12:45:05Z,GHSA-xxxx-yyyy-zzzz\n\
                   2026-10-13T08:45:05Z,MAL-2026-90002\n\
                   2026-10-12T08:45:05Z,MAL-2026-90001\n";
        let after = chrono::DateTime::parse_from_rfc3339("2026-10-13T00:00:00Z")
            .unwrap()
            .timestamp_millis();
        let (ids, lines) = modified_mal_ids(csv.as_bytes(), after).unwrap();
        let names: Vec<&str> = ids.iter().map(|x| x.1.as_str()).collect();
        assert_eq!(names, ["MAL-2026-90002", "MAL-2026-90003"]);
        assert_eq!(lines, 4);
        let (none, _) = modified_mal_ids(csv.as_bytes(), i64::MAX).unwrap();
        assert!(none.is_empty());
    }

    #[test]
    fn records_label_their_packages() {
        let rec = r#"{"id":"MAL-2026-90003","published":"2026-10-13T16:44:00Z","modified":"2026-10-13T17:45:05Z",
          "affected":[{"package":{"name":"Agent_Probe.0042","ecosystem":"PyPI"}},{"package":{"name":"other","ecosystem":"npm"}}]}"#;
        let l = record_labels(rec, "PyPI").unwrap();
        assert_eq!(l.len(), 1);
        assert_eq!(l[0].target, "agent-probe-0042");
        assert_eq!(l[0].platform, Platform::Pypi);
        assert_eq!(l[0].kind, "osv-malicious");
        assert_eq!(l[0].link, "https://osv.dev/vulnerability/MAL-2026-90003");
        let w = r#"{"id":"MAL-1","withdrawn":"2026-10-13T00:00:00Z","affected":[]}"#;
        assert!(record_labels(w, "npm").unwrap().is_empty());
        assert!(record_labels("{}", "npm").is_err());
        assert_eq!(label_key(Platform::Npm, "@Scope/X_y"), "@scope/x_y");
    }
}
