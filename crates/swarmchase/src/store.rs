//! The data directory's files: the watch record store, retention, and the
//! JSON and NDJSON helpers the watch, cases and review share.

use anyhow::{Context, Result};
use sc_core::Observation;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::io::Write as _;
use std::path::Path;

/// Stored records captured at or after `since`, deduplicated by ID (the
/// first copy wins). Records with no timestamp count as captured at 0.
pub fn load_store(dir: &Path, since: i64) -> Result<Vec<Observation>> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for entry in std::fs::read_dir(dir)? {
        let p = entry?.path();
        if p.extension().and_then(|e| e.to_str()) != Some("ndjson") {
            continue;
        }
        let text = std::fs::read_to_string(&p)?;
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            let Ok(o) = serde_json::from_str::<Observation>(line) else {
                continue;
            };
            if o.ts >= since && seen.insert(o.id.clone()) {
                out.push(o);
            }
        }
    }
    Ok(out)
}

/// Delete run directories stamped before `cutoff` and stored records captured
/// before it. Records with no timestamp are kept: their age is unknown.
/// Returns (run dirs deleted, records deleted).
pub fn prune(out: &Path, cutoff: i64) -> Result<(usize, usize)> {
    let mut runs = 0;
    if let Ok(entries) = std::fs::read_dir(out.join("runs")) {
        for entry in entries {
            let p = entry?.path();
            let stamp = p.file_name().and_then(|n| n.to_str()).unwrap_or_default();
            let Ok(t) = chrono::NaiveDateTime::parse_from_str(stamp, "%Y%m%dT%H%M%SZ") else {
                continue; // not a run directory
            };
            if p.is_dir() && t.and_utc().timestamp() < cutoff {
                std::fs::remove_dir_all(&p).with_context(|| format!("deleting {}", p.display()))?;
                runs += 1;
            }
        }
    }
    let mut records = 0;
    if let Ok(entries) = std::fs::read_dir(out.join("store")) {
        for entry in entries {
            let p = entry?.path();
            if p.extension().and_then(|e| e.to_str()) != Some("ndjson") {
                continue;
            }
            let text = std::fs::read_to_string(&p)?;
            let mut kept = String::with_capacity(text.len());
            let mut dropped = 0;
            for line in text.lines().filter(|l| !l.trim().is_empty()) {
                let ts = serde_json::from_str::<Observation>(line).map_or(0, |o| o.ts);
                if ts > 0 && ts < cutoff {
                    dropped += 1;
                } else {
                    kept.push_str(line);
                    kept.push('\n');
                }
            }
            if dropped > 0 {
                let tmp = p.with_extension("ndjson.tmp");
                std::fs::write(&tmp, kept)?;
                std::fs::rename(&tmp, &p)?;
                records += dropped;
            }
        }
    }
    Ok((runs, records))
}

pub fn to_ndjson(obs: &[Observation]) -> Result<String> {
    let mut s = String::new();
    for o in obs {
        s.push_str(&serde_json::to_string(o)?);
        s.push('\n');
    }
    Ok(s)
}

pub fn append(p: &Path, text: &str) -> Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(p)
        .with_context(|| format!("opening {}", p.display()))?;
    f.write_all(text.as_bytes())?;
    Ok(())
}

pub fn read_json<T: for<'de> Deserialize<'de>>(p: &Path) -> Result<Option<T>> {
    match std::fs::read_to_string(p) {
        Ok(s) => Ok(Some(
            serde_json::from_str(&s).with_context(|| format!("parsing {}", p.display()))?,
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("reading {}", p.display())),
    }
}

/// Write via a temporary file and rename, so a crash never leaves half a file.
pub fn write_json<T: Serialize>(p: &Path, v: &T) -> Result<()> {
    let tmp = p.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_string_pretty(v)?)?;
    std::fs::rename(&tmp, p).with_context(|| format!("writing {}", p.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prune_deletes_old_runs_and_records() {
        let out = std::env::temp_dir().join(format!("swarmchase-prune-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&out);
        for stamp in ["20260101T000000Z", "20261001T000000Z"] {
            std::fs::create_dir_all(out.join("runs").join(stamp)).unwrap();
        }
        std::fs::create_dir_all(out.join("store")).unwrap();
        let rec = |id: &str, ts: i64| Observation {
            id: id.into(),
            ts,
            url: "https://a.example/".into(),
            ..Default::default()
        };
        let cutoff = sc_core::parse_ts("2026-06-01").unwrap();
        let nd = to_ndjson(&[
            rec("old", cutoff - 1),
            rec("new", cutoff),
            rec("undated", 0),
        ])
        .unwrap();
        std::fs::write(out.join("store").join("s.ndjson"), nd).unwrap();

        // A since-bound read skips what is older, and undated records.
        let recent: Vec<String> = load_store(&out.join("store"), cutoff)
            .unwrap()
            .into_iter()
            .map(|o| o.id)
            .collect();
        assert_eq!(recent, ["new"]);

        assert_eq!(prune(&out, cutoff).unwrap(), (1, 1));
        assert!(!out.join("runs").join("20260101T000000Z").exists());
        assert!(out.join("runs").join("20261001T000000Z").exists());
        let kept: Vec<String> = load_store(&out.join("store"), i64::MIN)
            .unwrap()
            .into_iter()
            .map(|o| o.id)
            .collect();
        assert_eq!(kept, ["new", "undated"]);
        std::fs::remove_dir_all(&out).unwrap();
    }
}
