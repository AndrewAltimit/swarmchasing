//! Moving a store of the older layout (`store/<source>.ndjson`, one file
//! per source) to the partitioned one ([`super::records`]).
//!
//! Each old file is split into its source's month partitions. A partition
//! is rewritten whole through a temporary file and a rename, merged with
//! what it already holds and deduplicated by record ID (an unreadable line
//! by its bytes), and the old file is deleted only once every partition it
//! feeds is written. So a migration cut short at any point loses nothing,
//! and the next one, which starts again from the old files still there,
//! stores nothing twice. Unreadable lines go to the source's `undated`
//! partition as they are, where the next check of the store sets them
//! aside with an alert, as for any damaged line. An old `<source>.damaged`
//! becomes `store/<source>/legacy.damaged`.

use super::records::{UNDATED, partition_of};
use super::{byte_lines, write_atomic};
use anyhow::{Context, Result};
use sc_core::Observation;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// What a migration moved.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Migrated {
    /// Old store files moved (records and set-aside lines).
    pub files: usize,
    /// Records read from them.
    pub records: usize,
    /// Unreadable lines among them, kept for the damage check.
    pub unreadable: usize,
}

impl Migrated {
    /// The digest note that reports it, once.
    pub fn note(&self) -> String {
        format!(
            "The record store moved to one file per source and month (`store/<source>/<YYYY-MM>.ndjson`): {} file(s) of the older layout, {} record(s){}. Reads bounded by the analysis window now skip older months, and retention deletes whole months.",
            self.files,
            self.records,
            if self.unreadable > 0 {
                format!(
                    ", and {} unreadable line(s) kept for the damage check",
                    self.unreadable
                )
            } else {
                String::new()
            }
        )
    }
}

/// Move every store file of the older layout in `store` into the
/// partitioned one. `None` when there was none. The caller holds the data
/// lock.
pub fn migrate_store(store: &Path) -> Result<Option<Migrated>> {
    migrate_with(store, &mut |_| Ok(()))
}

/// [`migrate_store`], calling `step` before each change to the disk, so a
/// test can cut the migration short at any of them.
fn migrate_with(
    store: &Path,
    step: &mut dyn FnMut(&Path) -> Result<()>,
) -> Result<Option<Migrated>> {
    let Ok(rd) = std::fs::read_dir(store) else {
        return Ok(None);
    };
    let mut old: Vec<_> = rd
        .filter_map(|e| Some(e.ok()?.path()))
        .filter(|p| {
            p.is_file()
                && !p
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with('.'))
        })
        .collect();
    old.sort();
    let mut done = Migrated::default();
    for p in &old {
        let ext = p.extension().and_then(|e| e.to_str());
        let source = p.file_stem().unwrap_or_default().to_string_lossy();
        let dir = store.join(source.as_ref());
        match ext {
            Some("ndjson") => {
                std::fs::create_dir_all(&dir)
                    .with_context(|| format!("creating {}", dir.display()))?;
                let (records, unreadable) = split(p, &dir, step)?;
                done.records += records;
                done.unreadable += unreadable;
            }
            Some("damaged") => {
                std::fs::create_dir_all(&dir)
                    .with_context(|| format!("creating {}", dir.display()))?;
                let to = dir.join("legacy.damaged");
                if to.exists() {
                    let bytes =
                        std::fs::read(p).with_context(|| format!("reading {}", p.display()))?;
                    let lines: Vec<Line<'_>> = byte_lines(&bytes).map(|l| (None, raw(l))).collect();
                    merge_into(&to, &lines, step)?;
                    step(p)?;
                    std::fs::remove_file(p).with_context(|| format!("deleting {}", p.display()))?;
                } else {
                    step(p)?;
                    std::fs::rename(p, &to)
                        .with_context(|| format!("moving {} to {}", p.display(), to.display()))?;
                }
            }
            _ => continue,
        }
        done.files += 1;
    }
    Ok((done.files > 0).then_some(done))
}

/// A line to merge: a record's ID, or none for a line that is not a
/// record, and its bytes.
type Line<'a> = (Option<String>, &'a [u8]);

fn raw<'a>(l: std::result::Result<&'a str, &'a [u8]>) -> &'a [u8] {
    match l {
        Ok(s) => s.as_bytes(),
        Err(b) => b,
    }
}

/// Split the old file `p` into `dir`'s partitions, then delete it.
/// Returns the records and unreadable lines it held.
fn split(
    p: &Path,
    dir: &Path,
    step: &mut dyn FnMut(&Path) -> Result<()>,
) -> Result<(usize, usize)> {
    let bytes = std::fs::read(p).with_context(|| format!("reading {}", p.display()))?;
    let mut parts: BTreeMap<String, Vec<Line<'_>>> = BTreeMap::new();
    let (mut records, mut unreadable) = (0, 0);
    for line in byte_lines(&bytes) {
        match line
            .ok()
            .and_then(|l| serde_json::from_str::<Observation>(l).ok())
        {
            Some(o) => {
                records += 1;
                parts
                    .entry(partition_of(o.ts))
                    .or_default()
                    .push((Some(o.id), raw(line)));
            }
            None => {
                unreadable += 1;
                parts
                    .entry(UNDATED.to_string())
                    .or_default()
                    .push((None, raw(line)));
            }
        }
    }
    for (part, lines) in &parts {
        merge_into(&dir.join(format!("{part}.ndjson")), lines, step)?;
    }
    step(p)?;
    std::fs::remove_file(p).with_context(|| format!("deleting {}", p.display()))?;
    Ok((records, unreadable))
}

/// Rewrite `to` as what it holds plus each of `lines` it does not hold
/// yet: a record by its ID, any other line by its bytes. Unchanged when
/// every line is there already.
fn merge_into(
    to: &Path,
    lines: &[Line<'_>],
    step: &mut dyn FnMut(&Path) -> Result<()>,
) -> Result<()> {
    let mut out = match std::fs::read(to) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(e).with_context(|| format!("reading {}", to.display())),
    };
    let mut ids = BTreeSet::new();
    let mut raws: BTreeSet<Vec<u8>> = BTreeSet::new();
    for line in byte_lines(&out) {
        match line
            .ok()
            .and_then(|l| serde_json::from_str::<Observation>(l).ok())
        {
            Some(o) => {
                ids.insert(o.id);
            }
            None => {
                raws.insert(raw(line).to_vec());
            }
        }
    }
    if !out.is_empty() && !out.ends_with(b"\n") {
        out.push(b'\n');
    }
    let before = out.len();
    for (id, line) in lines {
        let fresh = match id {
            Some(id) => ids.insert(id.clone()),
            None => raws.insert(line.to_vec()),
        };
        if fresh {
            out.extend_from_slice(line);
            out.push(b'\n');
        }
    }
    if out.len() > before {
        step(to)?;
        write_atomic(to, &out)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{append_records, load_store, to_ndjson};

    fn rec(id: &str, ts: i64) -> Observation {
        Observation {
            id: id.into(),
            ts,
            url: "https://a.example/".into(),
            ..Default::default()
        }
    }

    fn ts(d: &str) -> i64 {
        sc_core::parse_ts(d).unwrap()
    }

    /// An older-layout store: two sources over three months, an undated
    /// record, an unreadable line and a set-aside file.
    fn old_store(store: &Path) {
        let _ = std::fs::remove_dir_all(store);
        std::fs::create_dir_all(store).unwrap();
        let mut a = to_ndjson(&[
            rec("a1", ts("2026-01-05")),
            rec("a2", ts("2026-02-05")),
            rec("a3", 0),
        ])
        .unwrap();
        a.push_str("{ torn\n");
        a.push_str(&to_ndjson(&[rec("a4", ts("2026-02-06"))]).unwrap());
        std::fs::write(store.join("a.ndjson"), a).unwrap();
        std::fs::write(
            store.join("b.ndjson"),
            to_ndjson(&[rec("b1", ts("2026-03-01"))]).unwrap(),
        )
        .unwrap();
        std::fs::write(store.join("a.damaged"), "set aside\n").unwrap();
    }

    fn all_ids(store: &Path) -> Vec<String> {
        let mut v: Vec<String> = load_store(store, i64::MIN)
            .unwrap()
            .into_iter()
            .map(|o| o.id)
            .collect();
        v.sort();
        v
    }

    /// Every record line in the store, counting duplicates.
    fn record_lines(store: &Path) -> usize {
        let mut n = 0;
        for src in ["a", "b"] {
            if let Ok(rd) = std::fs::read_dir(store.join(src)) {
                for e in rd {
                    let p = e.unwrap().path();
                    if p.extension().and_then(|e| e.to_str()) == Some("ndjson") {
                        let s = std::fs::read_to_string(&p).unwrap();
                        n += s.lines().filter(|l| l.starts_with("{\"")).count();
                    }
                }
            }
            if let Ok(s) = std::fs::read_to_string(store.join(format!("{src}.ndjson"))) {
                n += s.lines().filter(|l| l.starts_with("{\"")).count();
            }
        }
        n
    }

    #[test]
    fn an_old_store_moves_into_months() {
        let d = std::env::temp_dir().join(format!("swarmchase-migrate-{}", std::process::id()));
        let store = d.join("store");
        old_store(&store);
        let m = migrate_store(&store).unwrap().unwrap();
        assert_eq!(
            m,
            Migrated {
                files: 3,
                records: 5,
                unreadable: 1
            }
        );
        assert!(m.note().contains("5 record(s)"), "{}", m.note());
        for f in [
            "a/2026-01.ndjson",
            "a/2026-02.ndjson",
            "a/undated.ndjson",
            "a/legacy.damaged",
            "b/2026-03.ndjson",
        ] {
            assert!(store.join(f).is_file(), "{f}");
        }
        assert!(!store.join("a.ndjson").exists());
        assert!(!store.join("a.damaged").exists());
        let undated = std::fs::read_to_string(store.join("a/undated.ndjson")).unwrap();
        assert!(undated.contains("{ torn"), "{undated}");
        assert_eq!(all_ids(&store), ["a1", "a2", "a3", "a4", "b1"]);
        // Once moved, there is nothing more to do, and no second note.
        assert_eq!(migrate_store(&store).unwrap(), None);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn a_migration_cut_short_anywhere_resumes_without_loss_or_duplicates() {
        let d = std::env::temp_dir().join(format!("swarmchase-migrate-cut-{}", std::process::id()));
        let store = d.join("store");
        // Count the steps of an uninterrupted migration.
        old_store(&store);
        let mut steps = 0;
        migrate_with(&store, &mut |_| {
            steps += 1;
            Ok(())
        })
        .unwrap();
        assert!(steps >= 6, "{steps}");
        for cut in 0..steps {
            old_store(&store);
            let mut n = 0;
            let r = migrate_with(&store, &mut |p| {
                n += 1;
                if n > cut {
                    anyhow::bail!("cut short before {}", p.display());
                }
                Ok(())
            });
            assert!(r.is_err(), "cut {cut}");
            // Meanwhile a run reads the store as it is, and stores a record
            // in the new layout.
            assert_eq!(all_ids(&store), ["a1", "a2", "a3", "a4", "b1"], "cut {cut}");
            append_records(&store, "a", &[rec("a5", ts("2026-02-07"))]).unwrap();
            // The next run finishes the move.
            assert!(migrate_store(&store).unwrap().is_some(), "cut {cut}");
            assert_eq!(
                all_ids(&store),
                ["a1", "a2", "a3", "a4", "a5", "b1"],
                "cut {cut}"
            );
            assert_eq!(record_lines(&store), 6, "cut {cut}: a record stored twice");
            let undated = std::fs::read_to_string(store.join("a/undated.ndjson")).unwrap();
            assert_eq!(undated.matches("{ torn").count(), 1, "cut {cut}");
            let aside = std::fs::read_to_string(store.join("a/legacy.damaged")).unwrap();
            assert_eq!(aside.matches("set aside").count(), 1, "cut {cut}");
            assert_eq!(migrate_store(&store).unwrap(), None, "cut {cut}");
        }
        std::fs::remove_dir_all(&d).unwrap();
    }
}
