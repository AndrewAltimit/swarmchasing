//! The watch record store, partitioned by source and month of record time:
//!
//! ```text
//! store/<source>/<YYYY-MM>.ndjson   records whose capture time falls in that UTC month
//! store/<source>/undated.ndjson     records with no capture time (ts <= 0)
//! store/<source>/<name>.damaged     unreadable lines set aside from <name>.ndjson
//! ```
//!
//! A read bounded by a time skips every month that ended before it, and
//! retention deletes whole months. A record with no capture time has no
//! age: it is read only by a read with no lower bound, and retention keeps
//! it. A store file directly under `store/` (the older one-file-per-source
//! layout, before [`super::migrate`] moves it) is read by every read.

use super::{append, byte_lines, read_ndjson, to_ndjson, write_atomic};
use anyhow::{Context, Result};
use sc_core::Observation;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write as _;
use std::path::{Path, PathBuf};

/// The partition of records with no capture time.
pub const UNDATED: &str = "undated";

/// The partition a record captured at `ts` goes to: its UTC month as
/// `YYYY-MM`, or [`UNDATED`] when it has no capture time.
pub fn partition_of(ts: i64) -> String {
    if ts <= 0 {
        return UNDATED.into();
    }
    chrono::DateTime::from_timestamp(ts, 0)
        .map_or_else(|| UNDATED.into(), |t| t.format("%Y-%m").to_string())
}

/// What a store file holds, by its name and place.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Span {
    /// A month: records captured in `[start, end)`.
    Month(i64, i64),
    Undated,
    /// A file of the older layout, or a name that is not a partition: it
    /// may hold any record.
    Any,
}

impl Span {
    fn of(stem: &str) -> Span {
        if stem == UNDATED {
            return Span::Undated;
        }
        month_span(stem).map_or(Span::Any, |(a, b)| Span::Month(a, b))
    }

    /// Whether the file may hold a record captured at or after `since`.
    fn reaches(self, since: i64) -> bool {
        match self {
            Span::Month(_, end) => end > since,
            Span::Undated => since <= 0,
            Span::Any => true,
        }
    }
}

/// `[start, end)` of the month named `YYYY-MM`, in Unix seconds.
fn month_span(name: &str) -> Option<(i64, i64)> {
    let (y, m) = name.split_once('-')?;
    if y.len() != 4 || m.len() != 2 {
        return None;
    }
    let (y, m): (i32, u32) = (y.parse().ok()?, m.parse().ok()?);
    let start = chrono::NaiveDate::from_ymd_opt(y, m, 1)?;
    let next = if m == 12 {
        chrono::NaiveDate::from_ymd_opt(y + 1, 1, 1)?
    } else {
        chrono::NaiveDate::from_ymd_opt(y, m + 1, 1)?
    };
    let secs = |d: chrono::NaiveDate| d.and_hms_opt(0, 0, 0).map(|t| t.and_utc().timestamp());
    Some((secs(start)?, secs(next)?))
}

/// A file of the store.
#[derive(Debug)]
struct StoreFile {
    path: PathBuf,
    /// The source it belongs to.
    source: String,
    span: Span,
}

impl StoreFile {
    /// `store/<source>/<file>` (or `store/<file>`), for messages.
    fn name(&self, store: &Path) -> String {
        let rel = self.path.strip_prefix(store).unwrap_or(&self.path);
        let parts: Vec<String> = rel
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect();
        format!("store/{}", parts.join("/"))
    }

    fn modified(&self) -> Option<i64> {
        let t = std::fs::metadata(&self.path)
            .and_then(|m| m.modified())
            .ok()?;
        let d = t.duration_since(std::time::UNIX_EPOCH).ok()?;
        i64::try_from(d.as_secs()).ok()
    }
}

/// The name of `p` relative to `store`, as messages give it.
fn display_name(store: &Path, p: &Path) -> String {
    StoreFile {
        path: p.to_path_buf(),
        source: String::new(),
        span: Span::Any,
    }
    .name(store)
}

fn hidden(p: &Path) -> bool {
    p.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.starts_with('.'))
}

fn has_ext(p: &Path, ext: &str) -> bool {
    p.extension().and_then(|e| e.to_str()) == Some(ext)
}

fn stem(p: &Path) -> String {
    p.file_stem()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned()
}

/// The entries of `dir`, sorted; none when it does not exist.
fn entries(dir: &Path) -> Result<Vec<PathBuf>> {
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("reading {}", dir.display())),
    };
    let mut v: Vec<PathBuf> = rd
        .map(|e| e.map(|e| e.path()))
        .collect::<std::io::Result<_>>()
        .with_context(|| format!("reading {}", dir.display()))?;
    v.retain(|p| !hidden(p));
    v.sort();
    Ok(v)
}

/// Every file of the store with extension `ext`, in path order: each
/// source directory's partitions, and the older layout's files directly
/// under `store/`.
fn files(store: &Path, ext: &str) -> Result<Vec<StoreFile>> {
    let mut out = Vec::new();
    for p in entries(store)? {
        if p.is_dir() {
            let source = p
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned();
            for q in entries(&p)? {
                if q.is_file() && has_ext(&q, ext) {
                    out.push(StoreFile {
                        span: Span::of(&stem(&q)),
                        source: source.clone(),
                        path: q,
                    });
                }
            }
        } else if has_ext(&p, ext) {
            out.push(StoreFile {
                source: stem(&p),
                span: Span::Any,
                path: p,
            });
        }
    }
    Ok(out)
}

/// The records of a store file, or none when it is gone (moved by a
/// migration that ran meanwhile).
fn read_records(p: &Path) -> Result<(Vec<Observation>, usize)> {
    match read_ndjson::<Observation>(p) {
        Err(_) if !p.exists() => Ok((Vec::new(), 0)),
        r => r,
    }
}

/// Stored records captured at or after `since`, deduplicated by ID (the
/// first copy wins). Records with no timestamp count as captured at 0.
/// Unreadable lines are skipped with a warning; see [`load_store_counted`].
pub fn load_store(dir: &Path, since: i64) -> Result<Vec<Observation>> {
    let (out, bad) = load_store_counted(dir, since)?;
    for (file, n) in bad {
        eprintln!("warning: {file}: {n} unreadable line(s) skipped");
    }
    Ok(out)
}

/// [`load_store`], with the number of unreadable lines in each store file
/// that has any. Months that ended before `since` are not opened.
pub fn load_store_counted(
    dir: &Path,
    since: i64,
) -> Result<(Vec<Observation>, BTreeMap<String, usize>)> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    let mut bad = BTreeMap::new();
    for f in files(dir, "ndjson")? {
        if !f.span.reaches(since) {
            continue;
        }
        let (records, n) = read_records(&f.path)?;
        if n > 0 {
            bad.insert(f.name(dir), n);
        }
        for o in records {
            if o.ts >= since && seen.insert(o.id.clone()) {
                out.push(o);
            }
        }
    }
    Ok((out, bad))
}

/// The stored records with the given IDs, per source, as
/// `(source, record)`. Each source's files are read most recently written
/// first, and reading stops once every wanted ID is found, so records a
/// recent run stored are found without reading the whole store.
pub fn load_ids(
    dir: &Path,
    wanted: &BTreeMap<String, BTreeSet<String>>,
) -> Result<Vec<(String, Observation)>> {
    let all = files(dir, "ndjson")?;
    let mut out = Vec::new();
    for (source, ids) in wanted {
        let mut left: BTreeSet<&str> = ids.iter().map(String::as_str).collect();
        let mut mine: Vec<(Option<i64>, &StoreFile)> = all
            .iter()
            .filter(|f| &f.source == source)
            .map(|f| (f.modified(), f))
            .collect();
        mine.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.path.cmp(&a.1.path)));
        for (_, f) in mine {
            if left.is_empty() {
                break;
            }
            for o in read_records(&f.path)?.0 {
                if left.remove(o.id.as_str()) {
                    out.push((source.clone(), o));
                }
            }
        }
    }
    Ok(out)
}

/// The IDs of every record stored for `source`.
pub fn source_ids(dir: &Path, source: &str) -> Result<BTreeSet<String>> {
    let mut out = BTreeSet::new();
    for f in files(dir, "ndjson")? {
        if f.source == source {
            out.extend(read_records(&f.path)?.0.into_iter().map(|o| o.id));
        }
    }
    Ok(out)
}

/// Append `obs` to `source`'s partitions, each record to the month it was
/// captured in.
pub fn append_records(dir: &Path, source: &str, obs: &[Observation]) -> Result<()> {
    let mut by_part: BTreeMap<String, Vec<Observation>> = BTreeMap::new();
    for o in obs {
        by_part
            .entry(partition_of(o.ts))
            .or_default()
            .push(o.clone());
    }
    if by_part.is_empty() {
        return Ok(());
    }
    let sdir = dir.join(source);
    std::fs::create_dir_all(&sdir).with_context(|| format!("creating {}", sdir.display()))?;
    for (part, recs) in by_part {
        append(&sdir.join(format!("{part}.ndjson")), &to_ndjson(&recs)?)?;
    }
    Ok(())
}

/// Lines of the store files in `dir` that cannot be read, moved out of the
/// way: each file is rewritten without them, and they are appended to
/// `<partition>.damaged` beside it, which no read of the store takes in.
/// So a damaged line is reported in the run that finds it, not in every
/// run after. The files checked are those a read from `since` opens and
/// those written to at or after `since`; damage comes from a write cut
/// short, so a file left alone since is as it was. Returns, per store file
/// that had any, the lines moved and the file they went to.
pub fn set_aside_damaged(dir: &Path, since: i64) -> Result<BTreeMap<String, (usize, String)>> {
    let mut out = BTreeMap::new();
    for f in files(dir, "ndjson")? {
        if !f.span.reaches(since) && f.modified().is_some_and(|m| m < since) {
            continue;
        }
        let p = &f.path;
        let bytes = match std::fs::read(p) {
            Ok(b) => b,
            Err(_) if !p.exists() => continue,
            Err(e) => return Err(e).with_context(|| format!("reading {}", p.display())),
        };
        let mut kept: Vec<u8> = Vec::with_capacity(bytes.len());
        let mut bad: Vec<u8> = Vec::new();
        let mut n = 0;
        for line in byte_lines(&bytes) {
            let ok = line
                .ok()
                .is_some_and(|l| serde_json::from_str::<Observation>(l).is_ok());
            let raw = match line {
                Ok(l) => l.as_bytes(),
                Err(b) => b,
            };
            let to = if ok { &mut kept } else { &mut bad };
            to.extend_from_slice(raw);
            to.push(b'\n');
            n += usize::from(!ok);
        }
        if n == 0 {
            continue;
        }
        let aside = p.with_extension("damaged");
        // The damaged lines first, so a failure in between leaves them in
        // both places rather than in neither.
        let mut w = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&aside)
            .with_context(|| format!("opening {}", aside.display()))?;
        w.write_all(&bad)
            .with_context(|| format!("writing {}", aside.display()))?;
        write_atomic(p, &kept)?;
        out.insert(f.name(dir), (n, display_name(dir, &aside)));
    }
    Ok(out)
}

/// What [`prune_store`] deleted.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct StorePruned {
    /// Whole month files, every record in them older than the cutoff.
    pub files: usize,
    /// Records deleted one by one from a month the cutoff falls in (or
    /// from a file of the older layout).
    pub records: usize,
}

/// Delete stored records captured before `cutoff`: each month that ended
/// by then as a whole file, and the older records of the month the cutoff
/// falls in line by line. Records with no timestamp, and unreadable lines
/// in a file that is kept, are kept: their age is unknown. Damaged lines
/// set aside ([`set_aside_damaged`]) go once their file was last written
/// before `cutoff`. A source directory left empty is removed.
pub fn prune_store(dir: &Path, cutoff: i64) -> Result<StorePruned> {
    let mut done = StorePruned::default();
    for f in files(dir, "damaged")? {
        if f.modified().is_some_and(|m| m < cutoff) {
            std::fs::remove_file(&f.path)
                .with_context(|| format!("deleting {}", f.path.display()))?;
        }
    }
    for f in files(dir, "ndjson")? {
        let p = &f.path;
        match f.span {
            Span::Undated => continue,
            Span::Month(_, end) if end <= cutoff => {
                std::fs::remove_file(p).with_context(|| format!("deleting {}", p.display()))?;
                done.files += 1;
                continue;
            }
            Span::Month(start, _) if start >= cutoff => continue,
            Span::Month(..) | Span::Any => {}
        }
        let bytes = std::fs::read(p).with_context(|| format!("reading {}", p.display()))?;
        let mut kept: Vec<u8> = Vec::with_capacity(bytes.len());
        let mut dropped = 0;
        // An unreadable line has no known age, so it is kept as it is.
        for line in byte_lines(&bytes) {
            let ts = line
                .ok()
                .and_then(|l| serde_json::from_str::<Observation>(l).ok())
                .map_or(0, |o| o.ts);
            if ts > 0 && ts < cutoff {
                dropped += 1;
            } else {
                kept.extend_from_slice(match line {
                    Ok(l) => l.as_bytes(),
                    Err(b) => b,
                });
                kept.push(b'\n');
            }
        }
        if dropped > 0 {
            write_atomic(p, &kept)?;
            done.records += dropped;
        }
    }
    for p in entries(dir)? {
        if p.is_dir() && entries(&p).is_ok_and(|v| v.is_empty()) {
            let _ = std::fs::remove_dir(&p);
        }
    }
    Ok(done)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(id: &str, ts: i64) -> Observation {
        Observation {
            id: id.into(),
            ts,
            url: "https://a.example/".into(),
            ..Default::default()
        }
    }

    fn scratch(name: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("swarmchase-records-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn ids(v: &[Observation]) -> Vec<&str> {
        v.iter().map(|o| o.id.as_str()).collect()
    }

    fn ts(d: &str) -> i64 {
        sc_core::parse_ts(d).unwrap()
    }

    #[test]
    fn records_go_to_their_month_and_undated_ones_apart() {
        assert_eq!(partition_of(ts("2026-03-31T23:59:59Z")), "2026-03");
        assert_eq!(partition_of(ts("2026-04-01")), "2026-04");
        assert_eq!(partition_of(0), UNDATED);
        assert_eq!(partition_of(-5), UNDATED);
        assert_eq!(
            month_span("2026-12"),
            Some((ts("2026-12-01"), ts("2027-01-01")))
        );
        assert_eq!(month_span("2026-13"), None);
        assert_eq!(month_span("notes"), None);
        assert_eq!(Span::of("x-y"), Span::Any);
    }

    #[test]
    fn a_windowed_read_opens_only_the_months_it_reaches() {
        let d = scratch("window");
        let store = d.join("store");
        append_records(
            &store,
            "s",
            &[
                rec("jan", ts("2026-01-15")),
                rec("mar", ts("2026-03-02")),
                rec("mar-late", ts("2026-03-30")),
                rec("undated", 0),
            ],
        )
        .unwrap();
        assert!(store.join("s/2026-01.ndjson").is_file());
        assert!(store.join("s/2026-03.ndjson").is_file());
        assert!(store.join("s/undated.ndjson").is_file());
        // A month the window does not reach is not even opened: damage it,
        // and a windowed read neither fails nor counts it.
        std::fs::write(store.join("s/2026-01.ndjson"), b"\xff not a record\n").unwrap();
        let (got, bad) = load_store_counted(&store, ts("2026-03-10")).unwrap();
        assert_eq!(ids(&got), ["mar-late"]);
        assert!(bad.is_empty(), "{bad:?}");
        // An unbounded read takes in everything, and counts the damage.
        let (got, bad) = load_store_counted(&store, i64::MIN).unwrap();
        assert_eq!(ids(&got), ["mar", "mar-late", "undated"]);
        assert_eq!(bad.get("store/s/2026-01.ndjson"), Some(&1));
        // A file of the older layout is read by every read.
        std::fs::write(
            store.join("old.ndjson"),
            to_ndjson(&[rec("legacy", ts("2025-01-01"))]).unwrap(),
        )
        .unwrap();
        let got = load_store(&store, ts("2026-03-10")).unwrap();
        assert_eq!(ids(&got), ["mar-late"]);
        let got = load_store(&store, 0).unwrap();
        assert!(ids(&got).contains(&"legacy"));
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn ids_are_found_per_source_without_the_rest() {
        let d = scratch("ids");
        let store = d.join("store");
        append_records(&store, "a", &[rec("a1", ts("2026-01-01")), rec("a2", 0)]).unwrap();
        append_records(&store, "b", &[rec("b1", ts("2026-02-01"))]).unwrap();
        let wanted = BTreeMap::from([
            ("a".to_string(), BTreeSet::from(["a2".to_string()])),
            (
                "b".to_string(),
                BTreeSet::from(["b1".to_string(), "gone".to_string()]),
            ),
        ]);
        let mut got: Vec<(String, String)> = load_ids(&store, &wanted)
            .unwrap()
            .into_iter()
            .map(|(s, o)| (s, o.id))
            .collect();
        got.sort();
        assert_eq!(got, [("a".into(), "a2".into()), ("b".into(), "b1".into())]);
        assert_eq!(
            source_ids(&store, "a").unwrap(),
            BTreeSet::from(["a1".to_string(), "a2".to_string()])
        );
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn retention_deletes_whole_months_and_trims_the_one_the_cutoff_is_in() {
        let d = scratch("prune");
        let store = d.join("store");
        append_records(
            &store,
            "s",
            &[
                rec("jan", ts("2026-01-10")),
                rec("feb", ts("2026-02-10")),
                rec("mar-early", ts("2026-03-01")),
                rec("mar-late", ts("2026-03-20")),
                rec("apr", ts("2026-04-02")),
                rec("undated", 0),
            ],
        )
        .unwrap();
        append_records(&store, "gone", &[rec("g", ts("2026-01-03"))]).unwrap();
        // A month wholly before the cutoff goes without being read.
        std::fs::OpenOptions::new()
            .append(true)
            .open(store.join("s/2026-01.ndjson"))
            .unwrap()
            .write_all(b"{ torn\n")
            .unwrap();
        let cutoff = ts("2026-03-10");
        let done = prune_store(&store, cutoff).unwrap();
        assert_eq!(
            done,
            StorePruned {
                files: 3,
                records: 1
            }
        );
        assert!(!store.join("s/2026-01.ndjson").exists());
        assert!(!store.join("s/2026-02.ndjson").exists());
        assert!(!store.join("gone").exists(), "an emptied source goes");
        let left = load_store(&store, i64::MIN).unwrap();
        assert_eq!(ids(&left), ["mar-late", "apr", "undated"]);
        // Again: nothing more to delete.
        assert_eq!(prune_store(&store, cutoff).unwrap(), StorePruned::default());
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn damage_is_set_aside_in_the_files_a_run_reads_or_wrote() {
        let d = scratch("aside");
        let store = d.join("store");
        append_records(
            &store,
            "s",
            &[rec("old", ts("2020-01-01")), rec("new", ts("2026-03-01"))],
        )
        .unwrap();
        for part in ["2020-01", "2026-03"] {
            std::fs::OpenOptions::new()
                .append(true)
                .open(store.join(format!("s/{part}.ndjson")))
                .unwrap()
                .write_all(b"{ torn\n")
                .unwrap();
        }
        // The old month was written just now, so it is checked too.
        let moved = set_aside_damaged(&store, ts("2026-02-01")).unwrap();
        assert_eq!(
            moved.get("store/s/2026-03.ndjson"),
            Some(&(1, "store/s/2026-03.damaged".to_string()))
        );
        assert!(moved.contains_key("store/s/2020-01.ndjson"), "{moved:?}");
        assert!(
            set_aside_damaged(&store, ts("2026-02-01"))
                .unwrap()
                .is_empty()
        );
        let (got, bad) = load_store_counted(&store, i64::MIN).unwrap();
        assert_eq!(ids(&got), ["old", "new"]);
        assert!(bad.is_empty());
        // Retention deletes the set-aside lines once their file is older
        // than the cutoff, and not before.
        prune_store(&store, 0).unwrap();
        assert!(store.join("s/2026-03.damaged").exists());
        prune_store(&store, i64::MAX).unwrap();
        assert!(!store.join("s/2026-03.damaged").exists());
        std::fs::remove_dir_all(&d).unwrap();
    }
}
