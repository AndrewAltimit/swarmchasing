//! The data directory's files: the watch record store, retention, and the
//! JSON and NDJSON helpers the watch, cases and review share.

use anyhow::{Context, Result, bail};
use sc_core::Observation;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write as _;
use std::path::Path;

/// Whether `data` holds anything a data directory holds: `state.json`, the
/// watch store, labels or cases.
pub fn has_data(data: &Path) -> bool {
    ["state.json", "store", "labels", "cases"]
        .iter()
        .any(|p| data.join(p).exists())
}

/// Which directory `data` is, as an absolute path, and how it was chosen.
pub fn describe_data(data: &Path) -> String {
    let abs = std::path::absolute(data).unwrap_or_else(|_| data.to_path_buf());
    let env = match std::env::var("SWARMCHASE_DATA") {
        Ok(v) if !v.is_empty() => format!("SWARMCHASE_DATA is {v}"),
        _ => "SWARMCHASE_DATA is not set".into(),
    };
    format!(
        "{} (the data directory is --data, else SWARMCHASE_DATA, else ./data; {env})",
        abs.display()
    )
}

/// For a command that reads existing data: say so when `data` holds none,
/// which usually means the wrong directory.
pub fn hint_if_empty(data: &Path) {
    if !has_data(data) {
        eprintln!("hint: no watch data or cases in {}", describe_data(data));
    }
}

/// The non-blank lines of `bytes`, split on `\n` and decoded one by one:
/// `Err` for a line that is not UTF-8, so one bad line never hides the rest.
pub fn byte_lines(bytes: &[u8]) -> impl Iterator<Item = std::result::Result<&str, &[u8]>> {
    bytes
        .split(|&b| b == b'\n')
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l))
        .filter(|l| !l.iter().all(u8::is_ascii_whitespace))
        .map(|l| std::str::from_utf8(l).map_err(|_| l))
}

/// The records of an NDJSON file, and how many of its lines could not be
/// read (not UTF-8, or not a record): a torn last line from a crash, or a
/// damaged file.
pub fn read_ndjson<T: for<'de> Deserialize<'de>>(p: &Path) -> Result<(Vec<T>, usize)> {
    let bytes = std::fs::read(p).with_context(|| format!("reading {}", p.display()))?;
    let mut out = Vec::new();
    let mut bad = 0;
    for line in byte_lines(&bytes) {
        match line.ok().and_then(|l| serde_json::from_str(l).ok()) {
            Some(v) => out.push(v),
            None => bad += 1,
        }
    }
    Ok((out, bad))
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
/// that has any.
pub fn load_store_counted(
    dir: &Path,
    since: i64,
) -> Result<(Vec<Observation>, BTreeMap<String, usize>)> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    let mut bad = BTreeMap::new();
    let mut files: Vec<_> = std::fs::read_dir(dir)?
        .map(|e| e.map(|e| e.path()))
        .collect::<std::io::Result<_>>()?;
    files.sort();
    for p in files {
        if p.extension().and_then(|e| e.to_str()) != Some("ndjson") {
            continue;
        }
        let (records, n) = read_ndjson::<Observation>(&p)?;
        if n > 0 {
            let name = p.file_name().unwrap_or_default().to_string_lossy();
            bad.insert(format!("store/{name}"), n);
        }
        for o in records {
            if o.ts >= since && seen.insert(o.id.clone()) {
                out.push(o);
            }
        }
    }
    Ok((out, bad))
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
            let bytes = std::fs::read(&p).with_context(|| format!("reading {}", p.display()))?;
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
                write_atomic(&p, &kept)?;
                records += dropped;
            }
        }
    }
    Ok((runs, records))
}

/// The files of a run's full analysis, which only the newest runs keep.
pub const ANALYSIS_FILES: [&str; 2] = ["analysis.json", "case-notes.md"];

/// Delete [`ANALYSIS_FILES`] from every run directory but the newest
/// `keep` (by stamp); 0 keeps them all. The rest of each run (its digest,
/// `run.json`, `summary.json`, attention queue and new records) stays.
/// Returns how many runs lost their analysis.
pub fn trim_analyses(out: &Path, keep: usize) -> Result<usize> {
    if keep == 0 {
        return Ok(0);
    }
    let Ok(entries) = std::fs::read_dir(out.join("runs")) else {
        return Ok(0);
    };
    let mut runs: Vec<(String, std::path::PathBuf)> = Vec::new();
    for entry in entries {
        let p = entry?.path();
        let stamp = p.file_name().and_then(|n| n.to_str()).unwrap_or_default();
        if p.is_dir() && chrono::NaiveDateTime::parse_from_str(stamp, "%Y%m%dT%H%M%SZ").is_ok() {
            runs.push((stamp.to_string(), p));
        }
    }
    runs.sort();
    let mut trimmed = 0;
    for (_, dir) in runs.iter().rev().skip(keep) {
        let mut any = false;
        for f in ANALYSIS_FILES {
            let p = dir.join(f);
            if p.exists() {
                std::fs::remove_file(&p).with_context(|| format!("deleting {}", p.display()))?;
                any = true;
            }
        }
        trimmed += usize::from(any);
    }
    Ok(trimmed)
}

pub fn to_ndjson(obs: &[Observation]) -> Result<String> {
    let mut s = String::new();
    for o in obs {
        s.push_str(&serde_json::to_string(o)?);
        s.push('\n');
    }
    Ok(s)
}

/// Append `text` to the NDJSON file `p`. A last line left without its
/// newline (a write cut short) is ended first, so it stays one unreadable
/// line instead of swallowing the first line appended after it.
pub fn append(p: &Path, text: &str) -> Result<()> {
    use std::io::{Read as _, Seek as _, SeekFrom};
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .append(true)
        .open(p)
        .with_context(|| format!("opening {}", p.display()))?;
    if f.metadata()?.len() > 0 {
        let mut last = [0u8; 1];
        f.seek(SeekFrom::End(-1))?;
        f.read_exact(&mut last)?;
        if last[0] != b'\n' {
            f.write_all(b"\n")?;
        }
    }
    f.write_all(text.as_bytes())
        .with_context(|| format!("writing {}", p.display()))?;
    Ok(())
}

pub use sc_collect::temp_path;

/// Write `bytes` to `p` via a temporary file and a rename, so a crash never
/// leaves half a file; the temporary file is removed when either step fails.
/// The one atomic write every data directory file goes through
/// ([`sc_collect::write_atomic`]).
pub fn write_atomic(p: &Path, bytes: &[u8]) -> Result<()> {
    sc_collect::write_atomic(p, bytes).with_context(|| format!("writing {}", p.display()))
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
    write_atomic(p, serde_json::to_string_pretty(v)?.as_bytes())
}

/// `<p>.bak`: the copy [`write_json_kept`] keeps of the file it replaces.
fn backup_path(p: &Path) -> std::path::PathBuf {
    let name = p.file_name().unwrap_or_default().to_string_lossy();
    p.with_file_name(format!("{name}.bak"))
}

/// [`write_json`], first copying the file it replaces to `<p>.bak`, the
/// copy [`read_json_kept`] falls back to.
pub fn write_json_kept<T: Serialize>(p: &Path, v: &T) -> Result<()> {
    if p.is_file() {
        let bak = backup_path(p);
        let tmp = temp_path(&bak);
        let done = std::fs::copy(p, &tmp).and_then(|_| std::fs::rename(&tmp, &bak));
        if done.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        done.with_context(|| format!("writing {}", bak.display()))?;
    }
    write_json(p, v)
}

/// [`read_json`], falling back to `<p>.bak` with a warning when `p` cannot
/// be read or parsed (and to the error when the backup cannot either).
pub fn read_json_kept<T: for<'de> Deserialize<'de>>(p: &Path) -> Result<Option<T>> {
    match read_json(p) {
        Ok(v) => Ok(v),
        Err(e) => {
            let bak = backup_path(p);
            match read_json(&bak) {
                Ok(Some(v)) => {
                    eprintln!(
                        "warning: {e:#}; read the previous copy {} instead",
                        bak.display()
                    );
                    Ok(Some(v))
                }
                _ => Err(e),
            }
        }
    }
}

/// The name of a data directory's lock file.
pub const LOCK_FILE: &str = ".lock";

/// An exclusive advisory lock on a data directory, held until dropped.
/// Every command that writes the store or `state.json` takes it, so two
/// never write at once.
#[derive(Debug)]
pub struct DataLock {
    file: std::fs::File,
}

impl Drop for DataLock {
    /// Unlock explicitly rather than by closing: a child process forked
    /// while the lock was held shares the open file until it execs, and
    /// closing only our handle would leave the lock held until then.
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

/// Take `<data>/.lock` for `what`, or fail at once, naming the holder, when
/// another command holds it. The holder is written to `<data>/.lock.owner`,
/// beside the lock, because a locked file cannot be read on every platform.
pub fn lock_data(data: &Path, what: &str) -> Result<DataLock> {
    std::fs::create_dir_all(data).with_context(|| format!("creating {}", data.display()))?;
    let p = data.join(LOCK_FILE);
    let owner = data.join(format!("{LOCK_FILE}.owner"));
    let f = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&p)
        .with_context(|| format!("opening {}", p.display()))?;
    match f.try_lock() {
        Ok(()) => {}
        Err(std::fs::TryLockError::WouldBlock) => {
            let holder = std::fs::read_to_string(&owner).unwrap_or_default();
            let holder = holder.trim();
            bail!(
                "{} is in use by another swarmchase command{}; try again when it has finished",
                data.display(),
                if holder.is_empty() {
                    String::new()
                } else {
                    format!(" ({holder})")
                }
            );
        }
        Err(std::fs::TryLockError::Error(e)) => {
            return Err(e).with_context(|| format!("locking {}", p.display()));
        }
    }
    // Who holds it is only a hint for the message above.
    let _ = std::fs::write(
        &owner,
        format!(
            "{what}, pid {}
",
            std::process::id()
        ),
    );
    Ok(DataLock { file: f })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_torn_line_stays_alone_and_bad_bytes_do_not_stop_a_read() {
        let dir = std::env::temp_dir().join(format!("swarmchase-torn-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("store")).unwrap();
        let p = dir.join("store").join("s.ndjson");
        let rec = |id: &str| Observation {
            id: id.into(),
            ts: 100,
            url: "https://a.example/".into(),
            ..Default::default()
        };
        append(&p, &to_ndjson(&[rec("a")]).unwrap()).unwrap();
        // A write cut short: half a line, no newline, then bytes that are
        // not UTF-8 on a line of their own.
        let mut torn = to_ndjson(&[rec("b")]).unwrap();
        torn.truncate(torn.len() / 2);
        append(&p, &torn).unwrap();
        append(&p, &to_ndjson(&[rec("c")]).unwrap()).unwrap();
        {
            use std::io::Write as _;
            let mut f = std::fs::OpenOptions::new().append(true).open(&p).unwrap();
            f.write_all(b"\xff\xfe{\n").unwrap();
        }
        append(&p, &to_ndjson(&[rec("d")]).unwrap()).unwrap();
        let (got, bad) = load_store_counted(&dir.join("store"), 0).unwrap();
        let ids: Vec<&str> = got.iter().map(|o| o.id.as_str()).collect();
        assert_eq!(ids, ["a", "c", "d"]);
        assert_eq!(bad.get("store/s.ndjson"), Some(&2), "{bad:?}");
        // Pruning keeps what it cannot date, byte for byte.
        let before = std::fs::read(&p).unwrap();
        prune(&dir, 50).unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), before);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn only_the_newest_runs_keep_their_full_analysis() {
        let d = std::env::temp_dir().join(format!("swarmchase-trim-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let stamps = [
            "20261001T000000Z",
            "20261002T000000Z",
            "20261003T000000Z",
            "20261004T000000Z",
        ];
        for s in stamps {
            let r = d.join("runs").join(s);
            std::fs::create_dir_all(&r).unwrap();
            for f in ["analysis.json", "case-notes.md", "digest.md", "run.json"] {
                std::fs::write(r.join(f), "x").unwrap();
            }
        }
        std::fs::create_dir_all(d.join("runs").join("not-a-run")).unwrap();
        std::fs::write(d.join("runs/not-a-run/analysis.json"), "x").unwrap();
        assert_eq!(trim_analyses(&d, 0).unwrap(), 0);
        assert_eq!(trim_analyses(&d, 2).unwrap(), 2);
        // Again: nothing left to trim.
        assert_eq!(trim_analyses(&d, 2).unwrap(), 0);
        for (i, s) in stamps.iter().enumerate() {
            let r = d.join("runs").join(s);
            assert_eq!(r.join("analysis.json").exists(), i >= 2, "{s}");
            assert_eq!(r.join("case-notes.md").exists(), i >= 2, "{s}");
            assert!(r.join("digest.md").exists() && r.join("run.json").exists());
        }
        assert!(d.join("runs/not-a-run/analysis.json").exists());
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn a_second_writer_is_refused_until_the_first_is_done() {
        let d = std::env::temp_dir().join(format!("swarmchase-lock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let first = lock_data(&d, "watch").unwrap();
        let err = lock_data(&d, "case rename").unwrap_err().to_string();
        assert!(err.contains("in use") && err.contains("watch"), "{err}");
        drop(first);
        lock_data(&d, "case rename").unwrap();
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn a_damaged_state_falls_back_to_its_previous_copy() {
        let d = std::env::temp_dir().join(format!("swarmchase-bak-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let p = d.join("state.json");
        write_json_kept(&p, &1).unwrap();
        write_json_kept(&p, &2).unwrap();
        assert_eq!(read_json_kept::<i32>(&p).unwrap(), Some(2));
        std::fs::write(&p, "{ torn").unwrap();
        assert_eq!(read_json_kept::<i32>(&p).unwrap(), Some(1));
        std::fs::remove_file(d.join("state.json.bak")).unwrap();
        assert!(read_json_kept::<i32>(&p).is_err());
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn temporary_names_are_unique() {
        let p = Path::new("d/state.json");
        assert_ne!(temp_path(p), temp_path(p));
    }

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
