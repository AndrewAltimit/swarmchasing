//! On-disk HTTP response cache: one body file and one metadata file per URL,
//! named by the URL's SHA-256. A response younger than the TTL is served
//! without a request; an older one is revalidated with `If-None-Match` /
//! `If-Modified-Since`, and a `304` refreshes it. The cache sits in the data
//! directory (`<data>/cache/http/`), outside git, and is safe to delete.
//!
//! Both files are written through a temporary file and a rename, and the
//! metadata holds the body's SHA-256: a body that does not match (a write
//! cut short, a body from another response) is a miss, never served.
//!
//! Cached bodies are raw collector answers, before redaction, so the watch
//! deletes entries older than its TTL (at least a day) on every run
//! ([`prune_http_cache`]).

use crate::client::{Fetched, now_secs};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::Duration;

pub(crate) struct HttpCache {
    dir: PathBuf,
    ttl: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Meta {
    pub url: String,
    #[serde(default)]
    pub etag: Option<String>,
    #[serde(default)]
    pub last_modified: Option<String>,
    #[serde(default)]
    pub content_type: Option<String>,
    /// When the response was stored or last revalidated (Unix seconds).
    pub stored: i64,
    /// SHA-256 of the body file, hex. An entry without one (written before
    /// it was kept) is a miss.
    #[serde(default)]
    pub sha256: String,
}

pub(crate) struct Cached {
    pub meta: Meta,
    pub body: String,
}

impl HttpCache {
    pub fn new(dir: &Path, ttl: Duration) -> Self {
        Self {
            dir: dir.to_path_buf(),
            ttl,
        }
    }

    fn paths(&self, url: &str) -> (PathBuf, PathBuf) {
        let k = hex(&Sha256::digest(url.as_bytes()));
        (
            self.dir.join(format!("{k}.json")),
            self.dir.join(format!("{k}.body")),
        )
    }

    pub fn load(&self, url: &str) -> Option<Cached> {
        let (m, b) = self.paths(url);
        let meta: Meta = serde_json::from_str(&std::fs::read_to_string(m).ok()?).ok()?;
        if meta.url != url {
            return None;
        }
        let body = std::fs::read_to_string(b).ok()?;
        if meta.sha256.is_empty() || hex(&Sha256::digest(body.as_bytes())) != meta.sha256 {
            return None;
        }
        Some(Cached { meta, body })
    }

    pub fn fresh(&self, c: &Cached) -> bool {
        now_secs() - c.meta.stored < self.ttl.as_secs() as i64
    }

    /// Store a response. Failures are ignored: the cache is an optimisation.
    pub fn store(&self, url: &str, f: &Fetched, etag: Option<&str>, last_modified: Option<&str>) {
        let meta = Meta {
            url: url.to_string(),
            etag: etag.map(str::to_string),
            last_modified: last_modified.map(str::to_string),
            content_type: f.content_type.clone(),
            stored: now_secs(),
            sha256: hex(&Sha256::digest(f.body.as_bytes())),
        };
        self.write(&meta, &f.body);
    }

    /// Mark a cached response as revalidated now.
    pub fn touch(&self, url: &str, c: &Cached) {
        let meta = Meta {
            stored: now_secs(),
            ..c.meta.clone()
        };
        let (m, _) = self.paths(url);
        if let Ok(s) = serde_json::to_string(&meta) {
            let _ = write_atomic(&m, s.as_bytes());
        }
    }

    fn write(&self, meta: &Meta, body: &str) {
        if std::fs::create_dir_all(&self.dir).is_err() {
            return;
        }
        let (m, b) = self.paths(&meta.url);
        if write_atomic(&b, body.as_bytes()).is_ok()
            && let Ok(s) = serde_json::to_string(meta)
        {
            let _ = write_atomic(&m, s.as_bytes());
        }
    }
}

/// A temporary path beside `p` that no other writer uses: the process id
/// and a counter, so two writers never share one.
pub fn temp_path(p: &Path) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let name = p.file_name().unwrap_or_default().to_string_lossy();
    p.with_file_name(format!(
        ".{name}.{}.{}.tmp",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ))
}

/// Write `bytes` to `p` through a temporary file beside it ([`temp_path`])
/// and a rename, so a crash never leaves half a file. The temporary file is
/// removed when the write or the rename fails. Every rewritten file in the
/// data directory goes through here.
pub fn write_atomic(p: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = temp_path(p);
    let done = std::fs::write(&tmp, bytes).and_then(|()| std::fs::rename(&tmp, p));
    if done.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    done
}

/// What [`prune_http_cache`] found and removed.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct CacheStats {
    /// Entries kept, and their bytes on disk (metadata and body).
    pub entries: usize,
    pub bytes: u64,
    /// Entries removed, and the bytes they held.
    pub removed: usize,
    pub removed_bytes: u64,
}

/// Delete cache entries under `dir` stored or last revalidated more than
/// `max_age` before `now` (Unix seconds), with bodies whose metadata is
/// gone and temporary files left by a write cut short. Cached responses are
/// raw collector answers, not redacted records, so they are kept no longer
/// than they are useful. A missing directory is an empty cache.
pub fn prune_http_cache(dir: &Path, max_age: Duration, now: i64) -> std::io::Result<CacheStats> {
    let mut st = CacheStats::default();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(st),
        Err(e) => return Err(e),
    };
    let cutoff = now - max_age.as_secs() as i64;
    let mtime = |p: &Path| -> i64 {
        std::fs::metadata(p)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_secs() as i64)
    };
    let size = |p: &Path| std::fs::metadata(p).map_or(0, |m| m.len());
    let mut files: Vec<PathBuf> = entries
        .filter_map(|e| Some(e.ok()?.path()))
        .filter(|p| p.is_file())
        .collect();
    files.sort();
    for p in &files {
        let name = p.file_name().unwrap_or_default().to_string_lossy();
        if name.ends_with(".tmp") {
            if mtime(p) < cutoff {
                st.removed_bytes += size(p);
                std::fs::remove_file(p)?;
            }
            continue;
        }
        let Some(stem) = name.strip_suffix(".json") else {
            continue;
        };
        let body = p.with_file_name(format!("{stem}.body"));
        let bytes = size(p) + size(&body);
        let stored = std::fs::read_to_string(p)
            .ok()
            .and_then(|s| serde_json::from_str::<Meta>(&s).ok())
            .map_or_else(|| mtime(p), |m| m.stored);
        if stored < cutoff {
            std::fs::remove_file(p)?;
            if body.exists() {
                std::fs::remove_file(&body)?;
            }
            st.removed += 1;
            st.removed_bytes += bytes;
        } else {
            st.entries += 1;
            st.bytes += bytes;
        }
    }
    // A body whose metadata is gone can never be served.
    for p in &files {
        let name = p.file_name().unwrap_or_default().to_string_lossy();
        if let Some(stem) = name.strip_suffix(".body")
            && !p.with_file_name(format!("{stem}.json")).exists()
            && p.exists()
        {
            st.removed_bytes += size(p);
            std::fs::remove_file(p)?;
        }
    }
    Ok(st)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stores_loads_and_expires() {
        let dir = std::env::temp_dir().join(format!("sc-collect-cache-{}", std::process::id()));
        let c = HttpCache::new(&dir, Duration::from_secs(3600));
        let url = "https://example.org/feed.xml";
        assert!(c.load(url).is_none());
        let f = Fetched {
            status: 200,
            body: "hello".into(),
            content_type: Some("text/xml".into()),
            final_url: url.into(),
        };
        c.store(url, &f, Some("\"abc\""), None);
        let hit = c.load(url).unwrap();
        assert_eq!(hit.body, "hello");
        assert_eq!(hit.meta.etag.as_deref(), Some("\"abc\""));
        assert!(c.fresh(&hit));
        assert!(c.load("https://example.org/other").is_none());
        let stale = HttpCache::new(&dir, Duration::ZERO);
        assert!(!stale.fresh(&stale.load(url).unwrap()));

        // A body that does not match its metadata is a miss.
        let (_, body) = c.paths(url);
        std::fs::write(&body, "hel").unwrap();
        assert!(c.load(url).is_none());
        c.store(url, &f, None, None);
        assert_eq!(c.load(url).unwrap().body, "hello");
        let leftovers = std::fs::read_dir(&dir)
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .path()
                    .extension()
                    .is_some_and(|x| x == "tmp")
            })
            .count();
        assert_eq!(leftovers, 0);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn pruning_drops_old_entries_orphans_and_leftovers() {
        let dir =
            std::env::temp_dir().join(format!("sc-collect-cache-prune-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let c = HttpCache::new(&dir, Duration::from_secs(3600));
        let f = |body: &str| Fetched {
            status: 200,
            body: body.into(),
            content_type: None,
            final_url: String::new(),
        };
        c.store("https://a.example/old", &f("old"), None, None);
        c.store("https://a.example/new", &f("new"), None, None);
        // Age the first entry by rewriting its metadata.
        let old = c.load("https://a.example/old").unwrap();
        let (m, _) = c.paths("https://a.example/old");
        let meta = Meta {
            stored: now_secs() - 3 * 86_400,
            ..old.meta
        };
        std::fs::write(&m, serde_json::to_string(&meta).unwrap()).unwrap();
        // A body without metadata, and a temporary file a crash left.
        std::fs::write(dir.join("orphan.body"), "x").unwrap();
        std::fs::write(dir.join(".a.json.1.2.tmp"), "x").unwrap();
        let st = prune_http_cache(&dir, Duration::from_secs(86_400), now_secs()).unwrap();
        assert_eq!((st.entries, st.removed), (1, 1), "{st:?}");
        assert!(st.bytes > 0 && st.removed_bytes > 0);
        assert!(c.load("https://a.example/old").is_none());
        assert_eq!(c.load("https://a.example/new").unwrap().body, "new");
        assert!(!dir.join("orphan.body").exists());
        // A fresh temporary file may belong to a write in progress.
        assert!(dir.join(".a.json.1.2.tmp").exists());
        let later = now_secs() + 2 * 86_400;
        let st = prune_http_cache(&dir, Duration::from_secs(86_400), later).unwrap();
        assert_eq!((st.entries, st.removed), (0, 1), "{st:?}");
        assert!(!dir.join(".a.json.1.2.tmp").exists());
        assert_eq!(
            prune_http_cache(&dir.join("none"), Duration::ZERO, 0).unwrap(),
            CacheStats::default()
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_failed_rename_leaves_no_temporary_file() {
        let dir = std::env::temp_dir().join(format!("sc-collect-atomic-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        // The target is a non-empty directory, so the rename fails.
        std::fs::create_dir_all(dir.join("target").join("inside")).unwrap();
        assert!(write_atomic(&dir.join("target"), b"x").is_err());
        let left: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(left, ["target"], "{left:?}");
        write_atomic(&dir.join("f"), b"y").unwrap();
        assert_eq!(std::fs::read(dir.join("f")).unwrap(), b"y");
        let _ = std::fs::remove_dir_all(dir);
    }
}
