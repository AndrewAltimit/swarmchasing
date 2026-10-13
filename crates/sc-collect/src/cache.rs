//! On-disk HTTP response cache: one body file and one metadata file per URL,
//! named by the URL's SHA-256. A response younger than the TTL is served
//! without a request; an older one is revalidated with `If-None-Match` /
//! `If-Modified-Since`, and a `304` refreshes it. The cache sits in the data
//! directory (`<data>/cache/http/`), outside git, and is safe to delete.
//!
//! Both files are written through a temporary file and a rename, and the
//! metadata holds the body's SHA-256: a body that does not match (a write
//! cut short, a body from another response) is a miss, never served.

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

/// Write via a temporary file beside `p`, unique to this process and call,
/// and a rename.
fn write_atomic(p: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let name = p.file_name().unwrap_or_default().to_string_lossy();
    let tmp = p.with_file_name(format!(
        ".{name}.{}.{}.tmp",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, p).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })
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
}
