//! On-disk HTTP response cache: one body file and one metadata file per URL,
//! named by the URL's SHA-256. A response younger than the TTL is served
//! without a request; an older one is revalidated with `If-None-Match` /
//! `If-Modified-Since`, and a `304` refreshes it. The cache sits in the data
//! directory (`<data>/cache/http/`), outside git, and is safe to delete.

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
            let _ = std::fs::write(m, s);
        }
    }

    fn write(&self, meta: &Meta, body: &str) {
        if std::fs::create_dir_all(&self.dir).is_err() {
            return;
        }
        let (m, b) = self.paths(&meta.url);
        if std::fs::write(&b, body).is_ok()
            && let Ok(s) = serde_json::to_string(meta)
        {
            let _ = std::fs::write(m, s);
        }
    }
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
        let _ = std::fs::remove_dir_all(dir);
    }
}
