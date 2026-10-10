//! What the site is built from: the notice index, one page per notice, and
//! the feed, as files to write. No I/O: the caller writes them.

use crate::feed::atom_feed;
use crate::file::{NoticeFile, NoticeMeta, NoticeStatus, UpdateKind, check_notice};
use crate::markdown::{Block, md_blocks};
use sc_core::Rules;
use serde::Serialize;

/// One row of the site's notice index.
#[derive(Debug, Clone, Serialize)]
pub struct IndexEntry<'a> {
    pub id: &'a str,
    pub title: &'a str,
    pub status: NoticeStatus,
    pub published: &'a str,
    pub updated: &'a str,
    pub providers: &'a [String],
    pub affected: &'a [String],
    pub corrected: bool,
    pub retracted: bool,
}

pub fn index_entry(n: &NoticeFile) -> IndexEntry<'_> {
    let has = |k| n.meta.updates.iter().any(|u| u.kind == k);
    IndexEntry {
        id: &n.meta.id,
        title: &n.meta.title,
        status: n.meta.status,
        published: &n.meta.published,
        updated: &n.meta.updated,
        providers: &n.meta.providers,
        affected: &n.meta.affected,
        corrected: has(UpdateKind::Correction),
        retracted: has(UpdateKind::Retraction),
    }
}

/// A notice page for the site: its front matter and its body as blocks.
#[derive(Debug, Clone, Serialize)]
pub struct NoticePage<'a> {
    pub meta: &'a NoticeMeta,
    pub blocks: Vec<Block>,
}

/// The site's notice files, as (path relative to the output directory,
/// contents): `index.json`, `<id>.json` per notice, and `feed.xml`. Newest
/// update first. Refuses when any notice fails its check. `base_url` is the
/// site's URL; a trailing `/` is added when missing.
pub fn build_site(
    notices: &mut [NoticeFile],
    base_url: &str,
    rules: &Rules,
) -> Result<Vec<(String, String)>, String> {
    for n in notices.iter() {
        let problems = check_notice(n, rules);
        if !problems.is_empty() {
            return Err(format!("{}: {}", n.meta.id, problems.join("; ")));
        }
    }
    notices.sort_by(|a, b| {
        b.meta
            .updated
            .cmp(&a.meta.updated)
            .then(a.meta.id.cmp(&b.meta.id))
    });
    let mut out = Vec::new();
    let index: Vec<_> = notices.iter().map(index_entry).collect();
    out.push((
        "index.json".to_string(),
        serde_json::to_string(&index).map_err(|e| e.to_string())?,
    ));
    for n in notices.iter() {
        let page = NoticePage {
            meta: &n.meta,
            blocks: md_blocks(&n.body),
        };
        out.push((
            format!("{}.json", n.meta.id),
            serde_json::to_string(&page).map_err(|e| e.to_string())?,
        ));
    }
    let base = if base_url.ends_with('/') {
        base_url.to_string()
    } else {
        format!("{base_url}/")
    };
    out.push(("feed.xml".to_string(), atom_feed(notices, &base)));
    Ok(out)
}
