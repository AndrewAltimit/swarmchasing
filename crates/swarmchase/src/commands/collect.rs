//! `swarmchase collect`: records from a public index, or urlquery reports by
//! ID. Collectors read indexes only and never open a capture.

use crate::store::{read_json, to_ndjson, write_json};
use crate::util::{require_urlquery_key, write_out};
use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand};
use sc_collect::{CdxQuery, Client, Cursor, Kind, Source, Wayback};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Subcommand)]
pub enum CollectSource {
    /// Wayback Machine CDX index.
    Wayback(CollectArgs),
    /// Arquivo.pt CDX index. It cannot page: a full result is cut at --limit.
    Arquivo(CollectArgs),
    /// urlquery.net report search (needs URLQUERY_APIKEY). PATTERN is a urlquery
    /// search query; --from/--to are rounded to whole days.
    Urlquery(CollectArgs),
    /// Common Crawl CDX index rows (never WARC content). --endpoint picks the
    /// crawl: `latest` (default), `latest:N`, or a crawl id.
    Commoncrawl(CollectArgs),
    /// urlscan.io public search (URLSCAN_APIKEY optional). PATTERN is a urlscan
    /// search query, e.g. `task.domain:r.jina.ai`. A per-case lookup: its terms
    /// rule out scheduled collection.
    Urlscan(CollectArgs),
    /// Memento timemap of one exact URL across web archives. --endpoint is the
    /// timemap endpoint (default: LANL TimeTravel).
    Memento(CollectArgs),
    /// GH Archive public GitHub events matching PATTERN (`|`-separated
    /// substrings of repo names or payload URLs). --scan is the hours read.
    Gharchive(CollectArgs),
    /// npm registry search: package names, versions and publish times.
    Npm(CollectArgs),
    /// PyPI RSS feed items matching PATTERN (`*` for all). --endpoint is
    /// `updates` (default) or `packages`.
    Pypi(CollectArgs),
    /// Certificates in a CT log whose DNS names match PATTERN. --endpoint is the
    /// log's base URL; --scan the newest entries read (default 256).
    Ctlog(CollectArgs),
    /// Wayback captures of agent protocol footprints (agent cards, agent
    /// registration files, signature key directories) under PATTERN: hosts or
    /// `*.domain`s, `|`-separated. Index rows only; the files are never fetched.
    Wellknown(CollectArgs),
    /// Official MCP Registry servers whose name or declared URLs match
    /// PATTERN (`*` for all), updated since --from. Metadata only.
    Mcp(CollectArgs),
    /// Fetch urlquery.net reports by ID (needs URLQUERY_APIKEY), e.g. to turn a
    /// labelled report list such as Transluce's reports.csv into records for
    /// `swarmchase eval`. Appends to --out and skips IDs already in it, so an
    /// interrupted fetch continues where it stopped.
    UrlqueryReports {
        /// Labels file (CSV or NDJSON with ids) or a plain list of report IDs.
        ids: PathBuf,
        /// Output NDJSON (appended to).
        #[arg(short, long)]
        out: PathBuf,
        /// Fetch at most this many agent-labelled reports, evenly spaced over
        /// the list. Benign-labelled reports (the controls) are always fetched.
        #[arg(long)]
        sample: Option<usize>,
    },
}

#[derive(Args)]
pub struct CollectArgs {
    /// CDX URL pattern, e.g. `r.jina.ai/*` (a search query or filter for the
    /// search and stream sources)
    pattern: String,
    /// yyyyMMdd[hhmmss]
    #[arg(long)]
    from: Option<String>,
    #[arg(long)]
    to: Option<String>,
    #[arg(long, default_value_t = 5000)]
    limit: usize,
    /// exact | prefix | host | domain
    #[arg(long)]
    match_type: Option<String>,
    /// Records per request (Wayback pages through the index).
    #[arg(long, default_value_t = 1000)]
    page_size: usize,
    /// Which instance of the source: a CT log URL, a crawl id, a timemap
    /// endpoint, a PyPI feed.
    #[arg(long)]
    endpoint: Option<String>,
    /// How much of a streamed source to read: CT log entries, GH Archive hours.
    #[arg(long)]
    scan: Option<usize>,
    /// CDX filter applied by the index server, e.g. `collection:SAWP.*` for
    /// Arquivo.pt's on-demand saves (repeatable; Wayback and Arquivo.pt).
    #[arg(long)]
    filter: Vec<String>,
    /// Read the time range in windows of this many days (Wayback).
    #[arg(long)]
    slice_days: Option<u32>,
    /// A query known to match, run once as a canary (npm).
    #[arg(long)]
    canary: Option<String>,
    /// Most compressed megabytes to stream (GH Archive).
    #[arg(long)]
    max_mb: Option<u64>,
    /// Cache responses in <data>/cache/http (data: SWARMCHASE_DATA, else ./data)
    /// and revalidate them with ETags.
    #[arg(long)]
    cache: bool,
    /// Output NDJSON file (default stdout).
    #[arg(short, long)]
    out: Option<PathBuf>,
    /// Continue an interrupted Wayback pull into `--out` (progress is kept in `<out>.resume.json`).
    #[arg(long, requires = "out")]
    resume: bool,
}

/// How long a cached response is used without revalidation.
const CACHE_TTL: Duration = Duration::from_secs(3600);

pub fn run(source: CollectSource) -> Result<()> {
    let (args, kind) = match source {
        CollectSource::UrlqueryReports { ids, out, sample } => {
            return fetch_urlquery_reports(&ids, &out, sample);
        }
        CollectSource::Wayback(a) => (a, Kind::Wayback),
        CollectSource::Arquivo(a) => (a, Kind::Arquivo),
        CollectSource::Urlquery(a) => (a, Kind::Urlquery),
        CollectSource::Commoncrawl(a) => (a, Kind::CommonCrawl),
        CollectSource::Urlscan(a) => (a, Kind::Urlscan),
        CollectSource::Memento(a) => (a, Kind::Memento),
        CollectSource::Gharchive(a) => (a, Kind::GhArchive),
        CollectSource::Npm(a) => (a, Kind::Npm),
        CollectSource::Pypi(a) => (a, Kind::Pypi),
        CollectSource::Ctlog(a) => (a, Kind::CtLog),
        CollectSource::Wellknown(a) => (a, Kind::WellKnown),
        CollectSource::Mcp(a) => (a, Kind::Mcp),
    };
    let mut client = Client::new(Duration::from_secs(2))?;
    if args.cache {
        let data = std::env::var("SWARMCHASE_DATA")
            .ok()
            .filter(|d| !d.is_empty())
            .map_or_else(|| PathBuf::from("data"), PathBuf::from);
        client = client.with_cache(&data.join("cache").join("http"), CACHE_TTL);
    }
    let q = CdxQuery {
        pattern: args.pattern,
        from: args.from,
        to: args.to,
        limit: args.limit,
        match_type: args.match_type,
        collapse_digest: false,
        page_size: args.page_size,
        endpoint: args.endpoint,
        scan: args.scan,
        filter: args.filter,
        slice_days: args.slice_days,
        canary: args.canary,
        max_mb: args.max_mb,
    };
    if let (Some(out), Kind::Wayback) = (&args.out, kind) {
        return collect_wayback_to_file(&client, q, out, args.resume);
    }
    if args.resume {
        bail!("--resume only applies to wayback");
    }
    let key = match kind {
        Kind::Urlquery => Some(require_urlquery_key()?),
        k => k.key_from_env(),
    };
    let limit = q.limit;
    let pull = sc_collect::source(kind, q, key)?
        .pull(&client, None, None, limit)?
        .strict()?;
    if pull.truncated {
        eprintln!(
            "warning: {} returned a full page it cannot page past; narrow the pattern or dates, or raise --limit",
            kind.name()
        );
    }
    eprintln!(
        "{} records, {} requests{}",
        pull.observations.len(),
        pull.requests,
        if client.cache_hits() > 0 {
            format!(", {} from cache", client.cache_hits())
        } else {
            String::new()
        }
    );
    write_out(args.out.as_deref(), &to_ndjson(&pull.observations)?)
}

/// Report IDs to fetch: every benign-labelled one, plus agent-labelled ones
/// (all, or `sample` of them evenly spaced). Plain lists count as agent.
fn report_ids(text: &str, sample: Option<usize>) -> Vec<String> {
    let labels = sc_core::parse_labels(text);
    let (mut agents, mut benign): (Vec<String>, Vec<String>) = if labels.labels.is_empty() {
        let ids = text
            .lines()
            .map(|l| l.trim().rsplit('/').next().unwrap_or("").to_string())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(|l| {
                if l.contains(':') {
                    l
                } else {
                    format!("urlquery:{l}")
                }
            })
            .collect();
        (ids, Vec::new())
    } else {
        let mut a = Vec::new();
        let mut b = Vec::new();
        for (id, l) in labels.labels {
            if l.label == sc_core::Label::Agent {
                a.push(id);
            } else {
                b.push(id);
            }
        }
        (a, b)
    };
    agents.sort();
    benign.sort();
    if let Some(n) = sample.filter(|&n| n < agents.len()) {
        let step = agents.len() as f64 / n as f64;
        agents = (0..n)
            .map(|i| agents[(i as f64 * step) as usize].clone())
            .collect();
    }
    benign.extend(agents);
    benign
}

fn fetch_urlquery_reports(ids_path: &Path, out: &Path, sample: Option<usize>) -> Result<()> {
    let text = std::fs::read_to_string(ids_path)
        .with_context(|| format!("reading {}", ids_path.display()))?;
    let ids = report_ids(&text, sample);
    let have: std::collections::HashSet<String> = std::fs::read_to_string(out)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter_map(|v| v.get("id").and_then(|x| x.as_str()).map(str::to_string))
        .collect();
    let todo: Vec<&String> = ids.iter().filter(|i| !have.contains(*i)).collect();
    eprintln!(
        "{} report IDs selected, {} already in {}, {} to fetch",
        ids.len(),
        ids.len() - todo.len(),
        out.display(),
        todo.len()
    );
    let key = require_urlquery_key()?;
    if let Some(dir) = out.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)?;
    }
    let client = Client::new(Duration::from_secs(2))?;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(out)?;
    let (mut ok, mut failed) = (0usize, 0usize);
    for (n, id) in todo.iter().enumerate() {
        match client.urlquery_report(&key, id) {
            Ok(o) => {
                use std::io::Write as _;
                writeln!(f, "{}", serde_json::to_string(&o)?)?;
                ok += 1;
            }
            Err(e) => {
                eprintln!("  {e:#}");
                failed += 1;
            }
        }
        if (n + 1) % 50 == 0 {
            eprintln!("  {}/{} ({ok} ok, {failed} failed)", n + 1, todo.len());
        }
    }
    eprintln!(
        "fetched {ok}, failed {failed}; records in {}",
        out.display()
    );
    Ok(())
}

/// Progress of a long Wayback pull, saved after every page.
#[derive(Serialize, Deserialize)]
struct ResumeState {
    query: CdxQuery,
    resume_key: String,
    written: usize,
}

fn collect_wayback_to_file(client: &Client, q: CdxQuery, out: &Path, resume: bool) -> Result<()> {
    let state_path = PathBuf::from(format!("{}.resume.json", out.display()));
    let saved: Option<ResumeState> = read_json(&state_path)?;
    let (key, mut written) = match saved {
        Some(s) if resume => {
            if s.query.pattern != q.pattern
                || s.query.from != q.from
                || s.query.to != q.to
                || s.query.match_type != q.match_type
            {
                bail!(
                    "{} was saved for a different query (pattern {}, from {:?}, to {:?}); rerun with the same arguments or drop --resume",
                    state_path.display(),
                    s.query.pattern,
                    s.query.from,
                    s.query.to
                );
            }
            eprintln!("resuming after {} records", s.written);
            (Some(s.resume_key), s.written)
        }
        Some(_) => {
            eprintln!(
                "note: starting over; pass --resume to continue the saved pull in {}",
                state_path.display()
            );
            (None, 0)
        }
        None if resume => bail!("nothing to resume: {} not found", state_path.display()),
        None => (None, 0),
    };
    if let Some(dir) = out.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)?;
    }
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .append(key.is_some())
        .truncate(key.is_none())
        .open(out)
        .with_context(|| format!("opening {}", out.display()))?;
    let limit = q.limit;
    let src = Wayback { query: q };
    // Every page goes to the file, and its resume key to the state file,
    // before the next one is fetched.
    let pull = src
        .pull_each(
            client,
            None,
            key.map(Cursor::Key),
            limit.saturating_sub(written),
            &mut |page| {
                std::io::Write::write_all(&mut f, to_ndjson(&page.records)?.as_bytes())?;
                written += page.records.len();
                eprintln!("{written} records");
                if let Some(Cursor::Key(k)) = &page.next {
                    write_json(
                        &state_path,
                        &ResumeState {
                            query: src.query.clone(),
                            resume_key: k.clone(),
                            written,
                        },
                    )?;
                }
                Ok(())
            },
        )?
        .strict()?;
    if pull.complete {
        let _ = std::fs::remove_file(&state_path);
        eprintln!("done: {written} records in {}", out.display());
    } else {
        eprintln!(
            "stopped at --limit {limit}; more records remain (continue with --resume and a higher --limit)"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_ids_take_every_control_and_a_sample_of_agents() {
        let plain = "https://urlquery.net/report/aa\n# comment\nbb\nurlquery:cc\n";
        assert_eq!(
            report_ids(plain, None),
            ["urlquery:aa", "urlquery:bb", "urlquery:cc"]
        );
        assert_eq!(report_ids(plain, Some(1)), ["urlquery:aa"]);
    }
}
