//! `swarmchase dashboard`: the state of monitoring at a glance, as a local
//! page ([`crate::localui`]) or, with `--json`, as one JSON document.
//!
//! It answers, in order: what is new since the admin last looked (new and
//! escalated clusters, lone significant records), whether monitoring is
//! healthy (each source's standing, the digest's health alerts, rule
//! drift), what waits on the admin (the review queue, open cases and their
//! clocks), and the command for each next step. Everything is read from the
//! data directory a watch run leaves ([`overview`]); the page writes
//! nothing. Which run the admin last looked at is the page's own memory
//! (browser storage) or `--since`.

pub mod overview;

use crate::localui::{App, Response, Server};
use anyhow::{Result, bail};
use sc_core::Analysis;
use serde_json::json;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const SCRIPT: &str = include_str!("page/dashboard.js");
const STYLE: &str = include_str!("page/dashboard.css");

#[derive(clap::Args)]
pub struct DashboardArgs {
    /// Data directory (the watch's `--out`).
    #[arg(short, long, default_value = "data", env = "SWARMCHASE_DATA")]
    data: PathBuf,
    /// Watchlist, for each source's kind and the analysis window. Read when
    /// present.
    #[arg(long, default_value = "watchlist.toml")]
    watchlist: PathBuf,
    /// Port on 127.0.0.1.
    #[arg(long, default_value_t = 8767)]
    port: u16,
    /// Print the overview as JSON and exit instead of serving the page.
    #[arg(long)]
    json: bool,
    /// With `--json`: count as new what runs after this one collected
    /// (a run stamp, e.g. 20261011T060000Z). Default: the run before the
    /// latest, as the digest does.
    #[arg(long, requires = "json")]
    since: Option<String>,
}

/// Source name to kind, and the analysis window, from a watchlist.
fn read_watchlist(p: &Path) -> (BTreeMap<String, String>, i64) {
    let Ok(text) = std::fs::read_to_string(p) else {
        return (BTreeMap::new(), 30);
    };
    match toml::from_str::<crate::watch::Watchlist>(&text) {
        Ok(wl) => (
            wl.sources.into_iter().map(|s| (s.name, s.kind)).collect(),
            wl.analysis_window_days,
        ),
        Err(e) => {
            eprintln!("warning: {} not read: {e}", p.display());
            (BTreeMap::new(), 30)
        }
    }
}

pub fn run(args: DashboardArgs) -> Result<()> {
    crate::store::hint_if_empty(&args.data);
    let (kinds, window_days) = read_watchlist(&args.watchlist);
    let mut app = DashboardApp::new(args.data, kinds, window_days);
    if args.json {
        if let Some(s) = &args.since
            && !overview::is_stamp(s)
        {
            bail!("--since takes a run stamp such as 20261011T060000Z");
        }
        let v = app.overview(args.since.as_deref(), chrono::Utc::now().timestamp())?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        return Ok(());
    }
    Server::new(app, args.port).run("dashboard")
}

pub struct DashboardApp {
    data: PathBuf,
    kinds: BTreeMap<String, String>,
    window_days: i64,
    /// The latest run's stamp and analysis, reloaded when `LATEST` moves.
    cache: Option<(String, Option<Analysis>)>,
}

impl DashboardApp {
    pub fn new(data: PathBuf, kinds: BTreeMap<String, String>, window_days: i64) -> Self {
        Self {
            data,
            kinds,
            window_days,
            cache: None,
        }
    }

    fn analysis(&mut self) -> Result<Option<&Analysis>> {
        let latest = overview::latest(&self.data);
        let stale = match (&self.cache, &latest) {
            (Some((s, _)), Some(l)) => s != l,
            (None, Some(_)) => true,
            (_, None) => {
                self.cache = None;
                return Ok(None);
            }
        };
        if stale && let Some(l) = latest {
            let a = overview::load_analysis(&self.data, &l)?;
            self.cache = Some((l, a));
        }
        Ok(self.cache.as_ref().and_then(|(_, a)| a.as_ref()))
    }

    pub fn overview(&mut self, since: Option<&str>, now: i64) -> Result<serde_json::Value> {
        let data = self.data.clone();
        let kinds = std::mem::take(&mut self.kinds);
        let window_days = self.window_days;
        let res = self.analysis().and_then(|a| {
            overview::overview(&overview::Inputs {
                data: &data,
                kinds: &kinds,
                window_days,
                since,
                analysis: a,
                now,
            })
        });
        self.kinds = kinds;
        res
    }

    /// A run's digest as text.
    fn digest(&self, stamp: &str) -> Response {
        if !overview::is_stamp(stamp) {
            return Response::error(400, "not a run stamp");
        }
        match std::fs::read_to_string(self.data.join("runs").join(stamp).join("digest.md")) {
            Ok(text) => Response::json(200, &json!({ "stamp": stamp, "text": text })),
            Err(_) => Response::error(404, "no digest for that run"),
        }
    }
}

impl App for DashboardApp {
    fn title(&self) -> String {
        "Monitoring".into()
    }

    fn script(&self) -> &'static str {
        SCRIPT
    }

    fn style(&self) -> &'static str {
        STYLE
    }

    fn get(&mut self, path: &str) -> Option<Response> {
        let since = match path {
            "overview" => None,
            p => match p.strip_prefix("overview/since/") {
                Some(s) if overview::is_stamp(s) => Some(s.to_string()),
                Some(_) => return Some(Response::error(400, "not a run stamp")),
                None => {
                    return path.strip_prefix("digest/").map(|s| self.digest(s));
                }
            },
        };
        let now = chrono::Utc::now().timestamp();
        Some(match self.overview(since.as_deref(), now) {
            Ok(v) => Response::json(200, &v),
            Err(e) => Response::error(500, &format!("{e:#}")),
        })
    }

    fn post(&mut self, _path: &str, _body: &[u8], _now: &str) -> Response {
        Response::error(404, "the dashboard is read-only")
    }
}

#[cfg(test)]
mod tests;
