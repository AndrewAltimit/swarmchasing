//! Picking the records a case is opened from or extended with.

use crate::input::{InputArgs, read_inputs};
use crate::pinning::RulesText;
use crate::store::load_store;
use anyhow::{Context, Result, bail};
use clap::Args;
use sc_core::{Analysis, Observation, Tier, analyze};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Which records to take into a case.
#[derive(Args)]
pub struct Selection {
    /// Record files. Default: the watch store's last `--days` days.
    pub(super) input: Vec<PathBuf>,
    /// Days of the watch store to analyse. Default: the watchlist's
    /// `analysis_window_days`, the span the watch's digest analyses, so a
    /// cluster number from the digest names the same cluster here.
    #[arg(long)]
    pub(super) days: Option<i64>,
    /// The watchlist whose analysis window `--days` defaults to.
    #[arg(long, default_value = "watchlist.toml")]
    pub(super) watchlist: PathBuf,
    /// Clusters to take, by number in this analysis (C1) or stable key
    /// (k-3f9a2c1b); `swarmchase clusters` lists both.
    #[arg(long = "cluster")]
    pub(super) clusters: Vec<String>,
    /// Individual records to take, by ID.
    #[arg(long = "record")]
    pub(super) records: Vec<String>,
    /// Also take every flagged record on the hosts those records target,
    /// including other clusters, so the endpoint view is complete.
    #[arg(long)]
    pub(super) host_hits: bool,
    #[arg(long)]
    pub(super) rules: Option<PathBuf>,
}

/// Load records, analyse them, and pick the selected clusters and records.
pub(super) fn select(
    data: &Path,
    sel: &Selection,
    now: i64,
) -> Result<(RulesText, Vec<Observation>)> {
    if sel.clusters.is_empty() && sel.records.is_empty() {
        bail!("choose records with --cluster and/or --record");
    }
    let rules = RulesText::load(sel.rules.as_deref())?;
    let obs = if sel.input.is_empty() {
        let dir = data.join("store");
        if !dir.is_dir() {
            bail!(
                "no watch store at {} (pass record files, or set --data / SWARMCHASE_DATA)",
                dir.display()
            );
        }
        let days = match sel.days {
            Some(d) => d,
            None => window_days(&sel.watchlist)?,
        };
        load_store(&dir, now - days * 86_400)?
    } else {
        read_inputs(&InputArgs {
            input: sel.input.clone(),
            format: sc_core::Format::Auto,
            map: None,
            rules: None,
        })?
    };
    let a = analyze(obs, &rules.rules);
    let picked = pick(&a, &sel.clusters, &sel.records, sel.host_hits)?;
    Ok((rules, picked))
}

/// The watchlist's `analysis_window_days` (30 when the file or the setting
/// is missing): the records the watch analyses are those captured within
/// it, and its overlap only re-reads late captures for collection.
fn window_days(watchlist: &Path) -> Result<i64> {
    #[derive(serde::Deserialize)]
    struct Window {
        #[serde(default = "thirty")]
        analysis_window_days: i64,
    }
    fn thirty() -> i64 {
        30
    }
    let text = match std::fs::read_to_string(watchlist) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(thirty()),
        Err(e) => return Err(e).with_context(|| format!("reading {}", watchlist.display())),
    };
    let w: Window =
        toml::from_str(&text).with_context(|| format!("parsing {}", watchlist.display()))?;
    Ok(w.analysis_window_days)
}

pub(super) fn pick(
    a: &Analysis,
    clusters: &[String],
    records: &[String],
    host_hits: bool,
) -> Result<Vec<Observation>> {
    let mut idx = BTreeSet::new();
    for id in clusters {
        let c = a
            .cluster(id)
            .with_context(|| format!("no cluster `{id}` in this analysis"))?;
        idx.extend(c.members.iter().copied());
    }
    for id in records {
        let i = a
            .results
            .iter()
            .position(|r| &r.obs.id == id)
            .with_context(|| format!("no record `{id}` in this analysis"))?;
        idx.insert(i);
    }
    if !host_hits {
        return Ok(idx.into_iter().map(|i| a.results[i].obs.clone()).collect());
    }
    let hosts: BTreeSet<&str> = idx
        .iter()
        .filter_map(|&i| a.results[i].target_host.as_deref())
        .collect();
    for (i, r) in a.results.iter().enumerate() {
        if r.tier >= Tier::Suggestive && r.target_host.as_deref().is_some_and(|h| hosts.contains(h))
        {
            idx.insert(i);
        }
    }
    Ok(idx.into_iter().map(|i| a.results[i].obs.clone()).collect())
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::case::test_support::fixture;

    #[test]
    fn the_default_window_is_the_watchlists() {
        let d = std::env::temp_dir().join(format!("swarmchase-window-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let p = d.join("watchlist.toml");
        std::fs::write(&p, "analysis_window_days = 12\noverlap_days = 3\n").unwrap();
        assert_eq!(window_days(&p).unwrap(), 12);
        std::fs::write(&p, "overlap_days = 3\n").unwrap();
        assert_eq!(window_days(&p).unwrap(), 30);
        assert_eq!(window_days(&d.join("none.toml")).unwrap(), 30);
        // The committed watchlist parses.
        let committed = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../watchlist.toml");
        assert!(window_days(&committed).unwrap() > 0);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn pick_takes_clusters_and_optionally_every_hit_on_their_hosts() {
        let a = fixture();
        let c = a
            .clusters
            .iter()
            .find(|c| c.target_hosts.contains_key("portal.example.gov"))
            .unwrap();
        let ids = |host_hits| -> BTreeSet<String> {
            pick(&a, std::slice::from_ref(&c.id), &[], host_hits)
                .unwrap()
                .into_iter()
                .map(|o| o.id)
                .collect()
        };
        assert!(!ids(false).contains("late"));
        let ids = ids(true);
        assert!(ids.contains("r0") && ids.contains("late"), "{ids:?}");
        assert!(!ids.contains("other"));
        assert!(pick(&a, &["C99".into()], &[], false).is_err());
    }
}
