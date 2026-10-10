//! Picking the records a case is opened from or extended with.

use super::cli::Selection;
use crate::input::{InputArgs, read_inputs};
use crate::pinning::RulesText;
use crate::store::load_store;
use anyhow::{Context, Result, bail};
use sc_core::{Analysis, Observation, Tier, analyze};
use std::collections::BTreeSet;
use std::path::Path;

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
        load_store(&dir, now - sel.days * 86_400)?
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
