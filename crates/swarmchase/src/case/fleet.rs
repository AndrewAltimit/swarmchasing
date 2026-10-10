//! `case fleet`: the admin's decision to treat soft-linked clusters as one
//! fleet, or to split one off again (SC-FM 5.8).
//!
//! The analysis proposes candidate fleets from soft links and never merges
//! anything. A merge here is the admin's call: it is stored in `case.toml`
//! by stable cluster key, logged in the decision log with the soft links it
//! rests on and how to reverse it, and from then on reports and STIX exports
//! group the clusters as one fleet. A merge with no soft link between the
//! clusters needs the admin's reason (`--why`).

use super::{Case, Fleet};
use anyhow::{Result, bail};
use sc_core::{Analysis, Audience, Cluster, defang};
use std::collections::BTreeSet;
use std::fmt::Write as _;

/// The stable key of the cluster `sel` names (`C3` or `k-3f9a2c1b`) in the
/// case's analysis.
fn resolve(a: &Analysis, sel: &str) -> Result<String> {
    match a.cluster(sel) {
        Some(c) if !c.key.is_empty() => Ok(c.key.clone()),
        _ => bail!(
            "no cluster `{sel}` in the case's analysis (see `swarmchase case fleet show <id>`)"
        ),
    }
}

/// The cluster with stable key `key`, if the analysis has it.
pub(crate) fn by_key<'a>(a: &'a Analysis, key: &str) -> Option<&'a Cluster> {
    a.clusters.iter().find(|c| c.key == key)
}

/// `C3 k-3f9a2c1b`, or the bare key when the analysis no longer has it.
pub(crate) fn label(a: &Analysis, key: &str) -> String {
    match by_key(a, key) {
        Some(c) => format!("{} {key}", c.id),
        None => format!("{key} (not in the current analysis)"),
    }
}

/// The soft links between clusters in `keys`, one line each:
/// `k-a ↔ k-b: shared pauses (0.60): detail`. With `detail` false, the
/// kind and strength only.
pub(crate) fn soft_evidence(a: &Analysis, keys: &BTreeSet<String>, detail: bool) -> Vec<String> {
    let key = |id: &str| a.cluster(id).map(|c| c.key.clone()).unwrap_or_default();
    a.soft_links
        .iter()
        .filter_map(|l| {
            let (ka, kb) = (key(&l.a), key(&l.b));
            (keys.contains(&ka) && keys.contains(&kb)).then(|| {
                let mut s = format!("{ka} ↔ {kb}: {} ({:.2})", l.kind.label(), l.strength);
                if detail && !l.detail.is_empty() {
                    s += &format!(": {}", defang(&crate::util::truncate(&l.detail, 160)));
                }
                s
            })
        })
        .collect()
}

/// The candidate fleet (`F2`) holding every cluster in `keys`, if one does.
fn proposed_by(a: &Analysis, keys: &BTreeSet<String>) -> Option<String> {
    a.candidate_fleets
        .iter()
        .find(|f| {
            let in_f: BTreeSet<String> = f
                .clusters
                .iter()
                .filter_map(|id| a.cluster(id).map(|c| c.key.clone()))
                .collect();
            keys.is_subset(&in_f)
        })
        .map(|f| f.id.clone())
}

fn next_id(c: &Case) -> String {
    let n = c
        .fleets
        .iter()
        .filter_map(|f| f.id.strip_prefix("fleet-")?.parse::<usize>().ok())
        .max()
        .unwrap_or(0);
    format!("fleet-{}", n + 1)
}

fn evidence_text(lines: &[String]) -> String {
    if lines.is_empty() {
        "no soft link in the case's analysis".into()
    } else {
        format!("soft links: {}", lines.join("; "))
    }
}

/// Merge the clusters `sels` name, with any fleets already holding them,
/// into one fleet. Returns the fleet's id.
pub(crate) fn merge(
    c: &mut Case,
    a: &Analysis,
    sels: &[String],
    why: Option<&str>,
    today: &str,
) -> Result<String> {
    let named: BTreeSet<String> = sels.iter().map(|s| resolve(a, s)).collect::<Result<_>>()?;
    let mut keys = named.clone();
    let mut absorbed: Vec<String> = Vec::new();
    for f in &c.fleets {
        if f.clusters.iter().any(|k| named.contains(k)) {
            keys.extend(f.clusters.iter().cloned());
            absorbed.push(f.id.clone());
        }
    }
    if keys.len() < 2 {
        bail!("a fleet needs at least two clusters");
    }
    if let [one] = absorbed.as_slice()
        && c.fleets
            .iter()
            .any(|f| f.id == *one && f.clusters.len() == keys.len())
    {
        bail!("those clusters are already {one}");
    }
    let evidence = soft_evidence(a, &keys, true);
    let why = why.map(str::trim).filter(|w| !w.is_empty());
    if evidence.is_empty() && why.is_none() {
        bail!(
            "no soft link joins these clusters in the case's analysis; a merge on other evidence needs the reason, with --why"
        );
    }
    absorbed.sort_by_key(|id| {
        id.strip_prefix("fleet-")
            .and_then(|n| n.parse::<usize>().ok())
            .unwrap_or(usize::MAX)
    });
    let id = absorbed.first().cloned().unwrap_or_else(|| next_id(c));
    c.fleets.retain(|f| !absorbed.contains(&f.id));
    c.fleets.push(Fleet {
        id: id.clone(),
        clusters: keys.iter().cloned().collect(),
        since: today.to_string(),
    });
    c.fleets.sort_by(|x, y| x.id.cmp(&y.id));
    let mut text = format!(
        "fleet {id}: merged {} ({})",
        keys.iter().cloned().collect::<Vec<_>>().join(", "),
        evidence_text(&evidence)
    );
    if absorbed.len() > 1 {
        text += &format!("; joins {}", absorbed.join(", "));
    }
    if let Some(f) = proposed_by(a, &keys) {
        text += &format!("; proposed as candidate fleet {f}");
    }
    if let Some(w) = why {
        text += &format!("; why: {w}");
    }
    text += &format!(
        "; reverse with `swarmchase case fleet split {} <key>`",
        c.id
    );
    c.log(today, text);
    Ok(id)
}

/// Take the cluster `sel` names out of its fleet; a fleet left with one
/// cluster is dissolved. `sel` may be a key the analysis no longer has.
/// Returns the fleet's id.
pub(crate) fn split(
    c: &mut Case,
    a: &Analysis,
    sel: &str,
    why: Option<&str>,
    today: &str,
) -> Result<String> {
    let key = match resolve(a, sel) {
        Ok(k) => k,
        Err(_) if c.fleet_of(sel.trim()).is_some() => sel.trim().to_string(),
        Err(e) => return Err(e),
    };
    let Some(i) = c.fleets.iter().position(|f| f.clusters.contains(&key)) else {
        bail!("{key} is in no fleet of case {}", c.id);
    };
    let before: BTreeSet<String> = c.fleets[i].clusters.iter().cloned().collect();
    let set_aside: Vec<String> = soft_evidence(a, &before, true)
        .into_iter()
        .filter(|l| l.contains(&key))
        .collect();
    let id = c.fleets[i].id.clone();
    c.fleets[i].clusters.retain(|k| *k != key);
    c.fleets[i].since = today.to_string();
    let rest = c.fleets[i].clusters.clone();
    let dissolved = rest.len() < 2;
    if dissolved {
        c.fleets.remove(i);
    }
    let mut text = format!(
        "fleet {id}: split off {key} (set aside {})",
        if set_aside.is_empty() {
            "no soft link".to_string()
        } else {
            format!("soft links: {}", set_aside.join("; "))
        }
    );
    if dissolved {
        text += &format!("; {id} dissolved");
    }
    if let Some(w) = why.map(str::trim).filter(|w| !w.is_empty()) {
        text += &format!("; why: {w}");
    }
    text += &format!(
        "; reverse with `swarmchase case fleet merge {} {key} {}`",
        c.id,
        rest.join(" ")
    );
    c.log(today, text);
    Ok(id)
}

/// The case's fleets, then the candidate fleets the analysis proposes that
/// the case has not merged, with the command that would.
pub(crate) fn show(c: &Case, a: &Analysis, out: &mut impl std::io::Write) -> Result<()> {
    writeln!(out, "Fleets (the admin's grouping)")?;
    if c.fleets.is_empty() {
        writeln!(out, "  none")?;
    }
    for f in &c.fleets {
        let keys: BTreeSet<String> = f.clusters.iter().cloned().collect();
        writeln!(out, "  {} since {}", f.id, f.since)?;
        for k in &f.clusters {
            writeln!(out, "    {}", label(a, k))?;
        }
        for l in soft_evidence(a, &keys, false) {
            writeln!(out, "    soft link {l}")?;
        }
    }
    writeln!(
        out,
        "\nCandidate fleets (proposals from soft links; never merged automatically)"
    )?;
    let mut any = false;
    for f in &a.candidate_fleets {
        let keys: Vec<String> = f
            .clusters
            .iter()
            .filter_map(|id| a.cluster(id).map(|c| c.key.clone()))
            .collect();
        let merged = keys.iter().all(|k| c.fleet_of(k).is_some())
            && keys
                .iter()
                .filter_map(|k| c.fleet_of(k).map(|f| &f.id))
                .collect::<BTreeSet<_>>()
                .len()
                == 1;
        if merged {
            continue;
        }
        any = true;
        let kinds: Vec<&str> = f.kinds.iter().map(|k| k.label()).collect();
        writeln!(
            out,
            "  {}: {} — {} (weakest pair {:.2})",
            f.id,
            keys.iter()
                .map(|k| label(a, k))
                .collect::<Vec<_>>()
                .join(", "),
            kinds.join(", "),
            f.strength
        )?;
        writeln!(
            out,
            "    merge: swarmchase case fleet merge {} {}",
            c.id,
            keys.join(" ")
        )?;
    }
    if !any {
        writeln!(out, "  none")?;
    }
    Ok(())
}

/// The report section on the case's fleets, or nothing when it has none in
/// this analysis. Soft-link details appear in case notes only; other
/// audiences get each link's kind and strength.
pub(crate) fn report_section(c: &Case, a: &Analysis, audience: Audience) -> String {
    let mut s = String::new();
    let fleets: Vec<(&Fleet, Vec<&Cluster>)> = c
        .fleets
        .iter()
        .map(|f| {
            let members: Vec<&Cluster> = f.clusters.iter().filter_map(|k| by_key(a, k)).collect();
            (f, members)
        })
        .filter(|(_, m)| m.len() >= 2)
        .collect();
    if fleets.is_empty() {
        return s;
    }
    let _ = writeln!(
        s,
        "## Fleets\n\nWe treat the clusters below as one fleet, one operator behind several runs. Their records share no linking identifier; the grouping rests on the soft links listed, each of which unrelated clients can also share. It is an Inference and is revised as evidence arrives.\n"
    );
    for (f, members) in fleets {
        let keys: BTreeSet<String> = members.iter().map(|m| m.key.clone()).collect();
        let _ = writeln!(
            s,
            "- **{}**: {}",
            f.id,
            members
                .iter()
                .map(|m| format!("{} (`{}`, {})", m.id, m.key, m.tier.label()))
                .collect::<Vec<_>>()
                .join(", ")
        );
        for l in soft_evidence(a, &keys, audience == Audience::Internal) {
            let _ = writeln!(s, "  - {l}");
        }
    }
    s.push('\n');
    s
}

/// `md` with the fleet section put before its representative records, or
/// at the end.
pub(crate) fn with_fleets(md: String, section: &str) -> String {
    if section.is_empty() {
        return md;
    }
    match md.find("## Representative records") {
        Some(i) => format!("{}{section}{}", &md[..i], &md[i..]),
        None => format!("{md}\n{section}"),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::case::test_support::*;
    use crate::case::{case_records, load, new_case, update};
    use crate::evidence::Scope;
    use crate::pinning::{RulesText, case_rules};
    use sc_core::{Observation, analyze};

    /// Two runs with different inboxes, a day apart, opening every host
    /// with the same recon requests: two clusters, soft-linked.
    pub(crate) fn two_runs() -> Vec<Observation> {
        let mut obs = Vec::new();
        for (f, inbox) in [
            "0b6c1f0e-1111-4c2a-9a55-3f2e1d0c9b8a",
            "7d2e4a10-2222-4b3c-8a66-4e3f2a1b0c9d",
        ]
        .iter()
        .enumerate()
        {
            let t0 = 1_791_000_000 + f as i64 * 86_400;
            for (k, h) in ["a.example", "b.example", "c.example"].iter().enumerate() {
                let t = t0 + 60 * k as i64;
                for (j, p) in ["/robots.txt", "/.well-known/security.txt", "/.env"]
                    .iter()
                    .enumerate()
                {
                    obs.push(Observation {
                        id: format!("{f}{k}{j}"),
                        ts: t + j as i64,
                        url: format!("https://{h}{p}"),
                        ..Default::default()
                    });
                }
                obs.push(Observation {
                    id: format!("{f}{k}x"),
                    ts: t + 10,
                    url: format!("https://{h}/q?hook=https://webhook.site/{inbox}"),
                    ..Default::default()
                });
            }
        }
        obs
    }

    #[test]
    fn merge_and_split_are_logged_and_reversible() {
        let root = scratch("fleet");
        let rules = RulesText::load(None).unwrap();
        new_case(&root, "f-1", "Two runs", two_runs(), &rules, "2026-10-12").unwrap();
        let c = load(&root, "f-1").unwrap();
        let a = analyze(
            case_records(&root, &c, &Scope::All).unwrap(),
            &case_rules(&root, &c).unwrap(),
        );
        assert_eq!(a.clusters.len(), 2);
        let (k1, k2) = (a.clusters[0].key.clone(), a.clusters[1].key.clone());

        // Nothing is merged until the admin says so.
        assert!(c.fleets.is_empty());
        let mut buf = Vec::new();
        show(&c, &a, &mut buf).unwrap();
        assert!(String::from_utf8(buf).unwrap().contains("none"));

        let mut c = c;
        assert!(
            merge(&mut c, &a, &["C1".into()], None, "d").is_err(),
            "one cluster"
        );
        assert!(merge(&mut c, &a, &["C1".into(), "C9".into()], None, "d").is_err());
        let id = merge(&mut c, &a, &["C1".into(), k2.clone()], None, "2026-10-13").unwrap();
        assert_eq!(id, "fleet-1");
        let mut want = vec![k1.clone(), k2.clone()];
        want.sort();
        assert_eq!(c.fleets[0].clusters, want);
        let log = &c.decisions.last().unwrap().text;
        assert!(log.contains("recon preamble"), "{log}");
        assert!(
            log.contains("reverse with `swarmchase case fleet split f-1"),
            "{log}"
        );
        assert!(
            merge(&mut c, &a, &[k1.clone(), k2.clone()], None, "d").is_err(),
            "again"
        );

        // Reports group them; the details stay in case notes.
        let internal = report_section(&c, &a, Audience::Internal);
        assert!(
            internal.contains("## Fleets") && internal.contains(&k1),
            "{internal}"
        );
        assert!(internal.contains("robots.txt"), "{internal}");
        let provider = report_section(&c, &a, Audience::Provider);
        assert!(provider.contains("recon preamble") && !provider.contains("robots.txt"));
        let md = with_fleets("# R\n\n## Representative records\n\nx\n".into(), &provider);
        assert!(md.find("## Fleets").unwrap() < md.find("## Representative").unwrap());

        // Split dissolves a two-cluster fleet and says how to undo it.
        let id = split(&mut c, &a, &k2, Some("different payload kit"), "2026-10-14").unwrap();
        assert_eq!(id, "fleet-1");
        assert!(c.fleets.is_empty());
        let log = &c.decisions.last().unwrap().text;
        assert!(
            log.contains("dissolved") && log.contains("why: different payload kit"),
            "{log}"
        );
        assert!(
            log.contains(&format!("case fleet merge f-1 {k2} {k1}")),
            "{log}"
        );
        assert!(split(&mut c, &a, &k2, None, "d").is_err(), "in no fleet");
        assert!(report_section(&c, &a, Audience::Internal).is_empty());

        // Saved and read back.
        update(&root, "f-1", |x| {
            merge(x, &a, &[k1.clone(), k2.clone()], None, "2026-10-15").map(|_| ())
        })
        .unwrap();
        let text = std::fs::read_to_string(root.join("f-1").join("case.toml")).unwrap();
        assert!(text.contains("[[fleet]]"), "{text}");
        assert_eq!(load(&root, "f-1").unwrap().fleets.len(), 1);
        cleanup(&root);
    }

    #[test]
    fn merge_without_soft_links_needs_a_reason() {
        let root = scratch("fleet-why");
        let rules = RulesText::load(None).unwrap();
        new_case(&root, "w-1", "W", two_runs(), &rules, "2026-10-12").unwrap();
        let mut c = load(&root, "w-1").unwrap();
        // The same clusters with their soft links taken away.
        let mut a = analyze(two_runs(), &rules.rules);
        a.soft_links.clear();
        let shown: Vec<String> = a.clusters.iter().map(|c| c.key.clone()).collect();
        assert_eq!(shown.len(), 2, "{shown:?}");
        assert!(merge(&mut c, &a, &shown[..2], None, "d").is_err());
        merge(&mut c, &a, &shown[..2], Some("same uqtag family"), "d").unwrap();
        assert!(c.decisions.last().unwrap().text.contains("no soft link"));
        cleanup(&root);
    }
}
