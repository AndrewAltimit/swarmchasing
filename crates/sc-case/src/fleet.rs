//! `case fleet`: the admin's decision to treat soft-linked clusters as one
//! fleet, or to split one off again (SC-FM 5.8).
//!
//! The analysis proposes candidate fleets from soft links and never merges
//! anything. A merge here is the admin's call: it is stored in `case.toml`
//! by stable cluster key, logged in the decision log with the soft links it
//! rests on and how to reverse it, and from then on reports and STIX exports
//! group the clusters as one fleet. A merge with no soft link between the
//! clusters needs the admin's reason (`--why`).
//!
//! A fleet becomes a swarm only by `case fleet interaction`: the admin
//! records interaction between its runs they reviewed (SC-FM 1.3), usually
//! starting from the analysis's interaction edges, which never do it alone.

use crate::model::{Case, Fleet, SwarmEvidence};
use crate::text::truncate;
use crate::{Result, bail};
use sc_core::{Analysis, Audience, Cluster, SwarmEdge, SwarmEdgeKind, defang};
use std::collections::BTreeSet;
use std::fmt::Write as _;

/// The stable key of the cluster `sel` names (`C3` or `k-3f9a2c1b`) in the
/// case's analysis.
pub fn resolve(a: &Analysis, sel: &str) -> Result<String> {
    match a.cluster(sel) {
        Some(c) if !c.key.is_empty() => Ok(c.key.clone()),
        _ => bail!(
            "no cluster `{sel}` in the case's analysis (see `swarmchase case fleet show <id>`)"
        ),
    }
}

/// The cluster with stable key `key`, if the analysis has it.
pub fn by_key<'a>(a: &'a Analysis, key: &str) -> Option<&'a Cluster> {
    a.clusters.iter().find(|c| c.key == key)
}

/// `C3 k-3f9a2c1b`, or the bare key when the analysis no longer has it.
pub fn label(a: &Analysis, key: &str) -> String {
    match by_key(a, key) {
        Some(c) => format!("{} {key}", c.id),
        None => format!("{key} (not in the current analysis)"),
    }
}

/// The soft links between clusters in `keys`, one line each:
/// `k-a ↔ k-b: shared pauses (0.60): detail`. With `detail` false, the
/// kind and strength only.
pub fn soft_evidence(a: &Analysis, keys: &BTreeSet<String>, detail: bool) -> Vec<String> {
    let key = |id: &str| a.cluster(id).map(|c| c.key.clone()).unwrap_or_default();
    a.soft_links
        .iter()
        .filter_map(|l| {
            let (ka, kb) = (key(&l.a), key(&l.b));
            (keys.contains(&ka) && keys.contains(&kb)).then(|| {
                let mut s = format!("{ka} ↔ {kb}: {} ({:.2})", l.kind.label(), l.strength);
                if detail && !l.detail.is_empty() {
                    s += &format!(": {}", defang(&truncate(&l.detail, 160)));
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
pub fn merge(
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
    let swarm_evidence = c
        .fleets
        .iter()
        .filter(|f| absorbed.contains(&f.id))
        .flat_map(|f| f.swarm_evidence.iter().cloned())
        .collect();
    c.fleets.retain(|f| !absorbed.contains(&f.id));
    c.fleets.push(Fleet {
        id: id.clone(),
        clusters: keys.iter().cloned().collect(),
        since: today.to_string(),
        swarm_evidence,
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
pub fn split(
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
    // Interaction evidence naming the cluster no longer stands for this fleet.
    let prefix = format!("{key}#");
    let before_ev = c.fleets[i].swarm_evidence.len();
    c.fleets[i]
        .swarm_evidence
        .retain(|e| !e.runs.iter().any(|r| r.starts_with(&prefix)));
    let dropped_ev = before_ev - c.fleets[i].swarm_evidence.len();
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
    if dropped_ev > 0 {
        text += &format!("; {dropped_ev} interaction record(s) naming it set aside");
    }
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

/// The analysis's interaction edges between runs of clusters in `keys`.
pub fn swarm_edges<'a>(a: &'a Analysis, keys: &BTreeSet<String>) -> Vec<&'a SwarmEdge> {
    a.swarm_edges
        .iter()
        .filter(|e| keys.contains(&e.a.key) && keys.contains(&e.b.key))
        .collect()
}

fn edge_line(e: &SwarmEdge) -> String {
    format!(
        "{} {} ({}): {} {} {}",
        e.kind.id(),
        e.kind.label(),
        e.strength.label(),
        e.a.stable(),
        if e.kind == SwarmEdgeKind::Handoff {
            "→"
        } else {
            "↔"
        },
        e.b.stable()
    )
}

/// `k-3f9a2c1b#2` from `C3#2` or `k-3f9a2c1b#2`, checked against the fleet.
fn resolve_run(a: &Analysis, f: &Fleet, sel: &str) -> Result<String> {
    let Some((cl, n)) = sel.trim().rsplit_once('#') else {
        bail!("run `{sel}`: write it as <cluster>#<run>, e.g. C3#2 or k-3f9a2c1b#2");
    };
    let n: usize = n
        .parse()
        .ok()
        .filter(|&n| n > 0)
        .ok_or_else(|| crate::Error(format!("run `{sel}`: the run number counts from 1")))?;
    let key = match a.cluster(cl) {
        Some(c) => {
            if n > c.runs.len() {
                bail!("{} has {} run(s), not {n}", c.id, c.runs.len());
            }
            c.key.clone()
        }
        None => cl.to_string(),
    };
    if !f.clusters.contains(&key) {
        bail!("{key} is not in {}", f.id);
    }
    Ok(format!("{key}#{n}"))
}

/// Record interaction evidence the admin reviewed on fleet `fleet`: from
/// then on reports and the notice call it a swarm.
pub fn interaction(
    c: &mut Case,
    a: &Analysis,
    fleet: &str,
    kind: SwarmEdgeKind,
    runs: &[String],
    note: &str,
    today: &str,
) -> Result<()> {
    let note = note.trim();
    if note.is_empty() {
        bail!(
            "say what the records show (--note): interaction is the admin's reading, never the analysis's"
        );
    }
    let case_id = c.id.clone();
    let Some(f) = c.fleets.iter_mut().find(|f| f.id == fleet) else {
        bail!("no fleet `{fleet}` in case {case_id} (see `swarmchase case fleet show {case_id}`)");
    };
    let runs: Vec<String> = runs
        .iter()
        .map(|r| resolve_run(a, f, r))
        .collect::<Result<_>>()?;
    let keys: BTreeSet<String> = f.clusters.iter().cloned().collect();
    let support: Vec<String> = swarm_edges(a, &keys)
        .into_iter()
        .filter(|e| e.kind == kind && runs.contains(&e.a.stable()) && runs.contains(&e.b.stable()))
        .map(edge_line)
        .collect();
    f.swarm_evidence.push(SwarmEvidence {
        kind,
        runs: runs.clone(),
        note: note.to_string(),
        date: today.to_string(),
    });
    let n = f.swarm_evidence.len();
    let text = format!(
        "{fleet}: interaction recorded ({} {}, runs {}; {}; why: {note}); reported as a swarm while it stands; reverse with `swarmchase case fleet withdraw {case_id} {fleet} {n}`",
        kind.id(),
        kind.label(),
        runs.join(", "),
        if support.is_empty() {
            "no matching edge in the case's analysis".to_string()
        } else {
            format!("analysis edges: {}", support.join("; "))
        }
    );
    c.log(today, text);
    Ok(())
}

/// Withdraw interaction record `n` (from 1) of fleet `fleet`.
pub fn withdraw(c: &mut Case, fleet: &str, n: usize, why: Option<&str>, today: &str) -> Result<()> {
    let case_id = c.id.clone();
    let Some(f) = c.fleets.iter_mut().find(|f| f.id == fleet) else {
        bail!("no fleet `{fleet}` in case {case_id}");
    };
    if n == 0 || n > f.swarm_evidence.len() {
        bail!(
            "{fleet} has {} interaction record(s)",
            f.swarm_evidence.len()
        );
    }
    let e = f.swarm_evidence.remove(n - 1);
    let mut text = format!(
        "{fleet}: interaction withdrawn ({} {}, runs {}: {})",
        e.kind.id(),
        e.kind.label(),
        e.runs.join(", "),
        e.note
    );
    if !f.is_swarm() {
        text += "; reported as a fleet again";
    }
    if let Some(w) = why.map(str::trim).filter(|w| !w.is_empty()) {
        text += &format!("; why: {w}");
    }
    c.log(today, text);
    Ok(())
}

/// The case's fleets, then the candidate fleets the analysis proposes that
/// the case has not merged, with the command that would.
pub fn show(c: &Case, a: &Analysis, out: &mut impl std::io::Write) -> Result<()> {
    writeln!(out, "Fleets (the admin's grouping)")?;
    if c.fleets.is_empty() {
        writeln!(out, "  none")?;
    }
    for f in &c.fleets {
        let keys: BTreeSet<String> = f.clusters.iter().cloned().collect();
        writeln!(out, "  {} ({}) since {}", f.id, f.noun(), f.since)?;
        for k in &f.clusters {
            writeln!(out, "    {}", label(a, k))?;
        }
        for l in soft_evidence(a, &keys, false) {
            writeln!(out, "    soft link {l}")?;
        }
        for (n, e) in f.swarm_evidence.iter().enumerate() {
            writeln!(
                out,
                "    interaction {} ({}): {} {}, runs {}: {}",
                n + 1,
                e.date,
                e.kind.id(),
                e.kind.label(),
                e.runs.join(", "),
                e.note
            )?;
        }
        let edges = swarm_edges(a, &keys);
        for e in &edges {
            writeln!(out, "    possible interaction {}", edge_line(e))?;
        }
        if !edges.is_empty() {
            writeln!(
                out,
                "    record one you reviewed: swarmchase case fleet interaction {} {} --kind <kind> --run <cluster>#<run> ... --note <what the records show>",
                c.id, f.id
            )?;
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
            "  {}: {}, {} (weakest pair {:.2})",
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
/// audiences get each link's kind and strength. A fleet is called a swarm
/// only when the case records interaction evidence for it; the public
/// notice gets those swarms alone, without keys, links or notes.
pub fn report_section(c: &Case, a: &Analysis, audience: Audience) -> String {
    let mut s = String::new();
    let fleets: Vec<(&Fleet, Vec<&Cluster>)> = c
        .fleets
        .iter()
        .filter(|f| audience != Audience::Public || f.is_swarm())
        .map(|f| {
            let members: Vec<&Cluster> = f.clusters.iter().filter_map(|k| by_key(a, k)).collect();
            (f, members)
        })
        .filter(|(_, m)| m.len() >= 2)
        .collect();
    if fleets.is_empty() {
        return s;
    }
    let kinds = |f: &Fleet| -> String {
        let k: BTreeSet<&str> = f.swarm_evidence.iter().map(|e| e.kind.label()).collect();
        k.into_iter().collect::<Vec<_>>().join(", ")
    };
    if audience == Audience::Public {
        let _ = writeln!(s, "## Swarm\n");
        for (f, members) in fleets {
            let _ = writeln!(
                s,
                "We treat {} of the clusters here ({}) as one swarm: agents whose records, on our review, show them interacting ({}, SC-T9). This is an Inference from public records and is revised as evidence arrives.\n",
                members.len(),
                members
                    .iter()
                    .map(|m| m.id.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
                kinds(f)
            );
        }
        return s;
    }
    let any_swarm = fleets.iter().any(|(f, _)| f.is_swarm());
    let _ = writeln!(
        s,
        "## {}\n\nWe treat the clusters below as one fleet, one operator behind several runs. Their records share no linking identifier; the grouping rests on the soft links listed, each of which unrelated clients can also share. It is an Inference and is revised as evidence arrives.{}\n",
        if any_swarm {
            "Fleets and swarms"
        } else {
            "Fleets"
        },
        if any_swarm {
            " A fleet marked swarm also has interaction between its runs that we reviewed (SC-T9), listed under it; that too is an Inference."
        } else {
            ""
        }
    );
    for (f, members) in fleets {
        let keys: BTreeSet<String> = members.iter().map(|m| m.key.clone()).collect();
        let _ = writeln!(
            s,
            "- **{}**{}: {}",
            f.id,
            if f.is_swarm() { " (swarm)" } else { "" },
            members
                .iter()
                .map(|m| format!("{} (`{}`, {})", m.id, m.key, m.tier.label()))
                .collect::<Vec<_>>()
                .join(", ")
        );
        for l in soft_evidence(a, &keys, audience == Audience::Internal) {
            let _ = writeln!(s, "  - {l}");
        }
        for e in &f.swarm_evidence {
            let note = match audience {
                Audience::Internal | Audience::Provider => {
                    format!(": {}", defang(&truncate(&e.note, 200)))
                }
                _ => String::new(),
            };
            let _ = writeln!(
                s,
                "  - interaction (Inference): {} {}, runs {}{note}",
                e.kind.id(),
                e.kind.label(),
                e.runs.join(", ")
            );
        }
    }
    s.push('\n');
    s
}

/// `md` with the fleet section put before its representative records, or
/// at the end.
pub fn with_fleets(md: String, section: &str) -> String {
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
    use sc_core::{Observation, Rules, analyze};

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

    fn case(id: &str) -> Case {
        Case::new(id, "S", "d", None)
    }

    #[test]
    fn a_fleet_is_a_swarm_only_with_recorded_interaction() {
        let a = analyze(two_runs(), &Rules::default_rules());
        let (k1, k2) = (a.clusters[0].key.clone(), a.clusters[1].key.clone());
        let mut c = case("s-1");
        merge(&mut c, &a, &[k1.clone(), k2.clone()], None, "2026-10-13").unwrap();
        let internal = report_section(&c, &a, Audience::Internal);
        assert!(
            internal.starts_with("## Fleets\n") && !internal.contains("swarm"),
            "{internal}"
        );
        assert!(report_section(&c, &a, Audience::Public).is_empty());

        let add = |c: &mut Case, runs: &[&str], note: &str| {
            let runs: Vec<String> = runs.iter().map(|s| s.to_string()).collect();
            interaction(
                c,
                &a,
                "fleet-1",
                SwarmEdgeKind::Handoff,
                &runs,
                note,
                "2026-10-14",
            )
        };
        assert!(
            add(&mut c, &["C1#1", "C2#1"], " ").is_err(),
            "a note is required"
        );
        assert!(add(&mut c, &["C1#9"], "x").is_err(), "no such run");
        assert!(add(&mut c, &["C1"], "x").is_err(), "no run number");
        assert!(
            add(&mut c, &["k-00000000#1"], "x").is_err(),
            "not in the fleet"
        );
        assert!(!c.fleets[0].is_swarm());
        add(
            &mut c,
            &["C1#1", &format!("{k2}#1")],
            "C2 fetched the paste C1 wrote",
        )
        .unwrap();
        assert_eq!(
            c.fleets[0].swarm_evidence[0].runs,
            [format!("{k1}#1"), format!("{k2}#1")]
        );
        let log = &c.decisions.last().unwrap().text;
        assert!(
            log.contains("S2 hand-off") && log.contains("case fleet withdraw s-1 fleet-1 1"),
            "{log}"
        );

        let internal = report_section(&c, &a, Audience::Internal);
        assert!(
            internal.contains("## Fleets and swarms") && internal.contains("**fleet-1** (swarm)"),
            "{internal}"
        );
        assert!(internal.contains("C2 fetched the paste"), "{internal}");
        assert!(!report_section(&c, &a, Audience::Affected).contains("C2 fetched"));
        let public = report_section(&c, &a, Audience::Public);
        assert!(
            public.contains("## Swarm") && public.contains("hand-off"),
            "{public}"
        );
        assert!(
            !public.contains(&k1) && !public.contains("fetched"),
            "{public}"
        );
        let mut buf = Vec::new();
        show(&c, &a, &mut buf).unwrap();
        assert!(String::from_utf8(buf).unwrap().contains("fleet-1 (swarm)"));

        // Saved and read back.
        let text = c.to_toml().unwrap();
        assert!(
            text.contains("[[fleet.swarm_evidence]]") && text.contains("kind = \"handoff\""),
            "{text}"
        );
        let back = Case::parse(&text).unwrap();
        assert_eq!(back.fleets, c.fleets);

        // Withdrawn, it is a fleet again; split, its evidence goes too.
        let mut w = c.clone();
        assert!(withdraw(&mut w, "fleet-1", 2, None, "d").is_err());
        withdraw(&mut w, "fleet-1", 1, Some("misread"), "d").unwrap();
        assert!(!w.fleets[0].is_swarm());
        assert!(
            w.decisions
                .last()
                .unwrap()
                .text
                .contains("reported as a fleet again")
        );
        let mut more = c.clone();
        more.fleets[0].clusters.push("k-00000001".into());
        split(&mut more, &a, &k2, None, "d").unwrap();
        assert!(!more.fleets[0].is_swarm(), "{:?}", more.fleets);
        assert!(
            more.decisions
                .last()
                .unwrap()
                .text
                .contains("1 interaction record(s)")
        );
    }

    #[test]
    fn merge_and_split_are_logged_and_reversible() {
        let a = analyze(two_runs(), &Rules::default_rules());
        assert_eq!(a.clusters.len(), 2);
        let (k1, k2) = (a.clusters[0].key.clone(), a.clusters[1].key.clone());
        let mut c = case("f-1");

        // Nothing is merged until the admin says so.
        let mut buf = Vec::new();
        show(&c, &a, &mut buf).unwrap();
        assert!(String::from_utf8(buf).unwrap().contains("none"));

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
    }

    #[test]
    fn merge_without_soft_links_needs_a_reason() {
        let mut c = case("w-1");
        // The same clusters with their soft links taken away.
        let mut a = analyze(two_runs(), &Rules::default_rules());
        a.soft_links.clear();
        let shown: Vec<String> = a.clusters.iter().map(|c| c.key.clone()).collect();
        assert_eq!(shown.len(), 2, "{shown:?}");
        assert!(merge(&mut c, &a, &shown[..2], None, "d").is_err());
        merge(&mut c, &a, &shown[..2], Some("same uqtag family"), "d").unwrap();
        assert!(c.decisions.last().unwrap().text.contains("no soft link"));
    }
}
