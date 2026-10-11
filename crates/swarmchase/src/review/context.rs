//! `GET /api/context/<what>` for the review page: evidence a reviewer pulls
//! on demand to decide a group, beyond what the queue carries.
//!
//! `context/group/<record id>` describes the group holding that queued
//! record:
//!
//! - `rules`: each rule that fired in the group as the analysis ran it
//!   (description, kind, weight, tactic), how often it fired across the
//!   whole analysis and how many of those records it helped flag, and its
//!   false-alarm counts on the pre-era negative control when a control
//!   summary is loaded;
//! - `timeline`: when the group's records happened, binned, with the
//!   largest gaps and what the timestamps measure;
//! - `related`: records outside the group sharing a target host or a
//!   linking feature, with their tier, label and queue group;
//! - `earlier`: records already reviewed that share the group's rule set,
//!   cluster or target host, with their labels and notes.
//!
//! Everything comes from the analysis, the review store and the control
//! summary file. Nothing is fetched. Hosts and URLs are defanged, and no
//! record's IP address is sent.

use super::serve::{ReviewApp, group_of};
use crate::localui::Response;
use crate::suggest::defang_all;
use crate::util::truncate;
use anyhow::{Context, Result, bail};
use sc_core::rules::RuleDef;
use sc_core::{Analysis, ObsResult, Tier, TsKind, defang_host, fmt_ts};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};

/// Related and earlier records listed per group; the totals count them all.
const LIST: usize = 12;
/// Timeline bins.
const BINS: usize = 32;

/// What the context needs beyond the queue: the rules the analysis ran with,
/// the control summary, and an index built on first use.
#[derive(Default)]
pub struct Extra {
    rules: BTreeMap<String, RuleDef>,
    control: Option<Control>,
    index: Option<Index>,
}

impl ReviewApp {
    /// The rules the analysis ran with and, when one was found, the pre-era
    /// control summary.
    pub fn with_context(mut self, rules: &sc_core::Rules, control: Option<Control>) -> Self {
        self.ctx.rules = rules
            .set
            .rules
            .iter()
            .map(|r| (r.id.clone(), r.clone()))
            .collect();
        self.ctx.control = control;
        self
    }
}

/// Per-rule counts from a negative control summary (`eval pre-era`'s
/// `summary.json`, numbers only).
#[derive(Debug, Clone)]
pub struct Control {
    pub path: String,
    pub before: Option<String>,
    pub rules_version: Option<String>,
    pub records: usize,
    /// Rule id to (records it fired on, of those flagged suggestive or above).
    pub by_rule: BTreeMap<String, (usize, usize)>,
}

impl Control {
    /// Reads `eval pre-era`'s summary, or a bare control object.
    pub fn load(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let v: Value = serde_json::from_str(&text)
            .with_context(|| format!("{} is not JSON", path.display()))?;
        let c = v.get("control").unwrap_or(&v);
        let Some(records) = c.get("records").and_then(Value::as_u64) else {
            bail!("{} is not a control summary (no `records`)", path.display());
        };
        let k = |p: &Value| p.get("k").and_then(Value::as_u64).unwrap_or(0) as usize;
        let by_rule = c
            .get("by_rule")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|r| {
                let id = r.get("rule_id")?.as_str()?;
                Some((id.to_string(), (k(&r["fired"]), k(&r["flagged"]))))
            })
            .collect();
        let s = |key: &str| {
            v.get(key)
                .or_else(|| c.get(key))
                .and_then(Value::as_str)
                .map(str::to_string)
        };
        Ok(Self {
            path: path.display().to_string(),
            before: s("before"),
            rules_version: s("rules_version"),
            records: records as usize,
            by_rule,
        })
    }

    /// `--control`, else the first summary found under the data directory
    /// or under `data/` in the working directory. A missing default is no
    /// control; a missing or unreadable `--control` file is an error.
    pub fn find(given: Option<&Path>, data: &Path) -> Result<Option<Self>> {
        if let Some(p) = given {
            return Self::load(p).map(Some);
        }
        let rel = Path::new("controls").join("pre-era").join("summary.json");
        let candidates = [data.join(&rel), PathBuf::from("data").join(&rel)];
        match candidates.iter().find(|p| p.is_file()) {
            Some(p) => Self::load(p).map(Some),
            None => Ok(None),
        }
    }
}

/// Lookups over the whole analysis.
struct Index {
    /// Rule id to (records it fired on, of those suggestive or above).
    rules: HashMap<String, (usize, usize)>,
    by_host: HashMap<String, Vec<usize>>,
    by_feature: HashMap<String, Vec<usize>>,
    by_id: HashMap<String, usize>,
    /// Queue item position to its group key and title.
    groups: Vec<(String, String)>,
    /// Result index to its queue item position.
    queued: HashMap<usize, usize>,
}

impl Index {
    fn build(app: &ReviewApp) -> Self {
        let a = &app.a;
        let mut rules: HashMap<String, (usize, usize)> = HashMap::new();
        let mut by_host: HashMap<String, Vec<usize>> = HashMap::new();
        let mut by_feature: HashMap<String, Vec<usize>> = HashMap::new();
        let mut by_id = HashMap::new();
        for (i, r) in a.results.iter().enumerate() {
            by_id.insert(r.obs.id.clone(), i);
            let mut seen = BTreeSet::new();
            for h in &r.hits {
                if seen.insert(h.rule_id.as_str()) {
                    let e = rules.entry(h.rule_id.clone()).or_default();
                    e.0 += 1;
                    if r.tier >= Tier::Suggestive {
                        e.1 += 1;
                    }
                }
            }
            if let Some(h) = &r.target_host {
                by_host.entry(h.clone()).or_default().push(i);
            }
            for f in &r.features {
                by_feature.entry(f.to_string()).or_default().push(i);
            }
        }
        let groups = app.items.iter().map(|it| group_of(a, it.idx)).collect();
        let queued = app
            .items
            .iter()
            .enumerate()
            .map(|(p, it)| (it.idx, p))
            .collect();
        Self {
            rules,
            by_host,
            by_feature,
            by_id,
            groups,
            queued,
        }
    }
}

/// `None` is a 404.
pub(super) fn get(app: &mut ReviewApp, what: &str) -> Option<Response> {
    let id = pct_decode(what.strip_prefix("group/")?)?;
    if app.ctx.index.is_none() {
        app.ctx.index = Some(Index::build(app));
    }
    let &p = app.pos.get(&id)?;
    Some(Response::json(200, &group_context(app, p)))
}

/// Prose with every host defanged and sentences left alone: a dot between
/// two word characters becomes `[.]`, except in abbreviations of single
/// letters (`e.g.`) and in decimals (`1.5`).
fn defang_prose(s: &str) -> String {
    let s = sc_core::defang(s);
    let chars: Vec<char> = s.chars().collect();
    let word = |c: char| c.is_alphanumeric() || c == '-' || c == '_';
    let run = |i: usize, step: isize| {
        let mut j = i as isize + step;
        let mut t = String::new();
        while j >= 0 && (j as usize) < chars.len() && word(chars[j as usize]) {
            t.push(chars[j as usize]);
            j += step;
        }
        t
    };
    let mut out = String::with_capacity(s.len());
    for (i, &c) in chars.iter().enumerate() {
        if c == '.' && i > 0 && i + 1 < chars.len() && word(chars[i - 1]) && word(chars[i + 1]) {
            let (l, r) = (run(i, -1), run(i, 1));
            let abbrev = l.chars().count() == 1 && r.chars().count() == 1;
            let decimal =
                l.chars().all(|c| c.is_ascii_digit()) && r.chars().all(|c| c.is_ascii_digit());
            if !abbrev && !decimal {
                out.push_str("[.]");
                continue;
            }
        }
        out.push(c);
    }
    out
}

/// `%xx` escapes decoded; `None` when malformed or not UTF-8.
fn pct_decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hex = std::str::from_utf8(b.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn group_context(app: &ReviewApp, p: usize) -> Value {
    let ix = app.ctx.index.as_ref().expect("index built");
    let a = &app.a;
    let key = &ix.groups[p].0;
    // The queued records of the group, and every record it stands for: a
    // cluster's members, or the queued records of a shape.
    let queued: Vec<usize> = ix
        .groups
        .iter()
        .enumerate()
        .filter(|(_, g)| &g.0 == key)
        .map(|(q, _)| app.items[q].idx)
        .collect();
    let cluster = a.results[app.items[p].idx].cluster;
    let members: Vec<usize> = match cluster {
        Some(c) => a.clusters[c].members.clone(),
        None => queued.clone(),
    };
    json!({
        "key": key,
        "rules": rules_json(app, ix, &queued),
        "control": app.ctx.control.as_ref().map(|c| json!({
            "path": c.path,
            "before": c.before,
            "rules_version": c.rules_version,
            "same_rules": c.rules_version.as_deref().is_none_or(|v| v == a.rules_version),
            "records": c.records,
        })),
        "timeline": timeline_json(a, &members),
        "related": related_json(app, ix, key, &members),
        "earlier": earlier_json(app, ix, &queued, &members, cluster),
    })
}

fn rules_json(app: &ReviewApp, ix: &Index, queued: &[usize]) -> Value {
    let a = &app.a;
    let mut in_group: BTreeMap<&str, usize> = BTreeMap::new();
    let mut seen_hit: BTreeMap<&str, &sc_core::Hit> = BTreeMap::new();
    for &i in queued {
        let mut seen = BTreeSet::new();
        for h in &a.results[i].hits {
            if seen.insert(h.rule_id.as_str()) {
                *in_group.entry(&h.rule_id).or_default() += 1;
                seen_hit.entry(&h.rule_id).or_insert(h);
            }
        }
    }
    let mut out: Vec<Value> = in_group
        .iter()
        .map(|(&id, &n)| {
            let def = app.ctx.rules.get(id);
            let hit = seen_hit[id];
            let (fired, flagged) = ix.rules.get(id).copied().unwrap_or_default();
            let control = app.ctx.control.as_ref().map(|c| {
                let (f, fl) = c.by_rule.get(id).copied().unwrap_or_default();
                json!({ "fired": f, "flagged": fl, "of": c.records })
            });
            json!({
                "id": id,
                "kind": def.map_or(hit.kind, |d| d.kind),
                "weight": def.map_or(hit.weight, |d| d.weight),
                "tactic": def.and_then(|d| d.tactic).or(hit.tactic).map(|t| json!({ "id": t.id(), "label": t.label() })),
                "description": def.map(|d| defang_prose(&d.description)),
                "group": def.and_then(|d| d.group.as_deref()),
                "significant": def.is_some_and(|d| d.significant),
                "link": def.is_some_and(|d| d.link),
                "artifact": def.map_or(hit.artifact, |d| d.artifact),
                "in_group": n,
                "fired": fired,
                "flagged": flagged,
                "of": a.total,
                "control": control,
            })
        })
        .collect();
    out.sort_by_key(|r| {
        (
            -r["weight"].as_i64().unwrap_or(0),
            -r["in_group"].as_i64().unwrap_or(0),
        )
    });
    Value::Array(out)
}

/// What a record's timestamp measures, reading the source for older records.
fn ts_kind(r: &ObsResult) -> TsKind {
    match r.obs.ts_kind {
        TsKind::Unknown => TsKind::of_source(&r.obs.source),
        k => k,
    }
}

fn kind_name(k: TsKind) -> &'static str {
    match k {
        TsKind::Request => "request",
        TsKind::Capture => "capture",
        TsKind::Submit => "submit",
        TsKind::Unknown => "unknown",
    }
}

fn timeline_json(a: &Analysis, members: &[usize]) -> Value {
    let mut ts: Vec<i64> = Vec::new();
    let mut basis: BTreeMap<&str, usize> = BTreeMap::new();
    for &i in members {
        let r = &a.results[i];
        if r.obs.ts > 0 {
            ts.push(r.obs.ts);
            *basis.entry(kind_name(ts_kind(r))).or_default() += 1;
        }
    }
    ts.sort_unstable();
    let untimed = members.len() - ts.len();
    let (Some(&start), Some(&end)) = (ts.first(), ts.last()) else {
        return json!({ "timed": 0, "untimed": untimed });
    };
    let span = end - start;
    let mut bins = vec![0usize; BINS];
    for &t in &ts {
        let b = if span == 0 {
            0
        } else {
            (((t - start) as f64 / span as f64) * (BINS as f64 - 1.0)).round() as usize
        };
        bins[b.min(BINS - 1)] += 1;
    }
    let mut gaps: Vec<(i64, i64, i64)> = ts
        .windows(2)
        .map(|w| (w[1] - w[0], w[0], w[1]))
        .filter(|g| g.0 > 0)
        .collect();
    gaps.sort_by(|x, y| y.0.cmp(&x.0).then(x.1.cmp(&y.1)));
    let mut steps: Vec<i64> = ts.windows(2).map(|w| w[1] - w[0]).collect();
    steps.sort_unstable();
    let median = steps.get(steps.len() / 2).copied();
    json!({
        "timed": ts.len(),
        "untimed": untimed,
        "start": fmt_ts(start),
        "end": fmt_ts(end),
        "span": span,
        "median_step": median,
        "bins": bins,
        "gaps": gaps.iter().take(3).map(|g| json!({ "secs": g.0, "from": fmt_ts(g.1), "to": fmt_ts(g.2) })).collect::<Vec<_>>(),
        "basis": basis,
    })
}

/// A record as a short row: never its IP, its URL defanged.
fn row(app: &ReviewApp, ix: &Index, i: usize) -> serde_json::Map<String, Value> {
    let r = &app.a.results[i];
    let review = app.store.entries.get(&r.obs.id);
    let group = ix.queued.get(&i).map(|&q| &ix.groups[q]);
    let mut m = serde_json::Map::new();
    m.insert("id".into(), json!(r.obs.id));
    m.insert("tier".into(), json!(r.tier.label()));
    m.insert("score".into(), json!(r.score));
    m.insert("source".into(), json!(r.obs.source));
    m.insert("time".into(), json!(fmt_ts(r.obs.ts)));
    m.insert("url".into(), json!(defang_all(&truncate(&r.obs.url, 220))));
    m.insert(
        "cluster".into(),
        json!(r.cluster.map(|c| &app.a.clusters[c].id)),
    );
    m.insert("label".into(), json!(review.map(|v| v.label.as_str())));
    m.insert("group".into(), json!(group.map(|g| &g.0)));
    m.insert("group_title".into(), json!(group.map(|g| &g.1)));
    m
}

fn related_json(app: &ReviewApp, ix: &Index, key: &str, members: &[usize]) -> Value {
    let a = &app.a;
    let inside: BTreeSet<usize> = members.iter().copied().collect();
    let mut hosts = BTreeSet::new();
    let mut features = BTreeSet::new();
    for &i in members {
        let r = &a.results[i];
        if let Some(h) = &r.target_host {
            hosts.insert(h.clone());
        }
        for f in &r.features {
            features.insert(f.to_string());
        }
    }
    // Record to the reasons it is related, features first: they are rarer
    // and say more than a shared target.
    let mut found: BTreeMap<usize, Vec<String>> = BTreeMap::new();
    let mut by_reason: Vec<(String, usize)> = Vec::new();
    let mut add = |list: Option<&Vec<usize>>, reason: String| {
        let mut n = 0;
        for &i in list.into_iter().flatten() {
            if inside.contains(&i) {
                continue;
            }
            n += 1;
            found.entry(i).or_default().push(reason.clone());
        }
        if n > 0 {
            by_reason.push((reason, n));
        }
    };
    for f in &features {
        add(ix.by_feature.get(f), format!("shares {}", defang_all(f)));
    }
    for h in &hosts {
        add(ix.by_host.get(h), format!("target {}", defang_host(h)));
    }
    let mut list: Vec<(usize, Vec<String>)> = found.into_iter().collect();
    let feature_hits = |r: &[String]| r.iter().filter(|s| s.starts_with("shares ")).count();
    list.sort_by(|(i, ri), (j, rj)| {
        let (x, y) = (&a.results[*i], &a.results[*j]);
        let labelled = |r: &ObsResult| app.store.entries.contains_key(&r.obs.id);
        feature_hits(rj)
            .cmp(&feature_hits(ri))
            .then(labelled(y).cmp(&labelled(x)))
            .then(y.tier.cmp(&x.tier))
            .then(y.score.cmp(&x.score))
            .then(x.obs.ts.cmp(&y.obs.ts))
    });
    let total = list.len();
    let labelled = list
        .iter()
        .filter(|(i, _)| app.store.entries.contains_key(&a.results[*i].obs.id))
        .count();
    let rows: Vec<Value> = list
        .into_iter()
        .take(LIST)
        .map(|(i, reasons)| {
            let mut m = row(app, ix, i);
            m.insert(
                "why".into(),
                json!(reasons.into_iter().take(3).collect::<Vec<_>>()),
            );
            if m["group"].as_str() == Some(key) {
                m.insert("group".into(), Value::Null);
            }
            Value::Object(m)
        })
        .collect();
    by_reason.sort_by_key(|x| std::cmp::Reverse(x.1));
    by_reason.truncate(8);
    json!({
        "total": total,
        "labelled": labelled,
        "by_reason": by_reason.iter().map(|(r, n)| json!({ "why": r, "n": n })).collect::<Vec<_>>(),
        "records": rows,
    })
}

fn rule_set(rules: impl IntoIterator<Item = impl AsRef<str>>) -> Vec<String> {
    let mut v: Vec<String> = rules.into_iter().map(|r| r.as_ref().to_string()).collect();
    v.sort_unstable();
    v.dedup();
    v
}

fn earlier_json(
    app: &ReviewApp,
    ix: &Index,
    queued: &[usize],
    members: &[usize],
    cluster: Option<usize>,
) -> Value {
    let a = &app.a;
    let own: BTreeSet<&str> = queued
        .iter()
        .chain(members)
        .map(|&i| a.results[i].obs.id.as_str())
        .collect();
    let sets: BTreeSet<Vec<String>> = queued
        .iter()
        .map(|&i| rule_set(a.results[i].hits.iter().map(|h| &h.rule_id)))
        .filter(|s| !s.is_empty())
        .collect();
    let hosts: BTreeSet<&str> = members
        .iter()
        .filter_map(|&i| a.results[i].target_host.as_deref())
        .collect();
    let mut found = Vec::new();
    for (id, rv) in &app.store.entries {
        if own.contains(id.as_str()) {
            continue;
        }
        let here = ix.by_id.get(id).map(|&i| &a.results[i]);
        let mut why = Vec::new();
        if cluster.is_some() && here.is_some_and(|r| r.cluster == cluster) {
            why.push("same cluster".to_string());
        }
        if sets.contains(&rule_set(&rv.rules)) {
            why.push("same rules".to_string());
        }
        if let Some(h) = here
            .and_then(|r| r.target_host.as_deref())
            .filter(|h| hosts.contains(h))
        {
            why.push(format!("target {}", defang_host(h)));
        }
        if !why.is_empty() {
            found.push((rv, why));
        }
    }
    let mut tally: BTreeMap<&str, usize> = BTreeMap::new();
    for (rv, _) in &found {
        *tally.entry(rv.label.as_str()).or_default() += 1;
    }
    // Closest first (more reasons), then the latest.
    found.sort_by(|(x, wx), (y, wy)| {
        wy.len()
            .cmp(&wx.len())
            .then(y.reviewed_at.cmp(&x.reviewed_at))
    });
    let total = found.len();
    let rows: Vec<Value> = found
        .into_iter()
        .take(LIST)
        .map(|(rv, why)| {
            let group = ix
                .by_id
                .get(&rv.record.id)
                .and_then(|i| ix.queued.get(i))
                .map(|&q| &ix.groups[q]);
            json!({
                "id": rv.record.id,
                "label": rv.label,
                "note": rv.note.as_deref().map(defang_all),
                // What the label was judged against, so an agent label
                // below L2 reads as the exception it is.
                "label_grade": super::serve::label_grade_json(rv, || {
                    ix.by_id
                        .get(&rv.record.id)
                        .map(|&i| super::LabelGrade::of(a, i, &rv.label))
                }),
                "reviewed_at": rv.reviewed_at,
                "tier": rv.tier.label(),
                "rules": rule_set(&rv.rules),
                "url": defang_all(&truncate(&rv.record.url, 160)),
                "why": why,
                "group": group.map(|g| &g.0),
                "group_title": group.map(|g| &g.1),
            })
        })
        .collect();
    json!({ "total": total, "by_label": tally, "records": rows })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::review::{ReviewStore, queue};
    use crate::suggest::Suggestion;
    use sc_core::{Observation, Rules, analyze};

    fn app(name: &str) -> (ReviewApp, PathBuf) {
        let o = |id: &str, ts: i64, url: &str| Observation {
            id: id.into(),
            source: "wayback".into(),
            ts,
            url: url.into(),
            ip: Some("203.0.113.9".into()),
            ..Default::default()
        };
        let inbox = "https://webhook.site/0b6c1f0e-1111-4c2a-9a55-3f2e1d0c9b8a";
        let a = analyze(
            vec![
                o("c1", 1000, &format!("{inbox}?kind=headers0")),
                o(
                    "c2",
                    1040,
                    &format!(
                        "https://r.jina.ai/https://data.portal.example/p/1?uqtag=a1b2&cb={inbox}"
                    ),
                ),
                o(
                    "s1",
                    5000,
                    "https://r.jina.ai/https://t.example/?q=1%20OR%201=1",
                ),
                o(
                    "s2",
                    9000,
                    "https://r.jina.ai/https://t.example/?q=1%20OR%201=1&x=2",
                ),
                o("p1", 7000, "https://t.example/about"),
                o("x", 6000, "https://r.jina.ai/<script>alert(1)</script>"),
            ],
            &Rules::default_rules(),
        );
        let items = queue(&a, &BTreeSet::new(), Tier::Suggestive, 0);
        let dir =
            std::env::temp_dir().join(format!("swarmchase-ctx-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = ReviewStore::open(ReviewStore::path_in(&dir)).unwrap();
        let sug: BTreeMap<String, Suggestion> = BTreeMap::new();
        let app = ReviewApp::new(a, items, store, sug, "test".into());
        (app, dir)
    }

    fn ctx(app: &mut ReviewApp, id: &str) -> Value {
        let r = get(app, &format!("group/{id}")).expect("found");
        assert_eq!(r.status, 200);
        serde_json::from_slice(&r.body).unwrap()
    }

    #[test]
    fn defangs_hosts_in_prose_and_keeps_sentences() {
        assert_eq!(
            defang_prose("Jina Reader (r.jina.ai), e.g. ?agent=claude. Weight 1.5."),
            "Jina Reader (r[.]jina[.]ai), e.g. ?agent=claude. Weight 1.5."
        );
        assert_eq!(defang_prose("see https://t.co/x"), "see hxxps://t[.]co/x");
    }

    #[test]
    fn decodes_paths_and_404s_unknown_records() {
        assert_eq!(pct_decode("eval%3Acov-1").as_deref(), Some("eval:cov-1"));
        assert_eq!(pct_decode("a%2"), None);
        assert_eq!(pct_decode("%ff"), None);
        let (mut app, dir) = app("404");
        assert!(get(&mut app, "group/nope").is_none());
        assert!(get(&mut app, "other/s1").is_none());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn explains_rules_dates_and_relates_without_leaking() {
        let (mut app, dir) = app("explain");
        let rules = Rules::default_rules();
        let control = Control {
            path: "summary.json".into(),
            before: Some("2022-11-30".into()),
            rules_version: Some(app.a.rules_version.clone()),
            records: 900,
            by_rule: BTreeMap::new(),
        };
        app = app.with_context(&rules, Some(control));
        let v = ctx(&mut app, "s1");
        let text = v.to_string();
        assert!(!text.contains("203.0.113.9"), "no IPs: {text}");
        assert!(!text.contains("https://"), "{text}");
        assert!(!text.contains("r.jina.ai"), "{text}");
        assert!(!text.contains("t.example"), "{text}");

        let rule = v["rules"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["description"].is_string())
            .expect("a described rule");
        assert!(rule["fired"].as_u64().unwrap() >= 1);
        assert_eq!(rule["of"], 6);
        assert_eq!(rule["control"]["of"], 900);
        assert_eq!(v["control"]["same_rules"], true);

        // p1 shares the target host and sits outside the group.
        let related = v["related"]["records"].as_array().unwrap();
        let p1 = related
            .iter()
            .find(|r| r["id"] == "p1")
            .expect("p1 related");
        assert!(
            p1["why"][0]
                .as_str()
                .unwrap()
                .starts_with("target t[.]example")
        );
        assert!(related.iter().all(|r| r["id"] != "s1"));

        let t = &v["timeline"];
        assert_eq!(t["basis"]["capture"], t["timed"]);
        let bins: u64 = t["bins"]
            .as_array()
            .unwrap()
            .iter()
            .map(|b| b.as_u64().unwrap())
            .sum();
        assert_eq!(bins, t["timed"].as_u64().unwrap());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn lists_earlier_decisions_on_similar_records() {
        let (mut app, dir) = app("earlier");
        let s1 = app.a.results.iter().find(|r| r.obs.id == "s1").unwrap();
        let rules: Vec<String> = s1.hits.iter().map(|h| h.rule_id.clone()).collect();
        // A record reviewed in an earlier session, no longer in the analysis.
        app.store.entries.insert(
            "old1".into(),
            crate::review::Review {
                record: Observation {
                    id: "old1".into(),
                    url: "https://t.example/?q=2%20OR%202=2".into(),
                    ip: Some("203.0.113.9".into()),
                    ..Default::default()
                },
                label: "benign".into(),
                note: Some("pentest of https://t.example".into()),
                class: crate::review::CLASS_FLAGGED.into(),
                reviewed_at: "2026-01-01T00:00:00Z".into(),
                tier: Tier::Suggestive,
                score: 5,
                rules,
                rules_version: "x".into(),
                suggested: None,
                tuned: false,
                grade: None,
            },
        );
        // The group's own label is not an earlier decision.
        let body = r#"{"ids":["s1"],"label":"agent","note":"seen in a case"}"#;
        assert_eq!(
            crate::localui::App::post(&mut app, "label", body.as_bytes(), "now").status,
            200
        );
        let v = ctx(&mut app, "s1");
        let text = v.to_string();
        assert!(
            !text.contains("203.0.113.9") && !text.contains("t.example"),
            "{text}"
        );
        let e = &v["earlier"];
        let ids: Vec<&str> = e["records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, ["old1"], "{e}");
        assert_eq!(e["records"][0]["why"][0], "same rules");
        assert_eq!(e["records"][0]["note"], "pentest of hxxps://t[.]example");
        assert_eq!(e["by_label"]["benign"], 1);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn reads_the_pre_era_summary_shape() {
        let dir = std::env::temp_dir().join(format!("swarmchase-ctl-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("summary.json");
        let prop =
            |k: u32, n: u32| json!({ "k": k, "n": n, "value": null, "lo": null, "hi": null });
        let s = json!({
            "before": "2022-11-30",
            "rules_version": "9",
            "sources": [],
            "control": {
                "records": 500,
                "clusters": 3,
                "by_rule": [
                    { "rule_id": "relay.jina", "fired": prop(40, 500), "flagged": prop(2, 500) }
                ],
            },
        });
        std::fs::write(&p, s.to_string()).unwrap();
        let c = Control::load(&p).unwrap();
        assert_eq!(c.records, 500);
        assert_eq!(c.by_rule["relay.jina"], (40, 2));
        assert_eq!(c.before.as_deref(), Some("2022-11-30"));
        assert_eq!(c.rules_version.as_deref(), Some("9"));
        assert!(Control::find(None, &dir.join("nowhere")).is_ok());
        assert!(Control::find(Some(&dir.join("missing.json")), &dir).is_err());
        std::fs::write(&p, "{}").unwrap();
        assert!(Control::load(&p).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }
}
