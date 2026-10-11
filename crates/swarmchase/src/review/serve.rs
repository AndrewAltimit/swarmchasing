//! `review --serve`: the review queue as a local page ([`crate::localui`]).
//!
//! The page groups the queue by cluster, or for an unclustered record by its
//! shape (rules that fired and the start of its URL), so a run of
//! near-identical records is labelled at once. Each group shows its cluster's
//! agent grade and signals, any saved suggestion ([`super::hosted`]), and
//! every record as `review` prints it, decoded layers included, defanged and
//! never as a link. Labels go to the same review file as the terminal
//! session. Reviewed records stay on the page, so a label can be changed,
//! cleared or undone.
//!
//! The labelling rule is checked here, not left to the page: `agent` needs an
//! agent grade of L2 or higher, so each record and group says whether the
//! label is open to it, and flags a suggestion or a saved label that says
//! `agent` below it. The server still saves an `agent` label below L2 when
//! the admin confirms it, with the grade it was judged against
//! ([`LabelGrade`], marked `below_l2`), so the label is never read without
//! its context.

use super::{CLASS_FLAGGED, GradeFrom, Item, LabelGrade, Review, ReviewStore};
use crate::localui::{App, Response};
use crate::suggest::{Suggestion, defang_all};
use crate::util::truncate;
use anyhow::{Result, bail};
use sc_core::{AgentLevel, Analysis, defang_host, fmt_ts};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;

/// The page core, its extensions, then the boot that starts it.
const SCRIPT: &str = concat!(
    include_str!("page/review.js"),
    "
",
    include_str!("page/guide.js"),
    "
",
    include_str!("page/context.js"),
    "
",
    include_str!("page/boot.js"),
);
const STYLE: &str = concat!(
    include_str!("page/review.css"),
    "
",
    include_str!("page/guide.css"),
    "
",
    include_str!("page/context.css"),
);

/// The review group of record `idx`: its cluster, or its shape. Returns the
/// key and a title for the page, both defanged.
pub fn group_of(a: &Analysis, idx: usize) -> (String, String) {
    let r = &a.results[idx];
    if let Some(c) = r.cluster {
        let c = &a.clusters[c];
        return (
            format!("cluster:{}", c.id),
            format!("Cluster {} · {}", c.id, defang_all(&c.key)),
        );
    }
    let mut rules: Vec<&str> = r.hits.iter().map(|h| h.rule_id.as_str()).collect();
    rules.sort_unstable();
    rules.dedup();
    let bare = r
        .obs
        .url
        .split_once("://")
        .map_or(r.obs.url.as_str(), |(_, rest)| rest);
    let start: String = bare.chars().take(48).collect();
    let start = defang_all(&start);
    let rules = if rules.is_empty() {
        "no rule".to_string()
    } else {
        rules.join(", ")
    };
    (format!("shape:{rules}|{start}"), format!("{start}…"))
}

/// An agent grade for the page: rung, signals, counter-signals and caps.
fn grade_json(g: &sc_core::AgentAssessment) -> Value {
    let signal = |s: &sc_core::AgentSignal| json!({ "label": s.kind.label(), "records": s.records, "detail": defang_all(&s.detail) });
    json!({
        "code": g.level.code(),
        "label": g.level.label(),
        "signals": g.signals.iter().map(signal).collect::<Vec<_>>(),
        "counter": g.counter.iter().map(signal).collect::<Vec<_>>(),
        "caps": g.caps.iter().map(|k| k.label()).collect::<Vec<_>>(),
    })
}

#[derive(Deserialize)]
struct LabelRequest {
    ids: Vec<String>,
    /// `agent`, `benign`, `unsure`, or `clear` to remove the review.
    label: String,
    #[serde(default)]
    note: Option<String>,
    /// Set the note exactly as sent, `None` clearing it (undo). Otherwise a
    /// missing note keeps the one already saved.
    #[serde(default)]
    restore: bool,
    /// With `restore`: the grade each record's earlier label was saved
    /// with, by id, so an undo puts back the label as it was judged.
    #[serde(default)]
    grades: BTreeMap<String, LabelGrade>,
}

/// A saved label's grade for the page: what it was judged against, with
/// `stored` false when the line predates stored grades and the grade is
/// the one now.
pub(super) fn label_grade_json(v: &Review, now: impl FnOnce() -> Option<LabelGrade>) -> Value {
    match v.judged_grade(now) {
        Some((g, from)) => {
            let mut j = serde_json::to_value(&g).unwrap_or(Value::Null);
            if let Value::Object(m) = &mut j {
                m.insert("stored".into(), json!(from == GradeFrom::Stored));
                m.insert("below_rule".into(), json!(g.below_rule()));
                m.insert("code".into(), json!(g.code()));
                for k in ["signals", "counter", "caps"] {
                    m.entry(k).or_insert_with(|| json!([]));
                }
            }
            j
        }
        None => Value::Null,
    }
}

pub struct ReviewApp {
    pub(super) a: Analysis,
    pub(super) items: Vec<Item>,
    /// Record id to its position in `items`.
    pub(super) pos: BTreeMap<String, usize>,
    pub(super) store: ReviewStore,
    pub(super) suggestions: BTreeMap<String, Suggestion>,
    /// What is being reviewed, for the page header.
    pub(super) from: String,
    /// Decision context ([`super::context`]).
    pub(super) ctx: super::context::Extra,
}

impl ReviewApp {
    pub fn new(
        a: Analysis,
        items: Vec<Item>,
        store: ReviewStore,
        suggestions: BTreeMap<String, Suggestion>,
        from: String,
    ) -> Self {
        let pos = items
            .iter()
            .enumerate()
            .map(|(i, it)| (a.results[it.idx].obs.id.clone(), i))
            .collect();
        Self {
            a,
            items,
            pos,
            store,
            suggestions,
            from,
            ctx: Default::default(),
        }
    }

    /// The grade that decides record `idx`'s labels: its cluster's, else its
    /// own. `None` when it has neither.
    fn level_of(&self, idx: usize) -> Option<AgentLevel> {
        let r = &self.a.results[idx];
        match r.cluster {
            Some(c) => Some(self.a.clusters[c].agent.level),
            None => r.agent.as_ref().map(|g| g.level),
        }
    }

    /// Whether the labelling rule lets record `idx` be labelled `agent`.
    fn agent_allowed(&self, idx: usize) -> bool {
        self.level_of(idx)
            .is_some_and(|l| l >= AgentLevel::ModelWritten)
    }

    /// Every review in the file, this queue's or not, counted by label, and
    /// by label over the flagged records alone (what a precision estimate
    /// reads).
    fn stored_json(&self) -> Value {
        let mut all: BTreeMap<&str, usize> = BTreeMap::new();
        let mut flagged: BTreeMap<&str, usize> = BTreeMap::new();
        for v in self.store.entries.values() {
            *all.entry(v.label.as_str()).or_default() += 1;
            if v.class == CLASS_FLAGGED {
                *flagged.entry(v.label.as_str()).or_default() += 1;
            }
        }
        // Agent labels below L2, by the grade stored with them, else (an
        // older line) the grade now when the record is in this analysis.
        let below = super::count_below_rule(&self.store, &self.a);
        json!({
            "total": self.store.entries.len(), "by_label": all, "flagged": flagged,
            "agent_below_rule": below,
        })
    }

    fn item_json(&self, it: Item) -> Value {
        let r = &self.a.results[it.idx];
        let review = self.store.entries.get(&r.obs.id);
        let layers: Vec<Value> = r
            .layers
            .iter()
            .filter(|l| l.via != "submitted")
            .take(8)
            .map(|l| {
                json!({
                    "via": l.via,
                    "depth": l.depth,
                    "text": defang_all(&truncate(&l.text, 3000)),
                })
            })
            .collect();
        let hits: Vec<Value> = r
            .hits
            .iter()
            .map(|h| {
                json!({
                    "rule": h.rule_id,
                    "kind": h.kind,
                    "weight": h.weight,
                    "matched": defang_all(&truncate(&h.matched, 160)),
                })
            })
            .collect();
        let suggested = self
            .suggestions
            .get(&r.obs.id)
            .or_else(|| review.and_then(|v| v.suggested.as_ref()));
        let allowed = self.agent_allowed(it.idx);
        let says_agent = |l: Option<&str>| l == Some("agent") && !allowed;
        let label_grade = review.map_or(Value::Null, |v| {
            label_grade_json(v, || Some(LabelGrade::of(&self.a, it.idx, &v.label)))
        });
        json!({
            "id": r.obs.id,
            "class": it.class,
            "tier": r.tier.label(),
            "score": r.score,
            "source": r.obs.source,
            "time": fmt_ts(r.obs.ts),
            "url": defang_all(&truncate(&r.obs.url, 1200)),
            "layers": layers,
            "target": r.target_host.as_deref().map(defang_host),
            "final": r.obs.final_url.as_deref().map(|f| defang_all(&truncate(f, 300))),
            "hits": hits,
            "reference": r.obs.reference.as_deref().map(defang_all),
            "label": review.map(|v| v.label.as_str()),
            "note": review.and_then(|v| v.note.as_deref()),
            "reviewed_at": review.map(|v| v.reviewed_at.as_str()),
            "suggested": suggested,
            "grade": r.agent.as_ref().map(|g| g.level.code()),
            "agent_allowed": allowed,
            // A suggestion of `agent` the rule does not allow: not to accept.
            "conflict": says_agent(suggested.map(|s| s.label.as_str())),
            // A saved `agent` label the rule does not allow.
            "breaks_rule": says_agent(review.map(|v| v.label.as_str())),
            // What the saved label was judged against.
            "label_grade": label_grade,
        })
    }

    fn cluster_json(&self, idx: usize) -> Value {
        let Some(c) = self.a.results[idx].cluster.map(|c| &self.a.clusters[c]) else {
            return Value::Null;
        };
        let hosts: Vec<String> = crate::util::top_keys(&c.target_hosts, 4)
            .iter()
            .map(|h| defang_host(h))
            .collect();
        json!({
            "id": c.id,
            "key": defang_all(&c.key),
            "tier": c.tier.label(),
            "size": c.members.len(),
            "start": fmt_ts(c.start),
            "end": fmt_ts(c.end),
            "targets": hosts,
            "grade": grade_json(&c.agent),
        })
    }

    /// The group's grade: its cluster's, or for a shape group the lowest
    /// of its records' own grades, since a label on the group covers each.
    fn group_grade(&self, items: &[Item]) -> (Value, &'static str) {
        let first = &self.a.results[items[0].idx];
        if let Some(c) = first.cluster {
            return (grade_json(&self.a.clusters[c].agent), "cluster");
        }
        items
            .iter()
            .filter_map(|it| self.a.results[it.idx].agent.as_ref())
            .min_by_key(|g| g.level)
            .map_or((Value::Null, "none"), |g| (grade_json(g), "records"))
    }

    pub fn queue_json(&self) -> Value {
        let mut order: Vec<String> = Vec::new();
        let mut groups: BTreeMap<String, (String, Value, Vec<Item>)> = BTreeMap::new();
        for &it in &self.items {
            let (key, title) = group_of(&self.a, it.idx);
            let g = groups.entry(key.clone()).or_insert_with(|| {
                order.push(key);
                (title, self.cluster_json(it.idx), Vec::new())
            });
            g.2.push(it);
        }
        let groups: Vec<Value> = order
            .into_iter()
            .filter_map(|k| {
                let (title, cluster, items) = groups.remove(&k)?;
                let (grade, basis) = self.group_grade(&items);
                // The group's grade is the lowest any record is held to, so
                // a group label of `agent` is allowed only if every record's is.
                let level = items.iter().map(|it| self.level_of(it.idx)).min().flatten();
                let allowed = items.iter().all(|it| self.agent_allowed(it.idx));
                let items: Vec<Value> = items.into_iter().map(|it| self.item_json(it)).collect();
                let flagged = |f: &str| items.iter().filter(|i| i[f] == true).count();
                Some(json!({
                    "key": k, "title": title, "cluster": cluster,
                    "grade": grade, "grade_basis": basis,
                    "level": level.map(|l| l as u8),
                    "agent_allowed": allowed,
                    "conflicts": flagged("conflict"),
                    "rule_breaks": flagged("breaks_rule"),
                    "items": items,
                }))
            })
            .collect();
        let labeller = self
            .store
            .path
            .file_stem()
            .and_then(|s| s.to_str())
            .and_then(|s| s.strip_prefix("reviewed-"))
            .unwrap_or("default");
        json!({
            "file": self.store.path.display().to_string(),
            "labeller": labeller,
            "from": self.from,
            "rules_version": self.a.rules_version,
            "records": self.items.len(),
            "stored": self.stored_json(),
            "groups": groups,
        })
    }

    fn label(&mut self, req: &LabelRequest, now: &str) -> Result<Value> {
        let label = match req.label.as_str() {
            l @ ("agent" | "benign" | "unsure" | "clear") => l,
            other => bail!("unknown label `{other}`"),
        };
        if req.ids.is_empty() {
            bail!("no ids");
        }
        let mut targets = Vec::new();
        for id in &req.ids {
            let Some(&p) = self.pos.get(id) else {
                bail!("{id} is not in this queue");
            };
            targets.push(self.items[p]);
        }
        let note = req
            .note
            .as_deref()
            .map(|n| n.split_whitespace().collect::<Vec<_>>().join(" "))
            .filter(|n| !n.is_empty())
            .map(|n| truncate(&n, 500));
        let mut out = serde_json::Map::new();
        for it in targets {
            let r = &self.a.results[it.idx];
            let id = r.obs.id.clone();
            let before = self.store.entries.remove(&id);
            if label != "clear" {
                let suggested = self
                    .suggestions
                    .get(&id)
                    .cloned()
                    .or_else(|| before.as_ref().and_then(|b| b.suggested.clone()));
                let note = if req.restore {
                    note.clone()
                } else {
                    note.clone()
                        .or_else(|| before.as_ref().and_then(|b| b.note.clone()))
                };
                // An undo puts back the grade the label was saved with;
                // anything else is judged against the grade now.
                let grade = match req.grades.get(&id) {
                    Some(g) if req.restore => LabelGrade {
                        rule: (label == "agent" && !g.agent_allowed)
                            .then(|| super::BELOW_L2.to_string()),
                        ..g.clone()
                    },
                    _ => LabelGrade::of(&self.a, it.idx, label),
                };
                self.store.entries.insert(
                    id.clone(),
                    Review {
                        record: r.obs.clone(),
                        label: label.to_string(),
                        note,
                        class: it.class.to_string(),
                        reviewed_at: now.to_string(),
                        tier: r.tier,
                        score: r.score,
                        rules: r.hits.iter().map(|h| h.rule_id.clone()).collect(),
                        rules_version: self.a.rules_version.clone(),
                        suggested,
                        tuned: before.as_ref().is_some_and(|b| b.tuned),
                        grade: Some(grade),
                    },
                );
            }
            out.insert(id, self.item_json(it));
        }
        self.store.save()?;
        Ok(json!({ "items": out, "stored": self.stored_json() }))
    }
}

impl App for ReviewApp {
    fn title(&self) -> String {
        "Lead review".into()
    }

    fn script(&self) -> &'static str {
        SCRIPT
    }

    fn style(&self) -> &'static str {
        STYLE
    }

    fn get(&mut self, path: &str) -> Option<Response> {
        if let Some(what) = path.strip_prefix("context/") {
            return super::context::get(self, what);
        }
        (path == "queue").then(|| Response::json(200, &self.queue_json()))
    }

    fn post(&mut self, path: &str, body: &[u8], now: &str) -> Response {
        if path != "label" {
            return Response::error(404, "not found");
        }
        let Ok(req) = serde_json::from_slice::<LabelRequest>(body) else {
            return Response::error(400, "expected {ids, label, note}");
        };
        match self.label(&req, now) {
            Ok(v) => Response::json(200, &v),
            Err(e) => Response::error(400, &format!("{e:#}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::review::{CLASS_FLAGGED, queue};
    use sc_core::{Observation, Rules, Tier, analyze};
    use std::collections::BTreeSet;

    fn app(name: &str) -> (ReviewApp, std::path::PathBuf) {
        let o = |id: &str, ts: i64, url: &str| Observation {
            id: id.into(),
            source: "wayback".into(),
            ts,
            url: url.into(),
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
                    5100,
                    "https://r.jina.ai/https://t.example/?q=1%20OR%201=1&x=2",
                ),
                o("x", 6000, "https://r.jina.ai/<script>alert(1)</script>"),
            ],
            &Rules::default_rules(),
        );
        let items = queue(&a, &BTreeSet::new(), Tier::Suggestive, 0);
        let dir =
            std::env::temp_dir().join(format!("swarmchase-serve-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = ReviewStore::open(ReviewStore::path_in(&dir)).unwrap();
        let mut sug = BTreeMap::new();
        sug.insert(
            "s1".to_string(),
            Suggestion {
                label: "agent".into(),
                reason: "sqli".into(),
                model: "m".into(),
            },
        );
        (ReviewApp::new(a, items, store, sug, "test".into()), dir)
    }

    fn post(app: &mut ReviewApp, body: &str) -> Response {
        app.post("label", body.as_bytes(), "2026-10-11T00:00:00Z")
    }

    #[test]
    fn groups_near_duplicates_and_defangs() {
        let (app, dir) = app("groups");
        let q = app.queue_json();
        let groups = q["groups"].as_array().unwrap();
        let text = q.to_string();
        assert!(!text.contains("https://"), "{text}");
        assert!(!text.contains("r.jina.ai"), "{text}");
        let with = |id: &str| {
            groups
                .iter()
                .find(|g| g["items"].as_array().unwrap().iter().any(|i| i["id"] == id))
                .unwrap()
        };
        let g = with("s1");
        let ids: Vec<&str> = g["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["id"].as_str().unwrap())
            .collect();
        assert!(
            ids.contains(&"s2"),
            "same shape or cluster, one group: {ids:?}"
        );
        assert_eq!(g["items"][0]["suggested"]["label"], "agent");
        assert!(g["items"][0]["label"].is_null());
        let c = &with("c1")["cluster"];
        assert!(c["grade"]["code"].as_str().unwrap().starts_with('L'), "{c}");
        assert_eq!(with("c1")["grade_basis"], "cluster");
        let x = with("x");
        assert_eq!(
            x["grade_basis"], "records",
            "an unclustered group has its records' grade"
        );
        assert_eq!(x["grade"]["code"], x["items"][0]["grade"]);
        assert_eq!(q["labeller"], "default");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn flags_agent_below_l2_in_suggestions_and_labels() {
        let (mut app, dir) = app("rule");
        let q = app.queue_json();
        let g = q["groups"]
            .as_array()
            .unwrap()
            .iter()
            .find(|g| {
                g["items"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|i| i["id"] == "s1")
            })
            .unwrap()
            .clone();
        assert!(g["level"].as_u64().unwrap() < 2, "{g}");
        assert_eq!(g["agent_allowed"], false);
        assert_eq!(g["conflicts"], 1, "the agent suggestion on s1");
        assert_eq!(g["rule_breaks"], 0);
        let s1 = g["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["id"] == "s1")
            .unwrap();
        assert_eq!(s1["conflict"], true);
        assert_eq!(s1["agent_allowed"], false);
        // Every flag agrees with its parts, in every group.
        for g in q["groups"].as_array().unwrap() {
            for i in g["items"].as_array().unwrap() {
                let sug = i["suggested"]["label"] == "agent";
                assert_eq!(i["conflict"], sug && i["agent_allowed"] == false, "{i}");
                if g["agent_allowed"] == true {
                    assert_eq!(i["agent_allowed"], true, "{g}");
                }
            }
        }

        // The admin may still label agent; the label is saved and flagged.
        let r = post(&mut app, r#"{"ids":["s1"],"label":"agent"}"#);
        assert_eq!(r.status, 200);
        let body: Value = serde_json::from_slice(&r.body).unwrap();
        assert_eq!(body["items"]["s1"]["breaks_rule"], true);
        assert_eq!(body["stored"]["total"], 1);
        assert_eq!(body["stored"]["by_label"]["agent"], 1);
        assert_eq!(body["stored"]["flagged"]["agent"], 1);
        let q = app.queue_json();
        assert_eq!(q["stored"]["total"], 1);
        assert!(q.to_string().contains("\"rule_breaks\":1"));
        post(&mut app, r#"{"ids":["s1"],"label":"unsure"}"#);
        let q = app.queue_json();
        assert!(!q.to_string().contains("\"breaks_rule\":true"));
        assert_eq!(q["stored"]["by_label"]["unsure"], 1);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn labels_carry_the_grade_they_were_judged_against() {
        let (mut app, dir) = app("grade");
        // Agent below L2, with a reason: saved, with the grade and the marker.
        let r = post(
            &mut app,
            r#"{"ids":["s1"],"label":"agent","note":"same run as cluster c1"}"#,
        );
        assert_eq!(r.status, 200);
        let body: Value = serde_json::from_slice(&r.body).unwrap();
        let lg = &body["items"]["s1"]["label_grade"];
        assert_eq!(lg["rule"], "below_l2", "{lg}");
        assert_eq!(lg["below_rule"], true);
        assert_eq!(lg["agent_allowed"], false);
        assert_eq!(lg["stored"], true);
        assert!(lg["code"].as_str().unwrap().starts_with('L'), "{lg}");
        assert!(lg["signals"].is_array() && lg["caps"].is_array(), "{lg}");
        assert_eq!(body["stored"]["agent_below_rule"]["total"], 1);
        assert_eq!(body["stored"]["agent_below_rule"]["with_reason"], 1);
        assert_eq!(body["stored"]["agent_below_rule"]["graded_now"], 0);
        let saved = ReviewStore::open(ReviewStore::path_in(&dir)).unwrap();
        let s1 = &saved.entries["s1"];
        let g = s1.grade.as_ref().expect("stored with the label");
        assert!(g.below_rule());
        assert_eq!(g.basis, "cluster");
        assert!(g.cluster.is_some());
        assert_eq!(s1.note.as_deref(), Some("same run as cluster c1"));
        let line = std::fs::read_to_string(ReviewStore::path_in(&dir)).unwrap();
        assert!(line.contains(r#""rule":"below_l2""#), "{line}");

        // Any other label stores its grade too, with no marker.
        post(&mut app, r#"{"ids":["s2"],"label":"benign"}"#);
        let saved = ReviewStore::open(ReviewStore::path_in(&dir)).unwrap();
        let g2 = saved.entries["s2"].grade.as_ref().unwrap();
        assert!(g2.rule.is_none() && !g2.below_rule());

        // Undo puts back the grade the label was saved with, not the one now.
        let mut then = g.clone();
        then.code = Some("L0".into());
        let req = json!({"ids": ["s1"], "label": "agent", "note": "x", "restore": true, "grades": {"s1": then}});
        assert_eq!(post(&mut app, &req.to_string()).status, 200);
        let saved = ReviewStore::open(ReviewStore::path_in(&dir)).unwrap();
        let back = saved.entries["s1"].grade.as_ref().unwrap();
        assert_eq!(back.code.as_deref(), Some("L0"));
        assert!(back.below_rule(), "the marker follows the restored label");
        // Outside an undo, a sent grade is ignored.
        let req = json!({"ids": ["s1"], "label": "agent", "grades": {"s1": then}});
        post(&mut app, &req.to_string());
        let saved = ReviewStore::open(ReviewStore::path_in(&dir)).unwrap();
        assert_eq!(saved.entries["s1"].grade.as_ref(), Some(g));

        // An older line, without a grade: graded now, and said so.
        app.store.entries.get_mut("s1").unwrap().grade = None;
        let q = app.queue_json();
        let item = q["groups"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|g| g["items"].as_array().unwrap())
            .find(|i| i["id"] == "s1")
            .unwrap();
        assert_eq!(item["label_grade"]["stored"], false, "{item}");
        assert_eq!(item["label_grade"]["below_rule"], true);
        assert_eq!(q["stored"]["agent_below_rule"]["graded_now"], 1);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn labels_save_with_suggestion_and_can_be_changed_cleared_or_restored() {
        let (mut app, dir) = app("label");
        let r = post(
            &mut app,
            r#"{"ids":["s1","s2"],"label":"benign","note":" a  pentester "}"#,
        );
        assert_eq!(r.status, 200);
        let saved = ReviewStore::open(ReviewStore::path_in(&dir)).unwrap();
        let s1 = &saved.entries["s1"];
        assert_eq!(s1.label, "benign");
        assert_eq!(s1.note.as_deref(), Some("a pentester"));
        assert_eq!(s1.class, CLASS_FLAGGED);
        assert_eq!(
            s1.suggested.as_ref().unwrap().label,
            "agent",
            "suggestion kept beside, not as, the label"
        );
        assert!(saved.entries["s2"].suggested.is_none());

        // Changed: the note stays when none is sent.
        assert_eq!(
            post(&mut app, r#"{"ids":["s1"],"label":"agent"}"#).status,
            200
        );
        let saved = ReviewStore::open(ReviewStore::path_in(&dir)).unwrap();
        assert_eq!(saved.entries["s1"].label, "agent");
        assert_eq!(saved.entries["s1"].note.as_deref(), Some("a pentester"));

        // Restored (undo): the note is set exactly, here cleared.
        let r = r#"{"ids":["s1"],"label":"unsure","note":null,"restore":true}"#;
        assert_eq!(post(&mut app, r).status, 200);
        let saved = ReviewStore::open(ReviewStore::path_in(&dir)).unwrap();
        assert_eq!(saved.entries["s1"].label, "unsure");
        assert!(saved.entries["s1"].note.is_none());

        // Cleared.
        assert_eq!(
            post(&mut app, r#"{"ids":["s2"],"label":"clear"}"#).status,
            200
        );
        let saved = ReviewStore::open(ReviewStore::path_in(&dir)).unwrap();
        assert!(!saved.entries.contains_key("s2"));

        assert_eq!(
            post(&mut app, r#"{"ids":["nope"],"label":"agent"}"#).status,
            400
        );
        assert_eq!(
            post(&mut app, r#"{"ids":["s1"],"label":"maybe"}"#).status,
            400
        );
        assert_eq!(app.post("other", b"{}", "t").status, 404);
        assert!(
            app.queue_json()
                .to_string()
                .contains("\"label\":\"unsure\"")
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}
