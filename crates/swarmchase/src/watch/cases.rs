//! New records against every case's indicators, and the status changes the
//! digest proposes. The watch never changes a case or notice itself.

use super::DAY;
use crate::case::{self, CaseStatus, NoticeStatus};
use crate::util::one_line;
use anyhow::Result;
use sc_core::{Observation, Rules, defang_host};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CaseWatch {
    /// Watch records that matched the case's indicators, oldest first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hits: Vec<CaseHit>,
    /// Proposals already in a digest. A standing proposal is listed on every
    /// run but only marks the first one as changed.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub proposed: BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseHit {
    pub id: String,
    pub ts: i64,
    /// The watch run that found it.
    pub run: String,
    /// Link to the public record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    /// The case indicators it shares.
    pub matched: Vec<String>,
}

/// The digest's "Case status" lines, and whether any is new since the last run.
#[derive(Default)]
pub struct CaseReport {
    pub lines: Vec<String>,
    pub changed: bool,
    /// Cases with a publication clock that has run and an admin step due.
    pub due: Vec<DueClock>,
}

/// A case whose clock has run: the indicator notice may be added, or an
/// operator may be named. A fact for the admin, never acted on here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DueClock {
    pub case: String,
    /// `indicators` (the indicator notice may be added) or `naming` (a
    /// naming update may name an operator).
    pub clock: &'static str,
    /// When it ran, as Unix seconds.
    pub since: i64,
    /// For `naming`: the hosts a naming update may name, defanged.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<String>,
}

impl DueClock {
    /// The digest line, with the command that starts the step.
    pub fn line(&self) -> String {
        let id = &self.case;
        match self.clock {
            "naming" => format!(
                "`{id}`: naming clock has run for {}; a naming update may name {}. Start with `swarmchase case notice {id} --naming`",
                self.hosts.join(", "),
                if self.hosts.len() == 1 { "it" } else { "them" }
            ),
            _ => format!(
                "`{id}`: indicator notice clock ran {}; the notice may be added once its checks pass. Start with `swarmchase notice add {id}`",
                sc_case::model::show_time(self.since)
            ),
        }
    }

    fn key(&self) -> String {
        format!("clock:{}:{}", self.clock, self.hosts.join(","))
    }
}

/// The clocks of case `c` that have run at `now` with the step still to
/// take. The indicator clock counts only once a report has been sent, and
/// only until the notice is added; the naming clock only after it.
pub fn due_clocks(c: &case::Case, now: i64) -> Vec<DueClock> {
    if c.status == CaseStatus::Closed {
        return Vec::new();
    }
    if !c.notice_added() {
        let clock = sc_case::lead::clock(c);
        return match clock.not_before {
            Some(t) if !c.sent.is_empty() && t <= now => vec![DueClock {
                case: c.id.clone(),
                clock: "indicators",
                since: t,
                hosts: Vec::new(),
            }],
            _ => Vec::new(),
        };
    }
    let ready: Vec<sc_case::naming::Operator> = sc_case::naming::operators(c)
        .into_iter()
        .filter(|o| o.may_name(now))
        .collect();
    if ready.is_empty() {
        return Vec::new();
    }
    vec![DueClock {
        case: c.id.clone(),
        clock: "naming",
        since: ready
            .iter()
            .filter_map(|o| o.consent.or(o.not_before))
            .min()
            .unwrap_or(now),
        hosts: ready.iter().map(|o| defang_host(&o.host)).collect(),
    }]
}

/// A case as the status check sees it.
struct CaseView<'a> {
    id: &'a str,
    status: CaseStatus,
    /// The published notice's status; `None` before the notice is published.
    notice: Option<NoticeStatus>,
    /// Newest capture time among the case's own records.
    last_seen: i64,
}

/// One run's check of every case.
pub struct CaseCheck<'a> {
    /// The cases directory, `<data>/cases`.
    pub root: &'a Path,
    /// The committed notices directory.
    pub notices: &'a Path,
    /// The current rules, to tell when they would change a pinned case's tiers.
    pub rules: &'a Rules,
    /// The run's stamp, recorded with each hit.
    pub stamp: &'a str,
    pub now: i64,
    /// An active notice with no matching record for this long could be marked contained.
    pub contained_after_days: i64,
}

impl CaseCheck<'_> {
    /// Match `fresh` against every case's indicators, record the hits in
    /// `watched`, and propose status changes. Errors are reported per case in
    /// the digest; they never stop the watch.
    pub fn monitor(
        &self,
        fresh: &[Observation],
        watched: &mut BTreeMap<String, CaseWatch>,
    ) -> CaseReport {
        let mut report = CaseReport::default();
        let cases = match case::all(self.root) {
            Ok(c) => c,
            Err(e) => {
                report.lines.push(format!("cases not checked: {e:#}"));
                return report;
            }
        };
        watched.retain(|id, _| cases.iter().any(|c| &c.id == id));
        for c in &cases {
            let cw = watched.entry(c.id.clone()).or_default();
            let (mut lines, mut keys) = match self.check(c, fresh, cw) {
                Ok(x) => x,
                Err(e) => {
                    let l = format!(
                        "`{}`: not checked: {}",
                        c.id,
                        one_line(&format!("{e:#}"), 200)
                    );
                    (vec![l.clone()], BTreeSet::from([l]))
                }
            };
            for d in due_clocks(c, self.now) {
                keys.insert(d.key());
                lines.push(d.line());
                report.due.push(d);
            }
            report.changed |= keys.iter().any(|k| !cw.proposed.contains(k));
            cw.proposed = keys;
            report.lines.extend(lines);
        }
        report
    }

    /// One case's digest lines, and keys naming them for change detection.
    fn check(
        &self,
        c: &case::Case,
        fresh: &[Observation],
        cw: &mut CaseWatch,
    ) -> Result<(Vec<String>, BTreeSet<String>)> {
        let rules = crate::pinning::case_rules(self.root, c)?;
        let ind = case::indicators(self.root, c, &rules)?;
        let known: BTreeSet<String> = cw.hits.iter().map(|h| h.id.clone()).collect();
        let new_hits = case_hits(&ind, fresh, &rules, self.stamp, &known);
        cw.hits.extend(new_hits.iter().cloned());
        let notice = match crate::notice::published_status(self.notices, &c.id)? {
            Some(s) => Some(s),
            None if c.status == CaseStatus::Published => Some(c.notice),
            None => None,
        };
        let view = CaseView {
            id: &c.id,
            status: c.status,
            notice,
            last_seen: ind.last_seen,
        };
        let mut lines = Vec::new();
        let mut keys = BTreeSet::new();
        if let Some((key, line)) =
            propose(&view, cw, &new_hits, self.now, self.contained_after_days)
        {
            keys.insert(key);
            lines.push(line);
        }
        let version = &self.rules.set.meta.version;
        // Compared on every run rather than by version name: a rule set edited
        // without a version bump changes tiers too.
        if c.status != CaseStatus::Closed {
            let n = crate::pinning::tier_changes(self.root, c, self.rules)?.len();
            if n > 0 {
                keys.insert(format!("rules:{version}:{n}"));
                lines.push(tier_change_line(&c.id, n, version));
            }
        }
        Ok((lines, keys))
    }
}

/// Records in `fresh` that match the case's indicators under its rules,
/// leaving out records already recorded as hits.
fn case_hits(
    ind: &case::CaseIndicators,
    fresh: &[Observation],
    rules: &Rules,
    stamp: &str,
    known: &BTreeSet<String>,
) -> Vec<CaseHit> {
    let mut hits: Vec<CaseHit> = fresh
        .iter()
        .filter(|o| !known.contains(&o.id))
        .filter_map(|o| {
            let matched = ind.matches(o, rules);
            (!matched.is_empty()).then(|| CaseHit {
                id: o.id.clone(),
                ts: o.ts,
                run: stamp.to_string(),
                reference: o.reference.clone(),
                matched,
            })
        })
        .collect();
    hits.sort_by(|a, b| a.ts.cmp(&b.ts).then_with(|| a.id.cmp(&b.id)));
    hits
}

/// The status change to propose for a case, as (key, digest line): reopen
/// when new records match a case whose notice is contained or historical or
/// which is closed; mark contained when an active notice's case has had no
/// matching record for `contained_after_days`. New hits on an active case are
/// reported without a proposal.
fn propose(
    v: &CaseView,
    cw: &CaseWatch,
    new_hits: &[CaseHit],
    now: i64,
    contained_after_days: i64,
) -> Option<(String, String)> {
    let id = v.id;
    let quiet_notice = matches!(
        v.notice,
        Some(NoticeStatus::Contained | NoticeStatus::Historical)
    );
    let closed = v.status == CaseStatus::Closed;
    if !new_hits.is_empty() {
        let what = hits_summary(new_hits);
        let add = format!(
            "`swarmchase case add {id} {}`",
            new_hits
                .iter()
                .take(20)
                .map(|h| format!("--record {}", h.id))
                .collect::<Vec<_>>()
                .join(" ")
        );
        if !(quiet_notice || closed) {
            let key = format!("hits:{}", new_hits[new_hits.len() - 1].id);
            return Some((key, format!("`{id}`: {what}. Add them with {add}")));
        }
        let mut was = Vec::new();
        let mut apply = Vec::new();
        if let Some(n) = v.notice.filter(|_| quiet_notice) {
            was.push(format!("notice {}", n.label()));
            apply.push(format!(
                "`swarmchase notice update {id} --kind status --status active`"
            ));
        }
        if closed {
            was.push("case closed".into());
            let to = if v.notice.is_some() {
                "published"
            } else {
                "open"
            };
            apply.push(format!("`swarmchase case set {id} --status {to}`"));
        }
        apply.push(add);
        return Some((
            format!("reopen:{}", new_hits[new_hits.len() - 1].id),
            format!(
                "`{id}`: propose reopen ({}): {what}. If approved: {}",
                was.join(", "),
                apply.join(", then ")
            ),
        ));
    }
    if v.notice != Some(NoticeStatus::Active) || closed {
        return None;
    }
    let last = cw.hits.iter().map(|h| h.ts).fold(v.last_seen, i64::max);
    if last <= 0 || now - last < contained_after_days * DAY {
        return None;
    }
    Some((
        "contained".into(),
        format!(
            "`{id}`: propose contained: no matching record since {} ({} days). If approved: `swarmchase notice update {id} --kind status --status contained`",
            sc_core::fmt_ts(last),
            (now - last) / DAY
        ),
    ))
}

/// "N new matching record(s) (indicators): links".
fn hits_summary(hits: &[CaseHit]) -> String {
    let matched: BTreeSet<&str> = hits
        .iter()
        .flat_map(|h| h.matched.iter().map(String::as_str))
        .collect();
    let mut shown: Vec<String> = matched
        .iter()
        .take(5)
        .map(|m| format!("`{}`", defang_host(m)))
        .collect();
    if matched.len() > 5 {
        shown.push(format!("{} more", matched.len() - 5));
    }
    let links: Vec<String> = hits
        .iter()
        .take(5)
        .map(|h| h.reference.clone().unwrap_or_else(|| h.id.clone()))
        .collect();
    format!(
        "{} new matching record(s) ({}): {}{}",
        hits.len(),
        shown.join(", "),
        links.join(", "),
        if hits.len() > 5 { ", …" } else { "" }
    )
}

fn tier_change_line(id: &str, n: usize, version: &str) -> String {
    format!(
        "{n} records in case `{id}` would change tier under rules {version}; run `swarmchase case rules {id}`"
    )
}

#[cfg(test)]
mod tests {
    use super::super::digest::{DigestInput, Health, Summary, digest};
    use super::*;
    use sc_core::analyze;

    const CASE_TS: i64 = 1_791_000_000;

    /// A data directory with case `p-1` opened from four records of one run
    /// against portal.example.gov, pinned to `rules`.
    fn case_data(name: &str, rules: &crate::pinning::RulesText) -> std::path::PathBuf {
        let data =
            std::env::temp_dir().join(format!("swarmchase-watch-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&data);
        let records: Vec<Observation> = (0..4)
            .map(|i| Observation {
                id: format!("c{i}"),
                ts: CASE_TS + i * 40,
                url: format!(
                    "https://r.jina.ai/https://portal.example.gov/q?id={i}%20UNION%20SELECT%201&uqtag=zz9"
                ),
                ..Default::default()
            })
            .collect();
        case::new_case(
            &data.join("cases"),
            "p-1",
            "Portal probe",
            records,
            rules,
            "2026-10-01",
        )
        .unwrap();
        data
    }

    fn obs(id: &str, ts: i64, url: &str) -> Observation {
        Observation {
            id: id.into(),
            ts,
            url: url.into(),
            reference: Some(format!("https://urlquery.example/report/{id}")),
            ..Default::default()
        }
    }

    #[test]
    fn new_records_match_case_indicators() {
        let rules = crate::pinning::RulesText::load(None).unwrap();
        let data = case_data("match", &rules);
        let c = case::load(&data.join("cases"), "p-1").unwrap();
        let ind = case::indicators(&data.join("cases"), &c, &rules.rules).unwrap();
        assert!(
            ind.features
                .contains_key(&"param:uqtag=zz9".parse::<sc_core::LinkFeature>().unwrap()),
            "{:?}",
            ind.features
        );
        assert!(ind.endpoints.contains("portal.example.gov"));

        let later = CASE_TS + 20 * DAY;
        let fresh = vec![
            // The run tag, on another host.
            obs(
                "tag",
                later,
                "https://r.jina.ai/https://other.example/x?id=1%20UNION%20SELECT%201&uqtag=zz9",
            ),
            // The endpoint, without the tag.
            obs(
                "host",
                later + 60,
                "https://portal.example.gov/q?id=9%20UNION%20SELECT%209",
            ),
            // Ordinary traffic to the endpoint: matches no rule.
            obs("plain", later + 120, "https://portal.example.gov/about"),
            // Unrelated flagged activity.
            obs(
                "other",
                later + 180,
                "https://elsewhere.example/q?id=1%20UNION%20SELECT%201",
            ),
            // One of the case's own records, seen again.
            obs(
                "c0",
                CASE_TS,
                "https://r.jina.ai/https://portal.example.gov/q?id=0%20UNION%20SELECT%201&uqtag=zz9",
            ),
        ];
        let hits = case_hits(&ind, &fresh, &rules.rules, "t1", &BTreeSet::new());
        let ids: Vec<&str> = hits.iter().map(|h| h.id.as_str()).collect();
        assert_eq!(ids, ["tag", "host"], "{hits:?}");
        assert!(
            hits[0].matched.iter().any(|m| m.contains("uqtag=zz9")),
            "{hits:?}"
        );
        assert_eq!(hits[1].matched, ["Endpoint portal.example.gov"]);
        // Hits already recorded are not reported again.
        let known = BTreeSet::from(["tag".to_string()]);
        assert_eq!(case_hits(&ind, &fresh, &rules.rules, "t2", &known).len(), 1);

        // Through the watch: hits are kept per case and listed in the digest.
        let mut watched = BTreeMap::new();
        let (root, notices) = (data.join("cases"), data.join("notices"));
        let run = CaseCheck {
            root: &root,
            notices: &notices,
            rules: &rules.rules,
            stamp: "t1",
            now: later + DAY,
            contained_after_days: 14,
        };
        let r = run.monitor(&fresh, &mut watched);
        assert!(r.changed, "{:?}", r.lines);
        assert_eq!(watched["p-1"].hits.len(), 2);
        assert!(
            r.lines[0].contains("2 new matching record(s)"),
            "{:?}",
            r.lines
        );
        assert!(
            r.lines[0].contains("--record tag --record host"),
            "{:?}",
            r.lines
        );
        let a = analyze(Vec::new(), &rules.rules);
        let sum = Summary::default();
        let d = digest(&DigestInput {
            stamp: "t1",
            analysis: &a,
            prev: &sum,
            next: &sum,
            new_ids: &BTreeSet::new(),
            health: &Health::default(),
            bursts: &[],
            cases: &r,
            window_days: 30,
            leads: &[],
            triage: &crate::watch::triage::TriageReport::default(),
            priority: &crate::watch::priority::assess(&[], &[], &r.due),
            attention: &Default::default(),
            autonomy: &[],
        });
        assert!(
            d.changed && d.text.contains("## Case status (1)"),
            "{}",
            d.text
        );
        assert!(d.text.contains("portal[.]example[.]gov"), "{}", d.text);
        std::fs::remove_dir_all(&data).unwrap();
    }

    fn view(notice: Option<NoticeStatus>, status: CaseStatus) -> CaseView<'static> {
        CaseView {
            id: "p-1",
            status,
            notice,
            last_seen: CASE_TS,
        }
    }

    #[test]
    fn quiet_active_notice_is_proposed_contained() {
        let v = view(Some(NoticeStatus::Active), CaseStatus::Published);
        let cw = CaseWatch::default();
        assert!(propose(&v, &cw, &[], CASE_TS + 13 * DAY, 14).is_none());
        let (key, line) = propose(&v, &cw, &[], CASE_TS + 15 * DAY, 14).unwrap();
        assert_eq!(key, "contained");
        assert!(line.contains("(15 days)"), "{line}");
        assert!(
            line.contains("`swarmchase notice update p-1 --kind status --status contained`"),
            "{line}"
        );
        // A recent hit keeps it active.
        let cw = CaseWatch {
            hits: vec![CaseHit {
                id: "h".into(),
                ts: CASE_TS + 10 * DAY,
                run: "t".into(),
                reference: None,
                matched: vec!["Run tag uqtag=zz9".into()],
            }],
            ..Default::default()
        };
        assert!(propose(&v, &cw, &[], CASE_TS + 15 * DAY, 14).is_none());
        // Before publication there is no notice to mark.
        let v = view(None, CaseStatus::Reported);
        assert!(propose(&v, &CaseWatch::default(), &[], CASE_TS + 30 * DAY, 14).is_none());
    }

    #[test]
    fn new_hits_on_a_contained_or_closed_case_propose_reopen() {
        let hit = CaseHit {
            id: "h1".into(),
            ts: CASE_TS + 40 * DAY,
            run: "t".into(),
            reference: Some("https://urlquery.example/report/h1".into()),
            matched: vec!["Callback channel ntfy.sh/zz9".into()],
        };
        let now = CASE_TS + 41 * DAY;
        let v = view(Some(NoticeStatus::Contained), CaseStatus::Published);
        let (key, line) = propose(
            &v,
            &CaseWatch::default(),
            std::slice::from_ref(&hit),
            now,
            14,
        )
        .unwrap();
        assert_eq!(key, "reopen:h1");
        assert!(line.contains("propose reopen (notice contained)"), "{line}");
        assert!(
            line.contains("https://urlquery.example/report/h1"),
            "{line}"
        );
        assert!(line.contains("ntfy[.]sh/zz9`"), "{line}");
        assert!(line.contains("--kind status --status active"), "{line}");

        let v = view(None, CaseStatus::Closed);
        let (_, line) = propose(
            &v,
            &CaseWatch::default(),
            std::slice::from_ref(&hit),
            now,
            14,
        )
        .unwrap();
        assert!(line.contains("(case closed)"), "{line}");
        assert!(
            line.contains("`swarmchase case set p-1 --status open`"),
            "{line}"
        );
        assert!(!line.contains("notice update"), "{line}");

        // On an active case new hits are news, not a proposal.
        let v = view(Some(NoticeStatus::Active), CaseStatus::Published);
        let (_, line) = propose(
            &v,
            &CaseWatch::default(),
            std::slice::from_ref(&hit),
            now,
            14,
        )
        .unwrap();
        assert!(!line.contains("propose"), "{line}");
    }

    /// A case with one provider and one targeted operator, both sent a
    /// report at `CASE_TS` when `sent`.
    fn clock_case(status: &str, sent: bool) -> case::Case {
        let mut text = format!(
            "id = \"p-1\"\ntitle = \"T\"\nstatus = \"{status}\"\nnotice = \"active\"\nopened = \"2026-09-22\"\n\
             [[endpoint]]\nhost = \"portal.example.gov\"\nstate = \"targeted\"\n"
        );
        for (org, role, endpoint, address) in [
            ("Example AI", "provider", "", "security@ai.example"),
            (
                "Portal",
                "affected",
                "endpoint = \"portal.example.gov\"\n",
                "security@portal.example.gov",
            ),
        ] {
            text += &format!(
                "[[contact]]\norg = \"{org}\"\nrole = \"{role}\"\n{endpoint}channel = \"email\"\naddress = \"{address}\"\nsource = \"\"\nconfidence = \"high\"\nfound_on = \"2026-09-22\"\n"
            );
            if sent {
                text += &format!(
                    "[[sent]]\ndate = \"2026-09-22\"\nrecipient = \"{address}\"\nchannel = \"email\"\nat = \"{}\"\n",
                    sc_case::model::rfc3339(CASE_TS)
                );
            }
        }
        case::Case::parse(&text).unwrap()
    }

    #[test]
    fn due_case_clocks_are_found() {
        // Nothing sent: no clock runs.
        assert!(due_clocks(&clock_case("open", false), CASE_TS + 30 * DAY).is_empty());
        // Reports sent: the indicator clock (0 h for these parties) has run.
        let c = clock_case("reported", true);
        let due = due_clocks(&c, CASE_TS + 60);
        assert_eq!(due.len(), 1, "{due:?}");
        assert_eq!((due[0].clock, due[0].since), ("indicators", CASE_TS));
        assert!(due[0].line().contains("`swarmchase notice add p-1`"));
        assert!(due_clocks(&c, CASE_TS - 60).is_empty());
        // Once the notice is added, the naming clock: not yet, then due.
        let c = clock_case("published", true);
        assert!(due_clocks(&c, CASE_TS + DAY).is_empty());
        let due = due_clocks(&c, CASE_TS + 60 * DAY);
        assert_eq!(due.len(), 1, "{due:?}");
        assert_eq!(due[0].clock, "naming");
        assert_eq!(due[0].hosts, ["portal[.]example[.]gov"]);
        assert!(due[0].line().contains("case notice p-1 --naming"));
        // A closed case has none.
        assert!(due_clocks(&clock_case("closed", true), CASE_TS + 60 * DAY).is_empty());
    }

    #[test]
    fn digest_says_when_current_rules_change_tiers_in_a_case() {
        // The case is pinned to a stricter edit of the bundled rules.
        let current = crate::pinning::RulesText::load(None).unwrap();
        let text = current
            .text
            .replace("suggestive = 3", "suggestive = 300")
            .replace("significant = 6", "significant = 600")
            .replace("significant = true", "significant = false");
        let strict = crate::pinning::RulesText {
            rules: Rules::from_toml(&text).unwrap(),
            text,
        };
        let data = case_data("rules", &strict);
        let c = case::load(&data.join("cases"), "p-1").unwrap();
        let n = crate::pinning::tier_changes(&data.join("cases"), &c, &current.rules)
            .unwrap()
            .len();
        assert!(n > 0);

        let mut watched = BTreeMap::new();
        let (root, notices) = (data.join("cases"), data.join("notices"));
        let run = CaseCheck {
            root: &root,
            notices: &notices,
            rules: &current.rules,
            stamp: "t",
            now: CASE_TS + DAY,
            contained_after_days: 14,
        };
        let r = run.monitor(&[], &mut watched);
        let v = current.version();
        assert_eq!(
            r.lines,
            [format!(
                "{n} records in case `p-1` would change tier under rules {v}; run `swarmchase case rules p-1`"
            )]
        );
        assert!(r.changed);
        // The same line on the next run is not news.
        let r = run.monitor(&[], &mut watched);
        assert_eq!(r.lines.len(), 1);
        assert!(!r.changed);
        std::fs::remove_dir_all(&data).unwrap();
    }
}
