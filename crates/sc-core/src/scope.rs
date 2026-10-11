//! Scope assessment (Field Manual chapter 15): for each cluster, what the
//! agents were evidently doing, what they reached, which of the S1–S7 scope
//! tests fail with the evidence, and the resulting finding.
//!
//! A tier measures payloads and tool use, not whether activity was out of
//! scope. This pass answers the four independent questions of FM-15.1 and
//! runs the FM-15.3 tests, conservatively: tool use alone (relays, carriers,
//! programs) fails no test. Everything here is an Inference for the admin's
//! review; it never changes a score, a tier or a link, and the public notice
//! text is unchanged except where the manual requires.

use crate::agentness::AgentLevel;
use crate::analyze::{Cluster, ObsResult};
use crate::escalation::Escalation;
use crate::model::{IndicatorKind, Tactic, Tier};
use crate::swarm::SwarmEdge;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The evident purpose of a cluster's ordinary requests (FM-15.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskClass {
    DataRetrieval,
    SearchReading,
    AccountSetup,
    SiteTesting,
    #[default]
    Unclear,
}

impl TaskClass {
    pub fn label(self) -> &'static str {
        match self {
            Self::DataRetrieval => "data retrieval",
            Self::SearchReading => "search and reading",
            Self::AccountSetup => "account setup",
            Self::SiteTesting => "testing of a named site",
            Self::Unclear => "unclear",
        }
    }
}

/// What kind of endpoint a request reached (FM-15.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetClass {
    PublicContent,
    Interactive,
    AccessControlled,
    Sensitive,
    ThirdPartyChannel,
    Benchmark,
}

impl TargetClass {
    pub fn label(self) -> &'static str {
        match self {
            Self::PublicContent => "public content",
            Self::Interactive => "interactive",
            Self::AccessControlled => "access-controlled",
            Self::Sensitive => "sensitive",
            Self::ThirdPartyChannel => "third-party channel",
            Self::Benchmark => "benchmark",
        }
    }
}

/// The outcome of one scope test.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeOutcome {
    Pass,
    Fail,
    NotAssessable,
}

/// One of the FM-15.3 scope tests, with the records that answer it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScopeTest {
    /// `S1`..`S7`.
    pub id: String,
    pub outcome: ScopeOutcome,
    /// The records (indexes into `Analysis::results`) the outcome rests on.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub records: Vec<usize>,
    pub detail: String,
}

/// The FM-15.4 finding for a cluster.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeFinding {
    InScope,
    ScopeExceeded,
    #[default]
    NotAssessable,
}

impl ScopeFinding {
    pub fn label(self) -> &'static str {
        match self {
            Self::InScope => "in scope",
            Self::ScopeExceeded => "scope exceeded",
            Self::NotAssessable => "not assessable",
        }
    }
}

/// A cluster's scope assessment (FM chapter 15). Inference for review:
/// never scored, never linked on.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Scope {
    pub task_class: TaskClass,
    /// Target classes the members reached, with how many records reached each.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub target_classes: BTreeMap<TargetClass, usize>,
    pub tests: Vec<ScopeTest>,
    pub finding: ScopeFinding,
    /// FM-15.1 question 1: the records hold attack payloads or escalated
    /// tool use (the tier is above noise).
    pub payload_present: bool,
    /// FM-15.1 question 2: an agent, not a person or a script, likely sent
    /// them (agent grade L4 or above).
    pub agent_present: bool,
    /// FM-15.1 question 3: the activity went beyond its evident task
    /// (`finding` is scope exceeded).
    pub out_of_scope: bool,
    /// FM-15.1 question 4: several agents acted together (an interaction
    /// edge touches this cluster).
    pub coordinated: bool,
}

impl Scope {
    /// The empty assessment of a cluster the pass did not run on (no tests):
    /// it is left out of the JSON.
    pub fn is_default(&self) -> bool {
        self.tests.is_empty()
    }
}

/// Paths that sit behind a login or other access control.
fn is_access_controlled(path: &str) -> bool {
    [
        "/login",
        "/signin",
        "/sign-in",
        "/signup",
        "/sign-up",
        "/register",
        "/auth",
        "/oauth",
        "/account",
        "/password",
        "/reset",
        "/token",
    ]
    .iter()
    .any(|p| path.starts_with(p))
}

/// Paths that expose configuration, source or administration: the task
/// rarely needs them (FM-15.2 sensitive).
fn is_sensitive(path: &str) -> bool {
    [
        "/.env",
        "/.git",
        "/.aws",
        "/.ssh",
        "/server-status",
        "/admin",
        "/wp-admin",
        "/config",
        "/backup",
        "/.ds_store",
        "/phpinfo",
        "/actuator",
    ]
    .iter()
    .any(|p| path.starts_with(p))
}

/// The target class a single flagged record reached.
fn target_class_of(r: &ObsResult, benchmark: bool) -> TargetClass {
    if r.hits.iter().any(|h| h.kind == IndicatorKind::Exfil) {
        return TargetClass::ThirdPartyChannel;
    }
    if benchmark {
        return TargetClass::Benchmark;
    }
    let path = r
        .target_host
        .as_deref()
        .and_then(|host| {
            r.layers
                .iter()
                .rev()
                .find(|l| l.host.as_deref() == Some(host))
        })
        .map(|l| crate::paths::normalize_path(&l.text))
        .unwrap_or_else(|| crate::paths::normalize_path(&r.obs.url));
    if is_sensitive(&path) {
        TargetClass::Sensitive
    } else if is_access_controlled(&path) {
        TargetClass::AccessControlled
    } else if r
        .layers
        .iter()
        .rev()
        .find(|l| l.host.as_deref() == r.target_host.as_deref())
        .is_some_and(|l| !l.params.is_empty())
    {
        TargetClass::Interactive
    } else {
        TargetClass::PublicContent
    }
}

/// Members with a hit of `kind`.
fn members_with_kind(results: &[ObsResult], c: &Cluster, kind: IndicatorKind) -> Vec<usize> {
    c.members
        .iter()
        .copied()
        .filter(|&m| results[m].hits.iter().any(|h| h.kind == kind))
        .collect()
}

/// Members with a hit of `tactic`.
fn members_with_tactic(results: &[ObsResult], c: &Cluster, tactic: Tactic) -> Vec<usize> {
    c.members
        .iter()
        .copied()
        .filter(|&m| results[m].hits.iter().any(|h| h.tactic == Some(tactic)))
        .collect()
}

fn guess_task_class(c: &Cluster) -> TaskClass {
    if !c.knowledge.benchmarks.is_empty() {
        TaskClass::SiteTesting
    } else if c.tactics.contains_key(&Tactic::AccountAcquisition) {
        TaskClass::AccountSetup
    } else if c.tactics.get(&Tactic::TaskRetrieval).copied().unwrap_or(0) > 0 {
        TaskClass::DataRetrieval
    } else {
        TaskClass::Unclear
    }
}

/// The scope assessment for one cluster.
pub(crate) fn assess(
    c: &Cluster,
    results: &[ObsResult],
    escalations: &[Escalation],
    swarm_edges: &[SwarmEdge],
) -> Scope {
    let benchmark = !c.knowledge.benchmarks.is_empty();
    let mut target_classes: BTreeMap<TargetClass, usize> = BTreeMap::new();
    for &m in &c.members {
        *target_classes
            .entry(target_class_of(&results[m], benchmark))
            .or_default() += 1;
    }
    let records_of = |tc: TargetClass| -> Vec<usize> {
        c.members
            .iter()
            .copied()
            .filter(|&m| target_class_of(&results[m], benchmark) == tc)
            .collect()
    };
    let task = guess_task_class(c);

    let mut tests = Vec::new();
    let test =
        |tests: &mut Vec<ScopeTest>, id: &str, outcome, records: Vec<usize>, detail: String| {
            tests.push(ScopeTest {
                id: id.to_string(),
                outcome,
                records,
                detail,
            });
        };

    // S1 Off-task target: needs a task class, and a target outside it.
    if task == TaskClass::Unclear {
        test(
            &mut tests,
            "S1",
            ScopeOutcome::NotAssessable,
            vec![],
            "the task class is unclear, so an off-task target cannot be judged".into(),
        );
    } else {
        let off: Vec<usize> = [TargetClass::AccessControlled, TargetClass::Sensitive]
            .iter()
            .flat_map(|&tc| records_of(tc))
            .collect();
        if task != TaskClass::SiteTesting && !off.is_empty() {
            test(
                &mut tests,
                "S1",
                ScopeOutcome::Fail,
                off,
                format!(
                    "a {} run reached access-controlled or sensitive targets",
                    task.label()
                ),
            );
        } else {
            test(
                &mut tests,
                "S1",
                ScopeOutcome::Pass,
                vec![],
                "targets are consistent with the evident task".into(),
            );
        }
    }

    // S2 Control circumvention: an anti-bot hit, or a route escalation on
    // this cluster. A relay used from the start is not enough.
    let antibot = members_with_kind(results, c, IndicatorKind::AntiBot);
    let escalated = escalations.iter().any(|e| e.clusters.contains(&c.id));
    if !antibot.is_empty() || escalated {
        test(
            &mut tests,
            "S2",
            ScopeOutcome::Fail,
            antibot.clone(),
            if escalated {
                "the route climbed to reach one target, past a block".into()
            } else {
                "anti-bot token generation or a CAPTCHA solver was used".into()
            },
        );
    } else {
        test(
            &mut tests,
            "S2",
            ScopeOutcome::Pass,
            vec![],
            "no block, challenge or rate limit was circumvented".into(),
        );
    }

    // S3 Sensitive paths: a request for a sensitive target the task did not
    // need.
    let sensitive = records_of(TargetClass::Sensitive);
    if !sensitive.is_empty() {
        test(
            &mut tests,
            "S3",
            ScopeOutcome::Fail,
            sensitive,
            "requests reached configuration, source or administration paths".into(),
        );
    } else {
        test(
            &mut tests,
            "S3",
            ScopeOutcome::Pass,
            vec![],
            "no sensitive path was requested".into(),
        );
    }

    // S4 Unsanctioned probing: attack payloads, and not a benchmark target.
    let exploit = members_with_kind(results, c, IndicatorKind::Exploit);
    if !exploit.is_empty() && !benchmark {
        test(
            &mut tests,
            "S4",
            ScopeOutcome::Fail,
            exploit,
            "attack payloads were sent to a party that did not sanction them".into(),
        );
    } else if !exploit.is_empty() {
        test(
            &mut tests,
            "S4",
            ScopeOutcome::NotAssessable,
            exploit,
            "attack payloads reached a benchmark target built to be tested".into(),
        );
    } else {
        test(
            &mut tests,
            "S4",
            ScopeOutcome::Pass,
            vec![],
            "no attack payload was sent".into(),
        );
    }

    // S5 Identity and credentials.
    let mut ident = members_with_tactic(results, c, Tactic::AccountAcquisition);
    ident.extend(members_with_tactic(results, c, Tactic::CredentialReuse));
    ident.sort_unstable();
    ident.dedup();
    if ident.is_empty() {
        test(
            &mut tests,
            "S5",
            ScopeOutcome::Pass,
            vec![],
            "no account or credential acquisition".into(),
        );
    } else {
        test(
            &mut tests,
            "S5",
            ScopeOutcome::Fail,
            ident,
            "accounts or credentials were acquired or reused".into(),
        );
    }

    // S6 Data sent out: a callback channel carrying fetched content.
    let exfil = members_with_kind(results, c, IndicatorKind::Exfil);
    if exfil.is_empty() {
        test(
            &mut tests,
            "S6",
            ScopeOutcome::Pass,
            vec![],
            "no data was sent to a channel outside the target".into(),
        );
    } else {
        test(
            &mut tests,
            "S6",
            ScopeOutcome::Fail,
            exfil,
            "data was sent to a callback inbox or side channel".into(),
        );
    }

    // S7 Coordination: an interaction edge touches this cluster and widens
    // a test that already failed. Edges are unreviewed hints, so coordination
    // alone fails nothing: it answers FM-15.1 question 4, not question 3.
    let coordinated = swarm_edges
        .iter()
        .any(|e| e.a.cluster == c.id || e.b.cluster == c.id);
    let widened: Vec<String> = tests
        .iter()
        .filter(|t| t.outcome == ScopeOutcome::Fail)
        .map(|t| t.id.clone())
        .collect();
    if coordinated && !widened.is_empty() {
        test(
            &mut tests,
            "S7",
            ScopeOutcome::Fail,
            vec![],
            format!(
                "an interaction edge ties this cluster's runs to another's while {} fails",
                widened.join(", ")
            ),
        );
    } else if coordinated {
        test(
            &mut tests,
            "S7",
            ScopeOutcome::NotAssessable,
            vec![],
            "an interaction edge touches this cluster, but no other test fails for it to widen"
                .into(),
        );
    } else {
        test(
            &mut tests,
            "S7",
            ScopeOutcome::NotAssessable,
            vec![],
            "coordination is a fleet-level judgment; no edge touches this cluster".into(),
        );
    }

    let failed = tests.iter().any(|t| t.outcome == ScopeOutcome::Fail);
    let any_assessable = tests
        .iter()
        .any(|t| t.outcome != ScopeOutcome::NotAssessable);
    let finding = if failed {
        ScopeFinding::ScopeExceeded
    } else if any_assessable {
        ScopeFinding::InScope
    } else {
        ScopeFinding::NotAssessable
    };

    Scope {
        task_class: task,
        target_classes,
        tests,
        finding,
        payload_present: c.tier != Tier::Noise,
        agent_present: c.agent.level >= AgentLevel::AgentLikely,
        out_of_scope: finding == ScopeFinding::ScopeExceeded,
        coordinated,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze::analyze;
    use crate::model::Observation;
    use crate::rules::Rules;

    fn obs(id: &str, ts: i64, url: &str) -> Observation {
        Observation {
            id: id.into(),
            ts,
            url: url.into(),
            ..Default::default()
        }
    }

    fn scope_of(obs: Vec<Observation>) -> Scope {
        let a = analyze(obs, &Rules::default_rules());
        a.clusters[0].scope.clone()
    }

    #[test]
    fn tool_use_alone_fails_no_test() {
        // A program that fetches an open dataset through an echo service: tool
        // escalation (T2), no payload, no channel. Every test passes or is not
        // assessable; the finding is in scope.
        let t = 1_791_000_000;
        let url = |i: i64| {
            format!(
                "https://httpbin.org/anything?u=https://data.portal.example/records%3Fpage%3D{i}&uqtag=scopez"
            )
        };
        let s = scope_of(vec![
            obs("a", t, &url(1)),
            obs("b", t + 30, &url(2)),
            obs("c", t + 60, &url(3)),
        ]);
        assert!(
            s.tests.iter().all(|t| t.outcome != ScopeOutcome::Fail),
            "{:?}",
            s.tests
        );
        assert_ne!(s.finding, ScopeFinding::ScopeExceeded);
    }

    #[test]
    fn payloads_and_a_channel_exceed_scope() {
        let t = 1_791_000_000;
        let inbox = "https://webhook.site/0b6c1f0e-1111-4c2a-9a55-3f2e1d0c9b8a";
        let url = |i: i64| {
            format!(
                "https://data.portal.example/item?id={i}%20UNION%20SELECT%20null,version()--&cb={inbox}"
            )
        };
        let s = scope_of(vec![
            obs("a", t, &url(1)),
            obs("b", t + 30, &url(2)),
            obs("c", t + 60, &url(3)),
        ]);
        assert_eq!(s.finding, ScopeFinding::ScopeExceeded);
        assert!(s.payload_present);
        let failed: Vec<&str> = s
            .tests
            .iter()
            .filter(|t| t.outcome == ScopeOutcome::Fail)
            .map(|t| t.id.as_str())
            .collect();
        assert!(failed.contains(&"S4"), "{failed:?}");
        assert!(failed.contains(&"S6"), "{failed:?}");
    }

    #[test]
    fn coordination_alone_exceeds_no_scope() {
        // Interaction hints answer "coordinated", not "out of scope": S7 fails
        // only alongside another failed test.
        let text = include_str!("../../../samples/eval/swarm-interaction.ndjson");
        let obs = crate::ingest::parse_input(
            text,
            crate::ingest::Format::Ndjson,
            &crate::ingest::FieldMap::default(),
        )
        .observations;
        let a = analyze(obs, &Rules::default_rules());
        let mut coordinated_in_scope = 0;
        for c in &a.clusters {
            let s = &c.scope;
            let fails: Vec<&str> = s
                .tests
                .iter()
                .filter(|t| t.outcome == ScopeOutcome::Fail)
                .map(|t| t.id.as_str())
                .collect();
            if fails.contains(&"S7") {
                assert!(fails.len() > 1, "{}: S7 alone fails", c.id);
            }
            if s.coordinated && fails.is_empty() {
                coordinated_in_scope += 1;
                assert!(!s.out_of_scope);
            }
        }
        assert!(coordinated_in_scope > 0, "no coordinated cluster in scope");
    }
}
