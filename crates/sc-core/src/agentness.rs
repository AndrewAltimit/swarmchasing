//! How likely it is that an AI agent, not a person or a conventional tool,
//! sent a cluster's requests.
//!
//! A tier says attack payloads were present. A penetration tester or a
//! scanner sending the same payloads through the same relays leaves the same
//! records. [`assess`] grades each cluster on a ladder by the strongest
//! *combination* of agent signals it shows, never by a summed score:
//!
//! - **L0** payloads only;
//! - **L1** self-described: a model or vendor name, or an agent test tag,
//!   which anyone can write, so it reads like L0;
//! - **L2** model-written: residue, prose, invented identifiers, repeated cut
//!   lengths, stale knowledge or stale date tags;
//! - **L3** adaptive: L2 plus behaviour that answers responses (a changed
//!   request after an error, a route escalation, a probe chain at model
//!   pace), read only from request or submit times;
//! - **L4** agent likely: L3 plus machine pace while adapting, or a pace or
//!   scale beyond one person (fixed fan-out, one target sent to several scan
//!   services within seconds, round the clock), with no working-hours rhythm
//!   against it;
//! - **L5** documented: never computed; only the admin's case decision sets
//!   it (operator logs matching a harness, a provider's confirmation).
//!
//! Caps hold a grade down where the records cannot show more: capture times
//! only (L2), a working-hours rhythm at slow pace (L2, possibly a person
//! with model help), any working-hours rhythm (L3). Counter-signals
//! (declared testing, benchmark targets, scanner pace, an auto-submitter
//! sending ordinary links to the same services) are listed beside the
//! signals and never move the grade. Nothing here changes a score, a tier or
//! a link.

use crate::analyze::{Cluster, ObsResult};
use crate::chains::{Chain, ChainOptions, Pace};
use crate::escalation::Escalation;
use crate::model::{Hit, IndicatorKind, TsKind};
use crate::timing::{RhythmVerdict, TimeBasis};
use serde::{Deserialize, Serialize};

/// Agent-tag rules: an agent describing itself, like a vendor name. Every
/// other artifact rule of kind `agent_marker` is model-output residue.
pub const SELF_DESCRIBED: &[&str] = &["marker.uq_tags", "marker.test_tag", "marker.oai_tag"];

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum AgentLevel {
    #[default]
    PayloadsOnly,
    SelfDescribed,
    ModelWritten,
    Adaptive,
    AgentLikely,
    /// Set only by an admin's case decision.
    Documented,
}

impl AgentLevel {
    pub const ALL: [AgentLevel; 6] = [
        Self::PayloadsOnly,
        Self::SelfDescribed,
        Self::ModelWritten,
        Self::Adaptive,
        Self::AgentLikely,
        Self::Documented,
    ];

    /// `L0` .. `L5`.
    pub fn code(self) -> &'static str {
        ["L0", "L1", "L2", "L3", "L4", "L5"][self as usize]
    }

    pub fn label(self) -> &'static str {
        [
            "payloads only",
            "self-described",
            "model-written",
            "adaptive",
            "agent likely",
            "documented",
        ][self as usize]
    }

    /// What the level means, as a report says it.
    pub fn meaning(self) -> &'static str {
        match self {
            Self::PayloadsOnly | Self::SelfDescribed => {
                "Attack payloads were present; this alone does not show what sent them."
            }
            Self::ModelWritten => {
                "The requests carry content a language model writes. A person pasting model output leaves the same."
            }
            Self::Adaptive => "Model-written requests that change in answer to responses.",
            Self::AgentLikely => {
                "Adaptive, model-written requests at a pace or scale beyond one person."
            }
            Self::Documented => {
                "Documented by case work: operator logs matching an agent harness, or the provider's confirmation."
            }
        }
    }
}

impl std::str::FromStr for AgentLevel {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        let s = s.trim().to_ascii_lowercase().replace(['-', ' '], "_");
        Self::ALL
            .into_iter()
            .find(|l| s == l.code().to_ascii_lowercase() || s == l.label().replace([' ', '-'], "_"))
            .ok_or_else(|| {
                format!("unknown agent level `{s}` (L0..L5, or a name such as model_written)")
            })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalKind {
    // L1
    SelfId,
    VerifiedPlatform,
    // L2
    Residue,
    Prose,
    FabricatedIds,
    CutLengths,
    StaleKnowledge,
    StaleDates,
    // L3
    RetryAfterError,
    Escalation,
    ModelPaceChain,
    // L4
    MachinePace,
    FanOut,
    CrossService,
    RoundTheClock,
    // Counter-signals
    DeclaredTesting,
    Benchmark,
    ScannerPace,
    AutoSubmitter,
    WorkingHours,
    SpoofedIdentity,
}

impl SignalKind {
    /// The rung this signal supports; `None` for a counter-signal.
    pub fn level(self) -> Option<AgentLevel> {
        use SignalKind::*;
        Some(match self {
            SelfId | VerifiedPlatform => AgentLevel::SelfDescribed,
            Residue | Prose | FabricatedIds | CutLengths | StaleKnowledge | StaleDates => {
                AgentLevel::ModelWritten
            }
            RetryAfterError | Escalation | ModelPaceChain => AgentLevel::Adaptive,
            MachinePace | FanOut | CrossService | RoundTheClock => AgentLevel::AgentLikely,
            DeclaredTesting | Benchmark | ScannerPace | AutoSubmitter | WorkingHours
            | SpoofedIdentity => {
                return None;
            }
        })
    }

    pub fn label(self) -> &'static str {
        use SignalKind::*;
        match self {
            SelfId => {
                "names a model or vendor, or carries an agent test tag (anyone can write this)"
            }
            VerifiedPlatform => {
                "sent by a provider's agent platform, verified by its published key or address range (it shows who relayed the request, not that a model chose it)"
            }
            Residue => "model-output residue in requests",
            Prose => "natural-language prose in parameters",
            FabricatedIds => "identifiers no generator produces",
            CutLengths => "URLs cut at one repeated length, like an output limit",
            StaleKnowledge => "retired endpoints or old client versions",
            StaleDates => "date tags naming a consistent past date",
            RetryAfterError => "a changed request right after an error response",
            Escalation => "a route escalation to reach one page",
            ModelPaceChain => "a probe chain at model pace",
            MachinePace => "retries after errors at tool pace, faster than a person reads",
            FanOut => "parallel fan-out of one fixed width",
            CrossService => "one target sent to several scan services within seconds",
            RoundTheClock => "activity round the clock",
            DeclaredTesting => "declares authorised testing or research",
            Benchmark => "public benchmark or practice targets",
            ScannerPace => {
                "a probe chain at tool pace with no change after errors, as a scanner runs a list"
            }
            AutoSubmitter => {
                "ordinary links around it sent to the same services alike, as a mail gateway or security product submits every link it sees (whoever sent it the link made the records)"
            }
            WorkingHours => "activity in one time zone's working hours",
            SpoofedIdentity => {
                "names a provider's agent product from outside that provider's published ranges (the self-description is false)"
            }
        }
    }
}

/// One signal, with how many members show it and what it rests on (rule
/// ids, counts; never record content).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentSignal {
    pub kind: SignalKind,
    pub records: usize,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detail: String,
}

/// What holds a grade below what its signals reach.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentCap {
    /// Every timestamp is an archive capture: pace, retries and rhythm are
    /// unread.
    CaptureTimes,
    /// A working-hours rhythm at slow pace.
    HumanPace,
    /// A working-hours rhythm.
    WorkingHours,
}

impl AgentCap {
    pub fn ceiling(self) -> AgentLevel {
        match self {
            Self::CaptureTimes | Self::HumanPace => AgentLevel::ModelWritten,
            Self::WorkingHours => AgentLevel::Adaptive,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::CaptureTimes => {
                "capture times only: pace, retries and rhythm cannot be read, so the grade stops at L2"
            }
            Self::HumanPace => {
                "a working-hours rhythm at slow pace: possibly human-operated with model help, so the grade stops at L2"
            }
            Self::WorkingHours => {
                "a working-hours rhythm, which an unattended fleet need not keep, so the grade stops at L3"
            }
        }
    }
}

/// A cluster's grade on the ladder, with the signals, counter-signals and
/// caps behind it.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AgentAssessment {
    pub level: AgentLevel,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signals: Vec<AgentSignal>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub counter: Vec<AgentSignal>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub caps: Vec<AgentCap>,
}

/// The admin's grade for a case, the only way to reach L5.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GradeDecision {
    pub level: AgentLevel,
    pub date: String,
    /// What the decision rests on, with links.
    pub note: String,
}

/// Whether chain or escalation times can stand for request times.
fn timed(b: TimeBasis) -> bool {
    !matches!(b, TimeBasis::Capture | TimeBasis::Mixed)
}

/// Grade cluster `c`. `chains` and `escalations` are the analysis's; those
/// touching the cluster are read.
/// The rule ids among `hits` that self-describe (L1) and that are
/// model-output residue (L2).
fn hit_marks(hits: &[Hit]) -> (Vec<&str>, Vec<&str>) {
    let (mut tags, mut residue) = (Vec::new(), Vec::new());
    for h in hits {
        let id = h.rule_id.as_str();
        let list = if h.kind == IndicatorKind::SelfId || SELF_DESCRIBED.contains(&id) {
            &mut tags
        } else if h.artifact && h.kind == IndicatorKind::AgentMarker {
            &mut residue
        } else {
            continue;
        };
        if !list.contains(&id) {
            list.push(id);
        }
    }
    (tags, residue)
}

/// Grade a flagged record that is in no cluster, from its own hits:
/// self-description (L1) and model-output residue (L2). One record shows no
/// pace, retries or rhythm, so it never reaches L3; an archive capture is
/// capped as a cluster of captures is.
pub fn assess_record(r: &ObsResult) -> AgentAssessment {
    let mut out = AgentAssessment::default();
    let (tags, residue) = hit_marks(&r.hits);
    let mut push = |kind: SignalKind, ids: &[&str]| {
        if !ids.is_empty() {
            out.signals.push(AgentSignal {
                kind,
                records: 1,
                detail: ids.join(", "),
            });
        }
    };
    push(SignalKind::SelfId, &tags);
    push(SignalKind::Residue, &residue);
    if r.obs.ts_kind == TsKind::Capture {
        out.caps.push(AgentCap::CaptureTimes);
    }
    out.level = if !residue.is_empty() {
        AgentLevel::ModelWritten
    } else if !tags.is_empty() {
        AgentLevel::SelfDescribed
    } else {
        AgentLevel::PayloadsOnly
    };
    out
}

pub fn assess(
    c: &Cluster,
    results: &[ObsResult],
    chains: &[Chain],
    escalations: &[Escalation],
    opts: &ChainOptions,
) -> AgentAssessment {
    let mut out = AgentAssessment::default();
    let mut push = |kind: SignalKind, records: usize, detail: String| {
        if records > 0 {
            let s = AgentSignal {
                kind,
                records,
                detail,
            };
            match kind.level() {
                Some(_) => out.signals.push(s),
                None => out.counter.push(s),
            }
        }
    };

    // L1 and residue, from the members' hits.
    let (mut tags, mut residue): (Vec<&str>, Vec<&str>) = (Vec::new(), Vec::new());
    let (mut n_tag, mut n_res) = (0, 0);
    for &i in &c.members {
        let (t, r) = hit_marks(&results[i].hits);
        n_tag += usize::from(!t.is_empty());
        n_res += usize::from(!r.is_empty());
        for id in t {
            if !tags.contains(&id) {
                tags.push(id);
            }
        }
        for id in r {
            if !residue.contains(&id) {
                residue.push(id);
            }
        }
    }
    push(SignalKind::SelfId, n_tag, tags.join(", "));
    push(SignalKind::Residue, n_res, residue.join(", "));

    // L2 from the cluster's hints. One prose value can be a person's search;
    // two, or one in a foreign language for its target, count.
    let p = &c.prose;
    if p.values >= 2 || p.mismatched > 0 {
        push(SignalKind::Prose, p.values, String::new());
    }
    push(
        SignalKind::FabricatedIds,
        c.paths.fabricated_ids,
        String::new(),
    );
    if let Some(g) = c.cut_lengths.url.or(c.cut_lengths.value) {
        push(SignalKind::CutLengths, g.records, String::new());
    }
    let stale: Vec<&str> = c
        .knowledge
        .stale_knowledge
        .iter()
        .map(|u| u.id.as_str())
        .collect();
    push(
        SignalKind::StaleKnowledge,
        c.knowledge.stale_knowledge.iter().map(|u| u.records).sum(),
        stale.join(", "),
    );
    let sd = &c.timing.stale_dates;
    if sd.consistent {
        push(SignalKind::StaleDates, sd.behind, String::new());
    }

    // L3 and L4 from chains and escalations timed by requests or submits.
    let (mut retry, mut model, mut machine, mut scanner) = (0, 0, 0, 0);
    let mut slow_only = true;
    for ch in chains
        .iter()
        .filter(|ch| timed(ch.time_basis) && ch.members.iter().any(|m| c.members.contains(m)))
    {
        retry += ch.retries_after_error;
        match (ch.pace, ch.retries_after_error) {
            (Pace::Model, _) => model += ch.members.len(),
            (Pace::Tool, 0) => scanner += ch.members.len(),
            (Pace::Tool, n) => machine += n,
            (Pace::Slow, _) => {}
        }
        slow_only &= ch.pace == Pace::Slow;
    }
    push(SignalKind::RetryAfterError, retry, String::new());
    let (mut steps, mut route) = (0, String::new());
    for e in escalations
        .iter()
        .filter(|e| timed(e.time_basis) && e.clusters.contains(&c.id))
    {
        steps += e.steps.len();
        if route.is_empty() {
            route = e.route_line();
        }
    }
    push(SignalKind::Escalation, steps, route);
    push(SignalKind::ModelPaceChain, model, String::new());
    push(SignalKind::MachinePace, machine, String::new());
    if c.fanout.modal_width.is_some() {
        push(SignalKind::FanOut, c.fanout.batches, String::new());
    }
    // One target on several scan services within seconds is beyond a person
    // checking a link; the same on ordinary links around it is a gateway
    // or security product submitting everything, so it counts against.
    let xs = &c.cross_service;
    if !xs.is_empty() {
        let detail = format!(
            "{} target(s) on {} within {}s",
            xs.targets,
            xs.service_list(),
            xs.max_spread_secs
        );
        if xs.auto_submitter {
            push(
                SignalKind::AutoSubmitter,
                xs.records,
                format!(
                    "{detail}; {} ordinary target(s) alike around it",
                    xs.ambient
                ),
            );
        } else {
            push(SignalKind::CrossService, xs.records, detail);
        }
    }
    let rhythm = c.timing.rhythm.verdict;
    let days = c.timing.rhythm.days;
    if rhythm == RhythmVerdict::RoundTheClock {
        push(SignalKind::RoundTheClock, days, String::new());
    }

    // Counter-signals.
    push(
        SignalKind::DeclaredTesting,
        c.declared.iter().map(|d| d.records).sum(),
        String::new(),
    );
    let bench: Vec<&str> = c.knowledge.benchmarks.keys().map(String::as_str).collect();
    push(
        SignalKind::Benchmark,
        c.knowledge.benchmarks.values().sum(),
        bench.join(", "),
    );
    push(SignalKind::ScannerPace, scanner, String::new());
    let daytime = matches!(rhythm, RhythmVerdict::Daytime { .. });
    if daytime {
        push(SignalKind::WorkingHours, days, String::new());
    }

    // Caps, in their order.
    if c.time_basis == TimeBasis::Capture {
        out.caps.push(AgentCap::CaptureTimes);
    }
    if daytime {
        // Slow: no chain faster than slow pace and a cluster gap past model pace.
        let slow = slow_only
            && c.timing
                .median_gap_secs
                .is_some_and(|g| g > opts.model_pace_max_secs as f64);
        out.caps.push(if slow {
            AgentCap::HumanPace
        } else {
            AgentCap::WorkingHours
        });
    }

    // The strongest rung whose every lower rung from L2 holds.
    let has = |l: AgentLevel| out.signals.iter().any(|s| s.kind.level() == Some(l));
    let mut level = if has(AgentLevel::SelfDescribed) {
        AgentLevel::SelfDescribed
    } else {
        AgentLevel::PayloadsOnly
    };
    if has(AgentLevel::ModelWritten) {
        level = AgentLevel::ModelWritten;
        if has(AgentLevel::Adaptive) {
            level = AgentLevel::Adaptive;
            if has(AgentLevel::AgentLikely) {
                level = AgentLevel::AgentLikely;
            }
        }
    }
    for cap in &out.caps {
        level = level.min(cap.ceiling());
    }
    out.level = level;
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Observation;
    use crate::model::TsKind;
    use crate::rules::Rules;

    fn run(urls: &[(i64, &str, Option<u16>)], kind: TsKind) -> crate::Analysis {
        let obs = urls
            .iter()
            .enumerate()
            .map(|(i, &(ts, url, status))| Observation {
                id: format!("t:{i}"),
                ts,
                ts_kind: kind,
                url: url.into(),
                status,
                ..Default::default()
            })
            .collect();
        crate::analyze(obs, &Rules::default_rules())
    }

    #[test]
    fn an_unclustered_record_is_graded_from_its_own_hits() {
        let t0 = 1_791_000_000;
        let a = run(
            &[
                (
                    t0,
                    "https://r.jina.ai/https://t.example/?q=1%20OR%201=1",
                    None,
                ),
                (
                    t0 + 9_000,
                    "https://u.example/search?uqtag=r7k2&q=permits",
                    None,
                ),
                (
                    t0 + 18_000,
                    "https://v.example/login?user=admin%27--&k=YOUR_API_KEY",
                    None,
                ),
            ],
            TsKind::Capture,
        );
        let grade = |id: &str| {
            let r = a.results.iter().find(|r| r.obs.id == id).unwrap();
            assert!(r.cluster.is_none(), "{id} is unclustered");
            r.agent.as_ref().map(|g| g.level)
        };
        assert_eq!(grade("t:0"), Some(AgentLevel::PayloadsOnly));
        assert_eq!(grade("t:1"), Some(AgentLevel::SelfDescribed));
        assert_eq!(grade("t:2"), Some(AgentLevel::ModelWritten));
        let r = a.results.iter().find(|r| r.obs.id == "t:2").unwrap();
        assert_eq!(r.agent.as_ref().unwrap().caps, [AgentCap::CaptureTimes]);
    }

    #[test]
    fn self_described_rules_exist() {
        let r = Rules::default_rules();
        for id in SELF_DESCRIBED {
            assert!(r.rule(id).is_some(), "{id}");
        }
    }

    #[test]
    fn levels_parse_by_code_and_name() {
        assert_eq!("L5".parse::<AgentLevel>(), Ok(AgentLevel::Documented));
        assert_eq!(
            "model-written".parse::<AgentLevel>(),
            Ok(AgentLevel::ModelWritten)
        );
        assert_eq!(
            "agent_likely".parse::<AgentLevel>(),
            Ok(AgentLevel::AgentLikely)
        );
        assert!("L9".parse::<AgentLevel>().is_err());
    }

    #[test]
    fn payloads_alone_are_l0() {
        let t0 = 1_791_000_000;
        let a = run(
            &[
                (
                    t0,
                    "https://shop.example/item?id=1%20UNION%20SELECT%201",
                    None,
                ),
                (
                    t0 + 40,
                    "https://shop.example/item?id=2%20UNION%20SELECT%202",
                    None,
                ),
            ],
            TsKind::Request,
        );
        let c = &a.clusters[0];
        assert_eq!(c.agent.level, AgentLevel::PayloadsOnly, "{:?}", c.agent);
    }

    #[test]
    fn residue_with_retries_after_errors_is_adaptive() {
        residue_run(20, AgentLevel::Adaptive);
        // Retries at tool pace: faster than a person reads the error.
        residue_run(1, AgentLevel::AgentLikely);
    }

    fn residue_run(gap: i64, want: AgentLevel) {
        let t0 = 1_791_000_000;
        let base = "https://r.jina.ai/https://records.agency.example/search?q=";
        let urls: Vec<(i64, String, Option<u16>)> = (0..4)
            .map(|i| {
                (
                    t0 + i * gap,
                    format!("{base}{i}%27%20OR%201=1--%20YOUR_API_KEY&page={i}&uqtag=resz"),
                    Some(if i < 3 { 500 } else { 200 }),
                )
            })
            .collect();
        let refs: Vec<(i64, &str, Option<u16>)> =
            urls.iter().map(|(t, u, s)| (*t, u.as_str(), *s)).collect();
        let a = run(&refs, TsKind::Request);
        let c = &a.clusters[0];
        let kinds: Vec<SignalKind> = c.agent.signals.iter().map(|s| s.kind).collect();
        assert!(kinds.contains(&SignalKind::Residue), "{:?}", c.agent);
        assert!(
            kinds.contains(&SignalKind::RetryAfterError),
            "{:?}",
            c.agent
        );
        assert_eq!(c.agent.level, want, "{:?}", c.agent);

        // The same records timed by archive captures stop at L2.
        let a = run(&refs, TsKind::Capture);
        let c = &a.clusters[0];
        assert_eq!(c.agent.level, AgentLevel::ModelWritten, "{:?}", c.agent);
        assert_eq!(c.agent.caps, vec![AgentCap::CaptureTimes]);
    }

    #[test]
    fn slow_working_hours_cap_at_l2() {
        // Four days, one request an hour from 10:00 to 15:00 UTC.
        let day0 = 1_790_985_600; // a UTC midnight
        let urls: Vec<(i64, String, Option<u16>)> = (0..24)
            .map(|i| {
                let ts = day0 + (i / 6) * 86_400 + (10 + i % 6) * 3600;
                (
                    ts,
                    format!("https://p.example/q{i}?k=YOUR_API_KEY&uqtag=zz9"),
                    None,
                )
            })
            .collect();
        let refs: Vec<(i64, &str, Option<u16>)> =
            urls.iter().map(|(t, u, s)| (*t, u.as_str(), *s)).collect();
        let a = run(&refs, TsKind::Request);
        let c = &a.clusters[0];
        assert_eq!(c.agent.caps, vec![AgentCap::HumanPace], "{:?}", c.agent);
        assert_eq!(c.agent.level, AgentLevel::ModelWritten);
        assert!(
            c.agent
                .counter
                .iter()
                .any(|s| s.kind == SignalKind::WorkingHours)
        );
    }
}
