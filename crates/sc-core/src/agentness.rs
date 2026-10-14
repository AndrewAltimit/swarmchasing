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
//!   lengths, stale knowledge or stale date tags (page-borne residue, which a
//!   broken page carries in its own links, is listed but never sets L2);
//! - **L3** adaptive: L2 plus behaviour that answers responses (a changed
//!   request after an error, a route escalation, a probe chain at model
//!   pace), read only from request or submit times;
//! - **L4** agent likely: L3 plus machine pace while adapting, or a pace or
//!   scale beyond one person (fixed fan-out, one target sent to several scan
//!   services within seconds, round the clock), or a machine fetch tool's
//!   habit (a `/robots.txt` request before every page, a client-side rate
//!   ceiling), with no working-hours rhythm against it;
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
use crate::swarm::client_key;
use crate::timing::{RhythmVerdict, TimeBasis};
use serde::{Deserialize, Serialize};

/// Agent-tag rules: an agent describing itself, like a vendor name. Every
/// other artifact rule of kind `agent_marker` is model-output residue.
pub const SELF_DESCRIBED: &[&str] = &["marker.uq_tags", "marker.test_tag", "marker.oai_tag"];

/// Residue rules a page carries in its own links. A front-end that fails to
/// render writes `/p/{{item.slug}}` into its hrefs, and every crawler,
/// preview bot and feed poller following them sends it, so the match shows
/// a link was followed, not who wrote it. Listed as page-borne residue, it
/// never sets L2 on its own.
pub const PAGE_BORNE: &[&str] = &["marker.template_unrendered"];

/// Self-identification rules that say where a URL came from, not who sent
/// it: an assistant's citation tag (`utm_source=chatgpt.com`) rides along
/// on every click and every copy of a cited link. Never self-description.
pub const NOT_SELF_DESCRIBED: &[&str] = &["marker.assistant_citation"];

/// The referral parameter a citing site writes its own name into. A vendor
/// name matched in its value is the citation, not the client naming itself.
const REFERRAL_PARAM: &str = "utm_source=";

/// Whether hit `h` is the client describing itself (L1).
fn self_described(h: &Hit) -> bool {
    let id = h.rule_id.as_str();
    if NOT_SELF_DESCRIBED.contains(&id) {
        return false;
    }
    let referral = h
        .matched
        .get(..REFERRAL_PARAM.len())
        .is_some_and(|p| p.eq_ignore_ascii_case(REFERRAL_PARAM));
    (h.kind == IndicatorKind::SelfId || SELF_DESCRIBED.contains(&id)) && !referral
}

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
    /// Listed beside the L2 signals; never sets the grade.
    PageResidue,
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
    PerFetchRobots,
    RateCeiling,
    // Counter-signals
    DeclaredTesting,
    Benchmark,
    ScannerPace,
    AutoSubmitter,
    WorkingHours,
    SpoofedIdentity,
}

impl SignalKind {
    /// Whether the signal can set its rung. Page-borne residue is listed
    /// under L2 but leaves the grade where the other signals put it.
    pub fn grades(self) -> bool {
        self != Self::PageResidue
    }

    /// The rung this signal supports; `None` for a counter-signal.
    pub fn level(self) -> Option<AgentLevel> {
        use SignalKind::*;
        Some(match self {
            SelfId | VerifiedPlatform => AgentLevel::SelfDescribed,
            Residue | PageResidue | Prose | FabricatedIds | CutLengths | StaleKnowledge
            | StaleDates => AgentLevel::ModelWritten,
            RetryAfterError | Escalation | ModelPaceChain => AgentLevel::Adaptive,
            MachinePace | FanOut | CrossService | RoundTheClock | PerFetchRobots | RateCeiling => {
                AgentLevel::AgentLikely
            }
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
            PageResidue => {
                "residue a broken page also carries in its links, such as an unrendered template (it never sets the grade alone: any client following the link sends it)"
            }
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
            PerFetchRobots => {
                "a /robots.txt request before every page, on the same host each time, as an uncached robots-respecting fetch tool sends"
            }
            RateCeiling => {
                "requests hitting one per-window ceiling again and again and never passing it, as a client-side rate limiter allows"
            }
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

/// The rule ids among `hits` that self-describe (L1), that are
/// model-output residue (L2) and that are page-borne residue.
struct Marks<'a> {
    tags: Vec<&'a str>,
    residue: Vec<&'a str>,
    page: Vec<&'a str>,
}

fn hit_marks(hits: &[Hit]) -> Marks<'_> {
    let mut m = Marks {
        tags: Vec::new(),
        residue: Vec::new(),
        page: Vec::new(),
    };
    for h in hits {
        let id = h.rule_id.as_str();
        let list = if self_described(h) {
            &mut m.tags
        } else if h.kind == IndicatorKind::SelfId {
            continue;
        } else if h.artifact && h.kind == IndicatorKind::AgentMarker {
            if PAGE_BORNE.contains(&id) {
                &mut m.page
            } else {
                &mut m.residue
            }
        } else {
            continue;
        };
        if !list.contains(&id) {
            list.push(id);
        }
    }
    m
}

/// Grade a flagged record that is in no cluster, from its own hits:
/// self-description (L1) and model-output residue (L2; page-borne residue is
/// listed and leaves the grade alone). One record shows no
/// pace, retries or rhythm, so it never reaches L3; an archive capture is
/// capped as a cluster of captures is.
pub fn assess_record(r: &ObsResult) -> AgentAssessment {
    let mut out = AgentAssessment::default();
    let Marks {
        tags,
        residue,
        page,
    } = hit_marks(&r.hits);
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
    push(SignalKind::PageResidue, &page);
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

/// Grade cluster `c`. `chains` and `escalations` are the analysis's; those
/// touching the cluster are read. `clients` indexes every record by client,
/// so the unflagged requests of the cluster's clients are read too.
pub fn assess(
    c: &Cluster,
    results: &[ObsResult],
    chains: &[Chain],
    escalations: &[Escalation],
    opts: &ChainOptions,
    clients: &ClientIndex,
    ao: &AgentnessOptions,
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
    let (mut tags, mut residue, mut page): (Vec<&str>, Vec<&str>, Vec<&str>) =
        (Vec::new(), Vec::new(), Vec::new());
    let (mut n_tag, mut n_res, mut n_page) = (0, 0, 0);
    fn add<'a>(all: &mut Vec<&'a str>, ids: Vec<&'a str>) {
        for id in ids {
            if !all.contains(&id) {
                all.push(id);
            }
        }
    }
    for &i in &c.members {
        let m = hit_marks(&results[i].hits);
        n_tag += usize::from(!m.tags.is_empty());
        n_res += usize::from(!m.residue.is_empty());
        n_page += usize::from(!m.page.is_empty());
        add(&mut tags, m.tags);
        add(&mut residue, m.residue);
        add(&mut page, m.page);
    }
    push(SignalKind::SelfId, n_tag, tags.join(", "));
    push(SignalKind::Residue, n_res, residue.join(", "));
    push(SignalKind::PageResidue, n_page, page.join(", "));

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
    // A machine fetch tool's habits, from the requests of the cluster's
    // clients in each run, unflagged ones included.
    let tools = client_habits(c, results, clients, ao);
    if let Some(r) = &tools.robots {
        push(SignalKind::PerFetchRobots, r.records, r.detail.clone());
    }
    if let Some(r) = &tools.ceiling {
        push(SignalKind::RateCeiling, r.records, r.detail.clone());
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
    let has = |l: AgentLevel| {
        out.signals
            .iter()
            .any(|s| s.kind.grades() && s.kind.level() == Some(l))
    };
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

/// Machine fetch-tool habit settings (`[agentness]` in the rules file).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct AgentnessOptions {
    /// Per-fetch robots: a page counts as preceded when a `/robots.txt`
    /// request on its host comes at most this long before it.
    pub robots_window_secs: i64,
    /// Pages one client needs in a run.
    pub robots_min_pages: usize,
    /// Share of its pages that must be preceded.
    pub robots_min_share: f64,
    /// Robots requests preceding pages on one host, on at least one host: a
    /// polite crawler reads robots.txt once per host.
    pub robots_min_repeats: usize,
    /// Kept when the chance of so many preceded pages, robots requests
    /// placed at random over the client's span, is at most this.
    pub robots_max_chance: f64,
    /// Rate ceiling: the sliding window a client-side limiter counts in.
    pub rate_window_secs: i64,
    /// The ceiling (most requests in one window) must be at least this.
    pub rate_min_cap: usize,
    /// Windows at the ceiling with the client pressing on after them: the
    /// next request comes within `rate_press_secs` of the window's end.
    pub rate_min_saturated: usize,
    pub rate_press_secs: i64,
    /// Permutations of the run's own gaps, continued to
    /// `rate_max_permutations` while none holds the ceiling as well.
    pub rate_permutations: usize,
    pub rate_max_permutations: usize,
    /// Kept when the share of permutations holding the ceiling as well is at
    /// most this.
    pub rate_max_chance: f64,
}

impl Default for AgentnessOptions {
    fn default() -> Self {
        Self {
            robots_window_secs: 2,
            robots_min_pages: 3,
            robots_min_share: 0.8,
            robots_min_repeats: 2,
            robots_max_chance: 0.01,
            rate_window_secs: 60,
            rate_min_cap: 5,
            rate_min_saturated: 3,
            rate_press_secs: 60,
            rate_permutations: 199,
            rate_max_permutations: 1999,
            rate_max_chance: 0.001,
        }
    }
}

/// The rule naming the Model Context Protocol reference fetch server's user
/// agent.
const MCP_FETCH_RULE: &str = "header.mcp_fetch_ua";

/// Requests read per client and run, earliest first.
const MAX_EVENTS: usize = 2000;

/// Every record in no cluster with a request or submit time and a known
/// client (user agent, network and header set, as runs and strands key it),
/// by client then time: how a cluster's clients' unflagged requests are
/// found. Records of other clusters are never read for this one.
#[derive(Debug, Default)]
pub struct ClientIndex {
    rows: Vec<(String, i64, usize)>,
}

impl ClientIndex {
    pub fn new(results: &[ObsResult]) -> Self {
        let mut rows: Vec<(String, i64, usize)> = results
            .iter()
            .enumerate()
            .filter(|(_, r)| {
                r.cluster.is_none() && r.obs.ts > 0 && crate::timing::request_like(r.obs.ts_kind)
            })
            .filter_map(|(i, r)| client_key(r).map(|k| (k, r.obs.ts, i)))
            .collect();
        crate::sort::sort(&mut rows);
        Self { rows }
    }

    /// Records of client `key` timed in `[from, to]`.
    fn span<'a>(&'a self, key: &'a str, from: i64, to: i64) -> impl Iterator<Item = usize> + 'a {
        let i = self
            .rows
            .partition_point(|x| (x.0.as_str(), x.1) < (key, from));
        self.rows[i..]
            .iter()
            .take_while(move |x| x.0 == key && x.1 <= to)
            .map(|x| x.2)
    }
}

/// One habit found, with the pages or requests it rests on.
#[derive(Debug, Clone, PartialEq)]
struct Habit {
    records: usize,
    chance: f64,
    detail: String,
}

#[derive(Debug, Default)]
struct Habits {
    robots: Option<Habit>,
    ceiling: Option<Habit>,
}

/// Keep the more unlikely of two findings, adding up their records.
fn merge(slot: &mut Option<Habit>, h: Habit) {
    match slot {
        Some(s) => {
            let records = s.records + h.records;
            if h.chance < s.chance {
                *s = h;
            }
            s.records = records;
        }
        None => *slot = Some(h),
    }
}

/// Per-fetch robots and the rate ceiling, over each run of `c` and each of
/// its clients there: the run's own members from that client and the
/// client's requests in no cluster (at most `MAX_EVENTS` of those, earliest
/// first). A habit counts only when some of what it rests on is the
/// cluster's own: a preceded page, or a request in a window at the ceiling.
/// Records without a client feed the ceiling only, as one group of the
/// run's own members.
fn client_habits(
    c: &Cluster,
    results: &[ObsResult],
    clients: &ClientIndex,
    ao: &AgentnessOptions,
) -> Habits {
    let mut out = Habits::default();
    for (n, span) in c.runs.iter().enumerate() {
        let mut keys: Vec<(String, usize)> = Vec::new();
        let mut anonymous: Vec<usize> = Vec::new();
        for &m in &c.members {
            let r = &results[m];
            if r.obs.ts < span.start
                || r.obs.ts > span.end
                || r.obs.ts <= 0
                || !crate::timing::request_like(r.obs.ts_kind)
            {
                continue;
            }
            match client_key(r) {
                Some(k) => keys.push((k, m)),
                None => anonymous.push(m),
            }
        }
        crate::sort::sort(&mut keys);
        let label = format!("{}#{}", c.key, n + 1);
        for g in keys.chunk_by(|a, b| a.0 == b.0) {
            let k = g[0].0.as_str();
            let own: Vec<usize> = g.iter().map(|x| x.1).collect();
            let from = span.start - ao.robots_window_secs.max(0);
            let mut recs: Vec<usize> = clients.span(k, from, span.end).take(MAX_EVENTS).collect();
            recs.extend(&own);
            crate::sort::by_key(&mut recs, |&i| (results[i].obs.ts, i));
            if let Some(h) = per_fetch_robots(&recs, &own, results, ao) {
                merge(&mut out.robots, h);
            }
            recs.retain(|&i| results[i].obs.ts >= span.start);
            if let Some(h) = rate_ceiling(&recs, &own, results, ao, &[&label, k]) {
                merge(&mut out.ceiling, h);
            }
        }
        anonymous.truncate(MAX_EVENTS);
        if let Some(h) = rate_ceiling(&anonymous, &anonymous, results, ao, &[&label, ""]) {
            merge(&mut out.ceiling, h);
        }
    }
    out
}

/// One client's requests in a run: whether nearly every page request comes
/// right after a `/robots.txt` request on its host, robots.txt read again
/// for each page. Chance: the robots requests placed at random over the
/// client's span, as a Poisson-binomial tail over its pages. At least one
/// preceded page must be in `own`, the cluster's members.
fn per_fetch_robots(
    recs: &[usize],
    own: &[usize],
    results: &[ObsResult],
    ao: &AgentnessOptions,
) -> Option<Habit> {
    let w = ao.robots_window_secs.max(0);
    let mut robots: Vec<(String, i64, bool)> = Vec::new();
    let mut pages: Vec<(String, i64, bool)> = Vec::new();
    for &i in recs {
        let o = &results[i].obs;
        let Some(u) = crate::weburl::WebUrl::parse(&o.url) else {
            continue;
        };
        let Some(host) = u.host.clone() else {
            continue;
        };
        if u.path.eq_ignore_ascii_case("/robots.txt") {
            robots.push((host, o.ts, false));
        } else {
            pages.push((host, o.ts, own.contains(&i)));
        }
    }
    if pages.len() < ao.robots_min_pages.max(1) || robots.is_empty() {
        return None;
    }
    // Each page takes the latest unused robots request on its host within
    // the window before it.
    let (mut preceded, mut preceded_own) = (0usize, 0usize);
    let mut per_host: Vec<(String, usize)> = Vec::new();
    for (h, t, mine) in &pages {
        let pick = robots
            .iter()
            .enumerate()
            .filter(|(_, r)| !r.2 && r.0 == *h && r.1 <= *t && *t - r.1 <= w)
            .max_by_key(|(_, r)| r.1)
            .map(|(j, _)| j);
        if let Some(j) = pick {
            robots[j].2 = true;
            preceded += 1;
            preceded_own += usize::from(*mine);
            match per_host.iter_mut().find(|x| x.0 == *h) {
                Some(x) => x.1 += 1,
                None => per_host.push((h.clone(), 1)),
            }
        }
    }
    let repeats = per_host.iter().map(|x| x.1).max().unwrap_or(0);
    let n = pages.len();
    if (preceded as f64) < ao.robots_min_share * n as f64
        || repeats < ao.robots_min_repeats.max(1)
        || preceded_own == 0
    {
        return None;
    }
    let first = pages
        .iter()
        .map(|p| p.1)
        .chain(robots.iter().map(|r| r.1))
        .min()?;
    let last = pages
        .iter()
        .map(|p| p.1)
        .chain(robots.iter().map(|r| r.1))
        .max()?;
    let s = (last - first).max(1) as f64;
    let ps: Vec<f64> = pages
        .iter()
        .map(|(h, _, _)| {
            let r = robots.iter().filter(|x| x.0 == *h).count() as f64;
            (r * (w + 1) as f64 / s).min(1.0)
        })
        .collect();
    let chance = crate::chance::at_least(&ps, preceded);
    if chance > ao.robots_max_chance {
        return None;
    }
    let mcp = recs
        .iter()
        .any(|&i| results[i].hits.iter().any(|h| h.rule_id == MCP_FETCH_RULE));
    let mut detail = format!(
        "{preceded} of {n} page requests each came within {w} s after a /robots.txt request on the same host, {repeats} on one host (chance {chance:.1e}): an uncached robots-respecting fetch tool"
    );
    if mcp {
        detail.push_str(
            "; its user agent is the Model Context Protocol reference fetch server's, which reads robots.txt before every page it fetches autonomously",
        );
    }
    Some(Habit {
        records: preceded,
        chance,
        detail,
    })
}

/// The most requests in any window of `w` seconds, `[t, t + w)`.
fn ceiling_of(ts: &[i64], w: i64) -> usize {
    let mut j = 0;
    let mut most = 0;
    for i in 0..ts.len() {
        while j < ts.len() && ts[j] < ts[i] + w {
            j += 1;
        }
        most = most.max(j - i);
    }
    most
}

/// Windows holding `cap` requests that the client pressed on after (its
/// next request within `press` of the window's end), counted without
/// overlap.
fn saturated(ts: &[i64], w: i64, cap: usize, press: i64) -> usize {
    saturated_windows(ts, w, cap, press).len()
}

/// The windows [`saturated`] counts, as index ranges into `ts`.
fn saturated_windows(ts: &[i64], w: i64, cap: usize, press: i64) -> Vec<std::ops::Range<usize>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < ts.len() {
        let j = ts.partition_point(|&t| t < ts[i] + w);
        if j - i >= cap && j < ts.len() && ts[j] < ts[i] + w + press {
            out.push(i..j);
            i = j;
        } else {
            i += 1;
        }
    }
    out
}

/// A run's requests that reach one ceiling per window again and again, the
/// client pressing on each time, and never pass it, as a client-side rate
/// limiter allows. Chance: the run's own gaps permuted (seeded from `seed`),
/// the share holding the ceiling as well. A run that got a 429 response was
/// limited by the server, not itself, and is not read. At least one window
/// at the ceiling must hold a request in `own`, the cluster's members.
fn rate_ceiling(
    recs: &[usize],
    own: &[usize],
    results: &[ObsResult],
    ao: &AgentnessOptions,
    seed: &[&str],
) -> Option<Habit> {
    let w = ao.rate_window_secs.max(1);
    let cap0 = ao.rate_min_cap.max(2);
    let k0 = ao.rate_min_saturated.max(1);
    if recs.len() < cap0 * k0 + 1 || recs.iter().any(|&i| results[i].obs.status == Some(429)) {
        return None;
    }
    let mut timed: Vec<(i64, bool)> = recs
        .iter()
        .map(|&i| (results[i].obs.ts, own.contains(&i)))
        .collect();
    crate::sort::sort(&mut timed);
    let ts: Vec<i64> = timed.iter().map(|x| x.0).collect();
    let cap = ceiling_of(&ts, w);
    let press = ao.rate_press_secs.max(0);
    let windows = saturated_windows(&ts, w, cap, press);
    let k = windows.len();
    let own_window = windows.iter().any(|r| timed[r.clone()].iter().any(|x| x.1));
    if cap < cap0 || k < k0 || !own_window {
        return None;
    }
    let mut gaps: Vec<i64> = ts.windows(2).map(|x| x[1] - x[0]).collect();
    let mut rng = crate::chance::Mix(crate::chance::seed(seed));
    let base = ao.rate_permutations.max(1);
    let most = ao.rate_max_permutations.max(base);
    let (mut ge, mut perms) = (0usize, 0usize);
    let mut shuffled = Vec::with_capacity(ts.len());
    while perms < base || (ge == 0 && perms < most) {
        perms += 1;
        rng.shuffle(&mut gaps);
        shuffled.clear();
        shuffled.push(ts[0]);
        for &g in &gaps {
            shuffled.push(shuffled[shuffled.len() - 1] + g);
        }
        ge += usize::from(
            ceiling_of(&shuffled, w) <= cap && saturated(&shuffled, w, cap, press) >= k,
        );
    }
    let chance = (1 + ge) as f64 / (1 + perms) as f64;
    if chance > ao.rate_max_chance {
        return None;
    }
    Some(Habit {
        records: ts.len(),
        chance,
        detail: format!(
            "{k} windows of {w} s held exactly {cap} requests with more right after, and none held {} (chance {chance:.1e} under {perms} permutations of its own gaps): a client-side rate limiter",
            cap + 1
        ),
    })
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
    fn an_assistant_citation_tag_is_not_self_description() {
        let t0 = 1_791_000_000;
        let a = run(
            &[
                (
                    t0,
                    "https://records.agency.example/search?q=1%27%20OR%20%271%27=%271&utm_source=chatgpt.com",
                    None,
                ),
                (
                    t0 + 9_000,
                    "https://records.agency.example/permits?id=4471&utm_source=chatgpt.com&uqtag=cite7a",
                    None,
                ),
            ],
            TsKind::Capture,
        );
        let g = |i: usize| a.results[i].agent.clone().expect("flagged");
        let fired = |i: usize, id: &str| a.results[i].hits.iter().any(|h| h.rule_id == id);
        // The tag and the vendor name inside it fire, and neither describes
        // the client.
        assert!(fired(0, "marker.assistant_citation") && fired(0, "selfid.vendor_name"));
        assert_eq!(g(0).level, AgentLevel::PayloadsOnly, "{:?}", g(0));
        assert!(g(0).signals.is_empty(), "{:?}", g(0));
        // A run tag beside it still does, alone.
        assert_eq!(g(1).level, AgentLevel::SelfDescribed, "{:?}", g(1));
        assert_eq!(g(1).signals[0].detail, "marker.uq_tags", "{:?}", g(1));
        let r = Rules::default_rules();
        for id in NOT_SELF_DESCRIBED {
            assert!(r.rule(id).is_some(), "{id}");
        }
    }

    #[test]
    fn page_borne_rules_are_residue_rules() {
        let r = Rules::default_rules();
        for id in PAGE_BORNE {
            let rule = r.rule(id).unwrap_or_else(|| panic!("{id}"));
            assert!(
                rule.artifact && rule.kind == IndicatorKind::AgentMarker,
                "{id}"
            );
            assert!(!SELF_DESCRIBED.contains(id), "{id}");
        }
    }

    /// Four requests to one path through a relay, the first three answered
    /// with errors and changed after each, carrying `extra` in the path.
    fn retried(extra: &str) -> crate::Analysis {
        let t0 = 1_791_000_000;
        let base =
            "https://r.jina.ai/https://records.agency.example/p/%7B%7Bitem.slug%7D%7D/search";
        let urls: Vec<(i64, String, Option<u16>)> = (0..4)
            .map(|i| {
                (
                    t0 + i * 20,
                    format!("{base}?q={i}%27%20OR%201=1--{extra}&page={i}"),
                    Some(if i < 3 { 500 } else { 200 }),
                )
            })
            .collect();
        let refs: Vec<(i64, &str, Option<u16>)> =
            urls.iter().map(|(t, u, s)| (*t, u.as_str(), *s)).collect();
        run(&refs, TsKind::Request)
    }

    #[test]
    fn page_borne_residue_alone_sets_no_grade() {
        // An unrendered front-end template is in the page's own links:
        // listed, but it does not make the requests model-written, so the
        // retries after errors have no L2 to stand on.
        let a = retried("");
        let c = &a.clusters[0];
        let kinds: Vec<SignalKind> = c.agent.signals.iter().map(|s| s.kind).collect();
        assert!(kinds.contains(&SignalKind::PageResidue), "{:?}", c.agent);
        assert!(!kinds.contains(&SignalKind::Residue), "{:?}", c.agent);
        assert!(
            kinds.contains(&SignalKind::RetryAfterError),
            "{:?}",
            c.agent
        );
        assert_eq!(c.agent.level, AgentLevel::PayloadsOnly, "{:?}", c.agent);
        assert!(!SignalKind::PageResidue.grades());

        // Beside model-output residue the same cluster grades as before.
        let a = retried("%20YOUR_API_KEY");
        let c = &a.clusters[0];
        let kinds: Vec<SignalKind> = c.agent.signals.iter().map(|s| s.kind).collect();
        assert!(kinds.contains(&SignalKind::PageResidue), "{:?}", c.agent);
        assert!(kinds.contains(&SignalKind::Residue), "{:?}", c.agent);
        assert_eq!(c.agent.level, AgentLevel::Adaptive, "{:?}", c.agent);
    }

    #[test]
    fn an_unclustered_page_borne_record_stays_l0() {
        let a = run(
            &[(
                1_791_000_000,
                "https://www.shop.example/product/%7B%7Bitem.slug%7D%7D",
                None,
            )],
            TsKind::Capture,
        );
        let g = a.results[0].agent.as_ref().expect("flagged");
        assert_eq!(g.level, AgentLevel::PayloadsOnly, "{g:?}");
        assert_eq!(g.signals.len(), 1, "{g:?}");
        assert_eq!(g.signals[0].kind, SignalKind::PageResidue);
        assert_eq!(g.signals[0].detail, "marker.template_unrendered");
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

    /// One client's requests: `(ts, url, status)`.
    fn client(reqs: &[(i64, String, Option<u16>)], ua: &str) -> crate::Analysis {
        let obs = reqs
            .iter()
            .enumerate()
            .map(|(i, (ts, url, status))| Observation {
                id: format!("q:{i}"),
                ts: *ts,
                ts_kind: TsKind::Request,
                url: url.clone(),
                status: *status,
                user_agent: Some(ua.into()),
                asn: Some(16509),
                ..Default::default()
            })
            .collect();
        crate::analyze(obs, &Rules::default_rules())
    }

    fn signal(a: &crate::Analysis, kind: SignalKind) -> Option<AgentSignal> {
        assert_eq!(a.clusters.len(), 1, "{:?}", a.clusters);
        let c = &a.clusters[0];
        c.agent.signals.iter().find(|s| s.kind == kind).cloned()
    }

    const T: i64 = 1_791_000_000 + 1234;
    const GAPS: [i64; 9] = [23, 41, 17, 35, 29, 52, 19, 44, 31];

    /// Tagged pages on two hosts at model pace; `robots(i, host)` says
    /// whether page `i` is preceded by a robots.txt request on its host.
    fn fetches(robots: &dyn Fn(usize, usize) -> bool) -> Vec<(i64, String, Option<u16>)> {
        let mut out = Vec::new();
        let mut t = T;
        for (i, g) in GAPS.iter().enumerate() {
            t += g;
            let h = i % 2;
            if robots(i, h) {
                out.push((t - 1, format!("https://site{h}.example/robots.txt"), None));
            }
            out.push((
                t,
                format!("https://site{h}.example/docs/{i}?uqtag=fetch7"),
                Some(200),
            ));
        }
        out
    }

    #[test]
    fn robots_before_every_page_is_an_uncached_fetch_tool() {
        let a = client(&fetches(&|_, _| true), "python-httpx/0.27");
        let s = signal(&a, SignalKind::PerFetchRobots).expect("per-fetch robots");
        assert_eq!(s.records, GAPS.len(), "{s:?}");
        assert!(
            s.detail.contains("uncached robots-respecting fetch tool"),
            "{s:?}"
        );
        assert!(!s.detail.contains("Model Context Protocol"), "{s:?}");
        assert_eq!(s.kind.level(), Some(AgentLevel::AgentLikely));
        // The reference fetch server's user agent names it.
        let a = client(
            &fetches(&|_, _| true),
            "ModelContextProtocol/1.0 (Autonomous; +https://github.com/modelcontextprotocol/servers)",
        );
        let s = signal(&a, SignalKind::PerFetchRobots).expect("per-fetch robots");
        assert!(s.detail.contains("Model Context Protocol"), "{s:?}");
    }

    #[test]
    fn a_crawler_reading_robots_once_per_host_is_not_a_fetch_tool() {
        // Once per host, before its first page.
        let a = client(&fetches(&|i, _| i < 2), "python-httpx/0.27");
        assert_eq!(signal(&a, SignalKind::PerFetchRobots), None);
        // One page per host, robots.txt first: polite, never repeated.
        let mut t = T;
        let reqs: Vec<(i64, String, Option<u16>)> = GAPS
            .iter()
            .enumerate()
            .flat_map(|(i, g)| {
                t += g;
                [
                    (t - 1, format!("https://h{i}.example/robots.txt"), None),
                    (t, format!("https://h{i}.example/?uqtag=fetch7"), Some(200)),
                ]
            })
            .collect();
        let a = client(&reqs, "python-httpx/0.27");
        assert_eq!(signal(&a, SignalKind::PerFetchRobots), None);
    }

    /// The cluster holding the record with URL `url`.
    fn cluster_of<'a>(a: &'a crate::Analysis, url: &str) -> &'a crate::analyze::Cluster {
        let r = a.results.iter().find(|r| r.obs.url == url).unwrap();
        &a.clusters[r.cluster.expect("clustered")]
    }

    #[test]
    fn another_clusters_habit_is_not_inherited() {
        // A fetch tool's tagged pages form one cluster; two probes with
        // another tag, from the same user agent and network in the same
        // minutes, form another and must not read the first one's pages.
        let mut reqs = fetches(&|_, _| true);
        let probes = [
            "https://shop9.example/item?id=1%20UNION%20SELECT%201&uqtag=other9",
            "https://shop9.example/item?id=2%20UNION%20SELECT%202&uqtag=other9",
        ];
        reqs.push((T + 30, probes[0].into(), Some(200)));
        reqs.push((T + 290, probes[1].into(), Some(200)));
        let a = client(&reqs, "python-requests/2.31.0");
        let fetch = cluster_of(&a, &reqs[1].1);
        let probe = cluster_of(&a, probes[0]);
        assert_ne!(fetch.id, probe.id);
        let has = |c: &crate::analyze::Cluster| {
            c.agent
                .signals
                .iter()
                .any(|s| s.kind == SignalKind::PerFetchRobots)
        };
        assert!(has(fetch), "{:?}", fetch.agent);
        assert!(!has(probe), "{:?}", probe.agent);
    }

    #[test]
    fn a_habit_must_rest_on_the_clusters_own_requests() {
        // The client's unflagged pages each follow a robots.txt request, but
        // none of the cluster's own requests does.
        let mut reqs: Vec<(i64, String, Option<u16>)> = fetches(&|_, _| true)
            .into_iter()
            .map(|(t, u, s)| (t, u.replace("?uqtag=fetch7", ""), s))
            .collect();
        reqs.push((
            T + 20,
            "https://shop9.example/item?id=1%20UNION%20SELECT%201&uqtag=own3".into(),
            Some(200),
        ));
        reqs.push((
            T + 300,
            "https://shop9.example/item?id=2%20UNION%20SELECT%202&uqtag=own3".into(),
            Some(200),
        ));
        let a = client(&reqs, "python-httpx/0.27");
        assert_eq!(signal(&a, SignalKind::PerFetchRobots), None);
    }

    /// Requests a client wants at `want` gaps, held by a limiter of `cap`
    /// per 60 s.
    fn limited(cap: usize, n: usize, status: Option<u16>) -> Vec<(i64, String, Option<u16>)> {
        let want = [2, 4, 3, 6, 2, 5, 3, 2, 4, 7, 3];
        let mut ts: Vec<i64> = Vec::new();
        let mut t = T;
        for i in 0..n {
            t += want[i % want.len()];
            if i >= cap {
                t = t.max(ts[i - cap] + 60);
            }
            ts.push(t);
        }
        ts.iter()
            .enumerate()
            .map(|(i, &t)| {
                (
                    t,
                    format!("https://docs{}.example/p/{i}?uqtag=lim3", i % 4),
                    status,
                )
            })
            .collect()
    }

    #[test]
    fn a_client_side_rate_limit_is_a_ceiling() {
        let a = client(&limited(10, 60, Some(200)), "GeminiCLI/0.1");
        let s = signal(&a, SignalKind::RateCeiling).expect("rate ceiling");
        assert!(s.detail.contains("exactly 10 requests"), "{s:?}");
        assert!(s.detail.contains("none held 11"), "{s:?}");
        assert_eq!(s.kind.level(), Some(AgentLevel::AgentLikely));
    }

    #[test]
    fn server_429s_and_cron_batches_are_no_ceiling() {
        // The same shape after the server answered 429: its limit, not the
        // client's.
        let a = client(&limited(10, 60, Some(429)), "GeminiCLI/0.1");
        assert_eq!(signal(&a, SignalKind::RateCeiling), None);
        // A job sending five requests every five minutes: five per window
        // every time, and nothing pressing after.
        let reqs: Vec<(i64, String, Option<u16>)> = (0..12)
            .flat_map(|b| {
                (0..5).map(move |i| {
                    (
                        T + b * 300 + i * 2,
                        format!("https://api{i}.example/v1/x?uqtag=cron1"),
                        Some(200),
                    )
                })
            })
            .collect();
        let a = client(&reqs, "curl/8.5");
        assert_eq!(signal(&a, SignalKind::RateCeiling), None);
        // A steady request every six seconds: its permutations are itself.
        let reqs: Vec<(i64, String, Option<u16>)> = (0..60)
            .map(|i| {
                (
                    T + i * 6,
                    format!("https://api.example/v1/{i}?uqtag=steady1"),
                    Some(200),
                )
            })
            .collect();
        let a = client(&reqs, "curl/8.5");
        assert_eq!(signal(&a, SignalKind::RateCeiling), None);
    }

    #[test]
    fn ceiling_windows_are_counted_without_overlap() {
        let ts = [0, 1, 2, 60, 61, 62, 120, 121, 122, 500];
        assert_eq!(ceiling_of(&ts, 60), 3);
        // Three full windows, the last with nothing right after.
        assert_eq!(saturated(&ts, 60, 3, 60), 2);
    }
}
