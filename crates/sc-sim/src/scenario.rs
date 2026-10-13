//! Scenario files: who sends records, when, and how they relate.
//!
//! A scenario file is TOML with one `[[scenario]]` table per scenario, each
//! with `[[scenario.actor]]` tables. Every setting has a default, so a
//! scenario can be a name and one actor.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScenarioFile {
    #[serde(default)]
    pub scenario: Vec<Scenario>,
}

impl ScenarioFile {
    pub fn parse(text: &str) -> Result<Self, String> {
        let f: Self = toml::from_str(text).map_err(|e| e.to_string())?;
        for s in &f.scenario {
            s.check()?;
        }
        Ok(f)
    }
}

/// What the records' timestamps are the time of.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Basis {
    /// An operator's access log: request times, client address and agent.
    #[default]
    Request,
    /// A scan service: submit times, no client.
    Submit,
    /// An archive index: capture times, no client.
    Capture,
}

impl Basis {
    pub fn source(self) -> &'static str {
        match self {
            Self::Request => "access_log",
            Self::Submit => "urlquery",
            Self::Capture => "wayback",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scenario {
    pub name: String,
    #[serde(default = "one")]
    pub seed: u64,
    /// Runs of the scenario, with seeds `seed`, `seed + 1`, ...
    #[serde(default = "one_usize")]
    pub seeds: usize,
    #[serde(default)]
    pub basis: Basis,
    /// The scenario's start, RFC 3339.
    #[serde(default = "default_start")]
    pub start: String,
    /// The span background actors spread over, in hours.
    #[serde(default = "default_span")]
    pub span_hours: u32,
    /// A null scenario: background and single agents only, no two runs
    /// related, so every edge, soft link and candidate fleet drawn between
    /// different runs is false. The gate holds a ceiling on them.
    #[serde(default)]
    pub null: bool,
    #[serde(default)]
    pub actor: Vec<Actor>,
}

fn one() -> u64 {
    1
}
fn one_usize() -> usize {
    1
}
fn default_start() -> String {
    "2026-03-02T08:00:00Z".into()
}
fn default_span() -> u32 {
    48
}

impl Scenario {
    fn check(&self) -> Result<(), String> {
        if sc_core::parse_ts(&self.start).is_none() {
            return Err(format!("{}: start is not a time", self.name));
        }
        if self.actor.is_empty() {
            return Err(format!("{}: no actor", self.name));
        }
        if self.null
            && let Some(a) = self.actor.iter().find(|a| a.kind.relates())
        {
            return Err(format!(
                "{}: a null scenario relates no runs, but has a {:?} actor",
                self.name, a.kind
            ));
        }
        Ok(())
    }
}

/// How fast a client sends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Pace {
    /// Under 2 seconds between requests.
    Tool,
    /// 2 seconds to 2 minutes: a model choosing each request.
    #[default]
    Model,
    /// Minutes: a person.
    Human,
}

impl Pace {
    /// Gap bounds in seconds, drawn log-uniform.
    pub fn bounds(self) -> (f64, f64) {
        match self {
            Self::Tool => (0.3, 1.6),
            Self::Model => (4.0, 90.0),
            Self::Human => (150.0, 900.0),
        }
    }
}

/// How the agents of a swarm relate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Every agent writes to one callback inbox (S1).
    Sink,
    /// One dispatcher sends each step to every agent: their requests line up
    /// step by step at one offset (S3).
    Sync,
    /// The first agent reads hosts, the rest attack the same hosts after (S4).
    Roles,
    /// Agents split one host family between them and start together (S5).
    Shard,
    /// The first agent names a gist in its requests; the rest fetch it
    /// within the hour, then work their own hosts (S2).
    Handoff,
    /// The first agent is a planner sending a request at irregular
    /// dispatches, twenty times its pace apart (80 s to 30 min at model pace);
    /// each other agent sends one 40 to 85 seconds after each dispatch
    /// (co-activity).
    Dispatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// One agent run.
    Agent,
    /// Several agents of one operator that interact (`modes`).
    Swarm,
    /// Several agents on one scaffold, each with its own inbox and tags,
    /// days apart: one operator, no interaction.
    Fleet,
    /// One client splitting a host list into runs: one operator, one client.
    Scheduler,
    /// People reading pages through relays.
    RelayReaders,
    /// A mail gateway submitting the links it sees to scan services.
    MailGateway,
    /// A scheduled job, starting and pausing on the clock hour.
    Cron,
    /// A person running a conventional scanner (tool pace, no change after
    /// errors).
    Pentester,
    /// A person pasting a chatbot's payloads (human pace, retries).
    ChatbotPaster,
    /// Benign crawlers.
    Crawler,
    /// Records copying another actor's identifiers from a different client,
    /// as someone planting records would; with `copy_timing`, its request
    /// times as well.
    Planter,
    /// Agents of another operator whose requests copy the scaffolds of the
    /// fleets named in `bridges`, with their own tags: one run that looks
    /// like two fleets at once.
    Mimic,
    /// Agents that change route after each request goes unanswered: the
    /// target directly, then the same request through a relay 11 to 25
    /// minutes later (past the linking window, within the escalation
    /// window), each route a separate tool with its own run tag, so the
    /// steps fall in separate clusters of one run.
    Escalator,
    /// Several agents of one operator working one target list in the same
    /// hours, each 15 to 20 minutes after the last, in its own order, with
    /// its own client, inbox, tags and habits: one operator, no
    /// interaction.
    TargetList,
    /// Unrelated agents sent to one family of hosts within a few hours, as
    /// a news story or a disclosed flaw sends them: each its own operator.
    NewsSpike,
    /// One unrelated agent working the target lists of the actors it
    /// `bridges` (by index) in their hours: a cluster tied to two fleets.
    Hub,
}

impl Kind {
    /// Its runs share a swarm, an operator or copied identifiers with
    /// other runs.
    pub fn relates(self) -> bool {
        matches!(
            self,
            Self::Swarm
                | Self::Fleet
                | Self::Scheduler
                | Self::Planter
                | Self::Mimic
                | Self::TargetList
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Actor {
    pub kind: Kind,
    /// Agents in a swarm or fleet, runs of a scheduler, clients of a
    /// background actor.
    #[serde(default = "one_usize")]
    pub agents: usize,
    /// Records per agent or client.
    #[serde(default = "default_records")]
    pub records: usize,
    /// Distinct target hosts per agent.
    #[serde(default = "default_hosts")]
    pub hosts: usize,
    #[serde(default)]
    pub pace: Option<Pace>,
    /// Swarm modes.
    #[serde(default)]
    pub modes: Vec<Mode>,
    /// Share of requests answered with an error and retried with a change.
    #[serde(default)]
    pub retry: f64,
    /// Agents put a run tag (`uqtag`) on every request, as many do.
    #[serde(default = "yes")]
    pub tag: bool,
    /// Hours after the scenario start the actor begins.
    #[serde(default)]
    pub offset_hours: f64,
    /// Move the start to a seeded 7 to 53 minutes past its hour, so the
    /// actor's runs do not begin on a clock hour.
    #[serde(default)]
    pub off_hour: bool,
    /// Share of each use's templates a run draws from: a seeded subset per
    /// swarm or fleet, else per run, so unrelated actors do not all copy one
    /// small set of records and share its habits. 1 is the whole palette.
    #[serde(default = "whole")]
    pub palette_share: f64,
    /// For a planter: the actor (by index) whose identifiers it copies.
    #[serde(default)]
    pub copies: Option<usize>,
    /// For a planter: replay the copied actor's first run's request times,
    /// a few seconds later, as well as its tags and inbox.
    #[serde(default)]
    pub copy_timing: bool,
    /// For a mimic: the fleets (by actor index) whose scaffolds it sends.
    /// For a hub: the target-list actors (by index) whose hosts it works.
    #[serde(default)]
    pub bridges: Vec<usize>,
    /// For a fleet: hours between one agent's start and the next (26 by
    /// default), so a fleet can be spread over weeks.
    #[serde(default)]
    pub interval_hours: Option<f64>,
    /// For a fleet: agents from this index on run an upgraded harness,
    /// another parameter set and one template changed.
    #[serde(default)]
    pub upgrade_at: Option<usize>,
    /// For a synchronised swarm: each agent's request leaves up to this many
    /// seconds after its dispatch (2 by default). Beyond the lockstep
    /// tolerance it is a loose swarm.
    #[serde(default)]
    pub jitter_secs: Option<i64>,
    /// For single agents and background actors: their runs start within
    /// this many hours of the actor's start instead of over the scenario's
    /// span, as when news sends many unrelated clients to one target.
    #[serde(default)]
    pub window_hours: Option<f64>,
    /// For single agents: every agent draws its hosts from one shared host
    /// family of three times `hosts`, as unrelated clients on one popular
    /// target do.
    #[serde(default)]
    pub same_family: bool,
}

fn default_records() -> usize {
    8
}
fn default_hosts() -> usize {
    4
}
fn yes() -> bool {
    true
}
fn whole() -> f64 {
    1.0
}
