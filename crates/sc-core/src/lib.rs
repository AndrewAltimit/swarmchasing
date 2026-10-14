//! `sc-core`: platform-independent swarmchasing analysis.
//!
//! No I/O, no clock, no threads, so the same code runs in the CLI, on CI, and
//! in the browser via `sc-wasm`.

pub mod agentness;
pub mod analyze;
pub mod asn;
pub mod attribution;
pub mod biclique;
pub mod bursts;
pub mod canary;
pub mod capture;
pub mod chains;
pub mod chance;
pub mod coactivity;
pub mod community;
pub mod cotarget;
pub mod crossservice;
pub mod crosswalk;
pub mod declared;
pub mod dialect;
pub mod endpoints;
pub mod escalation;
pub mod eval;
pub mod extract;
pub mod fanout;
pub mod fingerprint;
pub mod fleet_track;
pub mod fleets;
pub mod generator;
pub mod identity;
pub mod ingest;
pub mod knowledge;
pub mod model;
pub mod notice;
pub mod paths;
pub mod plant;
pub mod platform;
pub mod prose;
pub mod recurrence;
pub mod redact;
pub mod report;
pub mod rules;
pub mod scaffold;
pub mod scope;
pub mod securitytxt;
pub mod sightings;
pub mod sort;
pub mod stamp;
pub mod swarm;
pub mod timing;
pub mod ua_platform;
pub mod urlquery;
mod weburl;

pub use agentness::{AgentAssessment, AgentLevel, AgentSignal, GradeDecision};
pub use analyze::{Analysis, Cluster, KnowledgeHints, ObsResult, Origin, analyze, is_context_kind};
pub use attribution::{AttributionLabel, Claim, Evidence, Role, Tag, attribute};
pub use bursts::{ArchiveBurst, archive_bursts};
pub use chains::{Chain, Pace};
pub use crossservice::CrossService;
pub use dialect::{CutLengths, Dialect, DialectPair};
pub use endpoints::{Activity, EndpointOptions, EndpointView, endpoints};
pub use escalation::{Escalation, Route};
pub use eval::summary::{Summary, summarize};
pub use eval::{EvalReport, Label, LabelSet, evaluate, parse_labels};
pub use extract::{
    Extracted, Layer, defang, defang_host, extract, intermediary_hosts, is_intermediary_host,
    unwrap_layers,
};
pub use fanout::FanOut;
pub use fingerprint::{Encoding, HeaderSet, encoding, header_set};
pub use fleets::{CandidateFleet, Family, PairEvidence, SoftLink, SoftLinkKind};
pub use identity::{Catalog, ClusterIdentity, IdentityClass, IdentityData, RecordIdentity};
pub use ingest::{FieldMap, Format, Parsed, parse_input};
pub use model::{
    Hit, IndicatorKind, LinkFeature, OPERATOR_SOURCE, Observation, Provenance, SUBMISSION_SOURCE,
    SourceKind, Tactic, Tier, TsKind, fmt_ts, parse_ts, top_counts,
};
pub use paths::{FabricatedId, PathStats, SharedInvention, fabricated_ids};
pub use plant::{Corroboration, PlantSignal, PlantSignalKind};
pub use recurrence::{ClusterRun, RecurrenceOptions, Rerun, TargetRun, cluster_reruns, reruns};
pub use redact::{redact_observation, redact_url};
pub use report::{Audience, Notice, ReportOptions, Reported, render_markdown, render_notice};
pub use rules::{DEFAULT_RULES, RuleSet, Rules};
pub use securitytxt::{SecurityTxt, parse_security_txt};
pub use stamp::{EvalSnapshot, Stamp, StampCluster};
pub use swarm::{EdgeStrength, RunRef, SwarmEdge, SwarmEdgeKind, SwarmOptions};
pub use timing::{SharedPause, SharedPauseOptions, StaleDates, shared_pauses, stale_dates};
