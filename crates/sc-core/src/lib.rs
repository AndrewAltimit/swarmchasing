//! `sc-core`: platform-independent swarmchasing analysis.
//!
//! No I/O, no clock, no threads, so the same code runs in the CLI, on CI, and
//! in the browser via `sc-wasm`.

pub mod analyze;
pub mod attribution;
pub mod bursts;
pub mod capture;
pub mod chains;
pub mod dialect;
pub mod endpoints;
pub mod eval;
pub mod extract;
pub mod fanout;
pub mod fingerprint;
pub mod ingest;
pub mod model;
pub mod notice;
pub mod paths;
pub mod recurrence;
pub mod redact;
pub mod report;
pub mod rules;
pub mod securitytxt;
pub mod stamp;
pub mod timing;
pub mod urlquery;

pub use analyze::{Analysis, Cluster, ObsResult, analyze};
pub use attribution::{Claim, Evidence, Role, attribute};
pub use bursts::{ArchiveBurst, archive_bursts};
pub use chains::{Chain, Pace};
pub use dialect::{CutLengths, Dialect, DialectPair};
pub use endpoints::{Activity, EndpointOptions, EndpointView, endpoints};
pub use eval::{EvalReport, Label, LabelSet, evaluate, parse_labels};
pub use extract::{Extracted, Layer, defang, defang_host, extract, unwrap_layers};
pub use fanout::FanOut;
pub use fingerprint::{Encoding, HeaderSet, encoding, header_set};
pub use ingest::{FieldMap, Format, Parsed, parse_input};
pub use model::{
    Hit, IndicatorKind, LinkFeature, OPERATOR_SOURCE, Observation, Tier, TsKind, fmt_ts, parse_ts,
    top_counts,
};
pub use paths::{FabricatedId, PathStats, fabricated_ids};
pub use recurrence::{ClusterRun, RecurrenceOptions, Rerun, TargetRun, cluster_reruns, reruns};
pub use redact::{redact_observation, redact_url};
pub use report::{Audience, Notice, ReportOptions, render_markdown, render_notice};
pub use rules::{DEFAULT_RULES, RuleSet, Rules};
pub use securitytxt::{SecurityTxt, parse_security_txt};
pub use stamp::{Stamp, StampCluster};
pub use timing::{SharedPause, SharedPauseOptions, StaleDates, shared_pauses, stale_dates};
