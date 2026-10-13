//! `sc-inbox`: outside reports of AI agent activity (SC-Submission v1),
//! without I/O.
//!
//! Agents, researchers and operators may send a structured report of a
//! swarm they saw. Every submission is untrusted input and a way to plant
//! records, so this crate assumes a submitter may have fabricated all of it,
//! and lets through to the admin only what would have been hard to
//! fabricate:
//!
//! - [`spec`]: the document, its validation and its size caps.
//! - [`import`]: STIX 2.1, X-ARF and IODEF v2 reports converted into
//!   SC-Submissions, under depth and size caps.
//! - [`intake`]: redaction at ingest, fingerprints, duplicate and repeat
//!   detection, rate limits per submitter.
//! - [`inert`]: instruction-shaped text flagged, and every string shown
//!   inert (escaped, defanged, one line).
//! - [`evidence`]: evidence classes by fabrication cost, record identities,
//!   and the records a submission states, as `reported` records.
//! - [`verify`]: whether a lookup's result shows a referenced record exists,
//!   matches, and predates the submission.
//! - [`triage`]: corroboration against the watch store, the grade of what
//!   the toolkit found itself, inflated claims, and the verdict.
//!
//! Nothing here fetches anything: the CLI looks references up by id
//! through the collectors' indexes and passes the results in. No URL in a
//! submission is ever opened, and callback identifiers are data only.

pub mod evidence;
pub mod import;
pub mod inert;
pub mod intake;
pub mod spec;
pub mod triage;
pub mod verify;

pub use evidence::EvidenceClass;
pub use import::{ConvertedFrom, Format};
pub use intake::{Intake, IntakeSettings, Prior, Refused, intake, intake_as};
pub use spec::{Caps, Evidence, PublicRecord, RecordSource, SPEC, Submission, parse};
pub use triage::{Assessment, Checks, Corroboration, TriageSettings, Verdict, assess, corroborate};
pub use verify::{Status, Verification, check};

use serde::{Deserialize, Serialize};

/// Every inbox setting: `<data>/inbox/settings.toml`, with `[intake]`
/// (caps under `[intake.caps]`) and `[triage]` tables. A missing file or
/// key takes the default.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub intake: IntakeSettings,
    pub triage: TriageSettings,
}
