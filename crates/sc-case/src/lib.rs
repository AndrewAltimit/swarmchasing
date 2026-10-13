//! `sc-case`: what a case is and what may be done with it, without I/O.
//!
//! The CLI keeps cases as files under `<data>/cases/<id>/`; this crate holds
//! everything about them that is not reading or writing those files, so the
//! CLI, the site generator and the browser toolkit share one copy:
//!
//! - [`model`]: what `case.toml` holds.
//! - [`actions`]: the admin's decisions on a case (classify an endpoint,
//!   record a send, a missing contact, an alternative explanation, a claim,
//!   a grade, a contact), each checked and logged.
//! - [`evidence`]: logs operators send back, and which renderings may use them.
//! - [`report`]: report options from a case, the affected hosts, who was reported.
//! - [`fleet`]: the admin's fleet merges and splits, and the interaction
//!   evidence that makes a fleet a swarm.
//! - [`lead`]: the indicator notice's clock each party's report starts.
//! - [`naming`]: the naming clock in working days, consent, the naming
//!   draft, and the check that a text names no party it may not.
//! - [`review`]: the second review of each stage's exact draft.
//! - [`pinning`]: names for pinned rule sets and the tier changes between two.
//! - [`checklist`]: the self-review checklists `notice add` and `notice
//!   update --naming` run.
//! - [`bundle`]: evidence bundle contents, the manifest and the stamp check.
//! - [`signing`] (feature `signatures`): the Ed25519 signature over a
//!   bundle's manifest, and its check against the published keys.
//! - [`incident`]: drafts for AI incident databases and reporting frameworks.
//! - [`notice`]: the notice file format and the one notice linter.
//! - [`providers`]: the provider directory (`contacts/providers.toml`).
//! - [`text`]: small text helpers shared with the CLI.
//!
//! No file, network or clock access, and no command-line parsing: callers
//! pass in the time and the text. It compiles for `wasm32-unknown-unknown`.

pub mod actions;
pub mod bundle;
pub mod checklist;
pub mod evidence;
pub mod fleet;
pub mod incident;
pub mod lead;
pub mod model;
pub mod naming;
pub mod notice;
pub mod pinning;
pub mod providers;
pub mod report;
pub mod review;
#[cfg(feature = "signatures")]
pub mod signing;
pub mod text;

pub use evidence::{OperatorEvidence, Scope};
pub use model::*;
pub use notice::{NoticeFile, NoticeMeta, NoticeStatus, NoticeUpdate, UpdateKind};

/// An error from a case operation: one line for the admin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

impl From<String> for Error {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self(e.to_string())
    }
}

impl From<&str> for Error {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// Return an [`Error`] built like `format!`.
#[macro_export]
macro_rules! bail {
    ($($t:tt)*) => {
        return Err($crate::Error(format!($($t)*)))
    };
}
