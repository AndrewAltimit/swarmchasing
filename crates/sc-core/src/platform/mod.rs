//! Coordinated-account swarms on public platforms (GitHub, npm, PyPI,
//! Hugging Face, Go modules, Wikimedia wikis): many accounts acting alike,
//! found in public event archives, event streams and registry metadata.
//!
//! A [`PlatformEvent`] is one public action (an issue opened, a comment, a
//! repository or package created) reduced at collection to what grouping
//! needs: a keyed hash of the account, a coarse account-age rank where the
//! platform numbers accounts in creation order, the target, the public link,
//! and a [`TextSketch`] of the text with per-instance values replaced by
//! slots. The text itself is not kept.
//!
//! [`detect`] groups events into candidate swarms by near-duplicate text
//! (MinHash over word shingles), shared templates (the same text once slot
//! values are taken out), templated names of created items, and, for
//! text-less events (stars, forks, pull requests opened), the one target
//! they act on. It then weighs each group by a chance model: how likely its
//! densest burst is if the same posts fell at random over the window, and
//! how likely so many of its accounts are new given how many accounts in
//! the window are. A text-less group, and a group of wiki edits, needs its
//! own burst: account age alone is a property of what such groups are (new
//! editors' sandboxes, a new project's first stars). Model-output residue,
//! coding-harness self-identification and target overlap are reported
//! beside the chance. Known benign automation is dropped at collection
//! ([`automation`]) and groups whose text matches a documented benign
//! template are listed as suppressed, not reported. A candidate is a hint
//! for the admin, never a finding.

pub mod automation;
mod detect;
pub mod residue;
pub mod text;

#[cfg(test)]
mod tests;

pub use detect::{detect, detect_platform};
pub use text::{TextSketch, name_template, sketch, wiki_title_template};

use crate::rules::Rules;
use serde::{Deserialize, Serialize};

/// The platform an event was read from.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    #[default]
    Github,
    Npm,
    Pypi,
    HuggingFace,
    /// Wikimedia wikis (Wikipedia and its sister projects), from
    /// EventStreams.
    Wikimedia,
    /// Go modules, from the module proxy's index.
    Go,
}

impl Platform {
    pub fn name(self) -> &'static str {
        match self {
            Self::Github => "github",
            Self::Npm => "npm",
            Self::Pypi => "pypi",
            Self::HuggingFace => "huggingface",
            Self::Wikimedia => "wikimedia",
            Self::Go => "go",
        }
    }
}

/// What the account did.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    IssueOpened,
    PullOpened,
    Comment,
    ReviewComment,
    RepoCreated,
    PackagePublished,
    SpaceCreated,
    ModelCreated,
    DatasetCreated,
    /// A repository starred (GitHub `WatchEvent`).
    Starred,
    /// A repository forked.
    Forked,
    ReleasePublished,
    DiscussionOpened,
    CommitComment,
    /// A wiki page created or edited (a GitHub wiki, a Wikimedia wiki).
    WikiEdited,
    #[default]
    Other,
}

impl Action {
    pub fn label(self) -> &'static str {
        match self {
            Self::IssueOpened => "issues opened",
            Self::PullOpened => "pull requests opened",
            Self::Comment => "comments",
            Self::ReviewComment => "review comments",
            Self::RepoCreated => "repositories created",
            Self::PackagePublished => "packages published",
            Self::SpaceCreated => "Spaces created",
            Self::ModelCreated => "models created",
            Self::DatasetCreated => "datasets created",
            Self::Starred => "stars",
            Self::Forked => "forks",
            Self::ReleasePublished => "releases published",
            Self::DiscussionOpened => "discussions opened",
            Self::CommitComment => "commit comments",
            Self::WikiEdited => "wiki edits",
            Self::Other => "other events",
        }
    }

    /// Creates or edits a named item, so its name can follow a template.
    pub fn creates(self) -> bool {
        matches!(
            self,
            Self::RepoCreated
                | Self::PackagePublished
                | Self::SpaceCreated
                | Self::ModelCreated
                | Self::DatasetCreated
                | Self::WikiEdited
        )
    }

    /// Text-less events of this action are grouped by the target they act
    /// on: many accounts starring, forking or opening pull requests on one
    /// repository at once. GitHub's event payloads carry no pull request
    /// title or body, so a pull request opened is text-less.
    pub fn by_target(self) -> bool {
        matches!(self, Self::Starred | Self::Forked | Self::PullOpened)
    }
}

/// One public action on a platform, as a collector keeps it.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PlatformEvent {
    /// Stable id: `gh:<event id>`, `npm:<name>@<version>`,
    /// `pypi:<name>@<version>`, `hf:<kind>:<id>`, `wm:<wiki>:<revision>`,
    /// `go:<module>@<version>`.
    pub id: String,
    pub platform: Platform,
    pub action: Action,
    /// When it happened (Unix seconds).
    pub ts: i64,
    /// Keyed hash of the account ([`actor_key`]); empty when the source
    /// does not say who acted (PyPI's feeds).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub actor: String,
    /// The account's numeric id divided by [`RANK_UNIT`], where the platform
    /// numbers accounts in creation order (GitHub): a coarse account-age
    /// proxy that does not identify the account.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_rank: Option<u64>,
    /// The platform says this is the account's first contribution anywhere
    /// (a wiki account's first edit). GitHub's event payloads no longer
    /// carry the author association, so GitHub events leave it unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_timer: Option<bool>,
    /// What it acted on: `owner/repo`, a package name, a Hub repo id.
    pub target: String,
    /// The event's public page.
    pub link: String,
    /// The created item's name with per-instance parts as slots
    /// ([`name_template`]); only for actions that create an item.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name_template: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<TextSketch>,
}

/// Account ids per rank unit: GitHub numbers on the order of tens of
/// thousands of new accounts a day, so one unit is well under a day.
pub const RANK_UNIT: u64 = 1000;

/// The keyed hash an account is stored as: links the account's events
/// without keeping its login. `id` is the platform's account id or login.
pub fn actor_key(platform: Platform, id: &str) -> String {
    use sha2::{Digest, Sha256};
    let h = Sha256::digest(format!("swarmchase-actor\0{}\0{id}", platform.name()).as_bytes());
    let hex: String = h.iter().take(8).map(|b| format!("{b:02x}")).collect();
    format!("acct:{hex}")
}

impl PlatformEvent {
    /// Sketch `text` into the event; `context` holds per-instance words
    /// (the target's owner and name, the actor's login) to replace with a
    /// slot. Empty text leaves the event without a sketch.
    pub fn with_text(mut self, text: &str, context: &[&str], rules: &Rules) -> Self {
        self.text = sketch(text, context, rules);
        self
    }

    /// The owner part of the target (`owner/repo`, `@scope/pkg`, `author/space`).
    pub fn owner(&self) -> &str {
        self.target
            .split_once('/')
            .map_or("", |(o, _)| o.trim_start_matches('@'))
    }
}

/// Tunables for [`detect`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PlatformOptions {
    /// Distinct accounts a group needs.
    pub min_accounts: usize,
    /// Events a group needs when the source names no account (PyPI feeds).
    pub min_flood: usize,
    /// Words a text needs to take part in text grouping: short replies
    /// ("thanks!", "+1") are shared by everyone.
    pub min_words: u32,
    /// Estimated Jaccard similarity of word shingles for a near-duplicate.
    pub similarity: f64,
    /// Width of the burst window the timing chance is taken over.
    pub burst_secs: i64,
    /// A burst starting this close to a clock hour counts for
    /// `clock_weight` of its size: scheduled jobs start on the hour.
    pub clock_tolerance_secs: i64,
    pub clock_weight: f64,
    /// Account ranks this close to the newest rank seen count as new.
    pub new_account_ranks: u64,
    /// A group is reported when its chance is at most this ...
    pub max_chance: f64,
    /// ... and rated moderate at or below this with two signals.
    pub moderate_chance: f64,
    /// Share of members carrying model-output residue that reports a group
    /// whatever its chance.
    pub residue_share: f64,
}

impl Default for PlatformOptions {
    fn default() -> Self {
        Self {
            min_accounts: 3,
            min_flood: 5,
            min_words: 8,
            similarity: 0.6,
            burst_secs: 900,
            clock_tolerance_secs: 120,
            clock_weight: 0.25,
            new_account_ranks: 1000,
            max_chance: 0.01,
            moderate_chance: 1e-4,
            residue_share: 0.5,
        }
    }
}

/// How strongly a candidate stands. There is no strong grade: a platform
/// swarm is a hint until the admin has read its events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HintStrength {
    Weak,
    Moderate,
}

/// What joined a group's events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Basis {
    /// Near-duplicate text (MinHash over word shingles).
    NearDuplicate,
    /// The same text once per-instance values are slots.
    Template,
    /// Created items whose names follow one template.
    NameTemplate,
    /// Text-less events on one target ([`Action::by_target`]).
    Target,
}

/// The densest burst of a group and its chance.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Burst {
    pub start: i64,
    pub window_secs: i64,
    /// Accounts (or events, without accounts) whose first event in the
    /// group falls in the window.
    pub in_window: usize,
    /// Points the timing was taken over.
    pub of: usize,
    /// The null model's window in seconds: the clock hours read in full
    /// (at least a tenth of the busiest hour's events) and the group's own.
    pub span_secs: i64,
    /// Points expected in one window if the group's points fell at random.
    pub expected: f64,
    /// Chance of a window this dense anywhere in the span.
    pub p_chance: f64,
    /// The window starts on a clock hour and was counted down.
    pub on_the_hour: bool,
}

/// New accounts among a group's accounts against the window's base rate.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NewAccounts {
    pub new: usize,
    /// Accounts with age data.
    pub of: usize,
    /// Share of all accounts in the window that are new.
    pub base_rate: f64,
    pub p_chance: f64,
}

/// One candidate swarm.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformSwarm {
    /// Neutral id from the earliest member, stable while that member stays.
    pub id: String,
    pub platform: Platform,
    pub basis: Vec<Basis>,
    /// Member events by action.
    pub actions: Vec<(Action, usize)>,
    pub events: usize,
    pub accounts: usize,
    pub start: i64,
    pub end: i64,
    /// The representative text or name, slots in place of per-instance values.
    pub template: String,
    /// Mean estimated similarity of the text members to the representative.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub similarity: Option<f64>,
    pub burst: Burst,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_accounts: Option<NewAccounts>,
    /// Residue rule ids and how many members carry each.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub residue: Vec<(String, usize)>,
    /// Coding-harness self-identification ids ([`residue::self_id`]) and
    /// how many members carry each: weak context, never evidence alone.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub self_id: Vec<(String, usize)>,
    /// Targets by accounts that acted on them, most first (at most ten).
    pub targets: Vec<(String, usize)>,
    pub distinct_targets: usize,
    /// Timing and account-age chances multiplied, as if independent.
    pub p_chance: f64,
    pub strength: HintStrength,
    /// What could make this benign, for the admin to rule out.
    pub caveats: Vec<String>,
    /// Up to ten member links, earliest first.
    pub links: Vec<String>,
    /// Every member event id.
    pub members: Vec<String>,
    pub reason: String,
}

/// A group left out, and why.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Suppressed {
    pub platform: Platform,
    /// The benign template it matched.
    pub why: String,
    pub events: usize,
    pub accounts: usize,
    pub template: String,
}

/// What [`detect`] found.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PlatformReport {
    pub events: usize,
    pub accounts: usize,
    pub swarms: Vec<PlatformSwarm>,
    /// Groups matching a benign template.
    pub suppressed: Vec<Suppressed>,
    /// Groups with enough accounts whose chance stayed above the threshold.
    pub below_threshold: usize,
    /// Events worth carrying to the next run: members of any multi-account
    /// group or carrying residue. Not serialised.
    #[serde(skip)]
    pub carry: Vec<String>,
}
