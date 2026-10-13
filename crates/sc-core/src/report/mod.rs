//! Disclosure drafts. Every report is a *draft* for a human to verify.
//!
//! `audience` holds the wording that differs per reader, `hints` the
//! one-line cluster hints. Each section is written by its own module:
//! `overview` (header, summary, indicators), `sections` (attribution and
//! the endpoint table), `identity` (declared agent identity), `agentness`
//! (agent grades), `timeline` (each
//! cluster and its hints), `pairs` (hints tying clusters together) and
//! `records` (representative records, method). This module selects the
//! clusters and lays the sections out in order.

mod agentness;
mod audience;
mod hints;
mod identity;
mod join;
mod overview;
mod pairs;
mod records;
mod sections;
mod timeline;

pub use audience::{Audience, Reported};

use sections::{attribution_section, endpoint_table};

use crate::analyze::{Analysis, Cluster};
use crate::attribution::{Claim, Evidence, attribute, merge};
use crate::model::{IndicatorKind, Tier};
use crate::notice::PublicView;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt::Write;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportOptions {
    #[serde(default)]
    pub audience: Audience,
    /// Cluster id (`C1`) or key (`k-3f9a2c1b`); `None` = every non-noise cluster.
    #[serde(default)]
    pub cluster: Option<String>,
    #[serde(default)]
    pub reporter: Option<String>,
    /// Date string supplied by the caller (core has no clock).
    #[serde(default)]
    pub generated: Option<String>,
    #[serde(default = "ten")]
    pub max_evidence: usize,
    /// Weakest evidence that may name a developer outside case notes.
    /// Never below `hosting_asn`: self-identification alone names no one.
    #[serde(default)]
    pub min_named: Evidence,
    /// Claims established by case work (shared identifiers, provider
    /// infrastructure, provider confirmation), merged with the records' own.
    #[serde(default)]
    pub claims: Vec<Claim>,
    /// Endpoints whose attack details the public notice withholds (marked
    /// compromised: the weakness may still be open).
    #[serde(default)]
    pub exposed_hosts: Vec<String>,
    /// Endpoints the admin classified as affected (compromised, targeted or
    /// historical). When given, the public notice names only these hosts and
    /// counts the rest; `None` names every host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub affected_hosts: Option<Vec<String>>,
    /// Who the case's recorded sends reached. The public notice says reports
    /// went out only to these parties, and says nothing about sends without it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reported: Option<Reported>,
    /// For the indicator notice: each affected host, lowercase, with how the
    /// notice describes it without identifying it ("a national government
    /// data portal"). When given, a public notice names no host at all: the
    /// described hosts appear by their description, the rest are counted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_descriptions: Option<BTreeMap<String, String>>,
    /// The admin's agent grade for the case ([`crate::agentness`]), shown
    /// beside the computed grades; the only way to L5. Set by the case, never
    /// read from options JSON, so the browser module carries no decoder.
    #[serde(skip)]
    pub agent_grade: Option<crate::agentness::GradeDecision>,
}

/// A public notice draft and what the admin must look at before publishing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Notice {
    pub markdown: String,
    /// What the draft withheld.
    pub withheld: Vec<String>,
    /// What could not be classified; withheld, but the admin decides.
    pub flags: Vec<String>,
    /// Withheld values that still appear in the draft. Empty unless
    /// something went wrong; the lines never repeat the values.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub leaks: Vec<String>,
}

fn ten() -> usize {
    10
}

impl Default for ReportOptions {
    fn default() -> Self {
        Self {
            audience: Audience::default(),
            cluster: None,
            reporter: None,
            generated: None,
            max_evidence: ten(),
            min_named: Evidence::default(),
            claims: Vec::new(),
            exposed_hosts: Vec::new(),
            affected_hosts: None,
            reported: None,
            target_descriptions: None,
            agent_grade: None,
        }
    }
}

fn kind_label(k: IndicatorKind) -> &'static str {
    match k {
        IndicatorKind::Relay => "Relay / fetch-through services",
        IndicatorKind::Carrier => "Carrier services and inline programs",
        IndicatorKind::Exploit => "Attack payloads",
        IndicatorKind::AgentMarker => "Agent tags and markers",
        IndicatorKind::CacheBuster => "Cache-busting parameters",
        IndicatorKind::SelfId => "Self-identification strings (unreliable)",
        IndicatorKind::Exfil => "Callback / exfiltration channels",
        IndicatorKind::Header => "Header fingerprints",
        IndicatorKind::Outcome => "Outcome states",
        IndicatorKind::AntiBot => "Anti-bot bypass",
        IndicatorKind::Infra => "Infrastructure",
    }
}

fn dur(secs: i64) -> String {
    match secs {
        s if s < 120 => format!("{s}s"),
        s if s < 7200 => format!("{}m", s / 60),
        s if s < 172800 => format!("{:.1}h", s as f64 / 3600.0),
        s => format!("{:.1}d", s as f64 / 86400.0),
    }
}

pub fn render_markdown(a: &Analysis, opts: &ReportOptions) -> String {
    let mut view = (opts.audience == Audience::Public).then(|| public_view(a, opts));
    render(a, opts, view.as_mut())
}

fn public_view(a: &Analysis, opts: &ReportOptions) -> PublicView {
    // The indicator notice names no host, so its view names none either.
    let affected = match &opts.target_descriptions {
        Some(_) => Some(&[][..]),
        None => opts.affected_hosts.as_deref(),
    };
    PublicView::new(a, &opts.exposed_hosts).with_affected(affected)
}

/// The descriptions that stand in for hosts, when the report is an
/// indicator notice.
fn descriptions(opts: &ReportOptions) -> Option<&BTreeMap<String, String>> {
    opts.target_descriptions
        .as_ref()
        .filter(|_| opts.audience == Audience::Public)
}

/// The public notice for these clusters, with what it withheld.
pub fn render_notice(a: &Analysis, opts: &ReportOptions) -> Notice {
    let opts = ReportOptions {
        audience: Audience::Public,
        ..opts.clone()
    };
    let mut view = public_view(a, &opts);
    let markdown = render(a, &opts, Some(&mut view));
    Notice {
        leaks: view.leaks(&markdown),
        markdown,
        withheld: view.withheld.into_iter().collect(),
        flags: view.flags.into_iter().collect(),
    }
}

/// One report being written: the analysis, the options and the clusters it
/// covers. Each section is a method in the module that holds it.
struct Report<'a> {
    a: &'a Analysis,
    opts: &'a ReportOptions,
    clusters: Vec<&'a Cluster>,
}

fn render(a: &Analysis, opts: &ReportOptions, mut view: Option<&mut PublicView>) -> String {
    let r = Report {
        a,
        opts,
        clusters: match &opts.cluster {
            Some(id) => a.clusters.iter().filter(|c| c.matches(id)).collect(),
            None => a.clusters.iter().filter(|c| c.tier > Tier::Noise).collect(),
        },
    };
    let mut s = String::new();
    r.header(&mut s);
    let (hosts, unnamed) = r.summary(&mut s, view.as_deref_mut());
    r.indicators(&mut s);

    let claims = r
        .clusters
        .iter()
        .fold(Vec::new(), |acc, c| merge(acc, &attribute(a, c)));
    attribution_section(
        &mut s,
        &merge(claims, &opts.claims),
        opts,
        r.clusters.len() == 1,
    );
    identity::section(&mut s, &r.clusters, opts);
    agentness::section(&mut s, &r.clusters, opts);

    if opts.audience != Audience::Provider {
        endpoint_table(
            &mut s,
            a,
            &hosts,
            unnamed,
            descriptions(opts),
            view.as_deref_mut(),
        );
    }

    r.timeline(&mut s, view.as_deref_mut());
    join::section(&mut s, a, &r.clusters, opts);
    r.ties(&mut s, view.as_deref());
    // Plant review (crate::plant): case notes only.
    if opts.audience == Audience::Internal {
        crate::plant::plant_review(&mut s, a, &r.clusters);
    }
    let _ = writeln!(s);

    r.records(&mut s, view);
    r.method(&mut s);

    let _ = writeln!(s, "## Requested action\n");
    let _ = writeln!(s, "{}", audience::requested_action(opts.audience));
    s
}

/// The count that stands in for hosts a public notice does not name.
fn hosts_not_named(n: usize) -> String {
    match n {
        1 => "1 other host not named here".into(),
        n => format!("{n} other hosts not named here"),
    }
}

/// What a timing hint's times were, when not plain request times.
fn basis_note(c: &Cluster) -> String {
    c.time_basis
        .note()
        .map(|n| format!(" ({n})"))
        .unwrap_or_default()
}

/// Whether a public notice withholds attack details for any of the cluster's hosts.
fn touches_exposed(view: Option<&PublicView>, c: &Cluster) -> bool {
    view.is_some_and(|v| c.target_hosts.keys().any(|h| v.exposed(h)))
}

#[cfg(test)]
mod tests;
