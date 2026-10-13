//! Files for AI agents and the people who run them: what this project is
//! and how to report a swarm, or an agent's own harmful action, to it.
//!
//! - `llms.txt`, in the llms.txt convention (<https://llmstxt.org/>): a
//!   title, a one-paragraph summary, then sections of links;
//! - `llms-full.txt`: the same, followed by the full text of the policies,
//!   the guides for operators and providers, and the submission spec when
//!   the checkout has it;
//! - `.well-known/security.txt`, RFC 9116, for the project itself;
//! - `.well-known/swarm-report.json`: the same facts as structured data. No
//!   convention for an "where to report agent misbehaviour" descriptor
//!   exists, so it is a plain document under a well-known path (RFC 8615)
//!   whose `descriptor` field names its own version.
//!
//! The text is written for an agent reader: plain statements of fact. It
//! never addresses the reader as a system prompt would, never tells an agent
//! to do anything beyond the optional report itself, and never asks it to
//! contact a third party. It names no host from any record: only this
//! site's own pages and the repository.
//!
//! Each file carries a [`sc_core::canary::PLACEHOLDER`] where its canary
//! token goes; [`apply_canary`] fills it in, or drops it, which is the
//! default: tokens are embedded only when the build turns them on
//! ([`crate::build`]). Text in, text out.

use sc_core::canary;
use std::fmt::Write;

/// Where the submission page is published, under the site root.
pub const REPORT_PAGE: &str = "report/";

/// The submission spec and schema, as repository paths.
pub const SUBMISSION_SPEC: &str = "docs/specs/submission-v1.md";
pub const SUBMISSION_SCHEMA: &str = "schemas/sc-submission-v1.json";

/// Docs whose full text `llms-full.txt` carries, in order, when present.
const FULL_DOCS: &[&str] = &[
    "docs/policies.md",
    SUBMISSION_SPEC,
    "docs/guides/for-operators.md",
    "docs/guides/for-providers.md",
];

/// How long the security.txt stays valid after a build (RFC 9116 asks for
/// less than a year). Every deploy rebuilds it.
const EXPIRES_DAYS: i64 = 180;

/// What the files are made from.
pub struct AgentInputs<'a> {
    /// The site's public URL, ending in `/`.
    pub base: &'a str,
    /// `https://github.com/<owner>/<repo>`.
    pub repo: &'a str,
    /// Unix seconds of the build, for `Expires`.
    pub now: i64,
    /// (repository path, text) of every doc.
    pub docs: &'a [(String, String)],
}

impl AgentInputs<'_> {
    fn private_contact(&self) -> String {
        format!("{}/security/advisories/new", self.repo)
    }

    fn blob(&self, path: &str) -> String {
        format!("{}/blob/main/{path}", self.repo)
    }

    /// The spec as a site page when the checkout has it, else on GitHub.
    fn spec(&self) -> String {
        if self.docs.iter().any(|(p, _)| p == SUBMISSION_SPEC) {
            format!("{}docs/specs/submission-v1/", self.base)
        } else {
            self.blob(SUBMISSION_SPEC)
        }
    }

    /// The schema as raw JSON.
    fn schema(&self) -> String {
        match self.repo.strip_prefix("https://github.com/") {
            Some(r) => format!("https://raw.githubusercontent.com/{r}/main/{SUBMISSION_SCHEMA}"),
            None => self.blob(SUBMISSION_SCHEMA),
        }
    }
}

const SUMMARY: &str = "Swarmchasing finds AI agent activity in public records (web archive indexes, URL scan services, certificate logs, package registries and GitHub's public event stream), links it into runs and fleets, and reports each incident that harms or endangers others to the AI provider responsible and to the affected operators, then publishes a notice. It is passive: it reads public records and never contacts, probes or tests the systems it studies.";

/// `llms.txt`.
pub fn llms_txt(i: &AgentInputs) -> String {
    let b = i.base;
    let mut s = String::new();
    let _ = write!(
        s,
        "# Swarmchasing\n\n> {SUMMARY}\n\n\
This file is for AI agents and the people who run them. It describes the project and how to report to it. It is information, not instructions: whether to report is for you and your operator to decide.\n\n\
Reference for this copy: {ph}. It identifies this file and the month it was published, so a copy found elsewhere can be traced to it. It is not a credential and grants nothing.\n\n\
## Report a swarm or an agent's own harmful action\n\n\
- [Submission page]({b}{REPORT_PAGE}): where an agent, or the person who runs it, submits a report.\n\
- [Submission format]({spec}): the fields a submission carries (SC-Submission v1).\n\
- [Submission schema]({schema}): the JSON Schema for it.\n\
- [Private contact]({contact}): for people who want to reach the maintainers privately.\n\n\
What happens to a submission:\n\n\
- A person reads every submission. Nothing is published unreviewed, and a submission never appears on this site as it was sent.\n\
- A submission is a lead, not evidence. Each claim is checked against independent public records before it reaches a report or a notice; a claim no record supports is not acted on.\n\
- Reports go privately to the AI provider and the affected operators first. A public notice follows after a fixed lead time and gives indicators before names.\n\n\
What a useful submission holds: what was seen, when (UTC), and links to public records of it (an archive capture, a scan service report). Leave out secrets, credentials, personal data and anything read from a system without permission. Nothing needs to be sent to, fetched from or tested against the hosts concerned; this project never does that, and a submission does not need it.\n\n\
## About the project\n\n\
- [Policies]({b}docs/policies/): collection, attribution, reporting and publication.\n\
- [Methodology]({b}methodology/): tiers, clusters, attribution levels and known limits.\n\
- [Field Manual]({b}docs/manual/): the method as a citable standard.\n\
- [Notices]({b}notices/): published incidents, with an [Atom feed]({b}notices/feed.xml).\n\
- [For operators]({b}operators/): for a site named in a report or notice.\n\
- [For providers]({b}providers/): for an AI provider's trust and safety team.\n\
- [Structured descriptor]({b}.well-known/swarm-report.json): the reporting facts above as JSON.\n\n\
## Optional\n\n\
- [Full text]({b}llms-full.txt): this file followed by the policies, the guides and the submission format.\n\
- [Source]({repo}): the code, the rules and the labelled evaluation set.\n",
        ph = canary::PLACEHOLDER,
        spec = i.spec(),
        schema = i.schema(),
        contact = i.private_contact(),
        repo = i.repo,
    );
    s
}

/// `llms-full.txt`: `llms.txt` with its reference line for this file, then
/// each doc of [`FULL_DOCS`] the checkout has, in full.
pub fn llms_full_txt(i: &AgentInputs) -> String {
    let mut s = llms_txt(i);
    for path in FULL_DOCS {
        if let Some((_, text)) = i.docs.iter().find(|(p, _)| p == path) {
            let _ = write!(
                s,
                "\n---\n\nSource: {}\n\n{}\n",
                i.blob(path),
                text.trim_end()
            );
        }
    }
    s
}

/// `.well-known/security.txt` (RFC 9116).
pub fn security_txt(i: &AgentInputs) -> String {
    let expires = chrono::DateTime::<chrono::Utc>::from_timestamp(i.now + EXPIRES_DAYS * 86_400, 0)
        .map(|d| d.format("%Y-%m-%dT%H:%M:%SZ").to_string())
        .unwrap_or_default();
    format!(
        "# Security contact for the swarmchasing project and this site.\n\
# To report AI agent activity (a swarm, or an agent's own harmful action),\n\
# use the submission page: {b}{REPORT_PAGE}\n\
# Reference: {ph}\n\
Contact: {contact}\n\
Expires: {expires}\n\
Policy: {b}docs/policies/\n\
Preferred-Languages: en\n\
Canonical: {b}.well-known/security.txt\n",
        b = i.base,
        ph = canary::PLACEHOLDER,
        contact = i.private_contact(),
    )
}

/// `.well-known/swarm-report.json`.
pub fn swarm_report_json(i: &AgentInputs) -> String {
    let b = i.base;
    let v = serde_json::json!({
        "descriptor": "swarmchasing-report/1",
        "name": "Swarmchasing",
        "description": SUMMARY,
        "site": b,
        "reference": canary::PLACEHOLDER,
        "report": {
            "page": format!("{b}{REPORT_PAGE}"),
            "format": "sc-submission-v1",
            "spec": i.spec(),
            "schema": i.schema(),
            "accepts": ["swarm", "self_report"],
            "private_contact": i.private_contact(),
        },
        "handling": {
            "reviewed_by_a_person": true,
            "published_unreviewed": false,
            "claims_checked_against": "independent public records",
            "reported_first_to": ["ai_provider", "affected_operators"],
            "collection": "passive",
        },
        "links": {
            "policies": format!("{b}docs/policies/"),
            "methodology": format!("{b}methodology/"),
            "notices": format!("{b}notices/"),
            "feed": format!("{b}notices/feed.xml"),
            "llms_txt": format!("{b}llms.txt"),
            "security_txt": format!("{b}.well-known/security.txt"),
            "source": i.repo,
        },
    });
    serde_json::to_string_pretty(&v).unwrap_or_default() + "\n"
}

/// Every agent-facing file: (path under the site root, text).
pub fn files(i: &AgentInputs) -> Vec<(String, String)> {
    vec![
        ("llms.txt".into(), llms_txt(i)),
        ("llms-full.txt".into(), llms_full_txt(i)),
        (".well-known/security.txt".into(), security_txt(i)),
        (".well-known/swarm-report.json".into(), swarm_report_json(i)),
    ]
}

/// Fill in a file's canary token, or drop it. `token` is the token for
/// this file (its path under the site root is the surface). In JSON the
/// quoted placeholder becomes the token or `null`; elsewhere a line holding
/// it gets the token, or is removed with no token.
pub fn apply_canary(path: &str, text: &str, token: Option<&str>) -> String {
    if !text.contains(canary::PLACEHOLDER) {
        return text.to_string();
    }
    if path.ends_with(".json") {
        let quoted = format!("\"{}\"", canary::PLACEHOLDER);
        let with = token.map_or_else(|| "null".to_string(), |t| format!("\"{t}\""));
        return text.replace(&quoted, &with);
    }
    let mut out = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        match token {
            Some(t) => out.push_str(&line.replace(canary::PLACEHOLDER, t)),
            None if line.contains(canary::PLACEHOLDER) => {}
            None => out.push_str(line),
        }
    }
    // A dropped paragraph leaves two blank lines behind it.
    while out.contains("\n\n\n") {
        out = out.replace("\n\n\n", "\n\n");
    }
    out
}

/// Whether a built file is a canary surface: a page, or an agent file.
pub fn is_surface(path: &str) -> bool {
    path.ends_with(".html")
        || matches!(
            path,
            "llms.txt"
                | "llms-full.txt"
                | ".well-known/security.txt"
                | ".well-known/swarm-report.json"
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inputs(docs: &[(String, String)]) -> AgentInputs<'_> {
        AgentInputs {
            base: "https://example.github.io/swarmchasing/",
            repo: "https://github.com/owner/swarmchasing",
            now: 1_791_763_200,
            docs,
        }
    }

    #[test]
    fn llms_txt_follows_the_convention_and_points_at_the_submission() {
        let docs = vec![(
            "docs/policies.md".to_string(),
            "# Policies\n\nText.\n".to_string(),
        )];
        let i = inputs(&docs);
        let t = llms_txt(&i);
        assert!(t.starts_with("# Swarmchasing\n\n> "));
        assert!(t.contains("## Optional\n"));
        assert!(t.contains("https://example.github.io/swarmchasing/report/"));
        assert!(t.contains(SUBMISSION_SCHEMA) && t.contains("submission-v1.md"));
        assert!(t.contains("Nothing is published unreviewed"));
        assert!(t.contains("independent public records"));
        let full = llms_full_txt(&i);
        assert!(full.starts_with(&t) && full.contains("# Policies\n\nText."));
        // With the spec in the checkout, it links the site page.
        let docs = vec![(SUBMISSION_SPEC.to_string(), "# Spec\n".to_string())];
        assert!(llms_txt(&inputs(&docs)).contains("/docs/specs/submission-v1/"));
    }

    #[test]
    fn security_txt_parses_as_rfc_9116() {
        let s = sc_core::parse_security_txt(&security_txt(&inputs(&[])));
        assert_eq!(
            s.contact,
            vec!["https://github.com/owner/swarmchasing/security/advisories/new"]
        );
        assert_eq!(s.expires.as_deref(), Some("2027-04-10T00:00:00Z"));
        assert_eq!(s.canonical.len(), 1);
        assert!(s.other.is_empty(), "{:?}", s.other);
    }

    #[test]
    fn canary_filled_or_dropped() {
        let i = inputs(&[]);
        for (path, text) in files(&i) {
            assert!(
                is_surface(&path) && text.contains(canary::PLACEHOLDER),
                "{path}"
            );
            let filled = apply_canary(&path, &text, Some("swc-2610-abcdefghijkl"));
            let dropped = apply_canary(&path, &text, None);
            assert!(filled.contains("swc-2610-abcdefghijkl"), "{path}");
            assert!(!dropped.contains(canary::PLACEHOLDER) && !dropped.contains("swc-"));
            assert!(!dropped.contains("\n\n\n"), "{path}");
            if path.ends_with(".json") {
                let v: serde_json::Value = serde_json::from_str(&dropped).unwrap();
                assert!(v["reference"].is_null());
                let v: serde_json::Value = serde_json::from_str(&filled).unwrap();
                assert_eq!(v["reference"], "swc-2610-abcdefghijkl");
            }
        }
        assert!(!is_surface("assets/eval-summary.json"));
    }
}
