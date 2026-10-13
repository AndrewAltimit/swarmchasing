//! Known benign automation, so dependency bots, release tooling and bulk
//! drives do not read as account swarms.
//!
//! Two lists. [`is_automation`] drops an event at collection by its login:
//! GitHub Apps (`name[bot]`), and accounts that run declared automation
//! under a user login. Apps act only where a repository owner installed
//! them, AI coding agents among them; that is the owner's choice, not a
//! swarm on others. [`benign_template`] names the benign kind of a group
//! whose slotted text matches a known automated or drive template; such
//! groups are listed as suppressed, never reported.

use regex::{Regex, RegexBuilder};
use std::sync::OnceLock;

/// Logins of automation that runs under a user account, lower case.
pub const AUTOMATION_LOGINS: &[&str] = &[
    "dependabot",
    "dependabot-preview",
    "renovate",
    "renovate-bot",
    "renovatebot",
    "greenkeeperio-bot",
    "snyk-bot",
    "pyup-bot",
    "github-actions",
    "actions-user",
    "web-flow",
    "pre-commit-ci",
    "allcontributors",
    "all-contributors",
    "imgbot",
    "imgbotapp",
    "codecov-commenter",
    "codecov-io",
    "coveralls",
    "sonarcloud",
    "netlify",
    "vercel",
    "mergify",
    "stale",
    "github-classroom",
    "weblate",
    "transifex-integration",
    "crowdin-bot",
    "semantic-release-bot",
    "release-please",
    "changeset-bot",
    "copybara-service",
    "google-oss-bot",
    "k8s-ci-robot",
    "k8s-triage-robot",
    "openshift-ci-robot",
    "openshift-merge-robot",
    "msftbot",
    "azure-pipelines",
    "gitter-badger",
];

/// Whether `login` is automation: a GitHub App (`[bot]`), a login ending in
/// `-bot`, `_bot` or `-robot`, or one of [`AUTOMATION_LOGINS`].
pub fn is_automation(login: &str) -> bool {
    let l = login.to_ascii_lowercase();
    l.ends_with("[bot]")
        || l.ends_with("-bot")
        || l.ends_with("_bot")
        || l.ends_with("-robot")
        || AUTOMATION_LOGINS.contains(&l.as_str())
}

/// Benign templates on slotted text ([`super::text::slot_tokens`] joined by
/// spaces): (kind, pattern).
pub const BENIGN_TEMPLATES: &[(&str, &str)] = &[
    (
        "dependency update",
        r"\bbumps? \S+ from\b|\bupdate dependency\b|\b(chore|build|fix)\s?deps(-dev)?\b|\bthis pr contains the following updates\b|\bconfigure renovate\b|\block file maintenance\b|\bdependabot\b|\brenovate\b",
    ),
    (
        "translation sync",
        r"\bnew translations?\b|\bupdated? translations?\b|\btranslated using weblate\b|\bcrowdin\b|\btransifex\b",
    ),
    (
        "release automation",
        r"\brelease please\b|\bversion packages\b|\bchangesets?\b|^chore \S+ release\b",
    ),
    (
        "contribution drive",
        r"\bhacktoberfest\b|\bgssoc\b|\bfirst[- ]contributions?\b|\b(please )?assign (this|it|the issue) to me\b|\bi would like to work on this\b|\bcan i work on this\b",
    ),
    (
        "classroom or course",
        r"\bgithub classroom\b|\bfeedback pull request\b|\bassignment\b.*\bclassroom\b",
    ),
    (
        "declared scanner",
        r"\bsnyk has created this pr\b|\bstepsecurity\b|\bsocket security\b|\bcodeql\b",
    ),
    (
        "platform default text",
        r"^(update|create|add|delete) \S+ (md|txt|yml|yaml|json)$|^add files via upload\b|^initial commit\b|^merge branch\b",
    ),
];

fn compiled() -> &'static [(&'static str, Regex)] {
    static SET: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();
    SET.get_or_init(|| {
        BENIGN_TEMPLATES
            .iter()
            .map(|(k, p)| {
                let re = RegexBuilder::new(p)
                    .case_insensitive(true)
                    .build()
                    .expect("benign templates compile");
                (*k, re)
            })
            .collect()
    })
}

/// The benign kind `slotted` (a sketch excerpt or a name template) matches.
pub fn benign_template(slotted: &str) -> Option<&'static str> {
    compiled()
        .iter()
        .find(|(_, re)| re.is_match(slotted))
        .map(|(k, _)| *k)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bots_and_declared_automation() {
        for l in [
            "dependabot[bot]",
            "Renovate-Bot",
            "github-actions",
            "k8s-ci-robot",
            "pre-commit-ci",
        ] {
            assert!(is_automation(l), "{l}");
        }
        for l in ["abbot", "robotics-fan", "octocat", "bottle"] {
            assert!(!is_automation(l), "{l}");
        }
    }

    #[test]
    fn benign_templates_on_slotted_text() {
        assert_eq!(
            benign_template("bumps <path> from <num> to <num>"),
            Some("dependency update")
        );
        assert_eq!(
            benign_template("hi i would like to work on this issue please assign it to me"),
            Some("contribution drive")
        );
        assert_eq!(
            benign_template("new translations <path> french"),
            Some("translation sync")
        );
        assert_eq!(
            benign_template("critical security vulnerability found in <user> please fix"),
            None
        );
    }
}
