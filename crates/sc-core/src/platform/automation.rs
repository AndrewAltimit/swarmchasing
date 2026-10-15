//! Known benign automation, so dependency bots, release tooling and bulk
//! drives do not read as account swarms.
//!
//! Two lists. [`is_automation`] drops an event at collection by its login:
//! GitHub Apps (`name[bot]`), and accounts that run declared automation
//! under a user login. Apps act only where a repository owner installed
//! them; that is the owner's choice, not a swarm on others. The coding-agent
//! Apps the declared-agents catalog names are told apart first
//! ([`classify_login`]): their events are tallied by product rather than
//! dropped unseen, and an undeclared App whose login claims one of those
//! products is a spoofing lead, unless it acts on a repository of the
//! product's provider, which installed it there. [`benign_template`] names the benign kind of a group
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

/// What a GitHub login is, for the collector.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LoginClass<'a> {
    /// A coding-agent App in the declared-agents catalog
    /// ([`crate::identity::DeclaredApp`]): tallied, not grouped.
    Declared(&'a crate::identity::DeclaredApp),
    /// An undeclared App whose login claims a declared product's name,
    /// acting outside the provider's own organisations: a spoofing lead,
    /// tallied by login.
    Lookalike(&'a crate::identity::DeclaredApp),
    /// Other automation ([`is_automation`]): dropped.
    Automation,
    Person,
}

/// The class of `login`, acting on a repository of `repo_owner`, against the
/// bundled catalog. An App named like a product on its provider's own
/// repository is the provider's own automation.
pub fn classify_login(login: &str, repo_owner: &str) -> LoginClass<'static> {
    static CATALOG: OnceLock<crate::identity::Catalog> = OnceLock::new();
    let c = CATALOG.get_or_init(crate::identity::Catalog::bundled);
    if let Some(a) = c.github_app(login) {
        LoginClass::Declared(a)
    } else if let Some(a) = c
        .github_lookalike(login)
        .filter(|a| !c.provider_repo(a, repo_owner))
    {
        LoginClass::Lookalike(a)
    } else if is_automation(login) {
        LoginClass::Automation
    } else {
        LoginClass::Person
    }
}

/// Repositories built to receive pull requests from first-time
/// contributors (`owner/repo`, lower case): a burst of new accounts on one
/// is what they are for.
pub const PRACTICE_TARGETS: &[&str] = &[
    "firstcontributions/first-contributions",
    "github/training-kit",
    "skills/introduction-to-github",
    "eddiehubcommunity/eddiehubcommunity",
];

/// Whether `target` is a [`PRACTICE_TARGETS`] repository.
pub fn practice_target(target: &str) -> bool {
    PRACTICE_TARGETS.contains(&target.to_ascii_lowercase().as_str())
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
    fn declared_coding_agents_and_lookalikes() {
        let declared = |l: &str| match classify_login(l, "someone") {
            LoginClass::Declared(a) => Some(a.provider.as_str()),
            _ => None,
        };
        assert_eq!(declared("claude[bot]"), Some("Anthropic"));
        assert_eq!(declared("chatgpt-codex-connector[bot]"), Some("OpenAI"));
        assert_eq!(declared("Copilot"), Some("GitHub"));
        assert_eq!(declared("google-labs-jules[bot]"), Some("Google"));
        match classify_login("claude-fleet[bot]", "someone") {
            LoginClass::Lookalike(a) => assert_eq!(a.provider, "Anthropic"),
            o => panic!("{o:?}"),
        }
        assert!(matches!(
            classify_login("codex-runner-7[bot]", "someone"),
            LoginClass::Lookalike(_)
        ));
        // A user login that names a product is a person, not an App.
        assert_eq!(classify_login("claude-fan", "someone"), LoginClass::Person);
        assert_eq!(
            classify_login("dependabot[bot]", "someone"),
            LoginClass::Automation
        );
        assert!(practice_target("FirstContributions/first-contributions"));
    }

    #[test]
    fn a_vendor_name_alone_or_the_vendors_own_app_is_no_spoofing_lead() {
        // The provider's name claims no product: its other Apps carry it.
        assert_eq!(
            classify_login("openai-sdks[bot]", "someone"),
            LoginClass::Automation
        );
        assert_eq!(
            classify_login("anthropic-release[bot]", "someone"),
            LoginClass::Automation
        );
        // A product's name on the provider's own repository: its own App.
        assert_eq!(
            classify_login("copilot-cli-release-app[bot]", "github"),
            LoginClass::Automation
        );
        assert_eq!(
            classify_login("codex-release[bot]", "OpenAI"),
            LoginClass::Automation
        );
        // The same names anywhere else stay leads.
        assert!(matches!(
            classify_login("copilot-cli-release-app[bot]", "someone"),
            LoginClass::Lookalike(a) if a.provider == "GitHub"
        ));
        assert!(matches!(
            classify_login("claude-fleet[bot]", "openai"),
            LoginClass::Lookalike(a) if a.provider == "Anthropic"
        ));
        assert!(matches!(
            classify_login("codex-runner-7[bot]", ""),
            LoginClass::Lookalike(_)
        ));
    }

    #[test]
    fn a_catalog_name_must_be_a_word_of_the_product_or_its_login() {
        let toml = |names: &str| {
            format!(
                "[[github_app]]\nlogin = \"chatgpt-codex-connector[bot]\"\nprovider = \"OpenAI\"\nproduct = \"Codex\"\nnames = [{names}]\nsource = \"https://example.org/\"\n"
            )
        };
        assert!(crate::identity::Catalog::from_toml(&toml("\"codex\", \"chatgpt\"")).is_ok());
        let e = crate::identity::Catalog::from_toml(&toml("\"codex\", \"openai\"")).unwrap_err();
        assert!(e.contains("`openai`"), "{e}");
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
