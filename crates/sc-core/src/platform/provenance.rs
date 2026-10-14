//! Build provenance of a candidate's packages: where the registry says a
//! release was built. npm's SLSA provenance statements and PyPI's publish
//! attestations name the source repository, the CI workflow, the ref and
//! commit, and the runner, signed by the CI's identity. The watch looks them
//! up for members of reported registry candidates
//! (`sc_collect::provenance`); this module holds what is kept and what a
//! candidate says about it.
//!
//! The repository is kept plain as `owner/repo`, as event targets are: it
//! is a public project, and the platform module hashes the accounts that
//! act, not the projects acted on. No publisher login, email address or
//! certificate is kept.
//!
//! Several packages built from one repository or one workflow is a strong
//! hint of one operator, still a hint: a monorepo publishes many packages
//! from one workflow by design. No member with provenance is weak context
//! only, since most packages carry none. Provenance changes neither a
//! candidate's chance nor its strength.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Where one package release says it was built.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PackageProvenance {
    /// The member event (`npm:<name>@<version>`, `pypi:<name>@<version>`).
    pub member: String,
    /// The package name.
    pub package: String,
    /// The code host the build ran on (`github`, `gitlab`), lower case.
    pub forge: String,
    /// The source repository as `owner/repo` (on GitLab, the full project
    /// path).
    pub repo: String,
    /// The workflow file in the repository (`.github/workflows/release.yml`);
    /// empty when the attestation does not say.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub workflow: String,
    /// The ref built (`refs/tags/v1.0.0`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_ref: Option<String>,
    /// The commit built.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    /// The runner (`github-hosted`, `self-hosted`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runner: Option<String>,
    /// The deployment environment the publisher named (PyPI).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
}

impl PackageProvenance {
    /// `forge:owner/repo`.
    pub fn source(&self) -> String {
        format!("{}:{}", self.forge, self.repo)
    }

    /// `forge:owner/repo:workflow`, or `None` without a workflow.
    pub fn workflow_key(&self) -> Option<String> {
        (!self.workflow.is_empty()).then(|| format!("{}:{}", self.source(), self.workflow))
    }
}

/// What a candidate's members' provenance says.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CandidateProvenance {
    /// Members with an answer: provenance or a registry saying there is
    /// none. A failed lookup is not an answer.
    pub looked_up: usize,
    /// Members whose release carries provenance.
    pub with: usize,
    /// Source repositories (`forge:owner/repo`) by distinct packages built
    /// there, most first.
    pub repos: Vec<(String, usize)>,
    /// Workflows (`forge:owner/repo:path`) by distinct packages, most first.
    pub workflows: Vec<(String, usize)>,
    /// Several packages of the candidate name one source repository.
    pub shared_repo: bool,
    /// Several packages of the candidate name one workflow.
    pub shared_workflow: bool,
    /// Each member's provenance.
    pub records: Vec<PackageProvenance>,
}

impl CandidateProvenance {
    /// Sum up `records` from `looked_up` answered lookups.
    pub fn new(looked_up: usize, mut records: Vec<PackageProvenance>) -> Self {
        records.sort();
        records.dedup();
        let mut repos: BTreeMap<String, BTreeSet<&str>> = BTreeMap::new();
        let mut workflows: BTreeMap<String, BTreeSet<&str>> = BTreeMap::new();
        for r in &records {
            repos.entry(r.source()).or_default().insert(&r.package);
            if let Some(w) = r.workflow_key() {
                workflows.entry(w).or_default().insert(&r.package);
            }
        }
        let ranked = |m: BTreeMap<String, BTreeSet<&str>>| {
            let mut v: Vec<(String, usize)> = m.into_iter().map(|(k, s)| (k, s.len())).collect();
            v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
            v
        };
        let repos = ranked(repos);
        let workflows = ranked(workflows);
        let with = records
            .iter()
            .map(|r| r.member.as_str())
            .collect::<BTreeSet<_>>()
            .len();
        Self {
            looked_up,
            with,
            shared_repo: repos.first().is_some_and(|r| r.1 >= 2),
            shared_workflow: workflows.first().is_some_and(|w| w.1 >= 2),
            repos,
            workflows,
            records,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(member: &str, package: &str, repo: &str, workflow: &str) -> PackageProvenance {
        PackageProvenance {
            member: member.into(),
            package: package.into(),
            forge: "github".into(),
            repo: repo.into(),
            workflow: workflow.into(),
            ..Default::default()
        }
    }

    #[test]
    fn several_packages_from_one_repository_are_shared() {
        let p = CandidateProvenance::new(
            4,
            vec![
                rec("npm:a@1", "a", "o/r", ".github/workflows/p.yml"),
                rec("npm:b@1", "b", "o/r", ".github/workflows/p.yml"),
                rec("npm:c@1", "c", "x/y", ""),
            ],
        );
        assert_eq!(p.with, 3);
        assert!(p.shared_repo && p.shared_workflow);
        assert_eq!(p.repos[0], ("github:o/r".to_string(), 2));
        assert_eq!(p.workflows.len(), 1);
    }

    #[test]
    fn versions_of_one_package_are_not_shared() {
        let p = CandidateProvenance::new(
            2,
            vec![
                rec("npm:a@1", "a", "o/r", "w.yml"),
                rec("npm:a@2", "a", "o/r", "w.yml"),
            ],
        );
        assert_eq!(p.with, 2);
        assert!(!p.shared_repo && !p.shared_workflow);
        let none = CandidateProvenance::new(3, vec![]);
        assert_eq!(none.with, 0);
        assert!(!none.shared_repo);
    }
}
