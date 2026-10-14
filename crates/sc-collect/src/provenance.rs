//! Build provenance of one package release, looked up by name and version
//! for members of reported registry candidates
//! ([`sc_core::platform::provenance`]): not a stream.
//!
//! - npm: the registry's attestations for a release
//!   (`registry.npmjs.org/-/npm/v1/attestations/<name>@<version>`,
//!   <https://docs.npmjs.com/viewing-package-provenance/>). Of the SLSA
//!   provenance statement only the workflow's repository, path and ref, the
//!   commit and the builder are read.
//! - PyPI: the release's file names from its JSON metadata, then the first
//!   file's provenance (`pypi.org/integrity/<project>/<version>/<file>/provenance`,
//!   <https://docs.pypi.org/attestations/consuming-attestations/>). The
//!   trusted publisher's repository, workflow and environment are read, and
//!   the ref, commit and runner from the signing certificate's Fulcio
//!   extensions. A publisher's email address (Google publishers) is not kept.
//!
//! Metadata only: no tarball, distribution file or repository is
//! downloaded, signatures are not verified (the statement is read as a
//! claim the registry serves), and no publisher login is kept. A 404 is an
//! answer: the release carries no provenance.
//!
//! Terms: npm's Open Source Terms
//! (<https://docs.npmjs.com/policies/open-source-terms>) and PyPI's Terms of
//! Service (<https://policies.python.org/pypi.org/Terms-of-Service/>), as in
//! their record collectors; both endpoints are publicly documented APIs. The
//! watch's per-run budget (`provenance_lookups`) keeps it to a few dozen
//! paced requests a run.

use crate::Client;
use crate::client::Opts;
use anyhow::{Context, Result, bail};
use base64::Engine as _;
use sc_core::platform::PackageProvenance;
use serde_json::Value;
use std::collections::BTreeMap;

const NPM_ATTESTATIONS: &str = "https://registry.npmjs.org/-/npm/v1/attestations/";
const PYPI_JSON: &str = "https://pypi.org/pypi/";
const PYPI_INTEGRITY: &str = "https://pypi.org/integrity/";
/// SLSA provenance's predicate type.
const SLSA: &str = "https://slsa.dev/provenance/";
/// PyPI release files tried for provenance at most.
const MAX_FILES: usize = 2;

fn not_found_ok() -> Opts {
    Opts {
        not_found_ok: true,
        ..Opts::default()
    }
}

/// A member event id's ecosystem, package and version: `npm:<name>@<version>`
/// or `pypi:<name>[@<version>]`. `None` for any other platform.
pub fn split_member(id: &str) -> Option<(&str, &str, Option<&str>)> {
    let (eco, rest) = id.split_once(':')?;
    if !matches!(eco, "npm" | "pypi") || rest.is_empty() {
        return None;
    }
    // A scoped npm name starts with `@`; the version follows the last `@`.
    match rest.rfind('@').filter(|&i| i > 0) {
        Some(i) => Some((
            eco,
            &rest[..i],
            Some(&rest[i + 1..]).filter(|v| !v.is_empty()),
        )),
        None => Some((eco, rest, None)),
    }
}

/// A name or version safe to put in a path; anything else is refused before
/// a request is made.
fn plain(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 214
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@' | '/' | '+'))
}

impl Client {
    /// The build provenance of a member event's release (`npm:` or `pypi:`
    /// id). `Ok(None)` when the release carries none; an error for any other
    /// id or a failed request.
    pub fn package_provenance(&self, member: &str) -> Result<Option<PackageProvenance>> {
        let Some((eco, name, version)) = split_member(member) else {
            bail!("not an npm or PyPI release: {member}");
        };
        if !plain(name) || !version.is_none_or(plain) {
            bail!("not a package name and version: {member}");
        }
        match (eco, version) {
            ("npm", Some(v)) => {
                let url = format!("{NPM_ATTESTATIONS}{}@{v}", name.replace('/', "%2f"));
                let f = self.fetch(&url, &[], not_found_ok())?;
                if f.status == 404 {
                    return Ok(None);
                }
                parse_npm_attestations(&f.body, member, name)
            }
            ("npm", None) => bail!("an npm release needs a version: {member}"),
            _ => {
                if name.contains('/') || version.is_some_and(|v| v.contains('/')) {
                    bail!("not a PyPI project and version: {member}");
                }
                let project = crate::platform::label_key(sc_core::platform::Platform::Pypi, name);
                let url = match version {
                    Some(v) => format!("{PYPI_JSON}{project}/{v}/json"),
                    None => format!("{PYPI_JSON}{project}/json"),
                };
                let f = self.fetch(&url, &[], not_found_ok())?;
                if f.status == 404 {
                    return Ok(None);
                }
                let (version, files) = pypi_files(&f.body)?;
                for file in files.iter().take(MAX_FILES) {
                    if !plain(file) || file.contains('/') {
                        continue;
                    }
                    let url = format!("{PYPI_INTEGRITY}{project}/{version}/{file}/provenance");
                    let f = self.fetch(&url, &[], not_found_ok())?;
                    if f.status == 404 {
                        continue;
                    }
                    return parse_pypi_provenance(&f.body, member, name);
                }
                Ok(None)
            }
        }
    }
}

/// The version and file names from a PyPI release's JSON metadata.
pub fn pypi_files(body: &str) -> Result<(String, Vec<String>)> {
    let v: Value = serde_json::from_str(body).context("PyPI: not JSON")?;
    let version = v
        .pointer("/info/version")
        .and_then(Value::as_str)
        .context("PyPI: no version")?
        .to_string();
    if !plain(&version) || version.contains('/') {
        bail!("PyPI: odd version {version}");
    }
    let files = v
        .get("urls")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|u| u.get("filename").and_then(Value::as_str))
        .map(str::to_string)
        .collect();
    Ok((version, files))
}

/// `https://github.com/owner/repo` (or `git+...@ref`) as (forge, owner/repo).
fn split_repo_url(u: &str) -> Option<(String, String)> {
    let u = u.strip_prefix("git+").unwrap_or(u);
    let rest = u.strip_prefix("https://")?;
    let rest = rest.split('@').next().unwrap_or(rest);
    let (host, path) = rest.split_once('/')?;
    let path = path.trim_end_matches('/').trim_end_matches(".git");
    if path.is_empty() {
        return None;
    }
    let forge = match host {
        "github.com" => "github".to_string(),
        "gitlab.com" => "gitlab".to_string(),
        h => h.to_lowercase(),
    };
    Some((forge, path.to_string()))
}

/// The provenance in an npm attestations response: the SLSA statement's
/// workflow, commit and builder. `None` without a SLSA statement.
pub fn parse_npm_attestations(
    body: &str,
    member: &str,
    package: &str,
) -> Result<Option<PackageProvenance>> {
    let v: Value = serde_json::from_str(body).context("npm attestations: not JSON")?;
    for a in v
        .get("attestations")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let slsa = a
            .get("predicateType")
            .and_then(Value::as_str)
            .is_some_and(|t| t.starts_with(SLSA));
        if !slsa {
            continue;
        }
        let Some(payload) = a
            .pointer("/bundle/dsseEnvelope/payload")
            .and_then(Value::as_str)
        else {
            continue;
        };
        let raw = base64::engine::general_purpose::STANDARD
            .decode(payload)
            .context("npm attestation: payload not base64")?;
        let st: Value = serde_json::from_slice(&raw).context("npm attestation: not JSON")?;
        let p = |path: &str| {
            st.pointer(&format!("/predicate{path}"))
                .and_then(Value::as_str)
                .map(str::to_string)
        };
        let dep = st
            .pointer("/predicate/buildDefinition/resolvedDependencies/0")
            .cloned()
            .unwrap_or(Value::Null);
        let repo_url = p("/buildDefinition/externalParameters/workflow/repository")
            .or_else(|| dep.get("uri").and_then(Value::as_str).map(str::to_string));
        let Some((forge, repo)) = repo_url.as_deref().and_then(split_repo_url) else {
            continue;
        };
        let runner = p("/runDetails/builder/id").map(|b| {
            b.rsplit('/')
                .next()
                .filter(|s| !s.is_empty())
                .unwrap_or(&b)
                .to_string()
        });
        return Ok(Some(PackageProvenance {
            member: member.to_string(),
            package: package.to_string(),
            forge,
            repo,
            workflow: p("/buildDefinition/externalParameters/workflow/path").unwrap_or_default(),
            git_ref: p("/buildDefinition/externalParameters/workflow/ref"),
            commit: dep
                .pointer("/digest/gitCommit")
                .and_then(Value::as_str)
                .map(str::to_string),
            runner,
            environment: None,
        }));
    }
    Ok(None)
}

/// The provenance in a PyPI integrity response: the first bundle's trusted
/// publisher, with the ref, commit and runner from its certificate.
pub fn parse_pypi_provenance(
    body: &str,
    member: &str,
    package: &str,
) -> Result<Option<PackageProvenance>> {
    let v: Value = serde_json::from_str(body).context("PyPI provenance: not JSON")?;
    let Some(b) = v
        .get("attestation_bundles")
        .and_then(Value::as_array)
        .and_then(|a| a.first())
    else {
        return Ok(None);
    };
    let pubr = |k: &str| {
        b.pointer(&format!("/publisher/{k}"))
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };
    let kind = pubr("kind").unwrap_or_default().to_lowercase();
    let ext = b
        .pointer("/attestations/0/verification_material/certificate")
        .and_then(Value::as_str)
        .and_then(|c| base64::engine::general_purpose::STANDARD.decode(c).ok())
        .map(|der| fulcio_extensions(&der))
        .unwrap_or_default();
    let (forge, repo) = match (kind.as_str(), pubr("repository")) {
        ("github", Some(r)) => ("github".to_string(), r),
        ("gitlab", Some(r)) => ("gitlab".to_string(), r),
        _ => match ext.get(&12).and_then(|u| split_repo_url(u)) {
            Some(x) => x,
            None => return Ok(None),
        },
    };
    let workflow = match (
        forge.as_str(),
        pubr("workflow").or(pubr("workflow_filepath")),
    ) {
        ("github", Some(w)) if !w.contains('/') => format!(".github/workflows/{w}"),
        (_, Some(w)) => w,
        _ => String::new(),
    };
    Ok(Some(PackageProvenance {
        member: member.to_string(),
        package: package.to_string(),
        forge,
        repo,
        workflow,
        git_ref: ext.get(&14).cloned(),
        commit: ext.get(&13).cloned(),
        runner: ext.get(&11).cloned(),
        environment: pubr("environment"),
    }))
}

/// Fulcio's certificate extensions (OID `1.3.6.1.4.1.57264.1.<n>`) whose
/// value is a UTF-8 string, by `n`, from a DER certificate. A plain scan
/// for the extension OIDs, enough for the identity fields; anything it
/// cannot read is skipped.
pub fn fulcio_extensions(der: &[u8]) -> BTreeMap<u8, String> {
    // OBJECT IDENTIFIER, length 10, 1.3.6.1.4.1.57264.1.
    const PREFIX: [u8; 11] = [0x06, 0x0a, 0x2b, 6, 1, 4, 1, 0x83, 0xbf, 0x30, 1];
    let len_at = |i: usize| -> Option<(usize, usize)> {
        let b = *der.get(i)?;
        if b & 0x80 == 0 {
            return Some((b as usize, i + 1));
        }
        let k = (b & 0x7f) as usize;
        if k == 0 || k > 2 {
            return None;
        }
        let mut n = 0usize;
        for j in 0..k {
            n = (n << 8) | *der.get(i + 1 + j)? as usize;
        }
        Some((n, i + 1 + k))
    };
    let mut out = BTreeMap::new();
    let mut i = 0;
    while i + PREFIX.len() < der.len() {
        if der[i..i + PREFIX.len()] != PREFIX {
            i += 1;
            continue;
        }
        let n = der[i + PREFIX.len()];
        let mut j = i + PREFIX.len() + 1;
        i += 1;
        // An optional `critical` BOOLEAN.
        if der.get(j) == Some(&0x01) {
            j += 3;
        }
        if der.get(j) != Some(&0x04) {
            continue;
        }
        let Some((len, start)) = len_at(j + 1) else {
            continue;
        };
        let Some(v) = der.get(start..start + len) else {
            continue;
        };
        // The newer extensions wrap a UTF8String; the deprecated ones
        // (1 to 6) hold raw bytes.
        let text = if v.first() == Some(&0x0c) {
            let Some((l, s)) = len_at(start + 1) else {
                continue;
            };
            der.get(s..s + l)
        } else {
            Some(v)
        };
        if let Some(t) = text.and_then(|t| std::str::from_utf8(t).ok()) {
            out.entry(n).or_insert_with(|| t.to_string());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const NPM: &str = include_str!("../tests/fixtures/provenance/npm-sigstore-3.0.0.json");
    const PYPI: &str =
        include_str!("../tests/fixtures/provenance/pypi-sigstore-3.6.1-provenance.json");
    const PYPI_RELEASE: &str =
        include_str!("../tests/fixtures/provenance/pypi-sigstore-3.6.1-release.json");

    #[test]
    fn member_ids_split() {
        assert_eq!(
            split_member("npm:@scope/pkg@1.0.0"),
            Some(("npm", "@scope/pkg", Some("1.0.0")))
        );
        assert_eq!(
            split_member("npm:@scope/pkg"),
            Some(("npm", "@scope/pkg", None))
        );
        assert_eq!(split_member("pypi:newpkg"), Some(("pypi", "newpkg", None)));
        assert_eq!(split_member("gh:123"), None);
    }

    #[test]
    fn reads_npm_slsa_provenance() {
        let p = parse_npm_attestations(NPM, "npm:sigstore@3.0.0", "sigstore")
            .unwrap()
            .unwrap();
        assert_eq!(p.forge, "github");
        assert_eq!(p.repo, "sigstore/sigstore-js");
        assert_eq!(p.workflow, ".github/workflows/release.yml");
        assert_eq!(p.git_ref.as_deref(), Some("refs/heads/main"));
        assert_eq!(
            p.commit.as_deref(),
            Some("3a57a741bfb9f7c3bca69b63e170fc28e9432e69")
        );
        assert_eq!(p.runner.as_deref(), Some("github-hosted"));
        // Only the publish attestation: no provenance.
        let v: Value = serde_json::from_str(NPM).unwrap();
        let only_publish = serde_json::json!({"attestations": [v["attestations"][0]]});
        assert!(
            parse_npm_attestations(&only_publish.to_string(), "npm:x@1", "x")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn reads_pypi_publisher_and_certificate() {
        let (version, files) = pypi_files(PYPI_RELEASE).unwrap();
        assert_eq!(version, "3.6.1");
        assert_eq!(files[0], "sigstore-3.6.1-py3-none-any.whl");
        let p = parse_pypi_provenance(PYPI, "pypi:sigstore@3.6.1", "sigstore")
            .unwrap()
            .unwrap();
        assert_eq!(p.forge, "github");
        assert_eq!(p.repo, "sigstore/sigstore-python");
        assert_eq!(p.workflow, ".github/workflows/release.yml");
        assert_eq!(p.git_ref.as_deref(), Some("refs/tags/v3.6.1"));
        assert_eq!(
            p.commit.as_deref(),
            Some("896cfe13105495e6dc6f8faf23e1007da35edeeb")
        );
        assert_eq!(p.runner.as_deref(), Some("github-hosted"));
        assert_eq!(p.environment, None);
        assert!(
            parse_pypi_provenance(r#"{"attestation_bundles":[]}"#, "pypi:x@1", "x")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn a_google_publisher_keeps_no_email() {
        let body = r#"{"attestation_bundles":[{"publisher":{"kind":"Google","email":"someone@example.com"},"attestations":[]}]}"#;
        assert!(
            parse_pypi_provenance(body, "pypi:x@1", "x")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn repository_urls_split() {
        assert_eq!(
            split_repo_url("git+https://github.com/o/r@refs/heads/main"),
            Some(("github".into(), "o/r".into()))
        );
        assert_eq!(
            split_repo_url("https://gitlab.com/g/sub/p"),
            Some(("gitlab".into(), "g/sub/p".into()))
        );
        assert_eq!(split_repo_url("ftp://x/y"), None);
        assert!(fulcio_extensions(&[0x06, 0x0a, 0x2b]).is_empty());
    }
}
