//! Evidence bundles and e-mail drafts for private reports.
//!
//! A bundle is a directory sent with a report:
//!
//! ```text
//! records.ndjson    the redacted records the report rests on
//! analysis.json     the analysis of those records
//! stamp.json        rules version, toolkit version and commit, and the tier of
//!                   every flagged record and cluster at the time
//! MANIFEST.sha256   SHA-256 of each file above
//! ```
//!
//! `verify` checks the manifest, re-runs the analysis from `records.ndjson`
//! and fails if any tier or cluster differs from the stamp, so a recipient (or
//! we, later) can confirm the report follows from the records.

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use sc_core::{Analysis, Observation, Rules, Stamp, analyze};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const FILES: [&str; 3] = ["records.ndjson", "analysis.json", "stamp.json"];

/// The stamp of an analysis, with this toolkit's version.
pub fn stamp(case: &str, generated: &str, commit: Option<String>, a: &Analysis) -> Stamp {
    Stamp::new(case, generated, env!("CARGO_PKG_VERSION"), commit, a)
}

/// The commit of the checkout the CLI runs in, when there is one.
pub fn git_commit() -> Option<String> {
    let out = std::process::Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Write a bundle into a new directory under `parent`, named by date.
pub fn write(
    parent: &Path,
    case: &str,
    records: &[Observation],
    rules: &Rules,
    today: &str,
    commit: Option<String>,
) -> Result<PathBuf> {
    let mut dir = parent.join(today);
    let mut n = 2;
    while dir.exists() {
        dir = parent.join(format!("{today}-{n}"));
        n += 1;
    }
    std::fs::create_dir_all(&dir)?;
    let a = analyze(records.to_vec(), rules);
    let st = stamp(case, today, commit, &a);
    let contents = [
        crate::store::to_ndjson(records)?,
        serde_json::to_string(&a)?,
        serde_json::to_string_pretty(&st)?,
    ];
    let mut manifest = String::new();
    for (name, text) in FILES.iter().zip(&contents) {
        std::fs::write(dir.join(name), text)?;
        manifest.push_str(&format!("{}  {name}\n", sha256_hex(text.as_bytes())));
    }
    std::fs::write(dir.join("MANIFEST.sha256"), manifest)?;
    Ok(dir)
}

/// A bundle's stamp.
pub fn read_stamp(dir: &Path) -> Result<Stamp> {
    let p = dir.join("stamp.json");
    let text = std::fs::read_to_string(&p).with_context(|| format!("reading {}", p.display()))?;
    serde_json::from_str(&text).context("parsing stamp.json")
}

/// Check a bundle. Returns the differences found; empty means it verifies.
pub fn verify(dir: &Path, rules: &Rules) -> Result<Vec<String>> {
    let mut diffs = Vec::new();
    let manifest = std::fs::read_to_string(dir.join("MANIFEST.sha256"))
        .with_context(|| format!("no MANIFEST.sha256 in {}", dir.display()))?;
    let listed: BTreeMap<&str, &str> = manifest
        .lines()
        .filter_map(|l| l.split_once("  "))
        .map(|(h, f)| (f.trim(), h.trim()))
        .collect();
    for f in FILES {
        let Some(want) = listed.get(f) else {
            diffs.push(format!("{f}: not in the manifest"));
            continue;
        };
        let got = sha256_hex(&std::fs::read(dir.join(f)).with_context(|| format!("reading {f}"))?);
        if &got != want {
            diffs.push(format!("{f}: SHA-256 differs from the manifest"));
        }
    }
    let st = read_stamp(dir)?;
    if st.rules_version != rules.set.meta.version {
        diffs.push(format!(
            "rules version {} differs from the bundle's {}; verify with the rules it was made with (--rules)",
            rules.set.meta.version, st.rules_version
        ));
    }
    let records =
        sc_core::stamp::parse_records(&std::fs::read_to_string(dir.join("records.ndjson"))?)
            .map_err(anyhow::Error::msg)
            .context("parsing records.ndjson")?;
    diffs.extend(st.differences(&analyze(records, rules)));
    // The bundle's own analysis should match its stamp too. One written by an
    // older toolkit may not parse; that is noted, not counted.
    let shipped =
        std::fs::read_to_string(dir.join("analysis.json")).context("reading analysis.json")?;
    match serde_json::from_str::<Analysis>(&shipped) {
        Ok(a) => diffs.extend(
            st.differences(&a)
                .into_iter()
                .map(|d| format!("analysis.json: {d}")),
        ),
        Err(e) => eprintln!("analysis.json not compared: {e}"),
    }
    Ok(diffs)
}

/// An unsent RFC 5322 message: the report as the body, the bundle files as
/// attachments. `X-Unsent: 1` makes mail clients open it as a draft; the
/// admin reviews and sends it from their own account.
pub fn eml(to: &str, subject: &str, body: &str, attachments: &[(String, Vec<u8>)]) -> String {
    let boundary = format!("swarmchase-{}", &sha256_hex(body.as_bytes())[..16]);
    let mut m = String::new();
    let mut line = |s: &str| {
        m.push_str(s);
        m.push_str("\r\n");
    };
    line(&format!("To: {}", to.replace(['\r', '\n'], "")));
    line(&format!("Subject: {}", subject.replace(['\r', '\n'], " ")));
    line("X-Unsent: 1");
    line("MIME-Version: 1.0");
    line(&format!(
        "Content-Type: multipart/mixed; boundary=\"{boundary}\""
    ));
    line("");
    line(&format!("--{boundary}"));
    line("Content-Type: text/plain; charset=utf-8");
    line("Content-Transfer-Encoding: base64");
    line("");
    for chunk in wrap_b64(body.as_bytes()) {
        line(&chunk);
    }
    for (name, bytes) in attachments {
        line(&format!("--{boundary}"));
        line(&format!(
            "Content-Type: application/octet-stream; name=\"{name}\""
        ));
        line(&format!(
            "Content-Disposition: attachment; filename=\"{name}\""
        ));
        line("Content-Transfer-Encoding: base64");
        line("");
        for chunk in wrap_b64(bytes) {
            line(&chunk);
        }
    }
    line(&format!("--{boundary}--"));
    m
}

fn wrap_b64(bytes: &[u8]) -> Vec<String> {
    let s = base64::engine::general_purpose::STANDARD.encode(bytes);
    s.as_bytes()
        .chunks(76)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect()
}

/// The bundle's files, for attaching.
pub fn attachments(dir: &Path) -> Result<Vec<(String, Vec<u8>)>> {
    FILES
        .iter()
        .chain(std::iter::once(&"MANIFEST.sha256"))
        .map(|f| Ok((f.to_string(), std::fs::read(dir.join(f))?)))
        .collect()
}

/// Fail with the differences, or say it verified.
pub fn report_verify(dir: &Path, rules: &Rules) -> Result<()> {
    let diffs = verify(dir, rules)?;
    if diffs.is_empty() {
        println!(
            "{}: verified (manifest, tiers and clusters match)",
            dir.display()
        );
        return Ok(());
    }
    for d in &diffs {
        eprintln!("{d}");
    }
    bail!("{}: {} difference(s)", dir.display(), diffs.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn records() -> Vec<Observation> {
        (0..4)
            .map(|i| Observation {
                id: format!("r{i}"),
                ts: 1_791_000_000 + i * 40,
                url: format!(
                    "https://r.jina.ai/https://portal.example.gov/q?id={i}%20UNION%20SELECT%201&uqtag=zz9"
                ),
                ..Default::default()
            })
            .collect()
    }

    #[test]
    fn bundle_verifies_and_detects_tampering() {
        let parent = std::env::temp_dir().join(format!("swarmchase-bundle-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&parent);
        let rules = Rules::default_rules();
        let dir = write(&parent, "t", &records(), &rules, "2026-10-12", None).unwrap();
        assert!(verify(&dir, &rules).unwrap().is_empty());
        let second = write(&parent, "t", &records(), &rules, "2026-10-12", None).unwrap();
        assert!(second.ends_with("2026-10-12-2"));

        // Drop a record and fix up the manifest: the hash check passes, the
        // re-analysis does not.
        let nd = std::fs::read_to_string(dir.join("records.ndjson")).unwrap();
        let fewer: String = nd.lines().skip(1).map(|l| format!("{l}\n")).collect();
        std::fs::write(dir.join("records.ndjson"), &fewer).unwrap();
        let diffs = verify(&dir, &rules).unwrap();
        assert!(diffs.iter().any(|d| d.contains("SHA-256")), "{diffs:?}");
        let manifest = std::fs::read_to_string(dir.join("MANIFEST.sha256"))
            .unwrap()
            .replace(&sha256_hex(nd.as_bytes()), &sha256_hex(fewer.as_bytes()));
        std::fs::write(dir.join("MANIFEST.sha256"), manifest).unwrap();
        let diffs = verify(&dir, &rules).unwrap();
        assert!(!diffs.iter().any(|d| d.contains("SHA-256")), "{diffs:?}");
        assert!(
            diffs.iter().any(|d| d.contains("records, stamp says 4")),
            "{diffs:?}"
        );
        std::fs::remove_dir_all(&parent).unwrap();
    }

    #[test]
    fn eml_is_a_draft_with_attachments() {
        let m = eml(
            "security@example.org\r\nBcc: x@evil.example",
            "Report",
            "Hello ünïcode",
            &[("records.ndjson".into(), b"{}\n".to_vec())],
        );
        assert!(m.starts_with("To: security@example.orgBcc: x@evil.example\r\n"));
        assert!(!m.contains("\r\nBcc:"), "no header injection");
        assert!(m.contains("X-Unsent: 1\r\n"));
        assert!(m.contains("filename=\"records.ndjson\""));
        assert!(m.contains(&base64::engine::general_purpose::STANDARD.encode("Hello ünïcode")));
        assert!(m.trim_end().ends_with("--"));
    }
}
