//! Evidence bundles and e-mail drafts for private reports, as files.
//!
//! What a bundle holds, its manifest and the stamp check are
//! [`sc_case::bundle`]; this module writes bundles into a case directory,
//! reads them back to verify them, adds the rules' figures on the committed
//! evaluation set to the stamp, signs the manifest when there is a signing
//! key ([`crate::signing`]), and builds unsent `.eml` drafts.

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use sc_case::bundle::{FILES, MANIFEST, check, contents, manifest_differences};
use sc_case::signing::{SIGNATURE, SecretKey, SignatureCheck};
use sc_core::{Observation, Rules, Stamp, analyze};
use std::path::{Path, PathBuf};

pub use sc_case::bundle::sha256_hex;

/// The committed evaluation set: `SWARMCHASE_EVAL_DIR`, else `samples/eval`
/// in the working directory, else the one in the checkout this was built from.
pub(crate) fn eval_dir() -> Option<PathBuf> {
    let built = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../samples/eval");
    std::env::var_os("SWARMCHASE_EVAL_DIR")
        .map(PathBuf::from)
        .into_iter()
        .chain([PathBuf::from("samples/eval"), built])
        .find(|p| p.is_dir())
}

/// Precision and recall of `rules` on the labelled records in `dir`
/// (`*.ndjson` carrying `label`). `None` when there are none.
pub(crate) fn eval_snapshot(dir: &Path, rules: &Rules) -> Option<sc_core::EvalSnapshot> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .ok()?
        .filter_map(|e| Some(e.ok()?.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "ndjson"))
        .collect();
    files.sort();
    let (mut records, mut labels) = (Vec::new(), sc_core::LabelSet::default());
    for p in &files {
        let text = std::fs::read_to_string(p).ok()?;
        let parsed = sc_core::parse_input(&text, sc_core::Format::Ndjson, &Default::default());
        records.extend(parsed.observations);
        labels.labels.extend(sc_core::parse_labels(&text).labels);
    }
    if labels.labels.is_empty() {
        return None;
    }
    let r = sc_core::evaluate(&analyze(records, rules), &labels);
    Some(sc_core::EvalSnapshot::of(&r))
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

/// Write a bundle into a new directory under `parent`, named by date. The
/// stamp carries this toolkit's version and, when the committed evaluation
/// set can be found, the rules' figures on it. With `signer`, the manifest
/// is signed into [`SIGNATURE`].
pub fn write(
    parent: &Path,
    case: &str,
    records: &[Observation],
    rules: &Rules,
    today: &str,
    commit: Option<String>,
    signer: Option<&SecretKey>,
) -> Result<PathBuf> {
    let mut dir = parent.join(today);
    let mut n = 2;
    while dir.exists() {
        dir = parent.join(format!("{today}-{n}"));
        n += 1;
    }
    std::fs::create_dir_all(&dir)?;
    let eval = eval_dir().and_then(|d| eval_snapshot(&d, rules));
    let b = contents(
        case,
        today,
        env!("CARGO_PKG_VERSION"),
        commit,
        records,
        rules,
        eval,
    )
    .map_err(anyhow::Error::msg)?;
    for (name, text) in &b.files {
        std::fs::write(dir.join(name), text)?;
        if let (Some(k), true) = (signer, *name == MANIFEST) {
            std::fs::write(dir.join(SIGNATURE), k.sign_manifest(text))?;
        }
    }
    Ok(dir)
}

/// A bundle's stamp.
pub fn read_stamp(dir: &Path) -> Result<Stamp> {
    let p = dir.join("stamp.json");
    let text = std::fs::read_to_string(&p).with_context(|| format!("reading {}", p.display()))?;
    serde_json::from_str(&text).context("parsing stamp.json")
}

/// Check a bundle. Returns the differences found; empty means it verifies.
/// What was noticed but does not fail it is printed to stderr.
pub fn verify(dir: &Path, rules: &Rules) -> Result<Vec<String>> {
    let manifest = std::fs::read_to_string(dir.join(MANIFEST))
        .with_context(|| format!("no {MANIFEST} in {}", dir.display()))?;
    let mut diffs = manifest_differences(&manifest, |f| {
        std::fs::read(dir.join(f)).map_err(|e| e.to_string())
    })
    .map_err(anyhow::Error::msg)?;
    let read =
        |f: &str| std::fs::read_to_string(dir.join(f)).with_context(|| format!("reading {f}"));
    let checked = check(
        &read("records.ndjson")?,
        &read("analysis.json")?,
        &read("stamp.json")?,
        rules,
        env!("CARGO_PKG_VERSION"),
        "verify with the rules it was made with (--rules)",
    )
    .map_err(anyhow::Error::msg)?;
    diffs.extend(checked.differences);
    for n in &checked.notes {
        eprintln!("{n}");
    }
    Ok(diffs)
}

/// The bundle's signature checked against `published` keys.
pub fn signature(dir: &Path, published: &[sc_case::signing::PublicKey]) -> Result<SignatureCheck> {
    let manifest = std::fs::read_to_string(dir.join(MANIFEST))
        .with_context(|| format!("no {MANIFEST} in {}", dir.display()))?;
    let p = dir.join(SIGNATURE);
    let sig = match std::fs::read_to_string(&p) {
        Ok(t) => Some(t),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e).with_context(|| format!("reading {}", p.display())),
    };
    Ok(sc_case::signing::check(
        &manifest,
        sig.as_deref(),
        published,
    ))
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

/// The bundle's files, for attaching: the signature too when there is one.
pub fn attachments(dir: &Path) -> Result<Vec<(String, Vec<u8>)>> {
    FILES
        .iter()
        .chain([&MANIFEST, &SIGNATURE])
        .filter(|f| **f != SIGNATURE || dir.join(f).is_file())
        .map(|f| Ok((f.to_string(), std::fs::read(dir.join(f))?)))
        .collect()
}

/// Fail with the differences, or say it verified. The signature is checked
/// against the keys in `key` or the published key file
/// ([`crate::signing::published`]); an invalid one fails, an unsigned
/// bundle does not.
pub fn report_verify(dir: &Path, rules: &Rules, key: Option<&Path>) -> Result<()> {
    let mut diffs = verify(dir, rules)?;
    let (key_file, keys) = crate::signing::published(key)?;
    let sig = signature(dir, &keys)?;
    match (&sig, &key_file) {
        (SignatureCheck::Signed { .. }, Some(p)) => {
            println!("{}, published in {}", sig.line(), p.display())
        }
        (SignatureCheck::Invalid { .. }, _) => diffs.push(sig.line()),
        _ => println!("{}", sig.line()),
    }
    if let Ok(st) = read_stamp(dir) {
        let pct = |x: Option<f64>| x.map_or("n/a".into(), |v| format!("{:.1}%", v * 100.0));
        println!(
            "stamped {} with rules {} following {}",
            st.generated,
            st.rules_version,
            st.method
                .as_deref()
                .unwrap_or("no method version (older stamp)")
        );
        if let Some(e) = &st.eval {
            println!(
                "evaluation at stamp time ({} labelled records): suggestive precision {} recall {}, significant precision {} recall {}",
                e.labelled,
                pct(e.suggestive_precision),
                pct(e.suggestive_recall),
                pct(e.significant_precision),
                pct(e.significant_recall)
            );
        }
    }
    if diffs.is_empty() {
        let signed = if matches!(sig, SignatureCheck::Signed { .. }) {
            "signature, "
        } else {
            ""
        };
        println!(
            "{}: verified ({signed}manifest, tiers and clusters match)",
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
        let dir = write(&parent, "t", &records(), &rules, "2026-10-12", None, None).unwrap();
        assert!(verify(&dir, &rules).unwrap().is_empty());
        let st = read_stamp(&dir).unwrap();
        assert_eq!(st.method.as_deref(), Some(sc_core::stamp::METHOD));
        let snap = st.eval.expect("the committed evaluation set is found");
        assert_eq!(snap.rules_version, rules.set.meta.version);
        assert!(snap.labelled > 0 && snap.suggestive_precision.is_some());

        // A bundle stamped before the method and eval fields still verifies.
        let old = parent.join("old");
        std::fs::create_dir_all(&old).unwrap();
        let mut v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join("stamp.json")).unwrap())
                .unwrap();
        v.as_object_mut().unwrap().remove("method");
        v.as_object_mut().unwrap().remove("eval");
        let files = [
            std::fs::read_to_string(dir.join("records.ndjson")).unwrap(),
            std::fs::read_to_string(dir.join("analysis.json")).unwrap(),
            serde_json::to_string_pretty(&v).unwrap(),
        ];
        let mut manifest = String::new();
        for (name, text) in FILES.iter().zip(&files) {
            std::fs::write(old.join(name), text).unwrap();
            manifest.push_str(&format!("{}  {name}\n", sha256_hex(text.as_bytes())));
        }
        std::fs::write(old.join("MANIFEST.sha256"), manifest).unwrap();
        assert!(verify(&old, &rules).unwrap().is_empty());
        let second = write(&parent, "t", &records(), &rules, "2026-10-12", None, None).unwrap();
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
    fn a_signed_bundle_verifies_and_tampering_breaks_it() {
        let parent = std::env::temp_dir().join(format!("swarmchase-signed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&parent);
        let rules = Rules::default_rules();
        let key = SecretKey::from_seed(&[11; 32]);
        let published = [key.public()];
        let dir = write(
            &parent,
            "t",
            &records(),
            &rules,
            "2026-10-12",
            None,
            Some(&key),
        )
        .unwrap();
        let signed = SignatureCheck::Signed {
            key_id: key.public().key_id(),
        };
        assert_eq!(signature(&dir, &published).unwrap(), signed);
        assert!(verify(&dir, &rules).unwrap().is_empty());
        let names: Vec<String> = attachments(&dir)
            .unwrap()
            .into_iter()
            .map(|a| a.0)
            .collect();
        assert_eq!(names.last().map(String::as_str), Some(SIGNATURE));
        let key_file = parent.join("k.pub");
        std::fs::write(&key_file, sc_case::signing::public_key_file(&published)).unwrap();
        report_verify(&dir, &rules, Some(&key_file)).unwrap();

        // Another key, published instead: the signature does not count.
        let other = [SecretKey::from_seed(&[12; 32]).public()];
        assert!(signature(&dir, &other).unwrap().fails());
        let other_file = parent.join("other.pub");
        std::fs::write(&other_file, sc_case::signing::public_key_file(&other)).unwrap();
        assert!(report_verify(&dir, &rules, Some(&other_file)).is_err());

        // A record dropped: the manifest check catches it while the
        // signature still holds; fixing the manifest up breaks the signature.
        let nd = std::fs::read_to_string(dir.join("records.ndjson")).unwrap();
        let fewer: String = nd.lines().skip(1).map(|l| format!("{l}\n")).collect();
        std::fs::write(dir.join("records.ndjson"), &fewer).unwrap();
        assert_eq!(signature(&dir, &published).unwrap(), signed);
        assert!(
            verify(&dir, &rules)
                .unwrap()
                .iter()
                .any(|d| d.contains("SHA-256"))
        );
        let manifest = std::fs::read_to_string(dir.join(MANIFEST))
            .unwrap()
            .replace(&sha256_hex(nd.as_bytes()), &sha256_hex(fewer.as_bytes()));
        std::fs::write(dir.join(MANIFEST), manifest).unwrap();
        assert!(signature(&dir, &published).unwrap().fails());
        assert!(report_verify(&dir, &rules, Some(&key_file)).is_err());

        // Unsigned: reported, not failed.
        let plain = write(&parent, "t", &records(), &rules, "2026-10-12", None, None).unwrap();
        assert_eq!(
            signature(&plain, &published).unwrap(),
            SignatureCheck::Unsigned
        );
        assert!(
            !attachments(&plain)
                .unwrap()
                .iter()
                .any(|a| a.0 == SIGNATURE)
        );
        report_verify(&plain, &rules, Some(&key_file)).unwrap();
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
