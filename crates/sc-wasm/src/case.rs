//! Evidence bundle check for the Tools page, in the tools module. The page
//! checks the manifest hashes itself (Web Crypto); this re-runs the analysis
//! and compares it with the stamp through `sc_case::bundle::check`, the same
//! check `swarmchase case verify` runs, and lists the attribution layers the
//! re-run supports, with any claims from case work merged in. The manifest's
//! signature is checked here too, against the key file the site publishes.

use sc_case::bundle::Checked;
use sc_core::attribution::{LayerSummary, merge, summaries};
use sc_core::{Claim, Evidence, Rules};
use wasm_bindgen::prelude::*;

/// Where the page says to find the rules a bundle was made with.
const RULES_HINT: &str = "load the rules it was made with in the Rules tab";

/// Re-run a bundle's analysis and compare it with its stamp. `rules_json`
/// empty means the bundled rules; `claims_json` is the claims array from
/// case work (as `report --claims` reads it), or empty. Returns `{"stamp":
/// Stamp, "differences": [...], "notes": [...], "rules_version": "...",
/// "analysis": Analysis, "layers": [LayerSummary], "withheld": n}`; no
/// differences means the bundle verifies. `analysis` is the re-run, not the
/// bundle's copy. `layers` is gated as a report at the default naming level
/// is: `withheld` counts the developer candidates below it.
#[wasm_bindgen]
pub fn verify_bundle(
    records_ndjson: &str,
    analysis_json: &str,
    stamp_json: &str,
    rules_json: &str,
    claims_json: &str,
) -> Result<String, JsError> {
    let rules = super::rules_from(rules_json)?;
    let claims = super::parse_claims(claims_json).map_err(|e| JsError::new(&e))?;
    let out = check(records_ndjson, analysis_json, stamp_json, &rules, &claims)
        .map_err(|e| JsError::new(&e))?;
    serde_json::to_string(&out).map_err(|e| JsError::new(&e.to_string()))
}

fn check(
    records_ndjson: &str,
    analysis_json: &str,
    stamp_json: &str,
    rules: &Rules,
    case_claims: &[Claim],
) -> Result<Verified, String> {
    let checked = sc_case::bundle::check(
        records_ndjson,
        analysis_json,
        stamp_json,
        rules,
        env!("CARGO_PKG_VERSION"),
        RULES_HINT,
    )?;
    // The claims every report on this bundle would see: case work's, then
    // each cluster's own, merged as the CLI merges them.
    let a = &checked.analysis;
    let claims = a.clusters.iter().fold(case_claims.to_vec(), |acc, c| {
        merge(acc, &sc_core::attribute(a, c))
    });
    let layers = summaries(&claims, Evidence::default());
    let withheld = claims
        .iter()
        .filter(|c| c.role == sc_core::Role::Developer && !c.nameable(Evidence::default()))
        .count();
    Ok(Verified {
        checked,
        layers,
        withheld,
    })
}

/// Check a bundle's `MANIFEST.sha256.sig` (`signature`, empty when the
/// bundle has none) over `manifest` against `public_keys`, the text of the
/// site's published key file (empty when it publishes none), through
/// `sc_case::signing::check` as `swarmchase case verify` does. Returns
/// `{"status": "signed"|"unchecked"|"invalid"|"unsigned", "key_id", "reason",
/// "line", "published": [key id]}`. A key file that does not parse throws.
#[wasm_bindgen]
pub fn verify_signature(
    manifest: &str,
    signature: &str,
    public_keys: &str,
) -> Result<String, JsError> {
    signature_check(manifest, signature, public_keys)
        .map(|v| v.to_string())
        .map_err(|e| JsError::new(&e))
}

fn signature_check(
    manifest: &str,
    signature: &str,
    public_keys: &str,
) -> Result<serde_json::Value, String> {
    use sc_case::signing::{check, parse_public_keys};
    let keys = if public_keys.trim().is_empty() {
        Vec::new()
    } else {
        parse_public_keys(public_keys).map_err(|e| format!("published key file: {e}"))?
    };
    let sig = (!signature.trim().is_empty()).then_some(signature);
    let c = check(manifest, sig, &keys);
    let mut v = serde_json::to_value(&c).map_err(|e| e.to_string())?;
    v["line"] = c.line().into();
    v["published"] = keys.iter().map(|k| k.key_id()).collect::<Vec<_>>().into();
    Ok(v)
}

/// `verify_bundle`'s result: the check, then the layers.
#[derive(serde::Serialize)]
struct Verified {
    #[serde(flatten)]
    checked: Checked,
    layers: Vec<LayerSummary>,
    withheld: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use sc_core::{Observation, Stamp, analyze};

    fn bundle(rules: &Rules) -> (String, String, String) {
        let records: Vec<Observation> = (0..4)
            .map(|i| Observation {
                id: format!("r{i}"),
                ts: 1_791_000_000 + i * 40,
                url: format!(
                    "https://r.jina.ai/https://portal.example.gov/q?id={i}%20UNION%20SELECT%201&uqtag=zz9"
                ),
                ..Default::default()
            })
            .collect();
        let nd: String = records
            .iter()
            .map(|r| serde_json::to_string(r).unwrap() + "\n")
            .collect();
        let a = analyze(records, rules);
        let st = Stamp::new("t-1", "2026-10-12", env!("CARGO_PKG_VERSION"), None, &a);
        (
            nd,
            serde_json::to_string(&a).unwrap(),
            serde_json::to_string(&st).unwrap(),
        )
    }

    fn checkv(r: &str, a: &str, st: &str, claims: &[Claim]) -> serde_json::Value {
        serde_json::to_value(check(r, a, st, &Rules::default_rules(), claims).unwrap()).unwrap()
    }

    #[test]
    fn a_fresh_bundle_verifies_with_its_layers() {
        let (nd, a, st) = bundle(&Rules::default_rules());
        let v = checkv(&nd, &a, &st, &[]);
        assert_eq!(v["differences"].as_array().unwrap().len(), 0, "{v}");
        assert_eq!(v["stamp"]["case"], "t-1");
        assert_eq!(v["analysis"]["total"], 4);
        assert!(v["withheld"].is_number());
        // Case claims join the layers.
        let claims: Vec<Claim> = serde_json::from_str(
            r#"[{"party":"Example AI","role":"developer","evidence":"provider_confirmed","details":["confirmed in writing"]}]"#,
        )
        .unwrap();
        let v = checkv(&nd, &a, &st, &claims);
        let dev = v["layers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|l| l["layer"] == "developer")
            .unwrap();
        assert_eq!(dev["party"], "Example AI");
        assert_eq!(dev["label"], "confirmed");
    }

    #[test]
    fn signatures_check_against_the_published_file() {
        use sc_case::signing::{SecretKey, public_key_file};
        let k = SecretKey::from_seed(&[4; 32]);
        let manifest = "aa  records.ndjson
";
        let sig = k.sign_manifest(manifest);
        let file = public_key_file(&[k.public()]);
        let v = signature_check(manifest, &sig, &file).unwrap();
        assert_eq!(v["status"], "signed");
        assert_eq!(v["key_id"], k.public().key_id());
        assert_eq!(v["published"][0], k.public().key_id());
        let v = signature_check(
            "bb  records.ndjson
",
            &sig,
            &file,
        )
        .unwrap();
        assert_eq!(v["status"], "invalid");
        assert!(v["line"].as_str().unwrap().starts_with("signature invalid"));
        let other = public_key_file(&[SecretKey::from_seed(&[5; 32]).public()]);
        assert_eq!(
            signature_check(manifest, &sig, &other).unwrap()["status"],
            "invalid"
        );
        assert_eq!(
            signature_check(manifest, "", &file).unwrap()["status"],
            "unsigned"
        );
        assert_eq!(
            signature_check(manifest, &sig, "").unwrap()["status"],
            "unchecked"
        );
        assert!(signature_check(manifest, &sig, "ed25519 nope").is_err());
    }

    #[test]
    fn other_rules_name_the_rules_tab() {
        let rules = Rules::default_rules();
        let (nd, a, st) = bundle(&rules);
        let other = st.replace(&rules.set.meta.version, "0000-00-00");
        let v = checkv(&nd, &a, &other, &[]);
        let d = v["differences"][0].as_str().unwrap();
        assert!(
            d.starts_with("rules version ") && d.ends_with(RULES_HINT),
            "{d}"
        );
        assert!(
            check("{bad", &a, &st, &rules, &[])
                .err()
                .unwrap()
                .starts_with("records.ndjson")
        );
    }
}
