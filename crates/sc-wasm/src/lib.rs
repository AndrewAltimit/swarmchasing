//! Browser bindings. Everything crosses the boundary as JSON strings so the
//! page needs nothing but `JSON.parse`.
//!
//! The crate builds two modules from one source, by feature:
//!
//! - `engine` (the default): what every analysis page loads on arrival,
//!   `analyze`, `unwrap`, `endpoints` and the small helpers ([`engine`]).
//! - `tools`: report drafts, the evidence bundle check and the
//!   labelled-set eval ([`tools`], [`case`]), plus everything the engine
//!   has. Keeping them out of the engine keeps the module the unwrap, rules
//!   and landing pages download small; carrying the engine's bindings lets
//!   the workbench load this one module for both its analysis and its
//!   report, never the two.
//!
//! Both carry the helpers in this file. Tests build both.
//!
//! Rules arrive as JSON: the bundled rules are converted when the module is
//! built, and edited rules (TOML, as the CLI reads them) by the small
//! `sc-rules-wasm` module, which keeps a TOML parser out of these.

use sc_core::{Analysis, Claim, RuleSet, Rules};
use std::cell::RefCell;
use wasm_bindgen::prelude::*;

#[cfg(any(feature = "tools", test))]
mod case;
#[cfg(any(feature = "engine", feature = "tools", test))]
mod engine;
#[cfg(any(feature = "tools", test))]
mod tools;

thread_local! {
    /// The analysis the module holds: the latest `analyze` (engine) or
    /// `prepare` (tools) result, which `endpoints`, `report`, `sightings`
    /// and `attribution` read. One slot, so in the tools module a report
    /// follows from the analysis the page shows without a re-run.
    static HELD: RefCell<Option<Analysis>> = const { RefCell::new(None) };
}

/// Keep `a` as the module's analysis.
fn hold(a: Analysis) {
    HELD.with(|h| *h.borrow_mut() = Some(a));
}

/// Drop the module's analysis, so the memory it held is free for the next.
#[cfg(any(feature = "engine", feature = "tools", test))]
fn release() {
    HELD.with(|h| *h.borrow_mut() = None);
}

/// Run `f` on the module's analysis; `missing` is the error without one.
fn with_held<T>(
    missing: &str,
    f: impl FnOnce(&Analysis) -> Result<T, JsError>,
) -> Result<T, JsError> {
    HELD.with(|h| match h.borrow().as_ref() {
        Some(a) => f(a),
        None => Err(JsError::new(missing)),
    })
}

/// `rules/default.toml` as JSON, converted by `build.rs`.
const DEFAULT_RULES_JSON: &str = include_str!(concat!(env!("OUT_DIR"), "/default_rules.json"));

/// A rule set from its JSON; empty means the bundled rules.
fn parse_rules(json: &str) -> Result<Rules, String> {
    let text = if json.trim().is_empty() {
        DEFAULT_RULES_JSON
    } else {
        json
    };
    let set: RuleSet = serde_json::from_str(text).map_err(|e| format!("rules: {e}"))?;
    Rules::compile(set)
}

fn rules_from(json: &str) -> Result<Rules, JsError> {
    parse_rules(json).map_err(|e| JsError::new(&e))
}

fn json<T: serde::Serialize>(v: &T) -> Result<String, JsError> {
    serde_json::to_string(v).map_err(|e| JsError::new(&e.to_string()))
}

fn parse_claims(text: &str) -> Result<Vec<Claim>, String> {
    if text.trim().is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_str(text).map_err(|e| format!("claims: {e}"))
}

/// Validate rules; returns `{"rules":n,"asns":n,"version":"..."}`.
#[wasm_bindgen]
pub fn check_rules(rules_json: &str) -> Result<String, JsError> {
    let r = rules_from(rules_json)?;
    Ok(serde_json::json!({"rules": r.set.rules.len(), "asns": r.set.asns.len(), "version": r.set.meta.version}).to_string())
}

#[wasm_bindgen]
pub fn defang(text: &str) -> String {
    sc_core::defang(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    // The bundled JSON, and edited TOML through sc-rules-wasm, read as the
    // CLI reads the TOML.
    #[test]
    fn json_rules_match_the_toml() {
        let as_json = |set: &RuleSet| serde_json::to_string(set).unwrap();
        let bundled = parse_rules("").unwrap();
        assert_eq!(as_json(&bundled.set), as_json(&Rules::default_rules().set));
        let edited = sc_core::DEFAULT_RULES.replace("weight = 2\n", "weight = 5\n");
        let via = parse_rules(&sc_rules_wasm::to_json(&edited).unwrap()).unwrap();
        assert_eq!(
            as_json(&via.set),
            as_json(&Rules::from_toml(&edited).unwrap().set)
        );
        assert!(parse_rules("{\"rule\": 3}").is_err_and(|e| e.starts_with("rules: ")));
    }

    #[test]
    fn claims_are_checked_against_the_cli_schema() {
        assert_eq!(parse_claims("  ").unwrap(), Vec::new());
        let ok = r#"[{"party":"Example AI","role":"developer","evidence":"provider_confirmed"}]"#;
        assert_eq!(
            parse_claims(ok).unwrap()[0].evidence,
            sc_core::Evidence::ProviderConfirmed
        );
        assert!(parse_claims(r#"[{"party":"X","role":"developer","evidence":"rumour"}]"#).is_err());
    }
}
