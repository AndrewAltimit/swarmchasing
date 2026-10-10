//! Rules files (TOML) to the JSON the analysis module reads.
//!
//! The analysis module (`sc-wasm`) takes rules as JSON, which keeps a TOML
//! parser out of the module every analysis page downloads. Edited rules are
//! TOML, as the CLI reads them; the site loads this small module only when
//! there are edited rules to convert. The conversion is structural (a TOML
//! value to the same JSON value): `sc-wasm` deserialises the rule set from
//! it exactly as `Rules::from_toml` does from the TOML.

use wasm_bindgen::prelude::*;

/// The TOML text as JSON, or the parse error.
pub fn to_json(toml_text: &str) -> Result<String, String> {
    let v: toml::Value = toml::from_str(toml_text).map_err(|e| format!("rules: {e}"))?;
    serde_json::to_string(&v).map_err(|e| format!("rules: {e}"))
}

/// A rules file as JSON; throws with the TOML parse error.
#[wasm_bindgen]
pub fn rules_json(toml_text: &str) -> Result<String, JsError> {
    to_json(toml_text).map_err(|e| JsError::new(&e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sc_core::{RuleSet, Rules};

    fn same(toml_text: &str) {
        let direct = Rules::from_toml(toml_text).unwrap().set;
        let via: RuleSet = serde_json::from_str(&to_json(toml_text).unwrap()).unwrap();
        assert_eq!(
            serde_json::to_string(&direct).unwrap(),
            serde_json::to_string(&via).unwrap()
        );
    }

    #[test]
    fn json_reads_as_the_toml_does() {
        same(sc_core::DEFAULT_RULES);
        same(
            r#"
[meta]
version = "x"
[linking]
archive_burst_ratio = 7.5
[[rule]]
id = "a.b"
kind = "relay"
target = "url"
pattern = '''(?i)\bx\s+"y"'''
weight = 4
link = true
"#,
        );
        assert!(to_json("[[rule]\nid=").unwrap_err().starts_with("rules: "));
    }
}
