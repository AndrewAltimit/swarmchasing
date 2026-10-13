//! The bundled rules and the declared-agent catalog as JSON, so the module
//! needs no TOML parser at run time (see `sc-rules-wasm`). The same
//! structural conversion edited rules go through; tests check each reads as
//! its TOML does.

use std::path::PathBuf;
use std::{env, fs};

fn main() {
    convert("rules/default.toml", "default_rules.json");
    convert("declared-agents.toml", "declared_agents.json");
}

/// `<repo>/<from>` (TOML) as `<OUT_DIR>/<to>` (JSON).
fn convert(from: &str, to: &str) {
    let src = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("cargo sets this"))
        .join("../..")
        .join(from);
    println!("cargo:rerun-if-changed={}", src.display());
    let text = fs::read_to_string(&src).unwrap_or_else(|e| panic!("reading {from}: {e}"));
    let v: toml::Value = toml::from_str(&text).unwrap_or_else(|e| panic!("{from} must parse: {e}"));
    let json = serde_json::to_string(&v).expect("TOML as JSON");
    let dest = PathBuf::from(env::var("OUT_DIR").expect("cargo sets this")).join(to);
    fs::write(dest, json).unwrap_or_else(|e| panic!("writing {to}: {e}"));
}
