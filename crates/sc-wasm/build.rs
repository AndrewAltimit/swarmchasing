//! The bundled rules as JSON, so the module needs no TOML parser at run
//! time (see `sc-rules-wasm`). The same structural conversion edited rules
//! go through; a test checks it reads as `Rules::default_rules` does.

use std::path::PathBuf;
use std::{env, fs};

fn main() {
    let src = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("cargo sets this"))
        .join("../../rules/default.toml");
    println!("cargo:rerun-if-changed={}", src.display());
    let text = fs::read_to_string(&src).expect("reading rules/default.toml");
    let v: toml::Value = toml::from_str(&text).expect("rules/default.toml must parse");
    let json = serde_json::to_string(&v).expect("rules as JSON");
    let dest =
        PathBuf::from(env::var("OUT_DIR").expect("cargo sets this")).join("default_rules.json");
    fs::write(dest, json).expect("writing default_rules.json");
}
