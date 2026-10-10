//! Embed the labelled evaluation set, every `samples/eval/*.ndjson` (the files
//! the CI eval gate reads), so the page can test edited rules against it.

use std::path::PathBuf;
use std::{env, fs};

fn main() {
    let dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("cargo sets this"))
        .join("../../samples/eval");
    println!("cargo:rerun-if-changed={}", dir.display());
    let mut files: Vec<PathBuf> = fs::read_dir(&dir)
        .map(|d| {
            d.filter_map(Result::ok)
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|x| x == "ndjson"))
                .collect()
        })
        .unwrap_or_default();
    files.sort();
    let mut out = String::from("pub const EVAL_SET: &[(&str, &str)] = &[\n");
    for f in &files {
        let name = f.file_name().unwrap_or_default().to_string_lossy();
        out += &format!(
            "    ({name:?}, include_str!({:?})),\n",
            f.display().to_string()
        );
    }
    out += "];\n";
    let dest = PathBuf::from(env::var("OUT_DIR").expect("cargo sets this")).join("eval_set.rs");
    fs::write(dest, out).expect("writing eval_set.rs");
}
