//! Every released `rules/default.toml` still loads as a pinned copy.
//!
//! A case renders with the rules it was pinned to, so a rules file from an
//! earlier release must keep loading after an option it holds is retired.
//! `fixtures/rules-history/` holds each released version, named by its
//! `[meta] version`. Add the outgoing file there when a release retires a
//! key.

use sc_core::Rules;
use std::path::Path;

#[test]
fn every_released_rules_file_loads_as_a_pin() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/rules-history");
    let mut names: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "toml"))
        .collect();
    names.sort();
    assert!(!names.is_empty(), "no fixtures in {}", dir.display());
    let mut retired = 0;
    for p in &names {
        let text = std::fs::read_to_string(p).unwrap();
        let (rules, warnings) =
            Rules::from_toml_lenient(&text).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
        assert!(!rules.set.rules.is_empty(), "{}", p.display());
        for w in &warnings {
            assert!(w.contains("rules: ignored "), "{}: {w}", p.display());
        }
        if Rules::from_toml(&text).is_err() {
            assert!(!warnings.is_empty(), "{}", p.display());
            retired += 1;
        }
    }
    // The fixtures include files with keys since retired, so the lenient
    // path is exercised, not only the strict one.
    assert!(retired > 0);
}

/// The shipped rules stay strict: a key they do not know fails the load.
#[test]
fn the_shipped_rules_load_strictly() {
    assert!(Rules::from_toml(sc_core::DEFAULT_RULES).is_ok());
    let misspelt = sc_core::DEFAULT_RULES.replace("[biclique]", "[biclique]\nswapz = 9");
    assert!(Rules::from_toml(&misspelt).is_err());
    let (_, w) = Rules::from_toml_lenient(&misspelt).unwrap();
    assert_eq!(w.len(), 1, "{w:?}");
}
