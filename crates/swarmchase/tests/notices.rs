//! Notice lint on a directory with no notices.

use crate::common::{Scratch, ok};

#[test]
fn lint_passes_on_an_empty_directory() {
    let s = Scratch::new("notices");
    std::fs::create_dir_all(s.path().join("notices")).unwrap();
    let r = ok(s.path(), &["notice", "--dir", "notices", "lint"]);
    assert!(r.stdout.contains("notices OK (0 checked)"), "{}", r.stdout);
}
