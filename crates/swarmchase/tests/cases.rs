//! A case from open to verified bundle, in a scratch data directory.

use crate::common::{Scratch, ok, run, samples, with_samples};

/// The stable key of the sample records' strongest cluster.
fn first_cluster_key(dir: &std::path::Path, files: &[String]) -> String {
    let r = ok(dir, &with_samples(&["clusters"], files));
    let line = r.stdout.lines().find(|l| l.starts_with("C1 ")).unwrap();
    line.split_whitespace().nth(1).unwrap().to_string()
}

/// The hosts listed in a case.toml.
fn hosts(case_toml: &str) -> Vec<String> {
    case_toml
        .lines()
        .filter_map(|l| l.strip_prefix("host = \""))
        .map(|h| h.trim_end_matches('"').to_string())
        .collect()
}

#[test]
fn case_from_a_cluster_key_to_a_verified_bundle() {
    let s = Scratch::new("case");
    let files = samples();
    let data = s.path().join("data");
    let data = data.to_str().unwrap();
    let key = first_cluster_key(s.path(), &files);

    let r = ok(
        s.path(),
        &with_samples(
            &[
                "case",
                "--data",
                data,
                "new",
                "it-1",
                "--title",
                "Sample",
                "--cluster",
                &key,
            ],
            &files,
        ),
    );
    assert!(r.stdout.contains("opened "), "{}", r.stdout);
    let r = ok(s.path(), &["case", "--data", data, "status", "it-1"]);
    assert!(r.stdout.starts_with("# it-1: Sample"), "{}", r.stdout);
    assert!(r.stdout.contains("(pinned)"), "{}", r.stdout);

    // Every endpoint at once, with the state last as in the one-host form.
    let toml_path = s.path().join("data/cases/it-1/case.toml");
    let hs = hosts(&std::fs::read_to_string(&toml_path).unwrap());
    assert!(!hs.is_empty());
    let mut args = vec!["case", "--data", data, "endpoint", "it-1"];
    args.extend(hs.iter().map(String::as_str));
    args.push("targeted");
    ok(s.path(), &args);
    let toml = std::fs::read_to_string(&toml_path).unwrap();
    assert!(!toml.contains("unreviewed"), "{toml}");
    // A host the case does not hold changes nothing.
    let r = run(
        s.path(),
        &[
            "case",
            "--data",
            data,
            "endpoint",
            "it-1",
            &hs[0],
            "nowhere.example",
            "historical",
        ],
    );
    assert!(
        !r.ok && r.stderr.contains("nowhere.example"),
        "{}",
        r.stderr
    );
    assert_eq!(std::fs::read_to_string(&toml_path).unwrap(), toml);
    // A near miss names the host it probably meant.
    let typo = format!("{}x", hs[0]);
    let r = run(
        s.path(),
        &[
            "case",
            "--data",
            data,
            "endpoint",
            "it-1",
            &typo,
            "historical",
        ],
    );
    assert!(
        !r.ok && r.stderr.contains(&format!("did you mean `{}`?", hs[0])),
        "{}",
        r.stderr
    );

    // Drafts for every contact whose role implies an audience; the send is
    // recorded from the draft itself.
    let operator = format!("security@{}", hs[0]);
    for (party, address) in [
        ("operator", operator.as_str()),
        ("registrar", "abuse@registrar.example"),
    ] {
        ok(
            s.path(),
            &[
                "case",
                "--data",
                data,
                "contact",
                "add",
                "it-1",
                "--party",
                party,
                "--org",
                "Example",
                "--channel",
                "email",
                "--address",
                address,
                "--source",
                "https://example.org/contact",
                "--endpoint",
                &hs[0],
            ],
        );
    }
    let r = ok(
        s.path(),
        &["case", "--data", data, "draft", "it-1", "--all"],
    );
    assert!(
        r.stdout
            .contains("skipped abuse@registrar.example (registrar): draft by hand"),
        "{}",
        r.stdout
    );
    let eml = r
        .stdout
        .lines()
        .find_map(|l| l.strip_prefix("wrote "))
        .and_then(|l| l.split(" (not sent").next())
        .unwrap_or_else(|| panic!("no draft in\n{}", r.stdout))
        .to_string();
    assert!(eml.ends_with(".eml") && eml.contains("affected"), "{eml}");
    assert_eq!(r.stdout.matches("wrote ").count(), 1, "{}", r.stdout);
    ok(
        s.path(),
        &["case", "--data", data, "sent", "it-1", "--draft", &eml],
    );
    let toml = std::fs::read_to_string(&toml_path).unwrap();
    assert!(
        toml.contains(&format!("recipient = \"{operator}\"")),
        "{toml}"
    );
    assert!(toml.contains("channel = \"email\""), "{toml}");
    // Nothing left to draft for: the operator was sent to.
    let r = run(
        s.path(),
        &["case", "--data", data, "draft", "it-1", "--all"],
    );
    assert!(!r.ok, "{}", r.stdout);
    assert!(r.stdout.contains("already sent"), "{}", r.stdout);
    // A draft for someone else is refused.
    let r = run(
        s.path(),
        &[
            "case",
            "--data",
            data,
            "sent",
            "it-1",
            "--draft",
            &eml,
            "--to",
            "other@example.org",
        ],
    );
    assert!(!r.ok && r.stderr.contains("the draft"), "{}", r.stderr);

    let r = ok(s.path(), &["case", "--data", data, "bundle", "it-1"]);
    let bundle = r
        .stdout
        .lines()
        .find_map(|l| l.strip_prefix("wrote "))
        .unwrap_or_else(|| panic!("no bundle path in\n{}", r.stdout))
        .to_string();
    let r = ok(s.path(), &["case", "--data", data, "verify", &bundle]);
    assert!(r.stdout.contains("verified"), "{}", r.stdout);

    // A rename moves the case; the old ID is gone.
    ok(
        s.path(),
        &["case", "--data", data, "rename", "it-1", "it-2"],
    );
    ok(s.path(), &["case", "--data", data, "status", "it-2"]);
    let r = run(s.path(), &["case", "--data", data, "status", "it-1"]);
    assert!(!r.ok);
    assert!(r.stderr.contains("did you mean `it-2`?"), "{}", r.stderr);
}

#[test]
fn an_empty_data_directory_gets_a_hint() {
    let s = Scratch::new("hint");
    let r = run(s.path(), &["review", "--data", "nothing-here"]);
    assert!(!r.ok);
    assert!(
        r.stderr.contains("hint: no watch data or cases in"),
        "{}",
        r.stderr
    );
    assert!(r.stderr.contains("nothing-here"), "{}", r.stderr);
    assert!(
        r.stderr.contains("SWARMCHASE_DATA is not set"),
        "{}",
        r.stderr
    );
    // The path is absolute, so it says where the command looked.
    let abs = std::path::absolute(s.path().join("nothing-here")).unwrap();
    assert!(r.stderr.contains(&*abs.to_string_lossy()), "{}", r.stderr);

    let r = ok(s.path(), &["case", "--data", "nothing-here", "status"]);
    assert!(r.stdout.contains("no cases in"), "{}", r.stdout);
}
