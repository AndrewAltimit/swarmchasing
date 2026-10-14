//! Drafts and exports for one recipient each: an address listed for two
//! operators' endpoints is two recipients, `draft --all` keeps going past a
//! draft already in the outbox, and an operator's export is named after it.

use crate::common::{Scratch, ok, run};
use std::path::{Path, PathBuf};

const SHARED: &str = "abuse@hosting.example";

/// A data directory holding case `sh-1`: one probe run over two operators'
/// hosts, both listing the same hosting company's address, and a provider.
fn data(s: &Scratch) -> String {
    let dir = s.path().join("data/cases/sh-1");
    std::fs::create_dir_all(dir.join("raw")).unwrap();
    let records: String = (0..6)
        .map(|i| {
            let host = if i % 2 == 0 {
                "portal.alpha.example"
            } else {
                "shop.beta.example"
            };
            format!(
                "{{\"id\":\"r{i}\",\"source\":\"urlquery\",\"ts\":{},\"url\":\"https://r.jina.ai/https://{host}/q?id={i}%20UNION%20SELECT%201&uqtag=zz9\"}}\n",
                1_791_000_000 + i * 40
            )
        })
        .collect();
    std::fs::write(dir.join("raw/records.ndjson"), records).unwrap();
    let mut toml = String::from(
        "id = \"sh-1\"\ntitle = \"Shared host\"\nstatus = \"open\"\nnotice = \"active\"\nopened = \"2026-10-12\"\n",
    );
    for host in ["portal.alpha.example", "shop.beta.example"] {
        toml += &format!("[[endpoint]]\nhost = \"{host}\"\nstate = \"targeted\"\n");
    }
    for (org, role, endpoint, address) in [
        ("Alpha", "affected", Some("portal.alpha.example"), SHARED),
        ("Beta", "affected", Some("shop.beta.example"), SHARED),
        ("Provider", "provider", None, "security@provider.example"),
    ] {
        toml += &format!(
            "[[contact]]\norg = \"{org}\"\nrole = \"{role}\"\n{}channel = \"email\"\naddress = \"{address}\"\nsource = \"\"\nconfidence = \"medium\"\nfound_on = \"2026-10-12\"\n",
            endpoint.map_or_else(String::new, |e| format!("endpoint = \"{e}\"\n"))
        );
    }
    std::fs::write(dir.join("case.toml"), toml).unwrap();
    s.path().join("data").to_string_lossy().into_owned()
}

/// `case --data <data>` and `rest`.
fn cmd<'a>(data: &'a str, rest: &[&'a str]) -> Vec<&'a str> {
    [&["case", "--data", data][..], rest].concat()
}

fn files(dir: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(dir)
        .map(|r| r.map(|e| e.unwrap().path()).collect())
        .unwrap_or_default();
    v.sort();
    v
}

/// The one file in `dir` whose name holds `part`.
fn named(dir: &Path, part: &str) -> PathBuf {
    let hits: Vec<PathBuf> = files(dir)
        .into_iter()
        .filter(|p| p.file_name().unwrap().to_string_lossy().contains(part))
        .collect();
    assert_eq!(hits.len(), 1, "{part} in {:?}", files(dir));
    hits[0].clone()
}

#[test]
fn one_address_for_two_operators_is_two_recipients() {
    let s = Scratch::new("drafts-shared");
    let data = data(&s);

    // The address alone names neither operator.
    let r = run(
        s.path(),
        &cmd(
            &data,
            &["draft", "sh-1", "--audience", "affected", "--to", SHARED],
        ),
    );
    assert!(!r.ok);
    assert!(r.stderr.contains("--endpoint"), "{}", r.stderr);
    assert!(
        r.stderr.contains("portal[.]alpha[.]example") && r.stderr.contains("shop[.]beta[.]example"),
        "{}",
        r.stderr
    );
    let r = run(
        s.path(),
        &cmd(
            &data,
            &["report", "sh-1", "--audience", "affected", "--to", SHARED],
        ),
    );
    assert!(!r.ok && r.stderr.contains("--endpoint"), "{}", r.stderr);

    // With the endpoint, each operator gets its own draft, of its own host.
    for endpoint in ["portal.alpha.example", "shop[.]beta[.]example"] {
        ok(
            s.path(),
            &cmd(
                &data,
                &[
                    "draft",
                    "sh-1",
                    "--audience",
                    "affected",
                    "--to",
                    SHARED,
                    "--endpoint",
                    endpoint,
                ],
            ),
        );
    }
    let outbox = s.path().join("data/cases/sh-1/outbox");
    named(&outbox, "portal-alpha");
    named(&outbox, "shop-beta");
    // What each draft says, as the report for the same recipient.
    for endpoint in ["portal.alpha.example", "shop.beta.example"] {
        ok(
            s.path(),
            &cmd(
                &data,
                &[
                    "report",
                    "sh-1",
                    "--audience",
                    "affected",
                    "--to",
                    SHARED,
                    "--endpoint",
                    endpoint,
                ],
            ),
        );
    }
    let reports = s.path().join("data/cases/sh-1/reports");
    let alpha = std::fs::read_to_string(named(&reports, "portal-alpha")).unwrap();
    let beta = std::fs::read_to_string(named(&reports, "shop-beta")).unwrap();
    assert!(alpha.contains("portal[.]alpha[.]example"), "{alpha}");
    assert!(!alpha.contains("shop[.]beta"), "{alpha}");
    assert!(beta.contains("shop[.]beta[.]example"), "{beta}");
    assert!(!beta.contains("portal[.]alpha"), "{beta}");

    // An endpoint the address is not listed for is refused.
    let r = run(
        s.path(),
        &cmd(
            &data,
            &[
                "draft",
                "sh-1",
                "--audience",
                "affected",
                "--to",
                SHARED,
                "--endpoint",
                "other.example",
            ],
        ),
    );
    assert!(!r.ok && r.stderr.contains("not listed"), "{}", r.stderr);
}

#[test]
fn draft_all_drafts_each_recipient_and_keeps_going_past_existing_drafts() {
    let s = Scratch::new("drafts-all");
    let data = data(&s);
    let outbox = s.path().join("data/cases/sh-1/outbox");

    let r = ok(s.path(), &cmd(&data, &["draft", "sh-1", "--all"]));
    assert_eq!(
        files(&outbox).len(),
        3,
        "{}\n{:?}",
        r.stdout,
        files(&outbox)
    );
    let alpha = named(&outbox, "portal-alpha");
    let beta = named(&outbox, "shop-beta");
    named(&outbox, "provider-security-provider-example");

    // The first draft is kept with its edits; one missing later is still
    // written.
    std::fs::write(&alpha, "edited").unwrap();
    std::fs::remove_file(&beta).unwrap();
    let r = ok(s.path(), &cmd(&data, &["draft", "sh-1", "--all"]));
    assert!(r.stdout.contains("draft exists"), "{}", r.stdout);
    assert_eq!(std::fs::read_to_string(&alpha).unwrap(), "edited");
    assert!(beta.is_file(), "{}", r.stdout);
    // --force writes them all again.
    ok(
        s.path(),
        &cmd(&data, &["draft", "sh-1", "--all", "--force"]),
    );
    assert_ne!(std::fs::read_to_string(&alpha).unwrap(), "edited");

    // A send recorded from one operator's draft leaves the other's due.
    for p in files(&outbox) {
        std::fs::remove_file(p).unwrap();
    }
    ok(s.path(), &cmd(&data, &["draft", "sh-1", "--all"]));
    let alpha = named(&outbox, "portal-alpha");
    ok(
        s.path(),
        &cmd(&data, &["sent", "sh-1", "--draft", alpha.to_str().unwrap()]),
    );
    for p in files(&outbox) {
        std::fs::remove_file(p).unwrap();
    }
    let r = ok(s.path(), &cmd(&data, &["draft", "sh-1", "--all"]));
    assert!(
        r.stdout.contains(
            "abuse@hosting.example for portal[.]alpha[.]example (affected): already sent"
        ),
        "{}",
        r.stdout
    );
    named(&outbox, "shop-beta");
    assert!(
        !files(&outbox)
            .iter()
            .any(|p| p.to_string_lossy().contains("portal-alpha")),
        "{:?}",
        files(&outbox)
    );
}

#[test]
fn an_operators_export_is_named_for_it_and_never_overwritten() {
    let s = Scratch::new("drafts-export");
    let data = data(&s);
    let exports = s.path().join("data/cases/sh-1/exports");
    let export = |endpoint: &str, more: &[&str]| {
        let mut a = cmd(
            &data,
            &[
                "export",
                "sh-1",
                "--audience",
                "affected",
                "--to",
                SHARED,
                "--endpoint",
                endpoint,
            ],
        );
        a.extend_from_slice(more);
        run(s.path(), &a)
    };
    assert!(export("portal.alpha.example", &[]).ok);
    assert!(export("shop.beta.example", &[]).ok);
    let alpha = named(&exports, "portal-alpha");
    let beta = named(&exports, "shop-beta");
    assert!(alpha.to_string_lossy().ends_with(".stix.json"));
    let a = std::fs::read_to_string(&alpha).unwrap();
    let b = std::fs::read_to_string(&beta).unwrap();
    assert!(a.contains("portal.alpha.example") && !a.contains("shop.beta"));
    assert!(b.contains("shop.beta.example") && !b.contains("portal.alpha"));

    // Again on the same day: refused unless forced.
    let r = export("portal.alpha.example", &[]);
    assert!(!r.ok && r.stderr.contains("--force"), "{}", r.stderr);
    assert!(export("portal.alpha.example", &["--force"]).ok);
    let r = export("portal.alpha.example", &["--format", "misp"]);
    assert!(r.ok, "{}", r.stderr);
    named(&exports, ".misp.json");
    assert_eq!(files(&exports).len(), 3, "{:?}", files(&exports));
}
