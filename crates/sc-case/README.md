# sc-case

What a case is and what may be done with it, without I/O. The [`swarmchase`](../swarmchase/README.md) CLI keeps cases as files under `<data>/cases/<id>/` ([case files](../../docs/reference/cases.md)); this crate holds everything about them that is not reading or writing those files, so the CLI, the site build ([`sc-publish`](../sc-publish/README.md)) and the browser toolkit share one copy.

It opens no files or connections, reads no clock and parses no command line: callers pass in the time and the text. It compiles for `wasm32-unknown-unknown`. The enums parse from the words the CLI takes (`FromStr`), so a command line can use them without this crate knowing about clap.

## Use

```rust
use sc_case::{Case, actions, lead, notice};

let mut c = Case::parse(&case_toml)?;
actions::classify(&mut c, &["portal.example.gov".into()], "targeted".parse()?, None, None, None, today)?;
let clock = lead::clock(&c); // when the indicator notice may be added, and each operator named
let problems = notice::lint_notice(&notice::parse_notice(&text)?, &rules); // empty: may be published
let text = c.to_toml()?; // the caller writes it back
```

## Modules

| Module | Covers |
|---|---|
| [`model`](src/model.rs) | What `case.toml` holds: status, admin, endpoints, typed contact roles, claims, sends, fleets, scope findings, naming consent, the self-review and second-review records. |
| [`actions`](src/actions.rs) | The admin's decisions: classify, send, no contact, alternative, claim, grade, plant review, contacts, settings. Each is checked and logged. |
| [`evidence`](src/evidence.rs) | Logs operators send back, and which rendering may use them (`Scope`). |
| [`report`](src/report.rs) | Report options from a case, the hosts a notice may name, who the sends reached, the claims a report sees. |
| [`fleet`](src/fleet.rs) | Fleet merges and splits, and the interaction evidence that makes a fleet a swarm. |
| [`lead`](src/lead.rs) | The indicator and naming clocks each party's report starts, in UTC working days for naming. |
| [`pinning`](src/pinning.rs) | Names for pinned rule sets, and the records whose tier differs between two rule sets. |
| [`checklist`](src/checklist.rs) | The self-review checklist `notice add` and `notice update --naming` run, from inputs the caller gathers. |
| [`bundle`](src/bundle.rs) | Evidence bundle contents, the manifest, and the stamp check (with a lean reader of `analysis.json`). |
| [`incident`](src/incident.rs) | Drafts for the AI Incident Database and the OECD framework, with an EU AI Act Article 73 section. |
| [`notice`](src/notice/mod.rs) | The notice file format and the one notice linter (front matter, leaks, wording). |
| [`providers`](src/providers.rs) | The provider directory, `contacts/providers.toml`, built in. |
| [`text`](src/text.rs) | Text helpers shared with the CLI. |

## Tests

```sh
cargo test -p sc-case
```

Unit tests sit beside the code. [`tests/shapes.rs`](tests/shapes.rs) reads committed fixtures (synthetic records, reserved example names): a `case.toml` with every section, one as the earliest case files were written, and a bundle as `case bundle` writes it. They must keep reading.
