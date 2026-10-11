# sc-publish

Public notices as files, and the site and feed built from them. The [`swarmchase`](../swarmchase/README.md) CLI's `notice` commands use it to check, update and build notices; committing a notice file is what publishes it.

The library opens no connections, and outside its `build` module it reads and writes no files: it takes text and returns text, and the caller does the I/O. `build` is that caller for the public site, shared by the `sc-site` binary and `swarmchase site build`: it reads committed inputs only, refuses anything under `data/` or `$SWARMCHASE_DATA`, and writes the site ([browser toolkit](../../docs/reference/browser-toolkit.md#how-the-site-is-built)). What a notice may carry, the withholding view and the leak lint, is in [`sc-core`](../sc-core/README.md#modules) (`notice`), because reports and the browser need it too; the notice format and the linter built on it are in [`sc-case`](../sc-case/README.md).

## Use

It is a workspace crate (not published):

```rust
use sc_core::Rules;
use sc_publish::{build_site, check_notice, parse_notice};

let rules = Rules::default_rules();
let mut notice = parse_notice(&text)?; // notices/<id>.md
let problems = check_notice(&notice, &rules); // empty when it may be published
let files = build_site(&mut [notice], "https://example.github.io/swarmchasing/", &rules)?;
for (path, contents) in files {
    // index.json, <id>.json, feed.xml: the caller writes them
}
```

## Modules

| Module | Covers |
|---|---|
| [`file`](src/file.rs) | The notice file (front matter, dated updates, Markdown body) and `check_notice`, the gate on publication: both from [`sc-case`](../sc-case/README.md), whose notice linter checks front matter, anything a notice withholds, and wording. |
| [`markdown`](src/markdown.rs) | The body as plain blocks (headings, paragraphs, quotes, lists, tables) and inline spans, which the page inserts as text. |
| [`feed`](src/feed.rs) | The Atom feed, one entry per update, newest first. |
| [`site`](src/site.rs) | The notice index and per-notice JSON, and the feed, as files to write (`notice build`). |
| [`pages`](src/pages/mod.rs) | Every page of the public site, from notices, docs, the rules and the labelled set: layout, Markdown docs, notices, rules explorer, evaluation, charts. |
| [`build`](src/build.rs) | Reads the committed inputs and writes the site into a directory (`build_site_dir`). |
| [`sc-site`](src/bin/sc-site.rs) | The binary around `build`; `swarmchase site build` calls the same entry. |

## Tests

```sh
cargo test -p sc-publish
```
