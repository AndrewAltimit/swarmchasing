# sc-publish

Public notices as files, and the site and feed built from them. The [`swarmchase`](../swarmchase/README.md) CLI's `notice` commands use it to check, update and build notices; committing a notice file is what publishes it.

It reads and writes no files and opens no connections: it takes text and returns text, and the caller does the I/O. What a notice may carry, the withholding view and the leak lint, is in [`sc-core`](../sc-core/README.md#modules) (`notice`), because reports and the browser need it too.

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
| [`file`](src/file.rs) | The notice file: TOML front matter (status, providers, affected hosts, dated updates) and the Markdown body; appending an update; the check that gates publication (no DRAFT banner, updates in order, nothing `lint_public` flags). |
| [`markdown`](src/markdown.rs) | The body as plain blocks (headings, paragraphs, quotes, lists, tables) and inline spans, which the page inserts as text. |
| [`feed`](src/feed.rs) | The Atom feed, one entry per update, newest first. |
| [`site`](src/site.rs) | The notice index and per-notice pages the site loads, and the feed, as files to write. |

## Tests

```sh
cargo test -p sc-publish
```
