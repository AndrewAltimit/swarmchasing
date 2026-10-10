# sc-collect

Passive collectors for public records: the Wayback Machine and Arquivo.pt CDX indexes, urlquery.net search and reports, crt.sh certificate logs, security.txt and RDAP. They return [`sc-core`](../sc-core/README.md) `Observation`s, with secrets already redacted.

Most people use it through the [`swarmchase`](../swarmchase/README.md) CLI (`collect`, `certs`, `contact`, `watch`, `case contacts`) rather than directly.

## Ground rules

What this crate does and does not implement keeps collection passive:

- It reads **indexes and public records only**. It never opens a captured page or a URL an agent submitted, which may be a live exploit or trigger a callback to the agent's operator.
- It never reads or writes agent callback channels (inboxes, notification topics, pastes).
- It is polite: one request at a time with a minimum interval, an identifying user agent, and backoff when a server is overloaded.
- Records are redacted before they leave the crate.

Archive captures get the id `<archive>:<timestamp>:<digest>` from [`sc_core::capture`](../sc-core/src/capture.rs), the same id an imported CDX export gets, and record their timestamp as a capture time.

A new collector must keep to these. See [docs/policies.md](../../docs/policies.md) for the collection policy.

## Use

It is a workspace crate (not published):

```rust
use sc_collect::{CdxQuery, Client};
use std::time::Duration;

let client = Client::new(Duration::from_millis(1500))?; // minimum gap between requests
let q = CdxQuery {
    pattern: "r.jina.ai/*".into(),
    from: Some("20260901".into()),
    to: None,
    limit: 5000,
    match_type: None,
    collapse_digest: false,
    page_size: 1000,
};
let records = client.wayback_cdx(&q)?;
```

`CdxQuery` also deserialises from a `watchlist.toml` source entry, with `limit` and `page_size` defaulting to 5000 and 1000.

| Method | Source |
|---|---|
| `wayback_cdx`, `wayback_cdx_page` | Wayback Machine CDX index, paged; the page form returns a resume key. |
| `arquivo_cdx` | Arquivo.pt CDX index. |
| `urlquery`, `urlquery_page` | urlquery.net report search. Takes an API key. |
| `urlquery_report` | One urlquery.net report by ID. |
| `crtsh` | Certificate Transparency via crt.sh. |
| `security_txt` | A domain's `/.well-known/security.txt`. |
| `rdap_domain` | A domain's RDAP record, for the registrar's abuse contact. |

`parse_wayback_cdx`, `parse_arquivo_cdx` and `parse_urlquery_search` parse a saved response without the network.

### Sources and paging

The record sources (`Wayback`, `Arquivo`, `Urlquery`, or `source(kind, query, key)`) implement the `Source` trait. `pull(client, since, cursor, limit)` fetches pages through the shared [`pager`](src/pager.rs) until the limit or the end, and returns a `Pull`: the records, the cursor to continue from, whether the source is exhausted, and the requests made. `pull_each` also shows each page as it arrives, so a caller can save progress page by page.

A pull that fails after its first page keeps what it has and says so in `Pull::stopped`; `Pull::strict` turns that back into an error. Wayback's resume key stays valid across runs (`Source::resumable`), so the watch continues a cut-short pull on its next run. A urlquery offset is valid only within one pull.

## Retries

Timeouts, dropped connections, HTTP 429 and 5xx are retried with exponential backoff (5 retries from 5 seconds, each wait capped at 5 minutes), honouring `Retry-After`. Other errors fail at once. Change the policy with `Client::with_retry`. `Client::requests` counts the requests sent, retries included, for sources with a quota.

Error messages name the URL and never a header value, so an API key does not end up in a log.

## Environment

| Variable | Used for |
|---|---|
| `SWARMCHASE_UA` | Overrides the user agent, which by default names the tool, its version and the repository. |

The urlquery API key is passed in by the caller; the CLI reads it from `URLQUERY_APIKEY`.

## Tests

```sh
cargo test -p sc-collect
```

The tests parse saved responses and feed the pager canned pages; none touches the network.

## Source

| File | Covers |
|---|---|
| [`lib.rs`](src/lib.rs) | `CdxQuery`, `Kind`, the `Source` trait. |
| [`client.rs`](src/client.rs) | The HTTP client: pacing, retries, `Retry-After`, user agent, request count. |
| [`pager.rs`](src/pager.rs) | Paging, cursors and `Pull`. |
| [`wayback.rs`](src/wayback.rs), [`arquivo.rs`](src/arquivo.rs), [`urlquery.rs`](src/urlquery.rs) | The record sources. |
| [`crtsh.rs`](src/crtsh.rs), [`securitytxt.rs`](src/securitytxt.rs), [`rdap.rs`](src/rdap.rs) | Lookups: certificates, security.txt, RDAP. |
