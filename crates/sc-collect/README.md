# sc-collect

Passive collectors for public records: the Wayback Machine and Arquivo.pt CDX indexes, urlquery.net search and reports, crt.sh certificate logs, security.txt and RDAP. They return [`sc-core`](../sc-core/README.md) `Observation`s, with secrets already redacted.

Most people use it through the [`swarmchase`](../swarmchase/README.md) CLI (`collect`, `certs`, `contact`, `watch`, `case contacts`) rather than directly.

## Ground rules

What this crate does and does not implement keeps collection passive:

- It reads **indexes and public records only**. It never opens a captured page or a URL an agent submitted, which may be a live exploit or trigger a callback to the agent's operator.
- It never reads or writes agent callback channels (inboxes, notification topics, pastes).
- It is polite: one request at a time with a minimum interval, an identifying user agent, and backoff when a server is overloaded.
- Records are redacted before they leave the crate.

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

The tests parse saved responses; none touches the network.
