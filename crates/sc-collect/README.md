# sc-collect

Passive collectors for public records. They return [`sc-core`](../sc-core/README.md) `Observation`s, with secrets already redacted:

- web archive indexes: the Wayback Machine, Arquivo.pt and Common Crawl CDX, and Memento timemaps;
- agent protocol footprints: Wayback captures of agent cards and signature key directories;
- scan services: urlquery.net and urlscan.io search;
- event streams and registries: GH Archive, npm search, PyPI feeds and the MCP Registry;
- certificates: crt.sh, and CT logs read directly;
- contacts: security.txt and RDAP.

It also holds the [Public Suffix List](src/psl.rs) helper and the [IP-to-ASN table](src/asn.rs) download.

Most people use it through the [`swarmchase`](../swarmchase/README.md) CLI (`collect`, `certs`, `contact`, `watch`, `asn`, `case contacts`) rather than directly.

## Ground rules

What this crate does and does not implement keeps collection passive:

- It reads **indexes and public records only**. It never opens a captured page or a URL an agent submitted, which may be a live exploit or trigger a callback to the agent's operator.
- It never downloads archived content (WARC records, mementos), package code, repositories or scanned pages: index rows and metadata only.
- It never reads or writes agent callback channels (inboxes, notification topics, pastes).
- It is polite: one request at a time with a minimum interval per host, an identifying user agent, and jittered backoff when a server is overloaded.
- Records are redacted before they leave the crate.

Archive captures get the id `<archive>:<timestamp>:<digest>:<url hash>` from [`sc_core::capture`](../sc-core/src/capture.rs), the same id an imported CDX export gets, and record their timestamp as a capture time.

A new collector must keep to these. Its module docs record the source's terms of use, with their URL, and what they allow. See [docs/policies.md](../../docs/policies.md) for the collection policy.

## Use

It is a workspace crate (not published):

```rust
use sc_collect::{CdxQuery, Client};
use std::time::Duration;

let client = Client::new(Duration::from_millis(1500))?; // minimum gap per host
let q = CdxQuery {
    pattern: "r.jina.ai/*".into(),
    from: Some("20260901".into()),
    ..Default::default() // limit 5000, page_size 1000
};
let records = client.wayback_cdx(&q)?;
```

`CdxQuery` also deserialises from a `watchlist.toml` source entry, with `limit` and `page_size` defaulting to 5000 and 1000. `endpoint` picks the instance of a source that has several (a CT log, a crawl, a feed). `scan` and `max_mb` bound how much of a streamed source one pull reads. `filter` passes CDX filters to the index server, `slice_days` reads a Wayback time range in windows, and `canary` names a search known to match.

| Method | Source |
|---|---|
| `wayback_cdx`, `wayback_cdx_page` | Wayback Machine CDX index, paged; the page form returns a resume key. |
| `arquivo_cdx` | Arquivo.pt CDX index. |
| `urlquery`, `urlquery_page` | urlquery.net report search. Takes an API key. |
| `urlquery_report` | One urlquery.net report by ID. |
| `crtsh` | Certificate Transparency via crt.sh. |
| `security_txt`, `security_txt_checked` | A domain's security.txt; the checked form says whether it has expired. |
| `rdap_domain` | A domain's RDAP record, for the registrar's abuse contact. |
| `download` | A large file streamed to disk (the ASN table). |
| `urlscan_by_id`, `gharchive_event`, `npm_release`, `pypi_release`, `crtsh_entry` | One record by id, for checking a reference a submission names ([`lookup.rs`](src/lookup.rs)). |

Every source has a `parse_*` function that reads a saved response without the network.

### Record sources

| `Kind` | Reads | Pattern | `ts_kind` |
|---|---|---|---|
| `wayback` | Wayback Machine CDX | CDX URL pattern | capture |
| `arquivo` | Arquivo.pt CDX (no paging) | CDX URL pattern | capture |
| `commoncrawl` | Common Crawl CDX, newest crawls | CDX URL pattern | capture |
| `memento` | One URL's Memento timemap | exact URL | capture |
| `urlquery` | urlquery.net search (key needed) | search query | submit |
| `urlscan` | urlscan.io public search | search query | submit |
| `gharchive` | GH Archive hourly events | substrings | request |
| `npm` | npm registry search | search text | request |
| `pypi` | PyPI RSS feeds | substrings | request |
| `ctlog` | One CT log's newest entries | substrings | request |
| `wellknown` | Wayback captures of agent footprint files | hosts or `*.domain`s | capture |
| `mcp` | Official MCP Registry list | substrings | request |

"Substrings" are `|`-separated and case-insensitive; `*` keeps everything. Each module's docs give the source's terms of use and what they allow.

### Sources and paging

The record sources (or `source(kind, query, key)`) implement the `Source` trait. `pull(client, since, cursor, limit)` fetches pages through the shared [`pager`](src/pager.rs) until the limit or the end, and returns a `Pull`: the records, the cursor to continue from, whether the source is exhausted, and the requests made. `pull_each` also shows each page as it arrives, so a caller can save progress page by page.

A pull that fails after its first page keeps what it has and says so in `Pull::stopped`; `Pull::strict` turns that back into an error. A source that cannot page (Arquivo.pt, a feed) sets `Pull::truncated` when a page came back full.

Wayback's resume key (with its time window, when sliced), Common Crawl's crawl-and-page cursor, the footprint source's scope-and-key cursor and the MCP Registry's cursor stay valid across runs (`Source::resumable`), so the watch continues a cut-short pull on its next run. A urlquery or npm offset is valid only within one pull.

Streamed sources read a bounded amount each pull from a checkpoint (`Source::checkpointed`): GH Archive reads on from the last hour read, up to `scan` hours and `max_mb`, decoded a line at a time; a CT log reads from its checkpoint when that is within the newest `scan` entries, else the newest `scan`. A backlog too long to catch up on is skipped and counted.

### Platform events

[`platform`](src/platform.rs) reads the same event stream and registries for a different purpose: every event of the kinds the coordinated-account detector groups, not only matches. `pull_platform` takes a `[[platform.source]]` entry (`gharchive`, `npm`, `pypi` or `huggingface`) and returns `sc_core::platform::PlatformEvent`s, with logins hashed, account ids reduced to a rank, text reduced to a slotted sketch and automation logins dropped. `gharchive_file` reads a GH Archive hour file from disk. Nothing inside an event's text is fetched, and a Space or repository is never opened ([methodology](../../docs/methodology.md#coordinated-accounts-on-public-platforms)).

### Coverage and canaries

Sources that read a stream or feed and keep only matches report a `Coverage` on each page, folded into `Pull::coverage`: what was read against what there was to read since the checkpoint, what was skipped, the next checkpoint, and a canary. The canary is something every working pull sees: GH Archive events that parse, CT entries with DNS names, PyPI feed items, or hits for npm's `canary` search. A failed canary means the source answered in a shape the parser no longer understands, so an empty pull proves nothing.

## Retries, limits and the cache

- **Retries.** Dropped connections, HTTP 429 and 5xx are retried with exponential backoff: 5 retries from 5 seconds, spread ±25%, each wait capped at 5 minutes. A gateway timeout (HTTP 504) or a request that timed out is retried only twice, because an index query too heavy for the server times out the same way every time. Other errors fail at once. Change the policy with `Client::with_retry`.
- **Unavailable hosts.** HTTP 503 (the Internet Archive's "Temporarily Offline") is retried for a span of time, `unavailable_patience` (10 minutes), rather than a count. A host still unavailable after that is marked down for the client's life: later requests to it fail at once, so one outage costs a watch run ten minutes, not ten minutes per source. `Client::down_hosts` lists them.
- **Retry-After.** A server's `Retry-After`, in seconds or as an HTTP date, is honoured as given.
- **Pacing.** The minimum interval applies per host, so sources on different hosts do not slow each other.
- **Size cap.** A response read into memory is capped at 64 MiB (`Client::with_max_body`). Large files are streamed with their own cap.
- **Cache.** `Client::with_cache(dir, ttl)` keeps responses on disk. One younger than `ttl` is reused without a request; an older one is revalidated with its ETag or Last-Modified. Requests carrying API keys are never cached.
- **Counts.** `Client::requests` counts the requests sent, retries included; `Client::cache_hits` counts reuses.

Error messages name the URL and never a header value, so an API key does not end up in a log.

## security.txt

`security_txt` takes a bare domain name and refuses a path, user info, port or IP address. It follows redirects only within that host, over HTTPS. It accepts `text/plain`, or no type when the body is not HTML. A file whose `Expires` has passed is returned marked expired: RFC 9116 makes it stale, not void.

## Environment

| Variable | Used for |
|---|---|
| `SWARMCHASE_UA` | Overrides the user agent, which by default names the tool, its version and the repository. |

API keys are passed in by the caller. `Kind::key_env` names the variable the CLI reads: `URLQUERY_APIKEY` (required for urlquery) and `URLSCAN_APIKEY` (optional for urlscan).

## Tests

```sh
cargo test -p sc-collect
```

The tests parse synthetic responses (never third-party records) and feed the pager canned pages; none touches the network.

## Source

| File | Covers |
|---|---|
| [`lib.rs`](src/lib.rs) | `CdxQuery`, `Kind`, the `Source` trait, substring filters. |
| [`client.rs`](src/client.rs) | The HTTP client: pacing, retries, `Retry-After`, size cap, user agent, request count. |
| [`cache.rs`](src/cache.rs) | The on-disk response cache. |
| [`pager.rs`](src/pager.rs) | Paging, cursors and `Pull`. |
| [`wayback.rs`](src/wayback.rs), [`arquivo.rs`](src/arquivo.rs), [`commoncrawl.rs`](src/commoncrawl.rs), [`memento.rs`](src/memento.rs) | Archive index sources. |
| [`urlquery.rs`](src/urlquery.rs), [`urlscan.rs`](src/urlscan.rs) | Scan-service sources. |
| [`gharchive.rs`](src/gharchive.rs), [`npm.rs`](src/npm.rs), [`pypi.rs`](src/pypi.rs), [`mcp.rs`](src/mcp.rs) | Event-stream and registry sources. |
| [`platform.rs`](src/platform.rs) | Platform events for the coordinated-account detector: GH Archive, npm, PyPI and Hugging Face Hub listings, sketched at parse time. |
| [`wellknown.rs`](src/wellknown.rs) | Agent protocol footprints in the Wayback index. |
| [`ctlog.rs`](src/ctlog.rs) | The CT log source and its SAN parser. |
| [`lookup.rs`](src/lookup.rs) | Single records by id, for `swarmchase inbox verify`. |
| [`crtsh.rs`](src/crtsh.rs), [`securitytxt.rs`](src/securitytxt.rs), [`rdap.rs`](src/rdap.rs) | Lookups: certificates, security.txt, RDAP. |
| [`psl.rs`](src/psl.rs), [`asn.rs`](src/asn.rs) | Registrable domains; the IP-to-ASN table download. |
| [`identity.rs`](src/identity.rs) | Providers' published range files and key directories, from the catalog's URLs only ([identity](../../docs/reference/identity.md)). |
