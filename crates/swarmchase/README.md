# swarmchase

The command-line tool. It reads public records of requests (scan service results, archive indexes, URL lists, a server's own access log), flags the ones that look like AI agent activity, links them into runs and clusters, and drafts reports and public notices. It also runs the scheduled watch and keeps the case files.

It drafts and never sends. Reports come out as files or unsent `.eml` drafts; notices are published by committing them. See the [ground rules](../../README.md#ground-rules).

## Install

From the repository root:

```sh
cargo install --path crates/swarmchase      # puts `swarmchase` on your PATH
cargo run -p swarmchase -- <command> …     # or run it in place
```

The rules in [`rules/default.toml`](../../rules/default.toml) are compiled in, so the binary works anywhere. A few commands read repository files by default (`watch` reads `watchlist.toml`, the `notice` commands read `notices/`), so run those from a checkout.

## Input

Every analysis command takes one or more files, or `-` for stdin. `--format auto` (the default) recognises:

| Format | What it is |
|---|---|
| `ndjson` | One JSON record per line: `id`, `source`, `ts` (Unix seconds or RFC 3339), `url`, and optionally `ip`, `asn`, `user_agent`, `headers`, `status`, `final_url`, `reference`. |
| `json` | A JSON array or object of records, including Wayback CDX JSON and urlquery.net search results and reports. |
| `lines` | One URL per line. |
| `access_log` | A web server's Common or Combined Log Format log. Name its host with `--map host=www.example.org`. |

For an export with other field names, map them: `--map ts=submitted_at,url=page.url`. Secrets in the input are replaced with `REDACTED-<hash>` before anything else sees them.

`--rules <file>` swaps in another rules file wherever rules apply.

## Commands

### Analyse

| Command | What it does |
|---|---|
| `scan <input>…` | Lists flagged records, strongest first. `--min-tier noise\|suggestive\|significant`, `--limit`. |
| `clusters <input>…` | Summarises the clusters: linked runs of records. Each has a number (`C1`, strongest first, which can change as records arrive) and a stable key (`k-3f9a2c1b`); every `--cluster` option takes either. |
| `endpoints <input>…` | Per target host: hits, first and last seen, payloads, clusters, and whether the hits are ongoing or historical. `--active-days`, `--from-now`, `--json`. |
| `analyze <input>…` | The full analysis as JSON (`-o` to write a file, `--flagged-only` to drop the rest). |
| `report <input>…` | A Markdown draft. `--audience provider\|affected\|internal\|public`, `--cluster C1` (or its key), `--min-named` (the weakest evidence that may name a developer), `--claims` (JSON claims from case work), `-o`. |
| `unwrap <url>` | Shows the relay and carrier layers inside one URL and the rules each layer triggers. |
| `defang <url>…` | Defangs URLs for sharing (`hxxps://host[.]example`). |
| `rules [file]` | Validates a rules file; `--dump` prints the bundled rules. |

```sh
swarmchase scan records.ndjson
echo 'https://r.jina.ai/https://portal.example.gov/q?id=1%20UNION%20SELECT%201' | swarmchase scan -
swarmchase report records.ndjson --audience provider --cluster C1 -o c1-provider.md
swarmchase report access.log --map host=www.example.org --audience affected   # your own server's log
swarmchase unwrap 'https://r.jina.ai/https://portal.example.gov/q?id=1%20UNION%20SELECT%201'
```

### Collect

Collectors read indexes and public records only. They never open a capture or a URL an agent submitted. Requests go one at a time per host with an identifying user agent (override with `SWARMCHASE_UA`), and retry on HTTP 429 and 5xx with jittered backoff, honouring `Retry-After`. Every `collect` source also takes `--endpoint`, `--scan` and `--cache` ([source kinds](../../docs/reference/watch.md#source-kinds)).

| Command | What it does |
|---|---|
| `collect wayback <pattern>` | Wayback Machine CDX index, e.g. `'r.jina.ai/*'`. `--from`/`--to` (`yyyyMMdd[hhmmss]`), `--match-type`, `--limit`, `--page-size`, `-o`, and `--resume` to continue an interrupted pull. |
| `collect arquivo <pattern>` | Arquivo.pt CDX index, same options. |
| `collect urlquery <query>` | urlquery.net report search. Needs `URLQUERY_APIKEY`. |
| `collect commoncrawl <pattern>` | Common Crawl CDX index rows, newest crawl by default. |
| `collect urlscan <query>` | urlscan.io public search, per case. `URLSCAN_APIKEY` optional. |
| `collect memento <url>` | One URL's captures across archives, from a Memento timemap. |
| `collect gharchive <substrings>` | Public GitHub events matching repo names or payload URLs. |
| `collect npm <text>`, `collect pypi <substrings>` | Package names, versions and publish times; never code. |
| `collect ctlog <substrings> --endpoint <log>` | Certificates in a CT log's newest entries whose names match. |
| `asn fetch`, `asn lookup <ip>…` | The offline IP-to-ASN table in `<data>/asn/`. |
| `collect urlquery-reports <ids> -o <out>` | Fetches urlquery reports by ID, or every ID in a labels file such as Transluce's `reports.csv`. Appends to `--out` and skips IDs already there; `--sample N` caps the agent-labelled reports. |
| `certs <query>` | Certificate Transparency lookup via crt.sh, e.g. `'%.example.com'`. |
| `contact <domain>` | The domain's RFC 9116 security.txt contact. |

```sh
swarmchase collect wayback 'r.jina.ai/*' --from 20260901 -o data/jina.ndjson
scripts/with-env.sh swarmchase collect urlquery r.jina.ai --from 20260901 -o data/uq.ndjson
```

### Watch and review

| Command | What it does |
|---|---|
| `watch [watchlist.toml]` | Pulls what is new from every source in the watchlist, analyses the recent window and writes a digest of what changed into `<data>/runs/<stamp>/digest.md`. Details: [Watch runs](../../docs/reference/watch.md). |
| `review` | Steps through recent watch leads and asks for a label (`a` agent, `b` benign, `u` unsure, `s` skip, `q` quit; `c` opens a case). `--unflagged N` adds a sample of unflagged records; `--list` prints the queue; `--stats` counts reviews and disagreements; `--suggest` shows a local model's suggestion. Details: [Reviewing leads](../../docs/reference/watch.md#reviewing-leads). |
| `eval <input>…` | Precision and recall of the rules on labelled records, and agent grades by actor. Labels come from a `label` field or `--labels` (NDJSON or CSV). With `--min-*` floors set it exits non-zero when one is not met, which is how CI gates rules changes. `--before <date>` grades a pre-agent negative control instead. |

```sh
swarmchase watch                              # uses watchlist.toml and $SWARMCHASE_DATA (or data/)
swarmchase review --unflagged 20
swarmchase eval samples/eval/*.ndjson
swarmchase eval data/labels/reviewed.ndjson   # everything reviewed so far
```

### Cases

`case` keeps one directory per incident under `<data>/cases/<id>/`, with its records, `case.toml`, reports, drafts, bundles and exports. Cases never go into git. The table of subcommands and what a case holds are in [Case files](../../docs/reference/cases.md); in brief:

```sh
swarmchase case new 2026-10-portal --title "Portal SQLi" --cluster C1 --host-hits
swarmchase case endpoint 2026-10-portal portal.example.gov targeted
swarmchase case contacts 2026-10-portal
swarmchase case draft 2026-10-portal --audience affected --to security@example.gov   # unsent .eml + bundle
swarmchase case sent 2026-10-portal --to security@example.gov                         # after the admin sends it; starts its lead time
swarmchase case reread 2026-10-portal                                                # an hour after `case notice`
swarmchase case verify data/cases/2026-10-portal/bundles/2026-10-12
swarmchase case status
```

Other subcommands: `add`, `claim`, `set`, `note`, `rename`, `bundle`, `report`, `rules`, `notice`, `export` (STIX 2.1), `no-contact`, `alternative`, `plant-review` and `checklist` for the self-review, and `evidence add|consent|withdraw|list` for logs an operator sends back.

### Notices

| Command | What it does |
|---|---|
| `notice add <case>` | Runs the self-review checklist, including the lead time, and copies a case's reviewed `notice.md` to `notices/<id>.md`. Committing the file publishes it. |
| `notice update <id> --kind …` | Appends a dated update, status change, correction, reply or retraction. |
| `notice lint [files]` | Checks front matter, update order, attribution wording and that nothing withheld got through. CI and the pre-commit hook run it. |
| `notice build --out <dir> --base-url <url>` | Writes the site's notice index, pages and Atom feed. |
| `site build [--out _site] [--base-url <url>]` | Builds the whole public site from the checkout, as `sc-site` does ([how the site is built](../../docs/reference/browser-toolkit.md#how-the-site-is-built)). |

Details: [Notices](../../docs/reference/notices.md).

## Environment

| Variable | Used for |
|---|---|
| `SWARMCHASE_DATA` | The data directory (`--out` / `--data`, default `data/`): watch state and store, labels, cases. Gitignored. |
| `URLQUERY_APIKEY` | urlquery.net collectors. Without it, `watch` skips urlquery sources and says so. |
| `URLSCAN_APIKEY` | Optional key for `collect urlscan`. |
| `SWARMCHASE_SITE_URL` | `notice build --base-url`. |
| `SWARMCHASE_UA` | Overrides the collectors' user agent. |

Keep secrets in `env.list` (gitignored) and run with [`scripts/with-env.sh`](../../scripts/with-env.sh); see [Local secrets](../../docs/reference/configuration.md#local-secrets).

## Exit status

Non-zero on an error, when `eval` misses a floor, when `case verify` finds a difference, and when `notice lint` or `notice add` finds a problem.

## Tests

```sh
cargo test -p swarmchase
```

Unit tests sit beside the code. [`tests/`](tests/integration.rs) runs the built binary over `samples/eval/` in scratch data directories: scan, clusters, a public report, a case from a cluster key to a verified bundle, notice lint, and an offline watch run. None touches the network.

## Source

| File | Covers |
|---|---|
| [`main.rs`](src/main.rs) | Argument parsing and dispatch. |
| [`commands/`](src/commands/mod.rs) | The analysis, collect and lookup commands, one module each. |
| [`input.rs`](src/input.rs) | Reading records and rules for the analysis commands. |
| [`store.rs`](src/store.rs) | The watch record store, retention, JSON and NDJSON files. |
| [`util.rs`](src/util.rs) | Output and text helpers, the urlquery key. |
| [`watch/`](src/watch/mod.rs) | The incremental watch: pulls and cursors ([`pull.rs`](src/watch/pull.rs)), the digest ([`digest.rs`](src/watch/digest.rs)), case monitoring and proposals ([`cases.rs`](src/watch/cases.rs)). |
| [`health.rs`](src/health.rs) | Source and rule health checks in the digest. |
| [`review.rs`](src/review.rs) | Interactive labelling. |
| [`suggest.rs`](src/suggest.rs) | Label suggestions from a local model (`review --suggest`), local hosts only. |
| [`eval.rs`](src/eval.rs) | The `eval` command. |
| [`case/`](src/case/mod.rs) | Case files: `case.toml` ([`model.rs`](src/case/model.rs)), the subcommands ([`cli.rs`](src/case/cli.rs)), record selection, status, report and e-mail drafts, lead times ([`lead.rs`](src/case/lead.rs)), the self-review checklist ([`checklist.rs`](src/case/checklist.rs)), and the indicators the watch matches. |
| [`pinning.rs`](src/pinning.rs) | The rules a case is pinned to, tier changes under other rules, leak checks under both. |
| [`contacts.rs`](src/contacts.rs) | security.txt and RDAP contact lookup, `case contacts`. |
| [`csirts.rs`](src/csirts.rs) | National CSIRTs by country ([`contacts/csirts.toml`](../../contacts/csirts.toml)). |
| [`bundle.rs`](src/bundle.rs) | Evidence bundles, `case verify` and `.eml` drafts. |
| [`evidence.rs`](src/evidence.rs) | Logs operators send back, `case evidence`. |
| [`stix/`](src/stix/mod.rs) | STIX 2.1 export: records to observables and indicators, one builder per object type, deterministic ids. |
| [`notice.rs`](src/notice.rs) | The notice draft (`case notice`); adding, updating, linting and building notices. |
| [`wording.rs`](src/wording.rs) | Wording checks on a notice: claim form, likelihood words, provider names in titles, "compromised", accusations. |
