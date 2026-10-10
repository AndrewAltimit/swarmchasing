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

Collectors read indexes and public records only. They never open a capture or a URL an agent submitted. Requests go one at a time with an identifying user agent (override with `SWARMCHASE_UA`), and retry on HTTP 429 and 5xx with exponential backoff, honouring `Retry-After`.

| Command | What it does |
|---|---|
| `collect wayback <pattern>` | Wayback Machine CDX index, e.g. `'r.jina.ai/*'`. `--from`/`--to` (`yyyyMMdd[hhmmss]`), `--match-type`, `--limit`, `--page-size`, `-o`, and `--resume` to continue an interrupted pull. |
| `collect arquivo <pattern>` | Arquivo.pt CDX index, same options. |
| `collect urlquery <query>` | urlquery.net report search. Needs `URLQUERY_APIKEY`. |
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
| `watch [watchlist.toml]` | Pulls what is new from every source in the watchlist, analyses the recent window and writes a digest of what changed into `<data>/runs/<stamp>/digest.md`. Details: [Watch runs](../../README.md#watch-runs). |
| `review` | Steps through recent watch leads and asks for a label (`a` agent, `b` benign, `u` unsure, `s` skip, `q` quit; `c` opens a case). `--unflagged N` adds a sample of unflagged records; `--list` prints the queue; `--stats` counts reviews and disagreements. Details: [Reviewing leads](../../README.md#reviewing-leads). |
| `eval <input>…` | Precision and recall of the rules on labelled records. Labels come from a `label` field or `--labels` (NDJSON or CSV). With `--min-*` floors set it exits non-zero when one is not met, which is how CI gates rules changes. |

```sh
swarmchase watch                              # uses watchlist.toml and $SWARMCHASE_DATA (or data/)
swarmchase review --unflagged 20
swarmchase eval samples/eval/*.ndjson
swarmchase eval data/labels/reviewed.ndjson   # everything reviewed so far
```

### Cases

`case` keeps one directory per incident under `<data>/cases/<id>/`, with its records, `case.toml`, reports, drafts, bundles and exports. Cases never go into git. The table of subcommands and what a case holds are in [Case files](../../README.md#case-files); in brief:

```sh
swarmchase case new 2026-10-portal --title "Portal SQLi" --cluster C1 --host-hits
swarmchase case endpoint 2026-10-portal portal.example.gov targeted
swarmchase case contacts 2026-10-portal
swarmchase case draft 2026-10-portal --audience affected --to security@example.gov   # unsent .eml + bundle
swarmchase case sent 2026-10-portal --to security@example.gov                         # after the admin sends it
swarmchase case verify data/cases/2026-10-portal/bundles/2026-10-12
swarmchase case status
```

Other subcommands: `add`, `claim`, `set`, `note`, `bundle`, `report`, `rules`, `notice`, `export` (STIX 2.1), and `evidence add|consent|withdraw|list` for logs an operator sends back.

### Notices

| Command | What it does |
|---|---|
| `notice add <case>` | Checks a case's reviewed `notice.md` and copies it to `notices/<id>.md`. Committing the file publishes it. |
| `notice update <id> --kind …` | Appends a dated update, status change, correction, reply or retraction. |
| `notice lint [files]` | Checks front matter, update order and that nothing withheld got through. CI and the pre-commit hook run it. |
| `notice build --out <dir> --base-url <url>` | Writes the site's notice index, pages and Atom feed. |

Details: [Notices](../../README.md#notices).

## Environment

| Variable | Used for |
|---|---|
| `SWARMCHASE_DATA` | The data directory (`--out` / `--data`, default `data/`): watch state and store, labels, cases. Gitignored. |
| `URLQUERY_APIKEY` | urlquery.net collectors. Without it, `watch` skips urlquery sources and says so. |
| `SWARMCHASE_SITE_URL` | `notice build --base-url`. |
| `SWARMCHASE_UA` | Overrides the collectors' user agent. |

Keep secrets in `env.list` (gitignored) and run with [`scripts/with-env.sh`](../../scripts/with-env.sh); see [Local secrets](../../README.md#local-secrets).

## Exit status

Non-zero on an error, when `eval` misses a floor, when `case verify` finds a difference, and when `notice lint` or `notice add` finds a problem.

## Source

| File | Covers |
|---|---|
| [`main.rs`](src/main.rs) | Argument parsing and the analysis, collect and lookup commands. |
| [`watch.rs`](src/watch.rs) | The incremental watch and its digest. |
| [`health.rs`](src/health.rs) | Source and rule health checks in the digest. |
| [`review.rs`](src/review.rs) | Interactive labelling. |
| [`eval.rs`](src/eval.rs) | The `eval` command. |
| [`case.rs`](src/case.rs) | Case files and their subcommands. |
| [`contacts.rs`](src/contacts.rs) | security.txt and RDAP contact lookup. |
| [`bundle.rs`](src/bundle.rs) | Evidence bundles, `case verify` and `.eml` drafts. |
| [`evidence.rs`](src/evidence.rs) | Logs operators send back. |
| [`stix.rs`](src/stix.rs) | STIX 2.1 export. |
| [`notice.rs`](src/notice.rs) | Adding, updating, linting and building notices. |
