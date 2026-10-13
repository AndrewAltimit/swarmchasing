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

Collectors read indexes and public records only. They never open a capture or a URL an agent submitted. Requests go one at a time per host with an identifying user agent (override with `SWARMCHASE_UA`), and retry on HTTP 429 and 5xx with jittered backoff, honouring `Retry-After`. Every `collect` source also takes `--endpoint`, `--scan` and `--cache` ([source kinds](../../docs/reference/watch.md#source-kinds)), and some take a source-specific option:

| Option | Source | Does |
|---|---|---|
| `--filter <f>` | Wayback, Arquivo.pt, Wikimedia | A CDX filter the index server applies, repeatable; `collection:SAWP.*` keeps Arquivo.pt's on-demand saves. For Wikimedia, `domain:<wiki>`, `!domain:<wiki>` or `ns:<n>`. |
| `--slice-days <n>` | Wayback | Reads the time range in windows of `n` days; a sliced pull resumes by window. |
| `--canary <query>` | npm | A query known to match, run once first, so an empty result is told apart from a broken search. |
| `--max-mb <n>` | GH Archive, Wikimedia | The most megabytes streamed per run (compressed, for GH Archive). |

| Command | What it does |
|---|---|
| `collect wayback <pattern>` | Wayback Machine CDX index, e.g. `'r.jina.ai/*'`. `--from`/`--to` (`yyyyMMdd[hhmmss]`), `--match-type`, `--limit`, `--page-size`, `-o`, `--resume` to continue an interrupted pull, and `--slice-days N` to read the range in windows of N days. |
| `collect arquivo <pattern>` | Arquivo.pt CDX index, same options. It cannot page, so a full result is cut at `--limit`. |
| `collect urlquery <query>` | urlquery.net report search. Needs `URLQUERY_APIKEY`. |
| `collect commoncrawl <pattern>` | Common Crawl CDX index rows, newest crawl by default. |
| `collect urlscan <query>` | urlscan.io public search, per case. `URLSCAN_APIKEY` optional. |
| `collect memento <url>` | One URL's captures across archives, from a Memento timemap. |
| `collect gharchive <substrings>` | Public GitHub events matching repo names or payload URLs. |
| `collect wikimedia <substrings>` | External links added to Wikimedia wiki pages in the last hour, matching the link or page title; `--scan` minutes. The links are never fetched. |
| `collect npm <text>`, `collect pypi <substrings>` | Package names, versions and publish times; never code. |
| `collect ctlog <substrings> --endpoint <log>` | Certificates in a CT log's newest entries whose names match. |
| `collect wellknown <hosts>` | Wayback index rows for agent footprints (agent cards, agent registration files, signature key directories) under `\|`-separated hosts or `*.domain`s. The files are never fetched. |
| `collect mcp <substrings>` | Official MCP Registry servers whose name or declared URLs match (`*` for all), updated since `--from`. Metadata only; no server is contacted. |
| `asn fetch`, `asn lookup <ip>…` | The offline IP-to-ASN table in `<data>/asn/`. |
| `identity refresh`, `identity status`, `identity check <input>` | Providers' published agent ranges and keys in `<data>/identity/`, and each record's declared identity: verified, spoofed or claimed ([identity](../../docs/reference/identity.md)). |
| `collect urlquery-reports <ids> -o <out>` | Fetches urlquery reports by ID, or every ID in a labels file such as Transluce's `reports.csv`. Appends to `--out` and skips IDs already there; `--sample N` caps the agent-labelled reports. |
| `certs <query>` | Certificate Transparency lookup via crt.sh, e.g. `'%.example.com'`. |
| `contact <domain>` | The domain's RFC 9116 security.txt contact. |

```sh
swarmchase collect wayback 'r.jina.ai/*' --from 20260901 -o data/jina.ndjson
swarmchase collect arquivo 'r.jina.ai/*' --filter 'collection:SAWP.*' --from 20260901 -o data/spn.ndjson
scripts/with-env.sh swarmchase collect urlquery r.jina.ai --from 20260901 -o data/uq.ndjson
```

### Watch and review

| Command | What it does |
|---|---|
| `watch [watchlist.toml]` | Pulls what is new from every source in the watchlist, analyses the recent window and writes a digest of what changed into `<data>/runs/<stamp>/digest.md`, with a machine-readable `run.json` beside it; `--triage` asks a local model about new leads. Details: [Watch runs](../../docs/reference/watch.md). |
| `review` | Steps through recent watch leads and asks for a label (`a` agent, `b` benign, `u` unsure, `s` skip, `q` quit; `c` opens a case). `--unflagged N` adds a sample of unflagged records; `--list` prints the queue; `--stats` counts reviews and disagreements; `--suggest`, `--serve` and `--export-hosted` add suggestions and a local page. Details: [Reviewing leads](../../docs/reference/watch.md#reviewing-leads). |
| `review agreement`, `misfires`, `check-suggestions`, `suggest-claude` | Compare model suggestions with the admin's labels, list rules that fire on benign records, validate a suggestions file, and ask Claude Code for suggestions on an export. Details: [AI assistance](../../docs/guides/ai-assistance.md). |
| `dashboard` | A read-only local page of the attention queue, what is new since you last looked, an activity timeline, a link graph of soft links, interaction and candidate fleets, source health and rule drift, the review queue, open cases and the autonomy record, with the command for each next step. `--json` prints the same overview. Details: [The dashboard](../../docs/reference/watch.md#the-dashboard). |
| `platform-swarms <events>…` | Candidate coordinated-account swarms in platform events (the watch's carried events, fixtures, or GH Archive hour files with `--gharchive`), defanged; `--json` for the full report. Hints, never findings. Details: [Platform swarms](../../docs/reference/watch.md#platform-swarms). |
| `review sample` | Writes a stratified, seeded sample of low-tier records as a queue for a [reviewed benign baseline](../../docs/reference/evaluation.md#a-reviewed-benign-baseline); `review <queue> --all` labels it. |
| `eval <input>…` | Precision and recall of the rules on labelled records, per record and per cluster, for all and for non-synthetic records. With `--min-*` floors set it exits non-zero when one is not met, which is how CI gates rules changes. `--before <date>` runs a pre-agent negative control instead. Details: [Evaluation](../../docs/reference/evaluation.md). |
| `eval repro`, `eval check-results`, `eval export-bench` | Measure a saved result again; check the committed results; write an SC-Bench file (`eval --bench` scores one). |
| `sim write <scenarios> -o <dir>` | Simulated labelled records, one NDJSON file per scenario and seed ([simulated scenarios](../../docs/reference/evaluation.md#simulated-scenarios)). |
| `sim bench <scenarios>` | Generate, analyse and measure every scenario; per scenario and summed, `--total` for the sum only, `--json` to save. Report only. |
| `sim score <input>…` | Interaction edges, soft links, candidate fleets and agent grades against labelled true runs, swarms and fleets ([swarm and fleet measurement](../../docs/reference/evaluation.md#swarm-and-fleet-measurement)). Report only. |

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
swarmchase case sent 2026-10-portal --to security@example.gov                         # after the admin sends it; starts its clocks
swarmchase case reread 2026-10-portal                                                # an hour after `case notice`
swarmchase case review 2026-10-portal --reviewer "R. Reviewer" --verdict approve      # a second person's review of the draft
swarmchase case verify data/cases/2026-10-portal/bundles/2026-10-12
swarmchase case status
```

Other subcommands: `add`, `claim`, `set`, `note`, `rename`, `bundle`, `report`, `rules`, `notice`, `export` (`--format stix`, `misp`, `oecd` with its EU AI Act Article 73 section, or `aiid`), `no-contact`, `scope`, `consent`, `naming`, `alternative`, `plant-review` and `checklist` for the self-review, `review-packet` and `review` for the second review, and `evidence add|consent|withdraw|list` for logs an operator sends back.

### Sightings

An operator's sightings file ([SC-Sightings v1](../../docs/specs/sightings-v1.md)) carries what a swarm left in its logs without the logs. `match` is read-only: it writes nothing into the watch data or a case, and the scheduled watch never runs it.

```sh
swarmchase sightings export access.log --map host=www.example.org -o sightings.json   # --include-hosts to add your hosts
swarmchase sightings match a.json b.json --vouch a.json=2026-10-portal --store       # clusters more than one party saw
```

### Inbox

`inbox` takes in outside swarm reports ([SC-Submission v1](../../docs/specs/submission-v1.md)) as files, keeps them redacted under `<data>/inbox/`, looks their public-record references up by id, and triages them so only hard-to-fabricate evidence reaches the admin. Details: [The inbox](../../docs/reference/inbox.md).

```sh
swarmchase inbox add drop/ --via drop
swarmchase inbox verify --all
swarmchase inbox triage
swarmchase inbox promote sub-20261010-1a2b3c4d --case 2026-10-portal
```

Other subcommands: `list`, `show`, `signature`.

### Notices

| Command | What it does |
|---|---|
| `notice add <case>` | Runs the self-review checklist and the second-review check, and copies a case's indicator notice `notice.md` to `notices/<id>.md`. Committing the file publishes it. |
| `notice update <id> --kind …` | Appends a dated update, status change, correction, reply or retraction. |
| `notice update <id> --naming` | Appends the case's reviewed `naming.md`, naming the operators whose lead has run or who consented. |
| `notice lint [files]` | Checks front matter, update order, attribution wording and that nothing withheld got through. CI and the pre-commit hook run it. |
| `notice build --out <dir> --base-url <url>` | Writes the site's notice index, pages and Atom feed. |
| `canary register [_site]`, `list`, `token`, `scan` | Canary tokens on our own pages: register a built site's tokens, list them, derive one, find copies in records ([page references](../../docs/reference/browser-toolkit.md#page-references)). |
| `site build [--out _site] [--base-url <url>]` | Builds the whole public site from the checkout, as `sc-site` does ([how the site is built](../../docs/reference/browser-toolkit.md#how-the-site-is-built)). |

Details: [Notices](../../docs/reference/notices.md).

## Environment

| Variable | Used for |
|---|---|
| `SWARMCHASE_DATA` | The data directory (`--out` / `--data`, default `data/`): watch state and store, labels, cases. Gitignored. |
| `SWARMCHASE_ADMIN` | The admin name `case new` records; else `git config user.name`. |
| `URLQUERY_APIKEY` | urlquery.net collectors. Without it, `watch` skips urlquery sources and says so. |
| `URLSCAN_APIKEY` | Optional key for `collect urlscan`. |
| `SWARMCHASE_SITE_URL` | `notice build --base-url`. |
| `SWARMCHASE_UA` | Overrides the collectors' user agent. |
| `SWARMCHASE_CANARY_SEED` | The secret seed of `canary`; never committed. |

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
| [`lib.rs`](src/lib.rs) | Argument parsing and dispatch; [`main.rs`](src/main.rs) calls it. |
| [`commands/`](src/commands/mod.rs) | The analysis, collect and lookup commands, one module each. |
| [`input.rs`](src/input.rs) | Reading records and rules for the analysis commands. |
| [`store.rs`](src/store.rs) | The watch record store, retention, JSON and NDJSON files. |
| [`util.rs`](src/util.rs) | Output and text helpers, the urlquery key. |
| [`watch/`](src/watch/mod.rs) | The incremental watch: pulls and cursors ([`pull.rs`](src/watch/pull.rs)), the digest ([`digest.rs`](src/watch/digest.rs)), case monitoring and proposals ([`cases.rs`](src/watch/cases.rs)), the digest priority ([`priority.rs`](src/watch/priority.rs)), the ledger ([`ledger.rs`](src/watch/ledger.rs)), the attention queue ([`attention.rs`](src/watch/attention.rs)), shadow autonomy ([`autonomy.rs`](src/watch/autonomy.rs)), local model triage ([`triage.rs`](src/watch/triage.rs)) and the run summary ([`run_summary.rs`](src/watch/run_summary.rs)). |
| [`health.rs`](src/health.rs) | Source and rule health checks in the digest. |
| [`review/`](src/review/mod.rs) | Interactive labelling; the local review page ([`serve.rs`](src/review/serve.rs)); hosted suggestions ([`hosted.rs`](src/review/hosted.rs)); suggestion agreement and rule misfires ([`agreement.rs`](src/review/agreement.rs), [`misfires.rs`](src/review/misfires.rs)); the benign-baseline sampler ([`sample.rs`](src/review/sample.rs)). |
| [`localui/`](src/localui/mod.rs) | The admin's local pages: server, security checks, shared style and helpers. |
| [`suggest.rs`](src/suggest.rs) | Label suggestions from a local model (`review --suggest`), local hosts only. |
| [`eval.rs`](src/eval.rs) | The `eval` command's tables, floors and saved results; `repro` and `check-results` ([`repro.rs`](src/eval/repro.rs)); SC-Bench export and scoring ([`bench.rs`](src/eval/bench.rs)). |
| [`case/`](src/case/mod.rs) | Case files on disk and every analysis of a case under its pinned rules (`Pinned`); the subcommands, one module per group ([`cli/`](src/case/cli/mod.rs)); record selection, status, report and e-mail drafts, the checklist's inputs, incident drafts, and the indicators the watch matches. The case model and decisions are [`sc-case`](../sc-case/README.md). |
| [`pinning.rs`](src/pinning.rs) | The rules a case is pinned to, tier changes under other rules, leak checks under both. |
| [`contacts/`](src/contacts/mod.rs) | security.txt and RDAP parsing, contact lookup for `case contacts`, provider seeding from the directory, `contacts verify`, and `swarmchase contacts`. |
| [`csirts.rs`](src/csirts.rs) | National CSIRTs by country ([`contacts/csirts.toml`](../../contacts/csirts.toml)). |
| [`bundle.rs`](src/bundle.rs) | Evidence bundles, `case verify` and `.eml` drafts. |
| [`evidence.rs`](src/evidence.rs) | Logs operators send back, `case evidence`. |
| [`stix/`](src/stix/mod.rs) | `case export --format stix\|misp`: the case scoped to an audience, built by [`sc-stix`](../sc-stix/README.md). |
| [`inbox/`](src/inbox/mod.rs) | `swarmchase inbox`: the files under `<data>/inbox/` ([`files.rs`](src/inbox/files.rs)) and lookups by id ([`verify.rs`](src/inbox/verify.rs)). What a submission is and how it is judged is [`sc-inbox`](../sc-inbox/README.md). |
| [`notice.rs`](src/notice.rs) | The notice draft (`case notice`); adding, updating, linting and building notices. |
