# swarmchasing

Rust tools for finding misaligned AI agent swarms and fleets in public records, linking their activity, and reporting it to the AI provider responsible and to the operators of affected systems.

The methods follow published incident work:
[swarmcha.se — agent fleet report](https://swarmcha.se/posts/chinese-agent-fleet),
[Transluce — agent activity](https://transluce.org/agent-activity),
[Transluce — US/Canada government](https://transluce.org/us-canada-gov).
In short, agents leave traces in public scan services and web archives. They wrap targets in relays, run fetch programs in remote browsers, call back to throwaway inboxes, and tag their requests. Those traces can be extracted, linked into runs, timed, and attributed.

## Layout

| Path | What |
|---|---|
| [`crates/sc-core`](crates/sc-core/README.md) | Platform-independent analysis: ingest, URL unwrapping, rule matching, scoring, clustering, timing, report drafting. No I/O, so it compiles to WASM. |
| [`crates/sc-collect`](crates/sc-collect/README.md) | Passive collectors: Wayback and Arquivo.pt CDX indexes, urlquery.net search (API key), crt.sh, security.txt. |
| [`crates/swarmchase`](crates/swarmchase/README.md) | The CLI: install, input formats and every command. |
| [`crates/sc-wasm`](crates/sc-wasm/README.md) | wasm-bindgen bindings for the browser toolkit, and their JSON API. |
| `rules/default.toml` | Indicator rules shared by the CLI and the browser (compiled in). |
| `samples/eval/` | Labelled evaluation set; CI fails if precision or recall drops ([README](samples/eval/README.md)). |
| `site/` | GitHub Pages toolkit (static HTML/JS + `site/pkg` built from `sc-wasm`). |
| `notices/` | Published notices, one `<id>.md` per incident; built into the site's Notices tab and feed. |
| `watchlist.toml` | Sources for `swarmchase watch`. |
| `scripts/ci/` | CI gates and helpers, shared by the workflows and the pre-commit hook (`scripts/git-hooks/`). |
| `docs/` | [Methodology](docs/methodology.md), [for operators](docs/for-operators.md), [policies](docs/policies.md). |

## Pipeline

1. **Ingest:** NDJSON, JSON, Wayback CDX JSON, urlquery.net search results and reports, URL lists, or web server access logs (Common or Combined Log Format, for an operator checking its own logs) are normalised to `Observation`s. Use `--map ts=a.b,url=c` for unfamiliar exports, and `--map host=www.example.org` to name the host of an access log.
2. **Unwrap:** relays (`r.jina.ai/https://…`, `*.translate.goog`), URL parameters, `data:` programs and base64 parameters are peeled until the real target is found.
3. **Match:** rules cover relays, carriers, attack payloads, agent tags, callback inboxes, anti-bot tokens, header fingerprints, outcome states, and residue of language-model output (Markdown around URLs, unfilled placeholders, tool-call JSON and markup, cut-off output). Placeholder values such as `YOUR_API_KEY` are kept through redaction so these rules can see them; real secret values are still hashed.
4. **Grade:** each record is *significant* (a rule marked significant fired, such as an unambiguous attack payload, or score ≥ 6), *suggestive* (score ≥ 3), or noise.
5. **Link:** records are clustered by shared inbox IDs and unique tags, by close timing against the same target with shared indicators, and by probe chains. A probe chain is a run of variants of one request to the same host and path, at most 5 minutes apart. It links its flagged requests even when different rules fired on each. Reports show each chain with its pace (scanner, model-in-the-loop, or slow) and the requests in it that no rule flagged. The pace is a hint, not evidence.
6. **Time:** analysis covers median cadence, bursts, fleet-wide pauses, concurrent runs, and the operator UTC offset implied by date tags. Each cluster with records on at least 3 days, at least 20 records and 12 active clock hours gets an hour-of-day profile: activity spread over the whole day reads as round the clock, and activity confined to a window of up to 12 hours reads as one time zone's working day and gives a UTC offset guess. Probe chains count variants sent right after an error response (status 400 or above). Clusters also list how their requests were URL-encoded (space style, hex case, double encoding, parameter order), date tags that name a day well before they were seen (like a model with no clock writing the date it believes is today), a recon opening (e.g. `/robots.txt`, `/.well-known/security.txt`, `/.env`) shared by three or more hosts, the same unusual path set requested across three or more hosts, and fabricated-looking identifiers (invalid or patterned UUIDs, hand-typed hashes). Pairs of clusters that share no identifier but whose pauses start and end within two minutes of each other more often than chance allows are listed as a link to check. Three more hints describe a cluster: its *payload dialect* (which canonical test payloads it uses, such as `<script>alert(1)</script>` or `<svg onload>`, `' OR 1=1--` or `' OR '1'='1`, and how deep its `../` runs go), its *parallel fan-out width* (how many alike requests land in the same second, as when an agent issues tool calls in parallel), and *repeated cut lengths* (truncated URLs cut at nearly the same length, as a model or tool output limit would; a scan service's own display limit can do the same). Clusters that use the same uncommon mix of payloads are listed as a link to check. These are hints shown in reports; none changes a score or links records.
7. **Endpoints:** flagged requests are grouped per target host: hits, first and last seen, attack payloads, clusters, and whether the hits are ongoing or historical.
8. **Report:** Markdown drafts are produced for the provider, the affected operator (with the endpoint table), internal notes, or the public notice, with defanged URLs. The public notice withholds what notices must not carry (see [Notices](#notices)).

## CLI

The [CLI README](crates/swarmchase/README.md) covers installing it, input formats and every command. In brief:

```sh
cargo run -p swarmchase -- scan records.ndjson               # flagged records, strongest first
cargo run -p swarmchase -- clusters records.ndjson           # linked runs
cargo run -p swarmchase -- endpoints records.ndjson          # per target host: hits, payloads, ongoing or historical
cargo run -p swarmchase -- report records.ndjson --audience provider --cluster C1 -o c1-provider.md
cargo run -p swarmchase -- report access.log --map host=www.example.org --audience affected   # your own server's log
cargo run -p swarmchase -- analyze records.ndjson -o case.analysis.json
cargo run -p swarmchase -- unwrap 'https://r.jina.ai/https://…'
cargo run -p swarmchase -- collect wayback 'r.jina.ai/*' --from 20260901 -o data/jina.ndjson
cargo run -p swarmchase -- collect wayback 'r.jina.ai/*' --from 20260901 -o data/jina.ndjson --resume   # continue an interrupted pull
URLQUERY_APIKEY=… cargo run -p swarmchase -- collect urlquery r.jina.ai --from 20260901 -o data/uq.ndjson
cargo run -p swarmchase -- certs '%.example.com'
cargo run -p swarmchase -- contact agency.example            # security.txt lookup
cargo run -p swarmchase -- watch watchlist.toml              # collect what's new, analyse, write a digest
cargo run -p swarmchase -- case new 2026-10-portal --title "Portal SQLi" --cluster C1   # open a case from watch leads
cargo run -p swarmchase -- review --unflagged 20             # label watch leads (and a benign sample) as agent / benign / unsure
cargo run -p swarmchase -- eval samples/eval/*.ndjson        # precision/recall of the rules on labelled records
cargo run -p swarmchase -- rules my-rules.toml               # validate a rules file
```

Collectors retry on HTTP 429 and 5xx with exponential backoff, honouring `Retry-After`.

### Local secrets

Copy [`env.list.example`](env.list.example) to `env.list` (gitignored) and fill in the keys you have: `URLQUERY_APIKEY`, the SMTP settings, `SWARMCHASE_DATA`. Run any command with them loaded, or load them into your shell:

```sh
scripts/with-env.sh cargo run -p swarmchase -- watch
source scripts/with-env.sh
```

The file is parsed, never executed, and variables already set in the environment take precedence. CI does not use it; the workflows read repository secrets.

### urlquery.net

urlquery's search API needs a key from a urlquery account, read from `URLQUERY_APIKEY` (the same variable `urlquery-cli` uses; put it in `env.list`). Without one, `watch` skips urlquery sources and says so in the digest, and a urlquery export (search response or report JSON) can still be loaded with any command or in the browser. urlquery's terms allow personal, non-commercial research use and forbid redistributing their content without permission, so reports and notices link to urlquery reports and quote only the indicators we derived from them.

### Watch runs

`watch` is incremental. Each source keeps a time cursor in `<data>/state.json`; records are deduplicated by ID and appended to `<data>/store/<source>.ndjson`. Wayback's index is sorted by URL rather than time, so a pull cut short by `limit` resumes from its resume key on the next run. Each pull overlaps the last by `overlap_days` to catch late-indexed captures. Every run analyses the last `analysis_window_days` of stored records together and writes `<data>/runs/<stamp>/digest.md`, covering new clusters, tier changes and endpoints hit for the first time. The digest also has a health section. It flags a source whose pull falls below a fifth of its median over recent runs, which usually means an API change, an expired key or a spent quota, and a source that has failed two runs in a row. It also flags a rule whose hit rate on new records jumps to three times its recent rate, and shows the HTTP requests each source made. Any health warning gets the digest emailed. The digest also lists **possible reruns**: a new run whose target hosts, and their order, repeat an earlier run in a different cluster on another day (hosts common to many runs count for little). It also lists **archive bursts**: many Wayback or Arquivo captures of one host within minutes, on a host the store otherwise holds few captures of (the `archive_burst_*` settings in the rules file). Both are leads to review; neither merges clusters. The watch also matches new records against every case's indicators (its clusters' linking features and its endpoints, under the case's pinned rules). The digest's *Case status* section proposes marking an active notice contained after `contained_after_days` (in `watchlist.toml`, default 14) without a matching record, proposes reopening a contained or historical notice or a closed case that has new matches, and flags cases whose records would change tier under the current rules. Apply an approved proposal with `swarmchase notice update <id> --kind status --status <s>`, which also updates the case. The watch changes nothing itself. At the end of each run, run directories and stored records older than `retain_days` (default 180) are deleted; copy anything a case needs into the case first. The data directory is `--out`, `SWARMCHASE_DATA`, or `data/`.

### Evaluation

`eval` scores the rules against labelled records: precision and recall at each tier, precision per rule, and recall per kind of activity. Labels come from a `label` field on each record, or from `--labels` (NDJSON or CSV, including Transluce's `reports.csv`). With `--min-*` floors it exits non-zero when a floor is not met, which is how CI gates rules changes ([`eval-gate.sh`](scripts/ci/eval-gate.sh)). `collect urlquery-reports` fetches labelled urlquery reports by ID for a held-out measurement; see [samples/eval/README.md](samples/eval/README.md).

### Case files

When a lead is worth pursuing, `case new <id> --title … --cluster C1 [--record ID] [--host-hits]` opens a case. It copies the selected records (from the watch store, or from files given as arguments) into `<data>/cases/<id>/raw/records.ndjson`, so retention cannot delete them, and writes `case.toml`. `--host-hits` also takes every flagged record on the same hosts, including other clusters. `case.toml` holds:

- the case status (`open`, `reported`, `published`, `closed`) and the notice status (`active`, `contained`, `historical`);
- each endpoint and the admin's decision on it: `compromised`, `targeted`, `historical`, `not-affected`, or still `unreviewed`;
- attribution claims established by case work;
- contacts;
- a dated decision log;
- the reports sent.

| Command | What it does |
|---|---|
| `case status [<id>]` | Lists cases, or shows one case and what it still needs. |
| `case endpoint <id> <host> <state> [--note …]` | Classifies an endpoint. |
| `case claim <id> --party … --evidence provider_confirmed --detail …` | Records an attribution claim. |
| `case set <id> --status … --notice … --min-named …` | Changes the status or the naming threshold. |
| `case note <id> "…"` | Adds a dated entry to the decision log. |
| `case add <id> …` | Adds new records. |
| `case contacts <id>` | Finds contacts for each endpoint not marked not-affected: the first security.txt on the host or its parent domains, else the registrar's abuse address from RDAP. Each contact has a source link, a confidence and a date. |
| `case report <id> --audience …` | Drafts a report into `reports/`, applying the case's claims and naming threshold. |
| `case draft <id> --audience provider\|affected --to <contact>` | Writes the report for one listed contact into `outbox/`. For an email contact it is an unsent `.eml` with a fresh evidence bundle attached; otherwise it is paste-ready text. |
| `case bundle <id>` | Writes an evidence bundle without drafting a report. |
| `case verify <bundle>` | Checks the manifest, re-runs the analysis and fails if any tier or cluster differs. |
| `case sent <id> --to … --channel …` | Records a send the admin made, and moves an open case to reported. |
| `case notice <id>` | Drafts the public notice into `notice.md` and lists what it withheld and what needs a decision. |
| `case rules <id> [--update]` | Shows the pinned rules version against the current one and the records whose tier would change; `--update` re-pins and logs the change. |
| `case export <id> --format stix --audience … [--to <contact>]` | Writes the case as a STIX 2.1 bundle (indicators, observed data per cluster, relationships, report) for recipients' tooling. It is scoped like the matching report: an affected export carries only that operator's own logs, and a public export withholds what the notice withholds and is linted. Ids are deterministic. |
| `case evidence add <id> <log> --org … --host …` | Adds logs an affected operator sent back. Only flagged requests, the same clients' other requests and probe chains are kept, redacted; the file itself is not kept, only its SHA-256. |
| `case evidence consent <id> <eid> --how …` | Records the operator's agreement to the public notice using its logs (`withdraw` reverses it). Until then they appear in private reports only. |

An evidence bundle holds:

- the records;
- their analysis;
- a stamp with the rules version, the toolkit version and commit, and the tier of every flagged record and cluster;
- a SHA-256 manifest of those files.

`case verify` checks the manifest, re-runs the analysis and compares both it and the bundle's own `analysis.json` with the stamp. A recipient can run the same check without installing anything, in the browser toolkit's Case tab.

Nothing is ever sent by the tool. Each change is logged with its date. Each case keeps the rules it was opened with in `<data>/rules/<version>.toml`. Its reports, notice draft, exports and bundles use those rules rather than the current ones, so a rules change between drafting and sending cannot silently change a tier. Cases never go into git, because an open case names organisations on unconfirmed evidence and private reports carry details that public notices withhold.

### Notices

A notice is drafted inside its case and published by committing it:

1. `case notice <id>` renders the public notice into `<data>/cases/<id>/notice.md`. It prints:
   - each thing it withheld;
   - each thing it could not classify, which is withheld until the admin decides;
   - anything that got through the withholding anyway.
2. The admin reviews and edits the draft.
3. `notice add <id>` checks the draft (with the case's pinned rules, and the current rules too when they differ) and copies it to `notices/<id>.md`, with front matter that holds the status and the dated updates. It refuses while any endpoint is unreviewed, and it never overwrites a notice that exists.
4. Committing and pushing the file publishes it.
5. Later changes go through `notice update <id> --kind update|status|correction|reply|retraction --text …` (`--status contained`; `--from` and `--text-file` for a statement quoted verbatim). Each one appends a dated entry and never rewrites an earlier one.

What a notice withholds:

| Withheld | Detail |
|---|---|
| Records that reach a callback channel | Webhook, request-bin and notification-topic identifiers, paste links, disposable inboxes: the whole URL and its record link. |
| Linking parameters that could be credentials | `tok`, `sid`, `session`, `nonce`. Run tags such as `uqtag` stay. |
| E-mail addresses | The local part of every address. |
| Compromised endpoints | Their attack details and request URLs. |
| Operator-supplied logs | Everything from them, until the operator agrees to publication. A report to one operator never carries another operator's logs. Records used with agreement are marked as provided by the operator. |

`notice lint` checks every committed notice for:

- callback channel identifiers;
- e-mail addresses other than role mailboxes;
- credential shapes;
- valid front matter and update order.

CI runs it, and so does the pre-commit hook when `notices/` is staged. At deploy, `notice build` turns `notices/` into `site/notices/`: an index, one page per notice and an Atom feed with one entry per update. It refuses to build if any notice fails the lint.

### Reviewing leads

`review` steps through the watch store's recent records, strongest cluster first, and asks for a label: `a` agent, `b` benign, `u` unsure, `s` skip, `q` quit. `c` opens a case from the shown record's cluster, and `c <case-id>` adds the cluster to an open case. Upper case labels every queued record in the cluster, and text after the key is a note (`b ordinary article read`). `--unflagged N` adds a stable sample of unflagged records, which grows the benign baseline and catches misses. Answers are saved one at a time to `<data>/labels/reviewed.ndjson`, which holds each record with its label, so `swarmchase eval <data>/labels/reviewed.ndjson` measures the rules against everything reviewed. `review --stats` counts reviews and disagreements; `--list` prints the queue. The file stays in the data directory and is never committed.

### Redaction

Secrets are replaced with `REDACTED-<sha256 prefix>` at ingest, in the CLI, the collectors and the browser. This covers cookie and token parameters, cookie jars, auth headers, JWTs and well-known API key formats. The hash is deterministic, so records that carried the same secret still link. Attack payloads, agent tags and run IDs are left intact because the rules need them.

## Browser toolkit

`scripts/ci/build-site.sh` builds `sc-wasm` into `site/pkg`. Serve it locally with `python -m http.server -d site 8080`. The page analyses pasted or loaded records entirely client-side, including an operator's own access log. It also unwraps single URLs, edits rules, parses security.txt and defangs URLs. Selecting a cluster shows its runs, daily rhythm, clock offset from date tags, stale date tags and the report hints (encoding styles, recon openings, unusual path sets, fabricated identifiers, probe chains); a separate card lists shared pauses and probe chains across the input. These are hints to check, not evidence. *Try an example* loads synthetic records, written to exercise the rules and never collected. In the Rules tab, *Test against labelled set* scores the bundled and the edited rules on the committed `samples/eval/*.ndjson` set side by side, and lists records whose tier changed and records still misclassified. The disclosure draft follows the CLI's naming gate: pick the weakest evidence that may name a developer, and paste claims from case work (the JSON `swarmchase report --claims` reads); outside case notes, a developer below that level is not named. The Notices tab lists published notices by status, provider and affected host. Each notice page shows its updates, corrections and statements. The Case tab checks an evidence bundle: pick its four files or its folder, and the page checks each SHA-256 against the manifest, re-runs the analysis with the rules in the Rules tab, and compares every tier and cluster with the stamp, as `case verify` does. It then shows the stamp, a timeline of each cluster's runs, the clusters and the records, defanged. Nothing leaves the browser.

Records carry attack payloads, so the page treats them as inert text. A strict Content-Security-Policy allows only the page's own script, styles and WASM module. Record text is inserted as text, never as HTML, and URLs are shown defanged and never as links. Notices reach the page as plain blocks and spans, never as HTML. `scripts/ci/check-site.py` checks the policy and the code statically. `node scripts/site-xss-check.mjs` loads XSS probes and a hostile notice into headless Chrome and fails if any of them runs.

## Ground rules

- **Passive only.** Read indexes and public records. Never open the URLs agents submitted, since they may carry live payloads or alert the operator. Never read from or post to their inboxes or notification topics.
- **Attribution is evidence-weighted.** Model names inside requests are weak, because agents misreport who built them. An ASN names a host, not a developer. Each report's Attribution section grades every claim on an evidence ladder (self-identification, hosting network, shared identifiers, provider infrastructure, provider confirmation). A developer is named outside case notes only at or above `--min-named`; claims established by case work come in with `--claims`.
- **Report and publish together.** Swarms are active incidents. Once the admin judges the evidence sufficient, reports go to the provider and affected operators and a public notice is published at the same time. Tools only draft. The admin sends and publishes.
- **Raw data stays out of git.** `data/` (watch data and case files) is gitignored. Only notices and curated samples are committed.

The full set is in [docs/policies.md](docs/policies.md).

## Docs

- [Methodology](docs/methodology.md): how records become tiers, clusters and claims, and the known limits.
- [For operators](docs/for-operators.md): what a report means, checking your own logs, sending logs back, replies, verifying a bundle.
- [Policies](docs/policies.md): collection, attribution, reporting and publication.
- [Contributing](CONTRIBUTING.md): gates, conventions and rule contributions.

## CI on a self-hosted runner

All workflows use `runs-on: self-hosted`. The runner is Ubuntu Linux arm64 (DGX Spark).

- `main-ci.yml`: repo gates, then fmt, clippy (`-D warnings`), tests and a wasm32 type-check; on `main` it then builds the browser toolkit and the notice pages and deploys `site/` to Pages. Pull requests get the gates and a lint pass. **Pull requests from forks run nothing**, because a self-hosted runner would otherwise run untrusted code on your machine. Also enable *Settings → Actions → Require approval for all outside collaborators*, and set *Settings → Pages → Source* to **GitHub Actions**.
- `watch.yml`: runs `watch` every 6 hours (and on demand). State lives outside the checkout in `$SWARMCHASE_DATA` (default `~/swarmchase-data` for the runner user), because `actions/checkout` cleans the workspace. Results are not uploaded as artifacts, since a public repo's artifacts are downloadable by anyone. When something changed, the digest is emailed to the admin, and failures send an alert. Email is sent with `curl` over SMTP and is configured with the repo secrets `SMTP_URL` (e.g. `smtps://smtp.example.com:465`), `SMTP_USER`, `SMTP_PASSWORD`, `MAIL_FROM` and `MAIL_TO`. Without them, runs still write digests on the runner. The optional secret `URLQUERY_APIKEY` enables the urlquery source.

Both keep cargo's build cache in `~/.cache/swarmchase-ci-target`, outside the checkout, keyed by compiler version ([`select-ci-target-dir.sh`](scripts/ci/select-ci-target-dir.sh)). The runner needs rustup and python3; `rust-toolchain.toml` pulls stable plus the `wasm32-unknown-unknown` target, and `wasm-pack` is installed on first use.

[CONTRIBUTING.md](CONTRIBUTING.md) lists the gates and the pre-commit hook.

## License

Released under the [Unlicense](LICENSE) (public-domain dedication). For jurisdictions that do not recognise the public domain, it is also available under the [MIT License](LICENSE-MIT). [NOTICE](NOTICE) covers what the licenses do not extend to: quoted third-party records and trademarks.
