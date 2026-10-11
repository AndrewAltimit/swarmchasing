# Watch runs and review

How `swarmchase watch` collects and reports, and how `swarmchase review` labels what it finds. The command summaries are in the [CLI README](../../crates/swarmchase/README.md#watch-and-review); the day-to-day flow is in the [admin workflow](../guides/admin-workflow.md).

## The data directory

Every watch, review and case command works in one data directory: `--out` (or `--data`), else `SWARMCHASE_DATA`, else `data/` relative to where the command runs. On the runner it is `$SWARMCHASE_DATA` outside the checkout ([runner](runner.md)). It is gitignored and never committed. A command that reads existing data (`review`, `case`, `notice add`) prints a hint naming the directory it resolved when that directory holds no watch data, labels or cases; a watch run says when it starts a new one.

| Path | Holds |
|---|---|
| `state.json` | Each source's time cursor, resume key or stream checkpoint, and health history. |
| `store/<source>.ndjson` | Stored records, deduplicated by ID. |
| `runs/<stamp>/digest.md` | One directory per run, with its digest. |
| `labels/reviewed.ndjson` | Records labelled with `swarmchase review`. |
| `cases/<id>/` | Case files ([cases](cases.md)). |
| `rules/<version>.toml` | Rules versions that cases pin. |
| `cache/http/` | Cached collector responses; safe to delete. |
| `asn/ip2asn-v4.tsv.gz` | The IP-to-ASN table, once fetched. |

## Collection

`watch` is incremental. It pulls the sources in [`watchlist.toml`](../../watchlist.toml), each of which carries a rationale: the agent behaviour it catches, the rule it feeds and what its noise looks like.

- **Cursors.** Each source keeps a time cursor in `state.json`. New records are deduplicated by ID and appended to the source's store file.
- **Wayback paging.** Wayback's index is sorted by URL rather than time, so a pull cut short by `limit`, or by a failed page, resumes from its resume key on the next run. A host too big for one index query is read by path prefix, and `slice_days` reads the time range in windows.
- **Checkpoints.** GH Archive and CT logs read on from where the last run stopped (`mark` in `state.json`), within a per-run budget.
- **Unavailable hosts.** A host answering HTTP 503 gets ten minutes of retries; if it stays down, later requests to it in the same run are not sent, and its sources continue next run.
- **Overlap.** Each pull overlaps the last by `overlap_days` to catch late-indexed captures.
- **Analysis window.** Every run analyses the last `analysis_window_days` of stored records together, so clusters can span runs. It reads only that window plus the overlap from the store, and this run's new records whatever their capture time.
- **urlquery.** urlquery sources need `URLQUERY_APIKEY`. Without it they are skipped and the digest says so ([configuration](configuration.md#urlquerynet)).
- **HTTP cache.** Responses are kept in `cache/http/` and reused for `http_cache_ttl_secs` (default 3600, 0 turns it off), then revalidated with their ETag. Requests that carry an API key are not cached.
- **ASN.** Once `swarmchase asn fetch` has put the IP-to-ASN table in `asn/`, records that carry an IP but no network get one ([configuration](configuration.md#ip-to-asn-table)).

### Source kinds

Each `[[source]]` names a `kind`. Its `pattern` means what the table says; `endpoint` and `scan` apply where noted.

| Kind | Reads | Pattern | Also |
|---|---|---|---|
| `wayback` | Wayback Machine CDX | CDX URL pattern | `match_type`, `filter`, `slice_days`; resumes |
| `arquivo` | Arquivo.pt CDX | CDX URL pattern | `filter`; cannot page, warns when cut at `limit` |
| `commoncrawl` | Common Crawl CDX | CDX URL pattern | `endpoint`: `latest`, `latest:N` or a crawl id |
| `memento` | One URL's timemap | exact URL | `endpoint`: the timemap service |
| `urlquery` | urlquery.net search | search query | needs `URLQUERY_APIKEY` |
| `urlscan` | urlscan.io public search | search query | per case only (terms) |
| `gharchive` | GH Archive events | substrings | `scan`: hours per run; `max_mb` |
| `npm` | npm registry search | search text | `canary`: a search that always hits |
| `pypi` | PyPI RSS feed | substrings | `endpoint`: `updates` or `packages` |
| `ctlog` | One CT log | substrings | `endpoint`: log URL; `scan`: entries per run |
| `wellknown` | Wayback agent footprints | hosts or `*.domain`s | resumes across runs |
| `mcp` | MCP Registry servers | substrings | metadata only; resumes across runs |

Substrings are `|`-separated and case-insensitive. Archive kinds date records by capture, scan services by submission, and the rest by when the request reached the service (`ts_kind`).

Streamed and feed kinds read a bounded amount each run and report their coverage, and their records are leads for review: the record's URL is the event, package, certificate, footprint or tool server, so the URL rules rarely fire on it. The `wellknown` kind reads only Wayback index rows for agent cards, agent registration files and signature key directories, never the files. The `mcp` kind keeps a server's name, version, publish time and declared hosts as reference data for linking. Every kind's terms of use are summarised in the [watchlist](../../watchlist.toml) and in its [collector](../../crates/sc-collect/README.md#record-sources).

## The digest

Each run writes `runs/<stamp>/digest.md`. It opens with source health, then covers new clusters, tier changes and endpoints hit for the first time. When something changed, the scheduled workflow emails it to the admin; nothing else leaves the runner.

### Health

The health block comes first, because a source that did not run hides whatever it would have found. Its alerts are:

- a source that failed this run, with a short reason such as `HTTP 504 after 3 attempts`, and how many runs in a row it has failed. One failure is enough, so every failure reaches the admin within one run;
- a host that stayed unavailable through its retries, so the run stopped sending to it;
- a source whose canary failed: it answered, but nothing came back in the shape the parser expects;
- a source skipped for the first time (no API key);
- a source whose pull falls below a fifth of its median over recent runs, which usually means an API change, an expired key or a spent quota. A source's first pull and a pull spread over several runs are catching up, so they do not count towards the median;
- a rule whose hit rate on one source's new records jumps to three times its recent rate on that source. Each source is compared with itself, because a relay's own rule fires on nearly every record from it.

Under *Capability lost this run* it lists each skipped, failed or stopped source with what its absence costs, and the part of a stream it skipped. When no submit-time source ran (urlquery is the only one scheduled), it says so first: without submission times, timing links, pace, agent grades above L2 and interaction edges are unavailable. *Quiet sources* notes a source that has pulled nothing for several runs, and whether its canary passed.

Any alert gets the digest emailed; lost capability and quiet sources alone do not. A failed source's reason never includes the request URL; the full error is in the run's log and in `state.json`.

### Sources and coverage

The sources table shows each source's records, requests, coverage and status. Coverage is what a stream or feed source read against what there was to read since its checkpoint, such as `6 of 6 hours, canary ok` or `1024 of 400000 entries, 398976 skipped` for a CT log that grows faster than a polite reader.

### Headline counts

The window's headline counts records with an indicator beyond the relay or carrier they came through: a hit whose kind is not a route kind (relay, cache buster, self-id, header, outcome) and is not a carrier rule naming the record's own host. Every watch source is a relay's or carrier's own host, so a plain "has a hit" count would equal the records pulled. Clusters are counted above noise; noise-tier clusters are listed in their own section and left out of the count.

*Significant records outside any cluster* lists significant records that joined no cluster, new ones first, with their rule ids, tier and defanged target host, so a lone strong record is not reduced to a host name.

### Possible reruns and archive bursts

- **Possible reruns.** A new run whose target hosts, and their order, repeat an earlier run in a different cluster on another day. Hosts common to many runs count for little. The thresholds are in [methodology](../methodology.md#descriptive-hints).
- **Archive bursts.** Many Wayback or Arquivo captures of one host within minutes, on a host the store otherwise holds few captures of, measured over the span the run reads, with how many carry an indicator beyond the relay. The `archive_burst_*` settings in the rules file set the thresholds.

Both are leads to review; neither merges clusters.

### Candidate fleets, escalations and common features

Over the whole window, up to ten lines each:

- **Candidate fleets.** Clusters tied by soft links, with the kinds and the weakest pair's strength. Merging one is a case decision ([fleets](cases.md#fleets)).
- **Escalations.** Requests for one page whose route climbed (direct, relay, program, remote browser), with the clusters they touch.
- **Common features.** Linking values shared too widely to link on, so they were demoted: records, hosts, span and the limit they passed.
- **Noise-tier clusters.** Clusters at noise tier, listed but not counted in the headline.

Clusters are named by number and stable key throughout (`C3 k-3f9a2c1b`), and hosts and values are defanged. These sections alone never make a run count as changed.

### Case status

The watch matches new records against every case's indicators: its clusters' linking features and its endpoints, under the case's pinned rules. The *Case status* section then proposes:

- marking an active notice contained after `contained_after_days` (in `watchlist.toml`, default 14) without a matching record;
- reopening a contained or historical notice, or a closed case, that has new matches;
- re-checking cases whose records would change tier under the current rules.

The watch changes nothing itself. Apply an approved proposal with `swarmchase notice update <id> --kind status --status <s>`, which also updates the case.

## Retention

At the end of each run, run directories and stored records older than `retain_days` (default 180, by capture time) are deleted. Copy anything a case needs into the case first (`case new` or `case add`). The policy is in [policies](../policies.md#collection).

## Reviewing leads

`review` steps through the watch store's recent records, strongest cluster first, and asks for a label.

| Key | Does |
|---|---|
| `a` / `b` / `u` | Labels the record agent, benign or unsure. |
| `A` / `B` / `U` | Labels every queued record in the cluster. |
| `s` / `q` | Skips the record, or quits. |
| `c` | Opens a case from the shown record's cluster. |
| `c <case-id>` | Adds the cluster to an open case. |

Text after the key is saved as a note (`b ordinary article read`). Answers are saved one at a time, so quitting loses nothing.

- `--unflagged N` adds a stable sample of unflagged records, which grows the benign baseline and catches misses.
- `--stats` counts reviews and disagreements, and Cohen's κ between labellers; `--list` prints the queue.
- `--labeller <name>` saves to `labels/reviewed-<name>.ndjson` instead, for a second, independent reviewer ([two labellers](evaluation.md#two-labellers)).
- `--suggest` shows a local model's label suggestion before each prompt ([label suggestions](#label-suggestions)).

Each answer goes to `labels/reviewed.ndjson` with the record, so `swarmchase eval <data>/labels/reviewed.ndjson` measures the rules against everything reviewed ([evaluation](evaluation.md)). The file stays in the data directory and is never committed.

### Label suggestions

`review --suggest` asks a language model for a label before each prompt and shows it as `suggestion: agent — <reason>`. The admin still answers; the suggestion is saved beside the label as `suggested` and is never the label, so eval reads only the admin's.

It is allowed only with a model running locally:

- **Local only.** `SWARMCHASE_LLM_URL` is an OpenAI-compatible server (`/v1/chat/completions`; the base URL is enough) on `localhost`, a loopback address, a private address (RFC 1918, or RFC 4193 for IPv6) or a link-local one. Any other host is refused before anything is sent, so records never reach a third-party API. The request goes through no proxy and follows no redirect. `SWARMCHASE_LLM_MODEL` names the model ([configuration](configuration.md#environment-variables)).
- **What it sees.** The defanged URL, target host and rule hits, the tier and score, and the cluster's size, tier, top rules and target hosts, with a fixed prompt asking for `{"label": "agent" | "benign" | "unsure", "reason": "…"}`. No IP addresses.
- **No fetching.** The model gets text and no tools; the prompt says the URLs are data, never to be visited.
- **Failures.** A timeout (60 s), an error or a reply that is not that JSON means no suggestion for the record; the review carries on.
