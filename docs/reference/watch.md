# Watch runs and review

How `swarmchase watch` collects and reports, and how `swarmchase review` labels what it finds. The command summaries are in the [CLI README](../../crates/swarmchase/README.md#watch-and-review); the day-to-day flow is in the [admin workflow](../guides/admin-workflow.md).

## The data directory

Every watch, review and case command works in one data directory: `--out` (or `--data`), else `SWARMCHASE_DATA`, else `data/` relative to where the command runs. On the runner it is `$SWARMCHASE_DATA` outside the checkout ([runner](runner.md)). It is gitignored and never committed. A command that reads existing data (`review`, `case`, `notice add`) prints a hint naming the directory it resolved when that directory holds no watch data, labels or cases; a watch run says when it starts a new one.

| Path | Holds |
|---|---|
| `state.json` | Each source's time cursor and resume key. |
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
- **Wayback paging.** Wayback's index is sorted by URL rather than time, so a pull cut short by `limit` resumes from its resume key on the next run.
- **Overlap.** Each pull overlaps the last by `overlap_days` to catch late-indexed captures.
- **Analysis window.** Every run analyses the last `analysis_window_days` of stored records together, so clusters can span runs. It reads only that window plus the overlap from the store, and this run's new records whatever their capture time.
- **urlquery.** urlquery sources need `URLQUERY_APIKEY`. Without it they are skipped and the digest says so ([configuration](configuration.md#urlquerynet)).
- **HTTP cache.** Responses are kept in `cache/http/` and reused for `http_cache_ttl_secs` (default 3600, 0 turns it off), then revalidated with their ETag. Requests that carry an API key are not cached.
- **ASN.** Once `swarmchase asn fetch` has put the IP-to-ASN table in `asn/`, records that carry an IP but no network get one ([configuration](configuration.md#ip-to-asn-table)).

### Source kinds

Each `[[source]]` names a `kind`. Its `pattern` means what the table says; `endpoint` and `scan` apply where noted.

| Kind | Reads | Pattern | Also |
|---|---|---|---|
| `wayback` | Wayback Machine CDX | CDX URL pattern | `match_type`, resumes across runs |
| `arquivo` | Arquivo.pt CDX | CDX URL pattern | cannot page; warns when cut at `limit` |
| `commoncrawl` | Common Crawl CDX | CDX URL pattern | `endpoint`: `latest`, `latest:N` or a crawl id |
| `memento` | One URL's timemap | exact URL | `endpoint`: the timemap service |
| `urlquery` | urlquery.net search | search query | needs `URLQUERY_APIKEY` |
| `urlscan` | urlscan.io public search | search query | per case only (terms) |
| `gharchive` | GH Archive events | substrings | `scan`: newest hours read |
| `npm` | npm registry search | search text | |
| `pypi` | PyPI RSS feed | substrings | `endpoint`: `updates` or `packages` |
| `ctlog` | One CT log | substrings | `endpoint`: log URL; `scan`: newest entries |

Substrings are `|`-separated and case-insensitive. Archive kinds date records by capture, scan services by submission, and the rest by when the request reached the service (`ts_kind`).

Streamed and feed kinds read a bounded sample each run, not the whole stream, and their records are leads for review: the record's URL is the event, package or certificate name, so the URL rules rarely fire on it. Every kind's terms of use are summarised in the [watchlist](../../watchlist.toml) and in its [collector](../../crates/sc-collect/README.md#record-sources).

## The digest

Each run writes `runs/<stamp>/digest.md`. It covers new clusters, tier changes and endpoints hit for the first time. When something changed, the scheduled workflow emails it to the admin; nothing else leaves the runner.

### Health

The health section flags:

- a source whose pull falls below a fifth of its median over recent runs, which usually means an API change, an expired key or a spent quota;
- a source that has failed two runs in a row;
- a rule whose hit rate on new records jumps to three times its recent rate.

It also shows the HTTP requests each source made. Any health warning gets the digest emailed.

### Possible reruns and archive bursts

- **Possible reruns.** A new run whose target hosts, and their order, repeat an earlier run in a different cluster on another day. Hosts common to many runs count for little. The thresholds are in [methodology](../methodology.md#descriptive-hints).
- **Archive bursts.** Many Wayback or Arquivo captures of one host within minutes, on a host the store otherwise holds few captures of, measured over the span the run reads. The `archive_burst_*` settings in the rules file set the thresholds.

Both are leads to review; neither merges clusters.

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
- `--stats` counts reviews and disagreements; `--list` prints the queue.

Each answer goes to `labels/reviewed.ndjson` with the record, so `swarmchase eval <data>/labels/reviewed.ndjson` measures the rules against everything reviewed ([evaluation](evaluation.md)). The file stays in the data directory and is never committed.
