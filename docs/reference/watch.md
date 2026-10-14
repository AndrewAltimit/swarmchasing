# Watch runs and review

How `swarmchase watch` collects and reports, and how `swarmchase review` labels what it finds. The command summaries are in the [CLI README](../../crates/swarmchase/README.md#watch-and-review); the day-to-day flow is in the [admin workflow](../guides/admin-workflow.md).

## The data directory

Every watch, review and case command works in one data directory: `--out` (or `--data`), else `SWARMCHASE_DATA`, else `data/` relative to where the command runs. On the runner it is `$SWARMCHASE_DATA` outside the checkout ([runner](runner.md)). It is gitignored and never committed. A command that reads existing data (`review`, `case`, `notice add`) prints a hint naming the directory it resolved when that directory holds no watch data, labels or cases. A watch run refuses such a directory unless given `--init`, so an unset or mistyped `SWARMCHASE_DATA` never starts a fresh store beside the real one. Start a data directory once with `swarmchase watch --init`; on the runner, run the watch workflow by hand with its `init` input ([runner](runner.md#watchyml)).

| Path | Holds |
|---|---|
| `state.json` | Each source's time cursor, resume key or stream checkpoint, query fingerprint and health history; records not yet in a digest; state of sources removed from the watchlist. |
| `state.json.bak` | The previous `state.json`, read when the current one does not parse. |
| `.lock`, `.lock.owner` | The data directory's writer lock and the command holding it ([one writer at a time](#one-writer-at-a-time)). |
| `store/<source>.ndjson` | Stored records, deduplicated by ID. |
| `runs/<stamp>/digest.md` | One directory per run, with its digest. |
| `runs/<stamp>/analysis.json`, `case-notes.md` | The run's full analysis and its Markdown report; only the newest runs keep them ([retention](#retention)). |
| `runs/<stamp>/run.json` | The run in a stable JSON ([the run summary](#the-run-summary)). |
| `runs/<stamp>/attention.json` | The run's [attention queue](#the-attention-queue). |
| `ledger.json` | Each cluster's history across runs ([the ledger](#the-ledger)). |
| `summary.json`, `ledger.json` (`.bak`, `.damaged`) | The previous copy, and a copy that could not be read, set aside ([interrupted runs](#interrupted-runs)). |
| `autonomy.ndjson` | What each [autonomy](#autonomy) level did or would have done. |
| `platform/` | The [platform pass](#platform-swarms): checkpoints, reported candidates, carried events, labels and provenance answers. |
| `runs/<stamp>/platform-swarms.json` | The run's platform swarm candidates. |
| `labels/reviewed.ndjson` | Records labelled with `swarmchase review`. |
| `labels/suggestions-local.ndjson` | The local model's suggestions on new leads ([model triage](#model-triage)). |
| `labels/suggestions-claude-watch.ndjson` | Claude's suggestions on new leads from hosted sources ([model triage](#model-triage)). |
| `cases/<id>/` | Case files ([cases](cases.md)). |
| `rules/<version>.toml` | Rules versions that cases pin. |
| `canary/registry.json` | Canary tokens registered from built sites ([canary sightings](#canary-sightings)). |
| `runs/<stamp>/canary.json` | The run's canary sightings, when it has any. |
| `cache/http/` | Cached collector responses, pruned every run ([retention](#retention)); safe to delete. |
| `asn/ip2asn-v4.tsv.gz` | The IP-to-ASN table, once fetched. |
| `identity/` | Providers' published agent ranges and key directories, once fetched ([identity](identity.md)). |
| `.stale-alerted` | The run stamp the staleness check last mailed about ([runner](runner.md#watch-staleyml)). |

## Collection

`watch` is incremental. It pulls the sources in [`watchlist.toml`](../../watchlist.toml), each of which carries a rationale: the agent behaviour it catches, the rule it feeds and what its noise looks like.

- **Cursors.** Each source keeps a time cursor in `state.json`. New records are deduplicated by ID and appended to the source's store file. A record stamped in the future moves the cursor no further than the run's own time. A source that cannot page and returns `limit` records moves its cursor no further than the oldest of them, since what lies before may be missing. IDs of records with no time stay in the seen list, so they are never added twice.
- **Wayback paging.** Wayback's index is sorted by URL rather than time, so a pull cut short by `limit`, or by a failed page, resumes from its resume key on the next run. A host too big for one index query is read by path prefix, and `slice_days` reads the time range in windows.
- **Checkpoints.** GH Archive, Wikimedia EventStreams, Hacker News, Bluesky, GitHub search and CT logs read on from where the last run stopped (`mark` in `state.json`), within a per-run budget. Every page read counts as progress, matches or not, so a failure after matchless hours resumes after them. A GH Archive hour whose file is corrupt or cut off is skipped and counted, not retried each run.
- **Unavailable hosts.** A host answering HTTP 503 gets ten minutes of retries; if it stays down, later requests to it in the same run are not sent, and its sources continue next run. The same holds at once for a host whose `Retry-After` asks for more than the five-minute cap on a wait, and for a host that times out on two requests in a row after their retries, so a hanging index cannot spend the run's time budget.
- **Overlap.** Each pull overlaps the last by `overlap_days` to catch late-indexed captures.
- **Analysis window.** Every run analyses the stored records captured in the last `analysis_window_days` together, so clusters can span runs, plus the run's new records whatever their capture time: an archive that indexes a capture late still gets it analysed once. The digest notes how many new records were captured before the window, and `run.json` counts them. The overlap before the window is read for the archive burst baseline only. `case new` defaults to the same window, so a cluster number from the digest names the same cluster there; a record named with `--record` is taken from the whole store when it is older.
- **Changed queries.** Each source's state holds a fingerprint of its kind, pattern, match type, filters and endpoint. A source edited under the same name starts over (cursor, seen IDs, resume key and checkpoint reset, health kept), records its store already holds are not reported again, and the digest says so. A state saved without a fingerprint counts as matching.
- **Removed sources.** The state of a source no longer in the watchlist is set aside under `retired` in `state.json`, with a digest note; a source added back under the same name continues from it.
- **urlquery.** urlquery sources need `URLQUERY_APIKEY`. Without it they are skipped and the digest says so ([configuration](configuration.md#urlquerynet)).
- **GitHub search.** `ghsearch` sources need `GITHUB_TOKEN`. Without it they are skipped and the digest says so.
- **HTTP cache.** Responses are kept in `cache/http/` and reused for `http_cache_ttl_secs` (default 3600, 0 turns it off), then revalidated with their ETag. Requests that carry an API key are not cached. Each entry holds its body's SHA-256; a body that does not match is a miss. Cached bodies are raw answers, not redacted records, so every run deletes entries older than the TTL, and at least a day ([retention](#retention)).
- **Store lines.** A store file is read line by line as bytes. A line that is not UTF-8 or not a record (a write cut short) is skipped and counted in a `store_damaged` health alert; the other lines are read. Before an append, a last line without its newline is ended, so it never swallows the next record.
- **ASN.** Once `swarmchase asn fetch` has put the IP-to-ASN table in `asn/`, records that carry an IP but no network get one ([configuration](configuration.md#ip-to-asn-table)).
- **Redaction.** Collectors redact what they return, and the watch redacts every pulled record again before it reaches the run directory or the store, so a collector that misses a field cannot put a secret in the store. Redaction is idempotent: a record redacted once passes through unchanged.

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
| `wikimedia` | External links added to wiki pages | substrings of the link or title | `scan`: minutes per run; `max_mb`; `filter` |
| `hackernews` | Links in Hacker News stories and comments | substrings of the link, title or text | `scan`: index queries of 1000 items per run |
| `bluesky` | Links in Bluesky posts (Jetstream) | substrings of the link or text | a sample; `scan`: minutes per run; `max_mb`; `endpoint` |
| `ghsearch` | Links in GitHub pull requests and commit messages | substrings, each one search | needs `GITHUB_TOKEN`; `scan`: requests per run; `endpoint`: `prs` or `commits` |
| `npm` | npm registry search | search text | `canary`: a search that always hits |
| `pypi` | PyPI RSS feed | substrings | `endpoint`: `updates` or `packages` |
| `ctlog` | One CT log | substrings | `endpoint`: log URL; `scan`: entries per run |
| `wellknown` | Wayback agent footprints | hosts or `*.domain`s | resumes across runs |
| `mcp` | MCP Registry servers | substrings | metadata only; resumes across runs |

Substrings are `|`-separated and case-insensitive. Archive kinds date records by capture, scan services by submission, and the rest by when the request reached the service (`ts_kind`).

Streamed and feed kinds read a bounded amount each run and report their coverage, and their records are leads for review: the record's URL is the event, package, certificate, footprint or tool server, so the URL rules rarely fire on it. The `wellknown` kind reads only Wayback index rows for agent cards, agent registration files and signature key directories, never the files. The `mcp` kind keeps a server's name, version, publish time and declared hosts as reference data for linking.

### GH Archive and Wikimedia notes

GitHub's event payloads are trimmed: a pull request carries its number and refs but no title, body, link or author association, and a push carries no commits. A `gharchive` source therefore finds pasted URLs in issues, comments, reviews, discussions and releases, and run tags in repository names; a pull request's record links to it by number. `scan` hours at most are read per run, and `max_mb` is sized to fit them, so the hour cap ends a run.

A `ghsearch` source fills the gap GitHub's trimmed payloads leave: it searches pull requests created and commits committed since its checkpoint, one search per substring, and checks every result against the substring again, since search matches words. Only matching links and run tags become records, the link as URL and the pull request or commit page as reference; the footers coding agents add to their own work never match. A search cut short by the request budget or GitHub's 1000-result cap counts as skipped.

A `bluesky` source reads Jetstream's posts for a sampled stretch: from its checkpoint, or the newest half hour when the checkpoint is older, for at most `scan` wall-clock minutes. Links posted outside the stretch are never seen, and the digest's coverage shows minutes read against minutes since the last run. Each link in a post's link facets or link card that matches is a record whose reference is the post's page; a post deleted during the read is dropped.

A `wikimedia` source reads the `mediawiki.page-links-change` stream
 from the millisecond after the last event read, until it reaches the time the run began or runs out of `scan` wall-clock minutes or `max_mb` megabytes; the rest waits for the next run. Each added external link is a record whose URL is the link, never fetched, and whose reference is the edit's diff. Bot-flagged accounts and the stream's `canary` events are dropped. `filter` takes `domain:<wiki>`, `!domain:<wiki>` and `ns:<n>`. Coverage is in minutes of stream time. Requests carry the client's identifying user agent, as Wikimedia's User-Agent policy asks. Every kind's terms of use are summarised in the [watchlist](../../watchlist.toml) and in its [collector](../../crates/sc-collect/README.md#record-sources).

### One writer at a time

A watch run holds an exclusive lock on the data directory (`.lock`) from start to finish; `case rename`, `watch reset`, `watch prune-cache`, `backup create` and `backup restore` take it too. A second command that needs it fails at once, naming the holder from `.lock.owner`, instead of writing beside the first. The lock is advisory and released when the command exits, however it exits. `state.json` and every other rewritten file are written to a temporary file of their own and renamed into place; the previous `state.json` is kept as `state.json.bak`, read with a warning when the current one does not parse.

A review file is saved under a lock of its own and merged: a save rereads the file and writes only what that command changed, so a `review --serve` page left open never undoes a `review tuned` run meanwhile.

### Interrupted runs

A run saves `state.json` after each source, with the IDs of the records it stored under `undigested`. They are cleared only once the run's digest and `run.json` are written. A run cut short after collecting (killed, out of time, a crash) leaves them, and the next run loads those records from the store and reports them as new, with a note in the digest and their number as `carried_over` in `run.json`. Steps after collection do not stop a run: a file that cannot be written or a history that cannot be read becomes a `step_failed` health alert, and the run goes on to its digest. A `summary.json` or `ledger.json` that does not parse is read from its `.bak` copy; when that fails too, the damaged file is kept as `.damaged`, the history starts afresh and the digest says so.

A step after the digest that fails (the run's `summary.json`, `LATEST`, retention) ends the run with an error, having lost nothing the digest reported.

### One source, or starting one over

`watch --only <name>` pulls one source, with its cursor, health and undigested records as a full run keeps them, and leaves the others as they are; the analysis and digest cover the store as usual. `watch reset <name>…` makes sources start over on their next run: it clears each one's cursor, seen IDs, resume key and checkpoint under the data lock, and keeps its health history.

`watch prune-cache [watchlist.toml]` deletes cached responses older than the TTL (at least a day), or older than `--max-age-hours`, as each run does.

### Checking a watchlist

`swarmchase watch --check [watchlist.toml]` reads a watchlist strictly and exits: a key no setting knows (a misspelt `limit` that a run would ignore, leaving the default), a value of the wrong type, a duplicate source name, an `[autonomy]` level that cannot be on, and every source built as a run builds it (its kind, endpoint and other settings). It reads no data directory and sends no request. CI and the pre-commit hook run it on the committed watchlist ([scripts](../../scripts/README.md#gates)).

## The digest

Each run writes `runs/<stamp>/digest.md`. It opens with the run's priority and source health, then covers new clusters, tier changes and endpoints hit for the first time. When something changed, the scheduled workflow emails it to the admin, with the priority in the subject (`[swarmchase] [HIGH] watch digest <stamp>`); nothing else leaves the runner.

### Needs attention

The first block gives the run a priority, `high`, `medium` or `low`, and lists the facts that set it, highest first. Only deterministic facts count:

| Priority | Set by |
|---|---|
| `high` | A new or escalated significant cluster at agent grade L2 or higher; a new significant record outside any cluster at L2; a case clock that has run; an `interrupt` that is on ([autonomy](#autonomy)). |
| `medium` | Any health alert (a source failed, skipped, collapsed or failed its canary, a host down, rule drift); a significant lead below L2; a suggestive lead at L2 or higher. |
| `low` | None of these. |

A lead is a cluster above noise that is new since the last run or rose a tier, or a new significant record that joined no cluster. New and risen are judged against the cluster's [ledger](#the-ledger) thread: a cluster whose key changed because its earliest record left the window is compared with its own previous run, not reported as new. A case clock has run when reports were sent and the indicator notice's lead time has passed with the notice not yet added, or when the notice is added and an operator may now be named. Each due clock is also a *Case status* line with the command that starts the step; the watch takes no step itself.

A model's suggestion never sets the priority: the same facts give the same priority whatever a model said. A new significant record outside any cluster at L2 or higher makes the run count as changed, like a new cluster.

### Attention queue

The next block counts the [attention queue](#the-attention-queue) by band and lists up to eight leads at `urgent` or `look`: the cluster, grade, records, trajectory, the facts that set its band, any caps, targets, momentum and covering case. Under it, each line an [autonomy](#autonomy) level wrote this run, marked `shadow` (would have) or `on` (did).

### Health

The health block comes first, because a source that did not run hides whatever it would have found. Its alerts are:

- a source that failed this run, with a short reason such as `HTTP 504 after 3 attempts`, and how many runs in a row it has failed. One failure is enough, so every failure reaches the admin within one run;
- a host that stayed unavailable through its retries, so the run stopped sending to it;
- a source whose canary failed: it answered, but nothing came back in the shape the parser expects;
- a source skipped for the first time (no API key);
- a source whose pull falls below a fifth of its median over recent runs, which usually means an API change, an expired key or a spent quota. A source's first pull and a pull spread over several runs are catching up, so they do not count towards the median;
- a rule whose hit rate on one source's new records jumps to three times its recent rate on that source. Each source is compared with itself, because a relay's own rule fires on nearly every record from it;
- a store file with lines that cannot be read, with their count. They are skipped; the other records are read;
- a step after collection that failed and was skipped, or a `summary.json` or `ledger.json` started afresh because it could not be read ([interrupted runs](#interrupted-runs)).

Under *Capability lost this run* it lists each skipped, failed or stopped source with what its absence costs, and the part of a stream it skipped. When no submit-time source ran (urlquery is the only one scheduled), it says so first: without submission times, timing links, pace, agent grades above L2 and interaction edges are unavailable. *Quiet sources* notes a source that has pulled nothing for several runs, and whether its canary passed.

Any alert gets the digest emailed; lost capability and quiet sources alone do not. A failed source's reason never includes the request URL; the full error is in the run's log and in `state.json`.

### Sources and coverage

The sources table shows each source's records, requests, coverage and status. Coverage is what a stream or feed source read against what there was to read since its checkpoint, such as `6 of 6 hours, canary ok` or `1024 of 400000 entries, 398976 skipped` for a CT log that grows faster than a polite reader.

The digest ends with a *Run time* line: the run's time up to the digest, each phase (`collect`, `platform`, `analysis`, `triage`) and the three slowest sources. `run.json` has the same in milliseconds. An *HTTP cache* line follows: responses served from the cache this run, entries kept and their size, and entries deleted.

### Headline counts

The window's headline counts records with an indicator beyond the relay or carrier they came through: a hit whose kind is not a route kind (relay, cache buster, self-id, header, outcome) and is not a carrier rule naming the record's own host. Every watch source is a relay's or carrier's own host, so a plain "has a hit" count would equal the records pulled. Clusters are counted above noise; noise-tier clusters are listed in their own section and left out of the count.

*Significant records outside any cluster* lists significant records that joined no cluster, new ones first, with their rule ids, tier and defanged target host, so a lone strong record is not reduced to a host name.

### Possible reruns and archive bursts

- **Possible reruns.** A new run whose target hosts, and their order, repeat an earlier run in a different cluster on another day. Hosts common to many runs count for little. The thresholds are in [methodology](../methodology.md#descriptive-hints).
- **Archive bursts.** Many Wayback or Arquivo captures of one host within minutes, on a host the store otherwise holds few captures of, measured over the span the run reads, with how many carry an indicator beyond the relay. The `archive_burst_*` settings in the rules file set the thresholds.

Both are leads to review; neither merges clusters.

### Candidate fleets, escalations and common features

Over the whole window, up to ten lines each:

- **Candidate fleets.** Clusters tied by soft links, with the kinds and the weakest pair's strength. Merging one is a case decision ([fleets](cases.md#fleets)). The same fleets by their keys across runs are under [fleet threads](#fleet-threads).
- **Escalations.** Requests for one page whose route climbed (direct, relay, program, remote browser), with the clusters they touch.
- **Common features.** Linking values shared too widely to link on, so they were demoted: records, hosts, span and the limit they passed.
- **Noise-tier clusters.** Clusters at noise tier, listed but not counted in the headline.

Clusters are named by number and stable key throughout (`C3 k-3f9a2c1b`), and hosts and values are defanged. These sections alone never make a run count as changed.

### Fleet threads

Each candidate fleet of the run by its key (`FK-...`, its number, `new` or the runs seen since its first), its member threads by cluster and key, its weakest edge ratio and density. Then the persistent pairs no current candidate fleet holds together: the two threads, the accumulated log ratio, the windows that counted on their own, the runs that linked them and the latest link kinds. Up to ten lines each; keys and kinds only, no host or value. Proposals only, like candidate fleets; the section never makes a run count as changed.

### Model triage

Off by default. The watch asks a model for a label on each new lead's strongest record, through one of two backends:

- **Local.** `watch --triage` (or `--triage=local`, or `SWARMCHASE_WATCH_TRIAGE` set to `local`, `1` or `true`) with `SWARMCHASE_LLM_URL` set asks the model at that URL, one record per ask. It uses the client of [label suggestions](#label-suggestions), with the same rules: a loopback, private or link-local endpoint only, defanged text, no IP addresses, no tools, no proxy, no redirect. It may see any lead.
- **Claude.** `watch --triage=claude` (or `SWARMCHASE_WATCH_TRIAGE=claude`) asks Claude through Claude Code, logged in as the user running the watch ([runner](runner.md#model-triage-with-claude)). Claude is a hosted model, so it is sent only leads from the [hosted sources](#hosted-suggestions), as the lines `review --export-hosted` writes, with their grade, `agent_allowed`, signals and rules; the rest are counted as withheld. All of a run's leads go in one call, or one per 25 records.

The rest is common to both:

- **Limits.** Leads are asked strongest first, up to `--triage-max` per run (default 20, `SWARMCHASE_TRIAGE_MAX`) and within `--triage-secs` (default 600, `SWARMCHASE_TRIAGE_SECS`). A local ask takes at most 60 s, and after three failed asks in a row the rest are left for the next run. A Claude call takes at most the time left; after two failed calls in a row, or a usage or rate limit, it asks no more that run.
- **Failures.** A missing or refused endpoint, a missing `claude`, a timeout, a failed call or a reply that is not the asked-for JSON is no suggestion. The run carries on and the digest says how many were asked, answered, left and withheld, and why it stopped.
- **Saved.** Answers are appended to `labels/suggestions-local.ndjson` or `labels/suggestions-claude-watch.ndjson`, one `{"id", "label", "reason", "model", "run"}` per line, the format review reads; Claude's lines also carry `grade` and `misfires`. A record already in the file is not asked again; its earlier suggestion is shown. Review reads Claude's file as a hosted model's, so a line for a record from any other source is dropped.
- **Shown.** *Model suggestions* names the backend and lists each lead's suggestion with its tier and agent grade. An `agent` suggestion on a lead below L2 is marked as against the labelling rule, under which `unsure` is the most that grade allows.

A suggestion is never a label: review saves it beside the admin's label as `suggested`, and eval reads only the admin's.

### Canary sightings

When the registry holds tokens ([page references](browser-toolkit.md#page-references)), each run searches its new records for them: the URL and every layer unwrapped from it, the final URL, the user agent and the header values. Each copy is a line under **Canary sightings** with the token, the field, the record id and source, the file it was issued on and its month, and a medium priority reason of kind `canary`. A token-shaped value the registry does not hold is listed as unverified. A record dated before its token's month is marked: the seed has leaked, the value was made up, or the record's time is wrong. Sightings never link records and never become leads in the attention queue. With an empty registry the check does nothing.

### Case status

The watch matches new records against every case's indicators: its clusters' linking features and its endpoints, under the case's pinned rules. The *Case status* section then proposes:

- marking an active notice contained after `contained_after_days` (in `watchlist.toml`, default 14) without a matching record;
- reopening a contained or historical notice, or a closed case, that has new matches;
- re-checking cases whose records would change tier under the current rules.

The watch changes nothing itself. Apply an approved proposal with `swarmchase notice update <id> --kind status --status <s>`, which also updates the case.

## Platform swarms

A separate pass in each run looks for accounts acting alike on GitHub, GitLab.com, Codeberg, package registries (npm, PyPI, NuGet, Packagist, RubyGems, crates.io, Go modules), the Hugging Face Hub, Wikimedia wikis, Hacker News, Bluesky and CVE records: near-identical or templated text, templated names, or text-less stars, forks and pull requests on one target, from several accounts in a burst beyond chance. The method and its thresholds are in [methodology](../methodology.md#coordinated-accounts-on-public-platforms). A failure in this pass is reported in its section and never stops the record analysis.

**Sources.** The watchlist's `[platform]` table holds `carry_hours` (default 72), `label_days` (default 30), `provenance_lookups` (default 40), optional `[platform.options]` (the detector's tunables, such as `min_accounts`, `burst_secs` and `max_chance`) and `[[platform.source]]` entries. Each has a `name`, a `kind` and the record source fields it uses:

| Kind | Reads | Fields |
|---|---|---|
| `gharchive` | GH Archive hours, every event of the kinds the detector reads | `scan`: hours per run (default 1); `max_mb`; `max_events` |
| `npm` | One npm search page | `pattern`: search text; `page_size` |
| `pypi` | One PyPI feed | `endpoint`: `packages` (default) or `updates`; `pattern`: substrings or `*` |
| `huggingface` | The Hub's newest listing | `endpoint`: `spaces` (default), `models` or `datasets`; `limit` (at most 1000) |
| `golang` | The Go module index, oldest first from the checkpoint | `scan`: requests of 2000 entries per run (default 6) |
| `wikimedia` | Edits from the `mediawiki.revision-create` stream | `scan`: minutes per run (default 5); `max_mb`; `filter` |
| `nuget` | NuGet's catalog pages committed since the checkpoint, oldest first | `scan`: pages per run (default 4) |
| `packagist` | Packagist's change feed since the checkpoint | none; the feed keeps a day |
| `rubygems` | RubyGems' newest listing (fifty gems) | `endpoint`: `latest` (default) or `just_updated` |
| `crates` | crates.io's newest crates, back to the checkpoint | `scan`: pages of 100 per run (default 3) |
| `gitlab` | GitLab.com's newest public projects, back to the checkpoint | `scan`: pages of 100 per run (default 3) |
| `codeberg` | Codeberg's newest repositories, back to the checkpoint | `scan`: pages of 50 per run (default 3) |

| `cve` | GitHub advisories of one type, oldest first from the checkpoint, or CVE List records new in its delta log | `endpoint`: `unreviewed` (default), `reviewed`, `malware` or `cvelist`; `scan`: requests of 100 (default 3), or records for `cvelist` (default 30) |
| `wikimedia-ai-cleanup` | Pages added to a wiki's suspected-AI-generated-text cleanup categories since the checkpoint, as labels | `endpoint`: the wiki (default `en.wikipedia.org`); `pattern`: the category name before ` from <month>`, `*` for the default; `scan`: API requests (default 4) |
| `osv` | OSV malicious-package records for one ecosystem, as labels | `endpoint`: `npm` (default), `PyPI`, `Go`, `crates.io`, `NuGet`, `Packagist` or `RubyGems`; `scan`: records per run (default 50) |
| `bluesky` | Posts from Jetstream, from the checkpoint or the newest half hour of stream time, whichever is later | `endpoint`: the Jetstream instance; `scan`: wall-clock minutes (default 3); `max_mb`; `max_events`; `max_lookups` (default 40) |
| `hackernews` | Stories and comments from the search index, newest back to the checkpoint | `scan`: queries of 1000 items (default 10); `max_lookups`: account-age lookups (default 40) |

`pattern` is required by the format; only `npm` and `pypi` read it. Sources that read from a checkpoint (all but `npm`, `pypi`, `huggingface` and `rubygems`) keep it in `platform/state.json`; a backlog over 24 hours (a week for `osv` and `wikimedia-ai-cleanup`, half an hour of stream for `bluesky`) is skipped to the newest stretch, and the section shows how much was read and skipped. A corrupt GH Archive hour is skipped and counted.

**Labels.** An `osv` or `wikimedia-ai-cleanup` source gives labels, not events: the packages OSV's malicious-package records name, or the wiki pages editors tagged as suspected AI-generated text. They are kept in `platform/labels.ndjson` for `label_days` (default 30). A candidate shown in the digest whose members published a labelled package or edited a labelled page gets a *Labelled* line with the records behind it, and `runs/<stamp>/platform-labels.json` lists every candidate's matches.

**Build provenance.** For the npm and PyPI candidates new or grown this run, the pass looks up the build provenance of member releases: npm's attestations and PyPI's integrity API, by name and version, at most `provenance_lookups` a run (0 turns them off), one member per candidate in turn, members on an OSV-labelled package first. Only the source repository, workflow, ref, commit, runner and deployment environment are kept; no package file is downloaded. Answers, including "none", go to `platform/provenance.ndjson` for `label_days`, so a release is looked up once.

Each npm or PyPI candidate with answers carries them as `provenance` in `platform-swarms.json`, and the digest gives it a *Provenance* line: the repositories and workflows its packages name, whether several packages share one, or that none carries provenance (weak context). It changes neither the chance nor the strength ([methodology](../methodology.md#coordinated-accounts-on-public-platforms)).

**Declared coding agents.** GitHub events from the coding-agent Apps that [`declared-agents.toml`](../../declared-agents.toml) lists (`github_app`) are tallied by product on the source's line, not grouped. An undeclared App whose login carries one of those products' names is listed below it as a spoofing lead, by login: App logins name software, not people.

**What is stored.** Nothing from the full stream. After grouping, only events worth another look are carried in `platform/carry.ndjson` for `carry_hours`: members of a group with two or more accounts and events carrying residue. Events hold a keyed hash for the account, never its login, and slotted text sketches, never the text. The run's candidates, suppressed groups and counts go to `runs/<stamp>/platform-swarms.json`.

**In the digest.** *Platform swarm hints* lists candidates that are new this run or have grown since they were last listed, each with its reason line (burst, new accounts, residue and their chances), what joined it, the slotted template, its targets, any coding-harness self-identification (weak context), its packages' build provenance, what is left to rule out, and up to five defanged links. A new or grown candidate counts as a change. Suppressed groups are summed by benign kind. Candidates are not leads for triage: the hosted model may see only archive and urlquery records ([policies](../policies.md#evidence-and-attribution)).

**On demand.** `swarmchase platform-swarms <events.ndjson>` runs the detector over carried events or fixtures, and `--gharchive <hour.json.gz>` over GH Archive hour files read locally; `--json` prints the full report and `--options` takes a TOML of tunables.

## The run summary

Each run also writes `runs/<stamp>/run.json`, the run in a small JSON for scripts, local dashboards and agents. `LATEST` names the newest run's stamp. The file stays in the data directory with the digest. Hosts in it are defanged, and it carries no record URL, IP address or model prompt. `schema` is `swarmchase-watch-run/1`; fields are only added within a version.

| Field | Holds |
|---|---|
| `schema` | `swarmchase-watch-run/1`. |
| `stamp`, `generated` | The run's stamp (its directory name) and its time, RFC 3339 UTC. |
| `rules_version` | The rules the analysis ran with. |
| `changed` | Whether the digest counts as changed, and so is emailed. |
| `priority`, `reasons` | `high`, `medium` or `low`, and the facts behind it ([needs attention](#needs-attention)). |
| `counts` | `records`, `new_records`, `significant`, `suggestive` and `clusters_above_noise` over the window; of the new records, `carried_over` and `new_before_window`. |
| `leads` | The run's new leads, strongest first ([leads](#lead-fields)). |
| `triage` | `enabled`, `backend`, `model`, `asked`, `answered`, `reused`, `left`, `withheld` and an optional `note` ([model triage](#model-triage)). |
| `health` | `alerts`, the `lost` capability lines, and `sources` with `name`, `kind`, `pulled`, `new`, `status` and `duration_ms`. |
| `cases` | `due` clocks (`case`, `clock`, `since`, `hosts`) and the number of case status `lines`. |
| `attention` | `by_band` counts, the first ten queue items as `top`, and `file` (`attention.json`). |
| `autonomy` | Each level's mode under `modes`, and this run's `decisions` (the lines of `autonomy.ndjson`). |
| `durations_ms` | Milliseconds per phase (`collect`, `platform`, `analysis`, `triage`, `report`) and `total` up to this file. |
| `digest` | The digest's file name in the same directory. |

A reason has `level`, `kind` (`lead`, `case_clock`, or an alert kind) and the digest's `text`. An alert has `kind` (`source_failed`, `source_skipped`, `source_collapsed`, `canary_failed`, `host_down`, `rule_drift`, `store_damaged`, `step_failed` or `other`), the `source` or host it concerns, and `text`. A source's `status` is `complete`, `partial`, `stopped`, `error` or `skipped`. A due clock's `clock` is `indicators` or `naming`, and `since` is Unix seconds.

### Lead fields

| Field | Holds |
|---|---|
| `kind`, `change` | `cluster` or `record`; `new`, or `escalated` for a cluster that rose a tier. |
| `id`, `key` | The cluster's number in this run (`C3`) and stable key, or the record id. |
| `record`, `source` | The record a model is asked about (the cluster's strongest) and its source. |
| `tier`, `score`, `records` | As the analysis gives them. |
| `grade` | The agent grade, `L0` to `L4`. |
| `targets` | Target hosts, defanged. |
| `suggestion` | `label`, `reason` and `model` from the local model, when there is one. Never a label. |

## The public log

`watch --public-log <path>` also writes a summary safe to show in a public CI log, and the scheduled workflow prints only that. It is built from an allowlist, not filtered from the run's output: one line per source with its name and kind (both from the watchlist), status word, `pulled`, `new` and `requests` counts and `duration_ms`, then a `total` line with the same counts, sources per status and the run's duration. Nothing in it is read from a record, an analysis, a lead, an error message or the priority. A name is printed with anything but letters, digits, `-`, `_` and `.` replaced, so it cannot carry a line break or a workflow command.

## The ledger

Each run analyses its window afresh: cluster numbers change, and a cluster's key changes when its earliest member leaves the window. `ledger.json` follows each cluster above noise across runs as a **thread**, so its history outlives the window. Code: [`ledger.rs`](../../crates/swarmchase/src/watch/ledger.rs).

- **Following.** A cluster continues the thread whose key it has, else the thread it shares the most member records with. Each thread keeps the latest 200 member ids for this.
- **Points.** One per run the thread was in the analysis: tier, grade, records, records that run collected (`added`), targets, interaction edges and attention band.
- **Events.** A new key, a merge (another thread's records joined it), a split, a rise in tier or grade, and a return.
- **Returns.** Linking features join records only within days, so an operator using the same inbox or tag weeks later starts a new cluster. A new thread carrying an earlier thread's linking feature names it in `recurs`, and after a quiet week or more the run records a return. Event text names the feature, never its value. Nothing is merged.
- **Trajectory.** On the latest run a thread is `new`, `back after a quiet spell`, `growing` (at least twice its records of a day before, and three more), `active` (records collected in the last day), `quiet`, or `dormant` (not in the analysis).
- **Fleets.** Each candidate fleet's member threads are matched to the earlier fleets' (Jaccard at least 0.5, one to one, largest overlap first). A match keeps its key; a new fleet takes `FK-` and 8 hex digits of a hash of its earliest member thread, with a suffix if taken. A key is never given to another fleet. Each keeps its members, first and latest run, runs seen, its largest size, and on its latest run its number, link kinds, weakest edge ratio and density ([SC-FM 5.18](../manual/05-linking.md#fm-518-fleets-across-windows)). Code: [`fleet_track.rs`](../../crates/sc-core/src/fleet_track.rs).
- **Pair evidence.** Each pair of threads a run links keeps the log of its combined soft-link ratio across runs. Overlapping windows count once: a run adds only when every record of the pair's two clusters comes after the records of the run counted last, and otherwise replaces that run's count when stronger. The total halves every 14 days. A pair is **persistent** at a total of `ln(1000)` (about 6.9), the conservative upper threshold of a sequential test at error rate 0.001.

Fleets and pair tracks are pruned with the threads, under the watch's retention. The ledger is descriptive. It changes no score, tier, grade or link.

## The attention queue

Each run ranks every cluster above noise into `runs/<stamp>/attention.json`. The rank is layered, never one weighted sum. Code: [`attention.rs`](../../crates/swarmchase/src/watch/attention.rs).

1. **Band**, set like the agent grade by the strongest combination of facts, then held down by caps.
2. Within a band, the grade (L1 ranks with L0), then the worst target class, then clusters no case covers before those a case does.
3. Last, **momentum**, which orders leads the facts above leave tied and never moves one across a band.

| Band | Set by |
|---|---|
| `urgent` | L3 or higher with access-controlled, sensitive or third-party targets; L2 with sensitive targets; L2 with the scope pass finding scope exceeded; L2, significant, with a moderate or strong interaction edge. |
| `look` | L2 or higher; significant with access-controlled or worse targets; significant and growing or back after a quiet spell. |
| `watch` | Anything else above noise. |

Target classes come from the [scope pass](../methodology.md#misalignment-and-scope); benchmark targets count as none.

| Cap | Holds the band at |
|---|---|
| A plant signal that counts, other than provenance monoculture | `look` |
| Members that declare testing or research | `look` |
| Benchmark or practice targets only | `watch` |

Provenance monoculture is left out because nearly every public record comes from a service anyone can submit to; it would hold every lead.

Momentum runs from 0 to 100. Each part is bounded, and the queue shows each with its points and reading:

| Part | Points | Full at |
|---|---:|---|
| growth | 25 | 8x the records of a day before |
| spread | 15 | 20 target hosts |
| interaction | 20 | a strong interaction edge (moderate 0.6, weak 0.3; a candidate fleet adds 0.3) |
| recency | 20 | latest record within 6 hours; none after a week |
| novelty | 15 | new or back after a quiet spell; a tier or grade rise this run gives 0.7 |
| volume | 5 | 200 records |

Nothing in the queue reads a model's suggestion.

## Autonomy

Autonomy levels are things the watch could do on its own about a lead in the queue. Each is internal and reversible. None sends, publishes, names or opens a case. Code: [`autonomy.rs`](../../crates/swarmchase/src/watch/autonomy.rs).

| Level | Would do | Fires on | Modes |
|---|---|---|---|
| `interrupt` | Raise the run's priority to high, so the digest reaches the admin now | Entering `urgent`; at `look` or above, growing 3x in a day or back after a quiet spell | off, shadow, on |
| `watch_harder` | Pull the lead's sources more often and watch its targets, passively | `urgent` | off, shadow |
| `draft_case` | Open a draft case, find contacts, draft the provider report | `urgent` for 2 runs or more over 12 hours, no case covering it | off, shadow |

Every trigger needs grade L2 or higher, since anyone can write a self-description. `interrupt` fires at most once a day per thread and `interrupts_per_day` times in all (default 3; the rest are logged as held back). `watch_harder` fires once a week per thread, `draft_case` once per thread.

The watchlist sets the modes:

```toml
[autonomy]
interrupt = "shadow"      # off | shadow | on
watch_harder = "shadow"   # off | shadow
draft_case = "shadow"     # off | shadow
interrupts_per_day = 3
```

Every level is in **shadow** by default: it only writes what it would have done to `autonomy.ndjson`. `interrupt = "on"` adds a high reason of kind `attention` to the run's priority and makes the digest count as changed; nothing else acts.

### Reading a level's record

The dashboard reads each line against what the admin decided later:

- **Agreed:** a case covers the lead, or, for `interrupt` and `watch_harder`, a record of it is labelled agent.
- **Disagreed:** its records were labelled with no agent label and no case, or, for `draft_case`, no case followed in two weeks.
- **Pending:** neither yet.

A lead's thread counts with every thread it was merged into. For `draft_case`, *never proposed* counts threads a case covers that the level did not propose. Switch a level on when its record shows it would have been right; the log is the evidence for that decision.

## Retention

At the end of each run, run directories and stored records older than `retain_days` (default 180, by capture time) are deleted, with ledger points and autonomy lines older than that. Only the newest `keep_analysis_runs` runs (default 8; 0 keeps all) keep their full `analysis.json` and `case-notes.md`, which grow with the window; older runs keep their digest, `run.json`, `summary.json`, attention queue and new records. The dashboard reads the newest run's analysis, and a case analyses its own records, so neither needs the older ones.

The platform pass keeps its carried events for `carry_hours` only. Cached HTTP responses older than `http_cache_ttl_secs`, and at least a day, are deleted on every run, before the digest; `watch prune-cache` does the same on demand. Copy anything a case needs into the case first (`case new` or `case add`). The policy is in [policies](../policies.md#collection).

## The dashboard

`swarmchase dashboard` shows the state of monitoring on `http://127.0.0.1:8767/` (`--port`), one of the [local pages](#local-pages). It reads the data directory (`-d`, as for `review`) and the watchlist (`--watchlist`, default `watchlist.toml`, for each source's kind) and writes nothing. It reloads when a new run lands, and `r` reloads by hand.

```sh
swarmchase dashboard -d "$SWARMCHASE_DATA"
swarmchase dashboard -d "$SWARMCHASE_DATA" --json --since 20261011T060000Z
```

When the latest run wrote a [run summary](#the-run-summary), the page opens with the digest's priority and its reasons, reads the health alerts from it, and lists the local model's suggestions on the run's leads, flagging an `agent` suggestion below L2 as against the labelling rule.

It answers these questions:

- **What needs you first.** The [attention queue](#the-attention-queue), filterable by band. Each lead shows its band, grade, trajectory, the facts that placed it, caps, targets, a sparkline of its records per run and a momentum bar; *Why this place* lists the momentum parts and the command that opens a case.
- **What is new.** Clusters above noise that are new or rose a tier, with their agent grade, and significant records outside any cluster, collected since a baseline run. The baseline is the run before the latest, as in the digest, or the run the admin marked seen (`s` on the page, remembered in that browser only; `--since` for `--json`). When that run was deleted by retention, the nearest kept run before it is used.
- **Whether monitoring is healthy.** Each source's status from `state.json` (failing, skipped, quiet, catching up, ok), its recent pulls, what its absence loses, the latest digest's health alerts, and rule drift recomputed on the latest run.
- **What waits on the admin.** The review queue as `review --serve` builds it from the latest run's analysis, with label progress and the agent labels below L2 counted apart, and each open case's clocks and what `case status` says it still needs.
- **How leads move.** The activity timeline draws each thread from the ledger as a row over the window: a bar per run, its height the records, its colour the band, solid when that run collected records for it, with dots for events.
- **What ties leads together.** The link graph draws the latest analysis's clusters above noise that something ties: soft links as grey lines, thicker for a stronger pair (combined as candidate fleets combine them), possible interaction (S1 to S6) as red dashed lines, interaction inside one cluster as a ring, and candidate fleets as shaded areas. Groups of tied clusters are laid out apart, largest first, and the same overview always draws the same picture. It can show only interaction or only fleets; selecting a cluster or a line lists each tie with its strength and defanged detail, and the table under it lists every tie. Up to 60 clusters are drawn, the queue's top ones first. A tie is a lead to check, never a merge.
- **How autonomy would have done.** Each level's mode and record (agreed, disagreed, pending, held back, never proposed) and its latest lines with their outcome ([reading a level's record](#reading-a-levels-record)).
- **What to run next.** Each item comes with its command, with the data directory filled in: `review --serve`, `case … new --cluster <key>`, a case's next step, or `scan` on a drifting source's records.

`d` shows the latest digest; `1` to `8` jump to the sections; `?` lists the keys.

### The overview document

The page reads one JSON document, `GET /api/overview` (`/api/overview/since/<stamp>` for another baseline). `--json` prints the same document, for a script or an agent. Hosts in it are defanged and no record URL is included. `schema` names the version; a field changes meaning or goes only with a new one.

| Field | Holds |
|---|---|
| `run` | The latest run's stamp, age in hours, `stale` past 12 hours, kept runs, rules version, the digest's path. |
| `since` | The baseline run's `stamp` and its `basis`: `previous-run`, `requested`, `nearest-kept-run`, `before-kept-runs` or `first-run`. |
| `new.clusters` | New or escalated clusters: `id`, `cluster_key`, `change`, `tier`, `grade`, `records`, `new_records`, `targets`, `rules`, `open_case`. |
| `new.lone` | Significant records outside any cluster collected since the baseline: `id`, `host`, `grade`, `score`, `rules`, `source`, `time`. |
| `new.endpoints` | Target hosts flagged for the first time since the baseline. |
| `health.sources` | Per source: `status`, `reason`, `pulled` history, `new_latest`, streak counts, and `lost` when failing or skipped. |
| `health.alerts` | The latest digest's health lines. |
| `health.drift` | Rules that fired well above their baseline on the latest run, per source, with both rates. |
| `waiting.review` | `unreviewed`, `groups`, counts by tier and label, `with_suggestion`, `agent_below_rule` (agent labels below L2: `total`, `flagged`, `graded_now`, `with_reason`, `unknown`), and the `command`. |
| `waiting.cases` | Each open case: status, `clock` lines, `notice_not_before`, `naming_ready`, `watch_hits`, and `needs` with commands. |
| `attention` | The latest run's queue: `stamp`, `by_band`, `total`, and up to 50 `items` with labels and an `open_case` command. |
| `timeline` | `from`, `to`, `total` and up to 40 `rows`: each thread's `points`, `events`, `band`, `trajectory`, `peak_grade` and queue `rank`. |
| `graph` | `clusters` above noise, `linked` (those with a tie), and the drawn `nodes` (`id`, `key`, `tier`, `grade`, queue `band` and `rank`, `records`, `targets`, `top_target`, `fleet`, `links`, `inner`), `links` (each pair's `soft` links and `soft_strength`, `swarm` edges and `swarm_strength`, shared `fleet`) and candidate `fleets`. |
| `autonomy` | `modes`, each level's record under `levels`, the log's `lines`, and the `recent` lines with their `outcome`. |
| `actions` | The next steps, most urgent first: `kind`, `title`, `detail`, `command`. |

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

Each record shows its agent grade. Labelling agent below L2 prints the grade, its signals and caps and the labelling rule, then asks for a reason, saved as the note: Enter saves the label with none, and `u` labels unsure instead. A note typed after the key is taken as the reason.

- `--unflagged N` adds a stable sample of unflagged records, which grows the benign baseline and catches misses.
- `review sample` writes a stratified, seeded sample as a queue file, and `review <queue> --all` labels every record in it ([a reviewed benign baseline](evaluation.md#a-reviewed-benign-baseline)).
- `--stats` counts reviews and disagreements, and Cohen's κ between labellers; `--list` prints the queue.
- `--labeller <name>` saves to `labels/reviewed-<name>.ndjson` instead, for a second, independent reviewer ([two labellers](evaluation.md#two-labellers)).
- `--suggest` shows a local model's label suggestion before each prompt ([label suggestions](#label-suggestions)).
- `--serve` labels the same queue in a browser on this machine ([the review page](#the-review-page)); `--export-hosted <file>` writes it for a hosted model's suggestions ([hosted suggestions](#hosted-suggestions)).

Each answer goes to `labels/reviewed.ndjson` with the record, so `swarmchase eval <data>/labels/reviewed.ndjson` measures the rules against everything reviewed ([evaluation](evaluation.md)). The file stays in the data directory and is never committed.

### Label lines

Each line is the stored record with these fields beside it:

| Field | Holds |
|---|---|
| `label` | `agent`, `benign` or `unsure`. |
| `note` | The admin's note; for an agent label below L2, the reason. |
| `class` | Why the record was queued: flagged, the unflagged sample, or the baseline sample. |
| `reviewed_at` | When it was labelled. |
| `tier`, `score`, `rules`, `rules_version` | What the rules said then. |
| `grade` | The agent grade the label was judged against ([below](#the-grade-on-a-label)). |
| `suggested` | A model's suggestion shown before the label, never the label. |
| `tuned` | Looked at while changing a rule ([evaluation](evaluation.md#a-reviewed-benign-baseline)). |

### The grade on a label

`grade` is the grade that decides the record's labels when it is labelled: its cluster's, else its own. It holds `code` and `label` (absent for an ungraded record), `basis` (`cluster`, `record` or `none`), `cluster`, `signals` and `counter` as `<signal> (<n> records)`, `caps`, and `agent_allowed`. An agent label below L2 also carries `"rule": "below_l2"`: an exception the admin chose, with the reason in `note` ([evaluating leads](../guides/evaluating-leads.md#exceptions-to-the-labelling-rule)).

A line without `grade` comes from before grades were stored. Its grade is unknown, so each reader grades it from the analysis it has and says so. The review page and the dashboard use their own analysis. `review --stats` and `review agreement` analyse the review file's own records, so a cluster with members outside the file may grade differently. `eval` uses the analysis of its inputs and does not judge a line whose record is not among them.

`review --stats` lists the agent labels below L2 with their grades and reasons. `review agreement` lists them too, and reads the stored grade before the grade now when a suggestion line records none.

### Label suggestions

`review --suggest` asks a language model for a label before each prompt and shows it as `suggestion: agent, <reason>`. The admin still answers; the suggestion is saved beside the label as `suggested` and is never the label, so eval reads only the admin's.

It is allowed only with a model running locally:

- **Local only.** `SWARMCHASE_LLM_URL` is an OpenAI-compatible server (`/v1/chat/completions`; the base URL is enough) on `localhost`, a loopback address, a private address (RFC 1918, or RFC 4193 for IPv6) or a link-local one. Any other host is refused before anything is sent, so records never reach a third-party API. The request goes through no proxy and follows no redirect. `SWARMCHASE_LLM_MODEL` names the model ([configuration](configuration.md#environment-variables)).
- **What it sees.** The defanged URL, target host and rule hits, the tier and score, and the cluster's size, tier, top rules and target hosts, with a fixed prompt asking for `{"label": "agent" | "benign" | "unsure", "reason": "…"}`. No IP addresses.
- **No fetching.** The model gets text and no tools; the prompt says the URLs are data, never to be visited.
- **Failures.** A timeout (60 s), an error or a reply that is not that JSON means no suggestion for the record; the review carries on.

### Hosted suggestions

A hosted model may suggest labels for public records only ([policies](../policies.md#evidence-and-attribution)):

```sh
swarmchase review --export-hosted data/labels/hosted.ndjson          # the flagged queue
swarmchase review <queue> --all --export-hosted data/labels/hosted-baseline.ndjson
```

- **What it writes.** One `{"id", "group", "text", "grade", "grade_basis", "agent_allowed", "signals", "counter", "caps", "rules"}` per record: the text the local model reads, the record's review group, the agent grade it is labelled against and the rules that fired. `--batch-size N` splits the export into numbered files and keeps each group in one. Records from `wayback`, `arquivo`, `memento`, `commoncrawl` and `urlquery` only; operator logs and the rest are counted as withheld. The list is in code, so a new source is withheld until it is added on purpose.
- **Where.** The file must be inside the data directory, and stays there.
- **Answers.** The model's suggestions go in `labels/suggestions-<name>.ndjson`, one `{"id", "label", "reason", "model", "grade", "misfires"}` per line (`grade` and `misfires` are optional). `review suggest-claude <export>...` asks Claude through Claude Code, as [model triage](#model-triage) does, and appends its answers to `labels/suggestions-claude-<export name>.ndjson`; records already in that file are skipped, so a run cut short by a usage limit resumes. `review check-suggestions` validates a file against its export. `review --serve` reads every such file; a line for a record from any other source is dropped, except in `suggestions-local.ndjson`, which a local model writes ([model triage](#model-triage)).
- **The loop.** `review agreement` compares the admin's labels with each model's, and `review misfires` lists rules that keep firing on records labelled benign. How to run it all: [AI assistance](../guides/ai-assistance.md).
- **No fetching.** Whoever runs the model gives it the file and no web access.

### The review page

`review --serve` serves the queue on `http://127.0.0.1:8765/` (`--port`) instead of prompting, with the same inputs and options as the terminal session. It is built on the shared [local pages](#local-pages).

- **Layout.** The queue of groups is on the left, with tabs for what is left to do, labels that differ from a suggestion, what is done, and everything, and a search by rule, host or id. The selected group is on the right: its agent grade and signals, its suggestion, the rules that fired, and each record with its decoded layers.
- **Groups.** Records are grouped by cluster, or by shape (the rules that fired and the start of the URL) when unclustered, so a run of near-identical records is labelled at once. Each record can still be labelled alone.
- **Flow.** Labelling a group moves to the next one. `z` undoes the last action, label and note included.
- **Triage.** The queue sorts in queue order, needs attention first (rule conflicts, then split suggestions, then mixed or differing labels), largest groups first, or by grade. Filters narrow it by grade (`L2 or higher`, `below L2`, or one rung), tier, source, suggestion and check. The browser remembers both.
- **Labelling rule.** `agent` needs an agent grade of L2 or higher. The server marks each record and group with whether the rule allows it, a suggestion of agent below L2, and a saved agent label below L2. The page shows these in the queue and on the group, and a group labelled so can be relabelled unsure in one step.
- **Exceptions.** Labelling agent below L2 opens a dialog with the grade, its signals and caps and the rule, and a reason field saved as the note; it offers unsure instead. The server saves every label with its grade ([the grade on a label](#the-grade-on-a-label)). An agent label below L2 shows as `agent < L2` in the queue and the done tab, with an exception field on each record giving the grade, signals, caps and reason, and in earlier decisions. The top bar counts them, and the session panel lists them with the review file's count and the precision estimate without them. An older line without a stored grade shows the grade now and says so.
- **Suggestions.** `accept suggestion` labels the selected group's unlabelled records as suggested, never across groups, and leaves any suggestion of agent below L2 for the admin. The suggestion is saved beside the label as `suggested`.
- **Bulk.** `A` / `B` / `U` (with Shift) label only the group's unlabelled records. Every bulk label is one undoable step, and an undo puts back each label with the grade it was saved with.
- **Session.** `p` opens the session panel: labels this session and in the review file, agreement between the labels and the suggestions as a table, labels that break the rule, and the agent share of decided flagged records with its 95% Wilson interval, the labels still needed for ±10 points, and the `swarmchase eval` command to run next.
- **Changing labels.** Reviewed records stay on the page, so a label can be changed or cleared. Labels go to the same file as the terminal session (`--labeller` included).
- **Rule context.** Each rule in the group shows its description, kind, weight and tactic from the rules the analysis ran with, how many records it fired on in the analysis and how many of those were flagged. With a pre-era control summary, it also shows how often the rule fired and flagged before agents existed ([negative control](evaluation.md#negative-control)). `--control <file>` names the summary; the default is `<data>/controls/pre-era/summary.json`, then `data/controls/pre-era/summary.json`.
- **Timeline.** When the group's records happened, binned, with the median step and the largest gaps, and whether the times are requests, submissions or archive captures ([FM-6.1](../manual/06-timing.md#fm-61-timestamp-kinds)).
- **Earlier decisions.** Reviewed records outside the group sharing its rule set, cluster or target host, with their labels and notes.
- **Related records.** Records anywhere in the analysis sharing a target host or a linking feature with the group, with tier and label, and a jump to their group when it is in the queue.
- **Programs and copying.** A decoded layer that reads as a program can be laid out as text with its outbound and page-reading calls marked. It is never run or rendered. Buttons copy a record's id, and the group's ids or defanged references, one per line.
- **Loading.** Context loads when a group is selected, from the analysis, the review file and the control summary only. Nothing is fetched.
- **Keys.** `j` / `k` move, `a` / `b` / `u` label the group, `s` accepts its suggestion, `x` clears, `z` undoes, `n` writes a note, `e` shows every record, `/` searches, `f` filters, `o` changes the sort, `p` opens the session panel, `1` to `4` switch tabs, `?` lists them.
- **Access.** Focus returns to the same control after each label, a dialog keeps focus inside it and gives it back on close, moving between groups is announced to screen readers, and rule flags carry words and an icon as well as colour.
- **Guide.** `g` opens the evaluator guide, with worked examples and a practice round that saves nothing, and `h` turns on blind review, which hides suggestions until a group is labelled. The same method in prose is [evaluating leads](../guides/evaluating-leads.md).

### Local pages

The admin's pages run on this machine from the CLI, never on the public site. They share one server and one look ([`localui`](../../crates/swarmchase/src/localui/mod.rs)):

- **Network.** The server listens on 127.0.0.1 only, refuses any other `Host` (no DNS rebinding), and accepts a change only with the token in the page it served and a same-origin `Origin`.
- **Content.** Records are shown defanged, as text nodes, never as links, under a content security policy that loads nothing but the page's own files.
- **Look.** Shared tokens and components (verdict buttons, chips, cards, keyboard help, toasts) follow the system's light or dark setting.
