# Watch runs and review

How `swarmchase watch` collects and reports, and how `swarmchase review` labels what it finds. The command summaries are in the [CLI README](../../crates/swarmchase/README.md#watch-and-review); the day-to-day flow is in the [admin workflow](../guides/admin-workflow.md).

## The data directory

Every watch, review and case command works in one data directory: `--out` (or `--data`), else `SWARMCHASE_DATA`, else `data/` relative to where the command runs. On the runner it is `$SWARMCHASE_DATA` outside the checkout ([runner](runner.md)). It is gitignored and never committed. A command that reads existing data (`review`, `case`, `notice add`) prints a hint naming the directory it resolved when that directory holds no watch data, labels or cases; a watch run says when it starts a new one.

| Path | Holds |
|---|---|
| `state.json` | Each source's time cursor, resume key or stream checkpoint, and health history. |
| `store/<source>.ndjson` | Stored records, deduplicated by ID. |
| `runs/<stamp>/digest.md` | One directory per run, with its digest. |
| `runs/<stamp>/run.json` | The run in a stable JSON ([the run summary](#the-run-summary)). |
| `labels/reviewed.ndjson` | Records labelled with `swarmchase review`. |
| `labels/suggestions-local.ndjson` | The local model's suggestions on new leads ([model triage](#model-triage)). |
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

Each run writes `runs/<stamp>/digest.md`. It opens with the run's priority and source health, then covers new clusters, tier changes and endpoints hit for the first time. When something changed, the scheduled workflow emails it to the admin, with the priority in the subject (`[swarmchase] [HIGH] watch digest <stamp>`); nothing else leaves the runner.

### Needs attention

The first block gives the run a priority, `high`, `medium` or `low`, and lists the facts that set it, highest first. Only deterministic facts count:

| Priority | Set by |
|---|---|
| `high` | A new or escalated significant cluster at agent grade L2 or higher; a new significant record outside any cluster at L2; a case clock that has run. |
| `medium` | Any health alert (a source failed, skipped, collapsed or failed its canary, a host down, rule drift); a significant lead below L2; a suggestive lead at L2 or higher. |
| `low` | None of these. |

A lead is a cluster above noise that is new since the last run or rose a tier, or a new significant record that joined no cluster. A case clock has run when reports were sent and the indicator notice's lead time has passed with the notice not yet added, or when the notice is added and an operator may now be named. Each due clock is also a *Case status* line with the command that starts the step; the watch takes no step itself.

A model's suggestion never sets the priority: the same facts give the same priority whatever a model said. A new significant record outside any cluster at L2 or higher makes the run count as changed, like a new cluster.

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

### Model triage

Off by default. With `watch --triage`, or `SWARMCHASE_WATCH_TRIAGE=1`, and `SWARMCHASE_LLM_URL` set, the watch asks the model at that URL for a label on each new lead's strongest record. It uses the client of [label suggestions](#label-suggestions), with the same rules: a loopback, private or link-local endpoint only, defanged text, no IP addresses, no tools, no proxy, no redirect.

- **Limits.** Leads are asked strongest first, up to `--triage-max` per run (default 20, `SWARMCHASE_TRIAGE_MAX`) and within `--triage-secs` (default 600, `SWARMCHASE_TRIAGE_SECS`), each ask at most 60 s. After three failed asks in a row the rest are left for the next run.
- **Failures.** A missing or refused endpoint, a timeout or a reply that is not the asked-for JSON is no suggestion. The run carries on and the digest says how many were asked, answered and left.
- **Saved.** Answers are appended to `labels/suggestions-local.ndjson`, one `{"id", "label", "reason", "model", "run"}` per line, the format review reads. A record already in the file is not asked again; its earlier suggestion is shown.
- **Shown.** *Model suggestions* lists each lead's suggestion with its tier and agent grade. An `agent` suggestion on a lead below L2 is marked as against the labelling rule, under which `unsure` is the most that grade allows.

A suggestion is never a label: review saves it beside the admin's label as `suggested`, and eval reads only the admin's.

### Case status

The watch matches new records against every case's indicators: its clusters' linking features and its endpoints, under the case's pinned rules. The *Case status* section then proposes:

- marking an active notice contained after `contained_after_days` (in `watchlist.toml`, default 14) without a matching record;
- reopening a contained or historical notice, or a closed case, that has new matches;
- re-checking cases whose records would change tier under the current rules.

The watch changes nothing itself. Apply an approved proposal with `swarmchase notice update <id> --kind status --status <s>`, which also updates the case.

## The run summary

Each run also writes `runs/<stamp>/run.json`, the run in a small JSON for scripts, local dashboards and agents. `LATEST` names the newest run's stamp. The file stays in the data directory with the digest. Hosts in it are defanged, and it carries no record URL, IP address or model prompt. `schema` is `swarmchase-watch-run/1`; fields are only added within a version.

| Field | Holds |
|---|---|
| `schema` | `swarmchase-watch-run/1`. |
| `stamp`, `generated` | The run's stamp (its directory name) and its time, RFC 3339 UTC. |
| `rules_version` | The rules the analysis ran with. |
| `changed` | Whether the digest counts as changed, and so is emailed. |
| `priority`, `reasons` | `high`, `medium` or `low`, and the facts behind it ([needs attention](#needs-attention)). |
| `counts` | `records`, `new_records`, `significant`, `suggestive` and `clusters_above_noise` over the window. |
| `leads` | The run's new leads, strongest first ([leads](#lead-fields)). |
| `triage` | `enabled`, `model`, `asked`, `answered`, `reused`, `left` and an optional `note` ([model triage](#model-triage)). |
| `health` | `alerts`, the `lost` capability lines, and `sources` with `name`, `kind`, `pulled`, `new` and `status`. |
| `cases` | `due` clocks (`case`, `clock`, `since`, `hosts`) and the number of case status `lines`. |
| `digest` | The digest's file name in the same directory. |

A reason has `level`, `kind` (`lead`, `case_clock`, or an alert kind) and the digest's `text`. An alert has `kind` (`source_failed`, `source_skipped`, `source_collapsed`, `canary_failed`, `host_down`, `rule_drift` or `other`), the `source` or host it concerns, and `text`. A source's `status` is `complete`, `partial`, `stopped`, `error` or `skipped`. A due clock's `clock` is `indicators` or `naming`, and `since` is Unix seconds.

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
- `review sample` writes a stratified, seeded sample as a queue file, and `review <queue> --all` labels every record in it ([a reviewed benign baseline](evaluation.md#a-reviewed-benign-baseline)).
- `--stats` counts reviews and disagreements, and Cohen's κ between labellers; `--list` prints the queue.
- `--labeller <name>` saves to `labels/reviewed-<name>.ndjson` instead, for a second, independent reviewer ([two labellers](evaluation.md#two-labellers)).
- `--suggest` shows a local model's label suggestion before each prompt ([label suggestions](#label-suggestions)).
- `--serve` labels the same queue in a browser on this machine ([the review page](#the-review-page)); `--export-hosted <file>` writes it for a hosted model's suggestions ([hosted suggestions](#hosted-suggestions)).

Each answer goes to `labels/reviewed.ndjson` with the record, so `swarmchase eval <data>/labels/reviewed.ndjson` measures the rules against everything reviewed ([evaluation](evaluation.md)). The file stays in the data directory and is never committed.

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
- **Answers.** The model's suggestions go in `labels/suggestions-<name>.ndjson`, one `{"id", "label", "reason", "model", "grade", "misfires"}` per line (`grade` and `misfires` are optional). `review check-suggestions` validates a file against its export. `review --serve` reads every such file; a line for a record from any other source is dropped, except in `suggestions-local.ndjson`, which a local model writes ([model triage](#model-triage)).
- **The loop.** `review agreement` compares the admin's labels with each model's, and `review misfires` lists rules that keep firing on records labelled benign. How to run it all: [AI assistance](../guides/ai-assistance.md).
- **No fetching.** Whoever runs the model gives it the file and no web access.

### The review page

`review --serve` serves the queue on `http://127.0.0.1:8765/` (`--port`) instead of prompting, with the same inputs and options as the terminal session. It is built on the shared [local pages](#local-pages).

- **Layout.** The queue of groups is on the left, with tabs for what is left to do, labels that differ from a suggestion, what is done, and everything, and a search by rule, host or id. The selected group is on the right: its agent grade and signals, its suggestion, the rules that fired, and each record with its decoded layers.
- **Groups.** Records are grouped by cluster, or by shape (the rules that fired and the start of the URL) when unclustered, so a run of near-identical records is labelled at once. Each record can still be labelled alone.
- **Flow.** Labelling a group moves to the next one. `z` undoes the last action, label and note included.
- **Triage.** The queue sorts in queue order, needs attention first (rule conflicts, then split suggestions, then mixed or differing labels), largest groups first, or by grade. Filters narrow it by grade (`L2 or higher`, `below L2`, or one rung), tier, source, suggestion and check. The browser remembers both.
- **Labelling rule.** `agent` needs an agent grade of L2 or higher. The server marks each record and group with whether the rule allows it, a suggestion of agent below L2, and a saved agent label below L2. The page shows these in the queue and on the group; labelling agent below L2 asks a second time, and a group labelled so can be relabelled unsure in one step.
- **Suggestions.** `accept suggestion` labels the selected group's unlabelled records as suggested, never across groups, and leaves any suggestion of agent below L2 for the admin. The suggestion is saved beside the label as `suggested`.
- **Bulk.** `A` / `B` / `U` (with Shift) label only the group's unlabelled records. Every bulk label is one undoable step.
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
