# Methodology

This page describes how swarmchasing turns public records into the claims in a report or notice. It is written for three readers: security teams at AI providers who receive a report, operators of affected sites, and researchers checking the method. Each section links to the code that does the work. Where a number is a setting, the page names the setting so you can check its current value.

The short version: the toolkit reads public indexes, redacts secrets, unwraps each recorded URL, matches indicator rules, grades each record, links flagged records into clusters, and describes their timing. The admin reviews the result, decides what is true, and sends and publishes, after a second person reviews each notice. No step is automatic past drafting.

Policies (what we collect, how we name, what notices withhold) are in [policies.md](policies.md). Guidance for operators is in [for-operators.md](guides/for-operators.md).

This page is the toolkit's implementation. The method as a standard, which other groups can apply with their own tools and cite by section, is the [Swarmchasing Field Manual](manual/README.md).

## Collection

The collectors are in [`sc-collect`](../crates/sc-collect/src/lib.rs). They read:

| Source | What is read | Used for |
|---|---|---|
| Wayback Machine CDX | Index rows: capture time, captured URL, status, digest | Scheduled watch, per-case pulls |
| Arquivo.pt CDX | Index rows, as above | Scheduled watch for its on-demand saves (`SAWP` collections) only, since its crawls are indexed too late; per-case pulls |
| Common Crawl CDX | Index rows of one crawl, never WARC content | Scheduled watch, per-case pulls |
| Memento timemaps | One URL's captures across archives | Per-case pulls |
| urlquery.net | Search results and reports by ID (needs an API key) | Scheduled watch; the held-out evaluation |
| urlscan.io | Public search results | Per-case lookups only; its terms need permission for systematic retrieval |
| GH Archive | Public GitHub events whose repository name or URLs match | Scheduled watch, as leads for review |
| npm, PyPI | Package names, versions and publish times matching run tags | Scheduled watch, as leads for review |
| Wikimedia EventStreams | External links added to wiki pages, matching relay hosts and run tags or added to configuration pages | Scheduled watch, as leads for review |
| Hacker News search index | Links in stories and comments matching relay hosts and run tags | Scheduled watch, as leads for review |
| Bluesky Jetstream | Links in posts matching relay hosts and run tags, in a sampled stretch each run | Scheduled watch, as leads for review |
| GitHub search | Links in pull request text and commit messages matching relay hosts and run tags (needs a token) | Scheduled watch, as leads for review |
| GH Archive, npm, PyPI, NuGet, Packagist, RubyGems, crates.io, Hugging Face Hub, Go module index, GitLab.com, Codeberg, Wikimedia EventStreams, Hacker News, Bluesky Jetstream, GitHub Advisory Database, CVE List | Event and listing metadata, sketched for [coordinated accounts](#coordinated-accounts-on-public-platforms) | Scheduled watch's platform pass, as hints |
| OSV data dumps | Malicious-package records (`MAL-` ids) for npm and PyPI | Scheduled watch's platform pass, as labels on candidates |
| MediaWiki API | Pages added to English Wikipedia's suspected-AI-generated-text cleanup categories | Scheduled watch's platform pass, as labels on candidates |
| CT logs, crt.sh | Certificate Transparency entries | Watch sample of one log (relay look-alikes); case work (`swarmchase certs`) |
| security.txt, RDAP | The affected organisation's published security contact, or its registrar's abuse address | Finding who to report to |

The scheduled watch pulls the sources in [`watchlist.toml`](../watchlist.toml). Each source there carries a rationale: which agent behaviour it catches, which rule it feeds, and what its noise looks like. The same file lists what is deliberately not watched, such as callback channels, and the case-only sources: urlscan.io (its terms), Memento timemaps (one URL's history) and Arquivo.pt's crawls (indexed too late for the window) are pulled per case with `swarmchase collect`, and crt.sh per name with `swarmchase certs`.

Passive limits, enforced by what the code does and does not implement:

- **Indexes only.** The archive collectors read CDX index rows. They never open a capture.
- **No submitted URLs.** Nothing fetches a URL an agent submitted. Those URLs may carry live payloads or alert the operator.
- **No callback channels.** Nothing reads from or posts to an agent's inbox, notification topic or paste. These are matched only inside records found through other sources.
- **No probing.** Nothing contacts suspected agent infrastructure. The only requests to an organisation's own host are for its security.txt, to find a reporting contact.
- **Politeness.** One request at a time, with a minimum interval (`min_interval_secs` in the watchlist), an identifying user agent, and exponential backoff on HTTP 429 and 5xx that honours `Retry-After`.

Records from every source, and an operator's own access log, are normalised into one [`Observation`](../crates/sc-core/src/model.rs) shape: an ID, a source, a timestamp, the URL, and where available the IP, ASN, user agent, headers, status, final URL and a link to the public record. Ingest is in [`ingest.rs`](../crates/sc-core/src/ingest.rs) and [`urlquery.rs`](../crates/sc-core/src/urlquery.rs).

## Redaction at ingest

Records can carry secrets an agent captured or used: session cookies, bearer tokens, API keys. They are useless as evidence and harmful to keep. [`redact.rs`](../crates/sc-core/src/redact.rs) replaces them before anything is stored or analysed, in the CLI, the collectors and the browser toolkit alike.

What is replaced:

- query and fragment parameters with a secret name: cookies, authorisation and access tokens, API keys, client secrets, passwords, session IDs, CSRF tokens, and some anti-bot tokens (the `SECRET_PARAM` list);
- any parameter value shaped like a dumped cookie jar (`a=1; b=2`);
- secret request headers: `Cookie`, `Authorization`, `X-API-Key` and similar (`SECRET_HEADER`);
- well-known credential shapes anywhere in the record: JWTs, AWS access key IDs, GitHub, GitLab and Slack tokens, `sk-` style model API keys, Google API keys (`SECRET_VALUE`).

Each secret becomes `REDACTED-` followed by the first 12 hex digits of its SHA-256. The hash is deterministic, so two records that carried the same secret can still be tied together: the same redacted value in two clusters is a strong soft link (`shared_secret`, see [soft links](#descriptive-hints)). Hashes of stock passwords (`password`, `admin`, `123456` and the like) do not count, because unrelated clients send them alike. It is unsalted. An operator holding a token can therefore check whether that token appears in a record. A short or guessable secret could be recovered from its hash by brute force.

What is kept:

- **Placeholders.** A value that is plainly a template placeholder (`YOUR_API_KEY`, `<your-token>`, `{{token}}`, `${KEY}`, `INSERT_KEY_HERE`) is not a secret. It is kept, because the model-output rules read it.
- **Payloads, tags and run IDs.** Attack payloads, agent tags and run identifiers are left intact. The rules need them.
- **Parameter names.** Only values are replaced, so a rule that matches a parameter name (an anti-bot token name, for example) still fires.
- **IP addresses.** They are not redacted.

## Unwrapping

Agents rarely request a target directly. They wrap it in a relay, send a program to a carrier, or encode it. [`extract.rs`](../crates/sc-core/src/extract.rs) peels those layers, breadth first, so the rules see every hop and the real target:

- **Relays in the path:** `r.jina.ai/https://target/…` yields the inner URL, with the outer query string carried along.
- **Translate proxies:** `www-example-com.translate.goog` yields `www.example.com` (a doubled hyphen is a literal hyphen).
- **Doubled schemes:** `https://https://example.org/…` (or `http://https%3A//…`) parses with the host `https`. That is not a host: the URL after the second scheme becomes a layer, and the outer layer has no host, so it can never be a target.
- **URL parameters:** a parameter value that is a URL or a `data:` URL becomes a layer, and so does a whole query string that is a URL (`corsproxy.io/?https://target/...`).
- **`data:` URLs:** the body is decoded (base64 or percent-encoded), kept as a layer of its own, and searched for embedded URLs.
- **Base64:** a parameter value, or a run of path segments (as in `httpbin.org/base64/<payload>`), is decoded when it looks like base64 of at least 16 characters. Either alphabet is accepted, padded or not, and a truncated payload decodes up to its last whole block, because scan services cut long URLs. A decoding counts only if it is at least 90% printable and contains letters, so random IDs are left alone. A decoded URL becomes a layer. Decoded program text is kept as a layer and searched for embedded URLs.

Unwrapping stops at 16 layers or 6 levels deep (`MAX_LAYERS`, `MAX_DEPTH`). `swarmchase unwrap '<url>'` and the browser's Unwrap tab show the layers of one URL and the rules each triggers.

The record's **target host** is the innermost layer whose host is not itself a relay, carrier or callback service. Quotes and backticks a model wrote around a URL are trimmed from its host (`https://example.com%60` targets `example.com`).

## Rules

Rules are data, in [`rules/default.toml`](../rules/default.toml). The same file is compiled into the CLI and the browser toolkit. Its `version` is a date, and each case pins the version it was opened with (see [Known limits](#known-limits-and-false-positive-traps)). The loader is [`rules.rs`](../crates/sc-core/src/rules.rs).

Each rule has a kind, a target, a pattern and a weight. The kinds:

| Kind | What it matches | Examples |
|---|---|---|
| `relay` | Fetch-through and conversion services | Jina Reader, CORS proxies, translate proxies |
| `carrier` | Echo, sandbox and code-hosting services, and programs carried in a request | httpbin, LiveCodes, `data:text/html` with a script, self-submitting forms |
| `exploit` | Attack payloads | SQL injection, path traversal, XSS, template and command injection |
| `agent_marker` | Tags agents put in URLs, and model-output residue | `uqtag=`, `CHATGPTTEST1`, `zz=oai<digits>`, Markdown around a URL |
| `cache_buster` | Cache-busting parameters | `_=`, `cb=`, `nocache=` |
| `self_id` | A model or vendor name in a parameter value | `?agent=claude` |
| `exfil` | Callback and output channels | webhook.site inboxes, request catchers, ntfy topics, pastes, disposable mail |
| `header` | Request header and user agent fingerprints | proxy `Via` headers, scripted or headless user agents |
| `outcome` | Where a scan ended | `about:neterror`, bot challenges |
| `anti_bot` | Anti-bot token generation or CAPTCHA solving | CAPTCHA-solver services |
| `infra` | Hosting infrastructure | sandbox hostnames |

A rule's target says what it reads: the host of each layer (suffix match), each layer's decoded text, parameter names, parameter values, request headers, the user agent, or the final URL. Patterns are case-insensitive regular expressions unless a rule says otherwise. A rule can also name a `check`, a test its matches must pass for what a regular expression cannot say. `repeated_token` (on a parameter value, [`prose.rs`](../crates/sc-core/src/prose.rs)) wants a word of three characters or more, or a phrase of two or three words, repeated five or more times in a row. `ua_platform_mismatch` (on a `Sec-CH-UA-Platform` header, [`ua_platform.rs`](../crates/sc-core/src/ua_platform.rs)) passes when the hint names another desktop system than the user agent, as a borrowed user agent does.

**Scoring.** Each rule counts at most once per record, whatever layer it matched in. A record's score adds the weights of the distinct rules that fired, with two constraints below. Weights are deliberately low for anything ordinary users also do: a relay is worth 1 or 2, a self-identification 1.

Rules that read the same artifact are not independent: one fetch program carried through httpbin fires `carrier.httpbin`, `carrier.html_program`, `carrier.inline_fetch_program` and often `marker.title_write`, and a run tag fires both `marker.uq_tags` and `marker.test_tag`. Such rules share an independence group, which counts once, at the largest weight among its rules that fired; context kinds together count at most one below the suggestive threshold ([FM-4.11](manual/04-indicators.md#fm-411-independence-groups-and-the-context-cap)). The toolkit does both in `Rules::score`, from the `group` field ([SC-Rules v1](specs/rules-v1.md)). A fetch program through an echo service is suggestive alone and significant with another independent indicator; a script page with no request there is noise.

**Significant rules.** A rule marked `significant = true` puts a record in the top tier on its own. These are the unambiguous attack payloads (UNION SELECT, boolean and time-based SQL injection, multi-step traversal and sensitive files, XSS, template and command injection) and a small number of infrastructure fingerprints. Weaker exploit rules, such as a single traversal step or a lone quote, are not significant on their own.

**Linking rules.** A rule marked `link = true` turns its matched text into a linking feature (see [Linking](#linking-into-clusters)). Only identifiers one operator would hold are linking rules: per-user callback inboxes (webhook.site IDs, request-catcher subdomains, ntfy topics) and specific test tags. A rule that many unrelated users share scores but never links. For example, `exfil.oast_service` matches an OAST service named without an inbox subdomain; it scores like the inbox rule but does not link.

**Model-output residue.** Agents built on language models sometimes leave the model's formatting in the URL they send. The residue rules match text a model wrote around a URL: Markdown link and code syntax, unfilled placeholders, tool-call JSON and function-call markup, JSON string tails, escaped newlines, output cut off mid-escape or with an ellipsis, generation loops (one word or a phrase of up to three words repeated five or more times in a row, `marker.repeated_token`), and similar artefacts. A person pasting a chatbot answer into a scan form produces the same residue. These rules therefore carry low weights, and none of them links records.

**Tactics.** Each rule names what a match shows the agent doing, in the swarmchasing tactic vocabulary: `T1` task retrieval (relays, readers), `T2` tool escalation (carriers, programs, remote browsers), `T3` access-control circumvention (anti-bot, challenge outcomes), `T4` vulnerability probing, `T5` account or identity acquisition, `T6` credential reuse, `T7` callback or side channels, `T8` off-task targets, `T9` inter-agent coordination. A rules file naming `T8`, `T9` or any other id as a rule's tactic fails to load.

Each rule kind has a default tactic, the Field Manual's [FM-4.4](manual/04-indicators.md#fm-44-default-tactics-by-rule-kind) table; a rule on another tactic is listed with its reason in a test (`TACTIC_EXCEPTIONS` in [`rules.rs`](../crates/sc-core/src/rules.rs)). `T8` and `T9` are cluster-level judgments and never a rule's tactic. A rule marked `artifact = true` is a trace of how the agent was built, not an action: model-output residue, run tags, self-identification, client headers, sandbox hosts.

Every hit carries its rule's tactic and artifact flag, and each cluster counts hits per tactic (`tactics`) and members with an artifact hit (`artifacts`). Case notes and provider reports print the artifact count per cluster; affected-operator reports and public notices do not. Tactics describe; they never change a score.

**ASN hints.** The `[[asn]]` table maps autonomous system numbers to the organisations that run them. It is context for attribution, never proof.

## Tiers

Each record is graded by [`analyze/pipeline.rs`](../crates/sc-core/src/analyze/pipeline.rs):

- **significant:** a significant rule fired, or the score reached `thresholds.significant`;
- **suggestive:** the score reached `thresholds.suggestive`;
- **noise:** anything else, including records with a score above zero.

Both thresholds are set in the rules file. A tier says the record's contents look like agent activity under the rules: payloads, programs, channels, residue. It does not say who sent it, or whether the activity went beyond its task ([misalignment and scope](#misalignment-and-scope)).

**One relay hit is never enough.** People use relays, CORS proxies and echo services every day. No relay rule weighs as much as the suggestive threshold, so a single relay hit never flags a record. It needs another indicator first: a payload, a tag, a callback channel, a program, or residue. The context cap keeps a record of context hits alone at noise: context kinds together contribute at most one below the suggestive threshold, so two relays, or a relay and a vendor name, stay noise ([FM-4.11](manual/04-indicators.md#fm-411-independence-groups-and-the-context-cap)).

A cluster gets its own tier: the highest tier among its members, raised one step only by corroboration. A suggestive cluster becomes significant when two of its suggestive-or-above members each carry a kind of evidence the other lacks: one record shows a callback channel and model residue, another the same channel and a carrier program. Context kinds, which ordinary clients produce too, do not count towards that: `relay`, `cache_buster`, `self_id`, `header` and `outcome`. A cluster of noise records stays noise, and weak rules collected across many members never add up to a higher tier.

The cluster's `score`, the distinct rules seen in any member scored as one record's would be, is listed for reference and does not set the tier. Code: `cluster_tier` in [`hints.rs`](../crates/sc-core/src/analyze/hints.rs).

## Linking into clusters

Only records with a score above zero are linked. Ordinary traffic to the same host is never swept into a cluster. Three things join two flagged records:

1. **A shared linking feature.** Two records that carry the same matched text from a linking rule, or the same value (three characters or more) of a parameter named in `linking.strong_params` (run tags such as `uqtag`, `tok`, `run`, `session`). The link is bounded in time: a feature's records, in time order, are joined while each is at most `linking.feature_link_window_secs` (3 days) after the last, and a longer gap starts a new group. The same inbox used again months later starts a new cluster. Records without a timestamp join the feature's only group, or form their own when it has several.

   A feature can also be too common to say anything about one operator: a tag copied from a published report, or a generic parameter value. A group whose feature appears on more than `linking.feature_max_hosts` target hosts does not link, and neither does one carrying more than `linking.feature_max_share` of all records in its time span (when that span holds at least `linking.feature_share_min_records` records; the share is off by default, because in a case file one fleet can be most of the records). Such a group is listed under `common_features` in the analysis and in internal reports, with the limit it passed.

   A tag quoted in a public report is common by definition, however few hosts carry it: anyone who read the report can copy it. `linking.published_tags` lists those tags, each with its source in a comment. A feature whose value is one of them (ignoring case) never links, and its group is listed as a common feature with the reason "quoted in a public report".

   A value carrying one of our own canary tokens ([page references](reference/browser-toolkit.md#page-references)) is treated the same way, whether or not the registry holds it: anyone can copy a token from our pages, so it never links records, and planting one cannot merge clusters. Redaction leaves a token in place, since it is public by construction. A copy is reported apart, as a canary sighting.
2. **Close timing against the same target.** Consecutive flagged records to the same target host, at most `linking.window_secs` apart, that share at least one rule of a kind other than the context kinds (`relay`, `cache_buster`, `self_id`, `header`, `outcome`). Every reader of a page through Jina Reader shares the relay rule, so a shared relay or cache buster alone never joins two records: a record placed beside a cluster would otherwise need nothing else to join it. Only request and submit times link this way (and times of unknown kind, read as requests). Archive capture times say when a crawler saved a URL, not when a client sent it, so two captures minutes apart are not joined by timing.
3. **Probe chains.** A run of requests to one host and path, each at most 5 minutes after the last (`chains.max_gap_secs`), with at least 3 distinct parameter sets (`chains.min_variants`) and at least one parameter whose value changes. This is one client trying variants of a request. The flagged requests in a chain are linked even when different rules fired on each. Code: [`chains.rs`](../crates/sc-core/src/chains.rs). Chains are formed on any timestamp kind, but only a chain timed by request or submit times hard-links its records; a capture-timed chain is listed as a hint and joins nothing on its own ([FM-5.4](manual/05-linking.md#fm-54-probe-chains)).

Links are transitive: if A links to B and B to C, all three form one cluster. A cluster needs at least two records. Each cluster lists the linking features its members share, so a reader can see what joined them.

Each cluster has a number (`C1`, strongest first, which changes as records arrive) and a stable key (`k-` and 8 hex digits). The key is a hash of the id of its earliest member, by timestamp and then id, with untimed members last. Anyone can submit a record to a public scanner and retry until its id sorts first, but its timestamp is when it was sent, so a record placed beside an existing cluster cannot take over its key. Code: `key_seed` in [`link.rs`](../crates/sc-core/src/analyze/link.rs).

Within a cluster, a gap longer than `linking.run_gap_secs` starts a new **run**.

Probe chains also carry descriptive detail that changes nothing: their **pace** and the requests in them that no rule flagged. The pace is the chain's median gap. Under 2 seconds (`chains.tool_pace_below_secs`) reads as a scanner or script. From 2 seconds to 2 minutes (`chains.model_pace_max_secs`) is consistent with a model choosing each request. Slower is a person or a model that reasons longer. Chains also count **retries after an error**: a changed request sent right after a response with status 400 or above. A scanner working through a list keeps going regardless; a model reading the error tends to change course. Both are hints, not evidence.

## Timing

[`timing.rs`](../crates/sc-core/src/timing/mod.rs) describes each cluster and the whole analysis. None of it changes a score or links records.

**What the times measure.** Each record says what its timestamp is (`ts_kind`): a request or the event a public log recorded (access and operator logs; a GH Archive event, a wiki edit on EventStreams, an npm or PyPI publication, a certificate log accepting an entry), a submission to a scan service (urlquery), or an archive capture (Wayback, Arquivo.pt, Common Crawl, Memento archives). Each cluster and probe chain carries the result as `time_basis`: `request`, `submit`, `capture`, or `mixed` when capture times sit alongside the others.

Hints that read request timing (chain pace, fan-out width, co-activity and the hour-of-day rhythm) never use capture times: rhythm and fan-out leave capture-time records out, and a chain timed by captures reports "capture times, not request times: pace not read". Submit times are close to request times and are used, labelled "submit times". Cadence, bursts and pauses describe whatever the times are.

**Cadence, bursts and pauses.** The median and 90th-percentile gap between records. A burst is at least `linking.burst_min` records, each within `linking.burst_gap_secs` of the last. A pause is a gap at least `linking.pause_min_secs` long and at least ten times the median gap, so a slow but steady cadence does not read as a string of pauses. The analysis also reports how many cluster runs were active at the same instant.

**Rhythm.** An hour-of-day profile, counted in distinct active clock hours rather than records, so one burst does not outweigh a day of steady activity. It needs records on at least 3 UTC days, at least 20 records and at least 12 active clock hours (`RHYTHM_MIN_*`). With enough data, the narrowest circular window of the day holding 90% of active hours is found:

- a window of at most 12 hours reads as one time zone's working day. Its middle is placed at 13:00 local time to give a UTC offset guess (`LOCAL_MIDDAY`);
- a window of 20 hours or more with normalised entropy of at least 0.85 reads as round the clock. People sleep; automated fleets need not;
- anything else is reported as unclear.

**Operator offset from date tags.** Agents sometimes put "today's" date in a URL (`archive_test=20261004`). A tag one day ahead of the UTC date, late in the UTC day, means the operator's clock is east of UTC. A tag one day behind means west. Every tagged record narrows the range of UTC offsets consistent with all of them. The analysis reports that range when the records agree, and says so when they do not. Tags more than a day from the UTC date are not "today" tags and are ignored here.

**Stale dates.** A tag at least 7 days behind the day it was seen (`STALE_MIN_DAYS`) is stale. An agent with no clock that writes "today" writes the date it believes it is, often one from its training data. A cluster's stale tags are reported as a pattern only when there are at least 3, they are at least half of all its tags, and at least 60% name one date or lag by about the same amount (`STALE_MIN_TAGS`, `STALE_AGREE_SHARE`). Tags two or more days ahead are counted separately as a wrong clock or a typo.

**Shared pauses.** Two clusters that share no identifier but go quiet together may have one scheduler, quota or operator behind them. For each pair of clusters above noise, the pauses of each are compared over the time both were active. A pair of pauses matches when their starts and their ends each fall within 120 seconds (`SHARED_PAUSE_TOLERANCE_SECS`).

Matches can happen by chance, so each pair is tested against a chance model. For every pause pair whose lengths differ by less than twice the tolerance, the chance of a match is the width of the window in which its start could fall and still match, divided by the time both clusters were active. The sum over all pause pairs is the number of matches expected by chance. The probability of seeing at least the observed number is taken from a Poisson distribution.

A pair of clusters is listed only when that probability is at most 1% (`SHARED_PAUSE_MAX_CHANCE`), either it has at least 2 matches or one matching pause is at least 3 hours long, and it survives a Benjamini-Hochberg cut at 5% (`SHARED_PAUSE_FDR`) over every pair of clusters active together; each states the pairs compared and the pairs that unlikely expected among them.

Pauses that start or end on a clock hour are not random under this model: unrelated cron jobs stop and start on the hour together. A match within the tolerance of a clock hour counts as a quarter of a match (`SHARED_PAUSE_CLOCK_WEIGHT`), and never qualifies on its own as a long pause.

A shared pause is a link to check by hand. It never merges clusters.

**Co-activity** ([`coactivity.rs`](../crates/sc-core/src/coactivity.rs)). Two clusters busy in the same minutes, or one consistently a little after the other, as when a planner dispatches workers ([FM-6.9](manual/06-timing.md#fm-69-co-activity)). Each cluster above noise with at least `co_activity.min_active_bins` (4) active bins, from request and submit times only, is binned into `co_activity.bin_secs` (60 second) bins. Over the union of the two clusters' spans, the bins where both are active are counted at each lag up to `co_activity.max_lag_bins` (5) either way; a lag reads its bin and the next, so a follower is not lost at a bin boundary. The best lag's count is the statistic.

Two chance models; the pair's chance is the larger. Analytic: each active bin of the quieter cluster meets the other's activity at the best lag with the share of the union span that activity covers (its own rate), and the chance is the Poisson-binomial tail of so many coincidences (rounded up from the weighted count), times the lags tried; it sets no floor, so a dispatch under two hours can qualify.

Circular shift: of `co_activity.shifts` (199) circular shifts of one cluster's activity over the union span and the real alignment, the share that align at least as well, `(ge + 1) / (shifts + 1)`, which keeps bursts and periods: two jobs on one ten-minute period align under every shift by a multiple of it. A short span allows fewer shifts; when too few remain for the share to reach `co_activity.max_chance`, the shifts only veto (no shift may align as well) and the analytic chance stands, so a dispatch under two hours can still qualify.

A pair is kept with at least `co_activity.min_coincidences` (4) coincidences, a chance of at most 1% (`co_activity.max_chance`), and under a Benjamini-Hochberg cut at `co_activity.fdr` (5%) over every pair tested; each states the pairs tested and the pairs that unlikely expected among them.

A coincidence within `co_activity.clock_tolerance_secs` (120 seconds) of a clock hour counts `co_activity.clock_weight` (a quarter), and when half or more of either cluster's active bins sit on clock hours, the shifts are whole hours and the analytic rate is the other's coverage of the bins at the same minute of the hour, so two jobs on one schedule stay aligned under both models. Bins where more than `soft_links.max_shared` clusters are active are left out when finding pairs to test. Each pair (`coactive_pairs`) carries its lag, coincidences, the mean over the shifts and the chance. It is a soft link, never a merge.

**Co-target** ([`cotarget.rs`](../crates/sc-core/src/cotarget.rs)). Two clusters working the same rare targets in the same hours, each at its own pace and in its own order, as when one operator hands one target list to several agents ([FM-5.16](manual/05-linking.md#fm-516-co-targets)). Each cluster above noise becomes a set of items, one per target host and action (`probe` for an exploit payload, `callback` for a callback inbox, `fetch` through a relay or carrier, else `visit`), each with its active `co_target.bin_secs` (one hour) bins from request and submit times. Two clusters share an item when both were active on it within `co_target.max_lag_bins` (1) bins.

A host touched by more than `co_target.max_holders` (4) senders, clusters above noise and records outside them, ties none: a story or a disclosed flaw that sends many unrelated agents to one site, and an operator's own access log where every record names its host, draw no pair. A pair needs shared items on `co_target.min_hosts` (3) hosts.

Its chance is the hypergeometric tail of sharing that many items when one cluster's items are drawn at random from every rare item any cluster above noise was active on; it leaves time aside, so it overstates how often unrelated clusters meet, never understates it. Pairs are kept at `co_target.max_chance` (1%) and under a Benjamini-Hochberg cut at `co_target.fdr` (5%) over every pair sharing an item. Each pair (`cotarget_pairs`) carries its shared items, hosts, the chance, the pairs tested and a rarity-weighted overlap. It is a soft link, never a merge.

**Ordered co-target** (`ordered_pairs` in [`cotarget.rs`](../crates/sc-core/src/cotarget.rs)). Two clusters working one ordered target list at the same time, each at its own pace ([FM-5.19](manual/05-linking.md#fm-519-ordered-co-targets)). Co-target ignores order, a rerun needs another day, and a synchronised start needs requests within seconds; this reads the order alone.

A pair of clusters above noise sharing at least `co_target.order_min_hosts` (5) rare hosts (rare as for co-targets) is tested when their first touches of those hosts, from request and submit times only, fall within `co_target.bin_secs` of each other's span. Each cluster's first touches put the shared hosts in an order; the statistic is the longest run of hosts both clusters touched in the same order (the longest increasing subsequence of one order read in the other), and a tie in either cluster's times never counts as agreement.

Its chance is that of so long a run in a random order of the shared hosts: exact up to 30 hosts (by the Robinson-Schensted correspondence, counting permutations by the hook length formula), and above that the union bound `C(k, L) / L!`, which overstates it. A public sorted or ranked list gives every reader one order with no shared operator, so a pair whose two orders both follow the hosts' sorted order (by text, or with numbers read as numbers, either way) as far as they follow each other ties nothing. Pairs are kept at `co_target.max_chance` and under a Benjamini-Hochberg cut at `co_target.fdr` over the pairs tested. Each pair (`ordered_cotarget_pairs`) carries the shared hosts, the run in order, the chance and the pairs tested. It is a soft link, never a merge.

## Descriptive hints

Several features describe a cluster without changing its score, its tier or its membership:

- **Encodings** ([`fingerprint.rs`](../crates/sc-core/src/fingerprint.rs)). How each URL was written: spaces as `%20` or `+`, hex case in escapes, double encoding, unescaped characters, trailing `&`, empty values, sorted parameter names. Only URLs that show at least one such choice are counted.
- **Recon preambles** ([`paths.rs`](../crates/sc-core/src/paths.rs)). The same opening sequence of well-known files (`/.well-known/security.txt`, `/.env`, `/llms.txt` and similar) on 3 or more hosts. An opening made only of what polite crawlers fetch (`/robots.txt`, `/sitemap.xml`) does not count. The path lists and thresholds are the `[paths]` settings. Unflagged requests on the cluster's hosts during its span are read too, because a recon opening is rarely flagged itself.
- **Unusual path sets.** The same set of at least 3 uncommon paths requested on 3 or more hosts (Jaccard similarity at least 0.6). Records rarely say whether a path existed, so this is "the same unusual path set", not "the same invented paths". Where records carry a status, 404 and 410 responses are counted.
- **Fabricated identifiers.** UUID-shaped values no generator produces (wrong version or variant digit, repeated groups, sequential or low-diversity digits) and hex "hashes" that are obviously typed by hand. Language models write such values when they invent a resource. The nil and max UUIDs are not reported.
- **Shared inventions.** One fabricated value carried by two or more clusters, listed on each with the number of clusters carrying it (`paths.shared_invention`), in case notes only. Models of one family invent the same placeholder, so this is a model-family hint and never a soft link between operators.
- **Probe chain pace and retries**, as above.
- **Reruns** ([`recurrence.rs`](../crates/sc-core/src/recurrence.rs)), in the watch digest. A later run whose target hosts, and their order, repeat an earlier run in a different cluster on another day, at least 6 hours later. Runs must share at least 4 hosts, overlap with a weighted Jaccard of at least 0.5 (hosts common to many runs are down-weighted), and agree on order for at least 70% of shared hosts.
- **Archive bursts**, in the watch digest. Many archive captures of one target host within minutes, on a host the store otherwise holds few captures of (the `linking.archive_burst_*` settings). A capture with no target behind its relay or carrier (the service's own page) is left out, so a burst never names the relay.
- **Payload dialect.** Which canonical test payloads a cluster uses, such as `<script>alert(1)</script>` or `<svg onload>`, `' OR 1=1--` or `' OR '1'='1`, and how deep its `../` runs go. Clusters that use the same uncommon mix of payloads are listed as a link to check.
- **Route escalation** ([`escalation.rs`](../crates/sc-core/src/escalation.rs)). Requests for one host and path, each at most `escalation.window_secs` (30 minutes) after the last, whose route climbs: a direct request, then a relay (Jina Reader, allorigins, markdown.new, a translate proxy), then a program carrier (httpbin, a `data:` or base64 program), then a remote browser (a code playground). The route lists in `[escalation]` name the rules for each level. An agent that cannot read a page tends to try harder like this; two people reading the same page by different routes look the same. Capture-time records are left out, because their order is the archive's.
- **Parallel fan-out width.** How many alike requests land in the same second, as when an agent issues tool calls in parallel (the `[fanout]` settings).
- **Cross-service fan-out** ([`crossservice.rs`](../crates/sc-core/src/crossservice.rs)). Members' targets, compared after unwrapping, each submitted to at least `fanout.cross_service_min` (2) submit-anywhere services within `fanout.cross_service_secs` (60 seconds), counted per cluster (`cross_service`: targets, records, services, spread). Only submit or request times count; archive capture times never do. Internal and provider reports give it one line: the services, the widest spread and the ambient count below.
- **Auto-submitters.** A mail gateway or security product that submits every link it sees fans out the same way, and whoever mailed the link made the records. Each cluster with cross-service fan-out also counts ordinary (noise-tier) targets on other hosts fanned out alike within `linking.window_secs` of its span (`ambient`). At `fanout.cross_service_ambient` (3) or more it is marked an auto-submitter, and the [agent grade](#agent-likelihood) lists it as a counter-signal instead of an L4 signal; the plant review lists it as auto-submitted. Two services carrying one target never count as corroboration ([provenance](#provenance-and-plant-review)).
- **Declared testing** ([`declared.rs`](../crates/sc-core/src/declared.rs)). Members that announce themselves as testing: a user agent, header or parameter saying "authorized security test", "for research purposes" or "this is a security test"; a bug-bounty header (`X-HackerOne-Research`, `X-Bug-Bounty` and similar); or words such as "pentest", "security research" or "bug bounty" next to an email address or bounty handle. Each cluster lists the declaring text and the contact it names (`declared`), in case notes only. It feeds the case's handling of authorised testing: the admin checks the claim with its owner. It never lowers or raises a score, because anyone can write it and an agent can copy it from its prompt.
- **Benchmark targets** ([`knowledge.rs`](../crates/sc-core/src/knowledge.rs)). Members hitting a public benchmark or practice target listed under `[[benchmark]]` in the rules file, each entry with its source: intentionally vulnerable demo sites (Acunetix's vulnweb hosts, Altoro Mutual, OWASP Juice Shop demos, Google Firing Range) and agent benchmark environments (WebArena, MiniWoB++, picoCTF hosts). Each cluster counts them per entry (`benchmarks`). Probing such a site is likely evaluation or training activity, not malice, and reports say so. It never lowers a score: an agent can be evaluated and misbehave in the same run.
- **Stale knowledge.** Retired API endpoints and old client versions listed under `[[stale]]`, each with its source (OpenAI's Engines endpoints, Twitter API v1.1, YQL, Graph API v2.x, query-string tokens on the GitHub API, old `openai-python` and `python-requests` user agents), plus API path versions (`/v1/`) below the newest one seen on the same host family anywhere in the input (`older_api_version`). An entry is reported per cluster (`stale_knowledge`: id, note, records, hosts) when at least two members carry it. A model writes requests from what its training data knew; old scripts and pinned clients do the same, so it is a hint.
- **Natural-language residue** ([`prose.rs`](../crates/sc-core/src/prose.rs)). Parameter values that are prose: at least 6 words with letters (`PROSE_MIN_WORDS`), or 12 characters in a script written without spaces. Each gets an offline language guess: the script first, then for Latin script the language whose common words it uses most (seven languages), or none when unclear. Each cluster counts distinct prose values and their languages (`prose`), and how many are in a language other than their target's country domain (`.de` German, `.jp` Japanese; `mismatched`). An agent prompted in one language often searches a foreign site in it. Searches by travellers and English-language sites abroad do the same, so it is a hint.
- **Relay stacks.** The relays and carriers each member went through, outermost first, ending at the target (`relay.jina → relay.translate_goog → target`), counted per cluster (`relay_stacks`). The order is the unwrapping order of the rule hits. A stack of two or more hops is listed in reports; one relay is every relay user's habit and is only counted.
- **Repeated cut lengths.** Truncated URLs cut at nearly the same length, as a model or tool output limit would (the `[cut_lengths]` settings). A scan service's own display limit can do the same.
- **Shared scaffolds** ([`scaffold.rs`](../crates/sc-core/src/scaffold.rs)). Clusters whose requests share a structure though they share no identifier: one harness behind separate inboxes and tags ([FM-5.14](manual/05-linking.md#fm-514-scaffold-fingerprints)). Each member becomes a template (see *Scaffold templates* after this list), and clusters are compared by their template mixes.

**Scaffold templates.** A member's template is its relay stack, the target path's segment types, its parameters in order as `name=slot` (a URL, a payload, prose, a redacted secret, or a number, word, hex, UUID or token with a power-of-two length class), its encoding style, its payload variants and whether it was cut. No host, path word or value is kept. A template counts only with at least `scaffold.min_specificity` (3) structural parts (relay hops, parameters, an informative encoding, payloads, a cut), and only when held by at most `soft_links.max_shared` clusters. Pairs sharing one are compared by the IDF-weighted similarity of their template mixes (the reruns' weighting).

**Scaffold chance.** The comparable clusters are the `n` clusters above noise that send a specific template at all. A template held by `h` of them and carried by `o_t` records outside the clusters (unclustered, unflagged, in noise clusters) has the base rate `(h - 1 + o_t) / (n - 1)`, one holder of the pair left out. A pair's chance is the base rate squared for the rarest usable template it shares, corrected for the number `T` of usable templates it shares, since the least of several is likelier than one: `1 - (1 - r²)^T`. Outside records count only as more holders, never as more population: appending unrelated traffic to an analysis changes no chance, and traffic that carries the shape makes it more common.

A template held by more than `scaffold.max_holders` (5) senders, clusters and outside records together, is a common default and ties none: one fleet on one harness and many operators on one framework default cannot be told apart from the records, and the method takes the safer reading. A pair is kept at a similarity of at least `scaffold.min_similarity` (0.5) with a chance of at most `scaffold.max_chance` (1%), and only when it survives a Benjamini-Hochberg cut at `scaffold.fdr` (5%) over the pairs compared. Each pair (`scaffold_pairs`) lists up to three shared templates, the holders, the outside records, the base rate, the chance, the pairs compared and the pairs that unlikely expected among them.

An analysis of a handful of comparable clusters ties none: with `n` below about 11, two holders already give a rate above a tenth. A fleet of more than five clusters on one shape reads as a common default.

**Scaffold lineage** (`lineage_pairs` in [`scaffold.rs`](../crates/sc-core/src/scaffold.rs)). An operator who upgrades a harness mid-fleet changes one structural part of its template, and exact templates split the fleet in two ([FM-5.20](manual/05-linking.md#fm-520-scaffold-lineage)). Each specific template has a deletion neighbourhood: its own key, and, when it has at least `scaffold.min_specificity + 1` parts, one key per structural part dropped (the relay route, a parameter, the encoding, the payloads, the cut) that leaves it specific. Two templates a parameter apart, or differing in one part, share a key. Two clusters above noise sharing a key but no specific template are compared.

The key's base rate is read as a template's, `(h - 1 + o) / (n - 1)`, with the same `scaffold.max_holders` and `soft_links.max_shared` caps. Unrelated templates built from common parts are often one part apart, and a cluster sending several shapes holds many keys, so the chance is not read from the shared key alone: keys held by the same clusters count as one family, and the chance is that an unrelated cluster holds as many of one side's usable key families as the other does, each at its base rate (a Poisson-binomial tail), the larger of the two sides; it must be at most `scaffold.max_chance` on its own.

Families of one side whose holder sets share another cluster are one family, at the highest rate: one framework's template seen by four users, one of them sending only some of its shapes, gives nested holder sets that are one piece of evidence, not two, and read as two they let unrelated users through at about the base rate squared. A fleet's own other members are holders too, so a lineage of more than two clusters needs many comparable clusters to pass, and a lineage of two a hundred or more.

A lineage is one harness before and after a change, so only pairs where one cluster's requests (request and submit times) end before the other's start are tested. The handover adds to the chance: that of a gap that short (an hour at least) when the two spans are placed at random over the span of the comparable clusters' requests, `(2gG - G²) / ((S - a)(S - b))` for spans `a` and `b` over `S`, free room `g = S - a - b` and gap `G` at most `g`. The two combine as one test (`x (1 - ln x)` for their product `x`).

Pairs are kept at `scaffold.max_chance` and under a Benjamini-Hochberg cut at `scaffold.fdr` over the pairs compared. Each pair (`lineage_pairs`) lists up to three shared keys, the kinds of part changed, the holders, the base rate, the handover gap and its chance, the combined chance and the pairs compared.

**Prompt echo** (`prompt_echo_pairs` in [`prose.rs`](../crates/sc-core/src/prose.rs)). Agents given one prompt write their queries from one template, each naming its own target ([FM-5.21](manual/05-linking.md#fm-521-prompt-echo)). Each prose parameter value of at least `prompt_echo.min_words` (6) words, in any record, is slotted as platform text is ([coordinated accounts](#coordinated-accounts-on-public-platforms)), with the target host and its labels as slots, and sketched. Two values are one template when their slotted text is equal, or a MinHash band agrees and the estimated similarity is at least `prompt_echo.min_similarity` (0.6).

The target's words are the host and its labels, and for a label with hyphens its parts and the parts joined (`acme-corp` gives `acme`, `corp` and `acmecorp`), each also in its possessive form, so a name written as prose writes it is a slot and never reaches the excerpt.

A template matching one of `prompt_echo.common_templates` (published query and dork lists, each with its source; `{site}` stands for the target's name) is public and ties none, as is one carried by more than `prompt_echo.max_holders` (5) senders, clusters and outside records together.

A template's base rate is `(h - 1 + o) / (n - 1)` over the `n` clusters writing prose, and the chance is scaffold lineage's: templates carried by the same clusters (or by holder sets sharing another cluster) are one family, and the chance is that an unrelated cluster meets one side in as many of its families as the other does, the larger of the two sides. The rarest shared template's rate squared reads the chance of that one template, not of any of the several a cluster writes, and lets three unrelated clusters copying one viral prompt pass among a few dozen writing prose.

A pair of one operator therefore passes only among a hundred or more clusters writing prose, and three copies of one prompt pass among a few hundred: a prompt copied by a few unrelated operators cannot be told from one operator's by its wording alone, which is what the published-template list is for. Kept at `prompt_echo.max_chance` and cut at `prompt_echo.fdr`. Each pair (`prompt_echo_pairs`) carries the shared templates, the slotted start of the rarest, its holders, its base rate, the chance and the pairs compared.

**Soft links and candidate fleets** ([`fleets.rs`](../crates/sc-core/src/fleets.rs)). The hints that relate two clusters are collected as soft links (`soft_links` in the analysis). The kinds:

- timing and habit: shared pauses, payload dialects, reruns of one target list;
- how requests were written: the same recon opening, overlapping unusual path sets, one encoding style across every member, the same fan-out width, the same cut length, the same request header set;
- routes and features: steps of one route escalation, the same relay stack of two or more hops (`relay_stack`), inboxes on the same callback service (`callback_service`: different webhook.site inboxes, say; one inbox links outright), and a linking feature too common to link on;
- **captured secrets** (`shared_secret`): one `REDACTED-<hash>` value in records of both clusters, a token one client captured and another reused;
- **structure, co-activity and co-targets**: a shared scaffold (`scaffold`), scaffold lineage (`scaffold_lineage`), prompt echo (`prompt_echo`), co-activity (`co_activity`), co-targets (`co_target`) and ordered co-targets (`ordered_co_target`). A pair already tied by shared pauses gets no co-activity link, since both read one timeline.

**Likelihood ratios.** Each kind's setting in `[soft_links]` is a likelihood ratio: how much likelier the link is between two clusters of one operator than between unrelated ones; 1 or less turns the kind off. A pair kept by a chance test (every kind with a chance model above) carries its kind's ratio in full. Any other link's ratio is its kind's raised to its similarity, where it has one, and to its **rarity**: a value held by `n` of the `N` clusters above noise counts `ln(N/n) / ln(N/2)` of its kind, in full when two clusters hold it and not at all when all do. A value shared by more than `soft_links.max_shared` clusters links none of them, and a link whose ratio comes out below `soft_links.min_link_lr` (2) is not listed. Each link's `strength` is `1 - 1/ratio`.

**Families.** Kinds that read one habit are not independent evidence, so they fall into four families: **harness** (encoding, header set, relay stack, scaffold, scaffold lineage, prompt echo, dialect, cut length, fan-out width), **timeline** (shared pauses, co-activity), **targets** (reruns, path sets, preambles, co-targets, ordered co-targets, escalations) and **identifiers** (captured secrets, common features, callback services). A pair counts its strongest link per family, and the families' ratios multiply.

**Where the ratios come from.** `swarmchase sim calibrate samples/sim/scenarios.toml` switches every kind on, counts the pairs of clusters on distinct true runs each kind links, one operator's and unrelated, and prints each kind's ratio with a conservative value: the lower 95% Wilson bound of the share of one operator's pairs linked over the upper bound of the share of unrelated pairs linked. The bundled ratios start from those conservative values for the kinds the simulator measures.

Pooled over every scenario, the unrelated pairs of a few crowded scenarios (hundreds of single agents) swamp the rest and make a kind look rarer among unrelated pairs than it is where one operator's pairs are (Simpson's effect). So `sim calibrate` also prints each scenario's ratio and a Mantel-Haenszel ratio over the scenarios where the kind fired and both kinds of pair exist, with the lower bound of its Greenland-Robins interval as the stratified conservative value; `sim calibrate --check` fails when a bundled ratio is above it.

Habit kinds the simulator measures only on its one small set of copied records (encoding style, relay stack, callback service) are off by judgment, and dialect is kept low. Kinds the committed scenarios do not produce (captured secrets, header sets, reruns among them) keep ratios set by judgment, marked as such in the rules file.

The simulator measures ordered co-targets (`ordered-list`), scaffold lineage and prompt echoes (`harness-crowd`) each in one scenario, with stratified lower bounds far above the scaffold's and the co-target's ratios: unrelated pairs in a crowd of a hundred agents seldom draw them. The bundled ratios are held at the parent kind's (co-target for ordered co-targets, scaffold for the other two), below their bounds, so a refinement of a test never outweighs the test itself.

**Candidate fleets.** Pairs whose combined ratio reaches `soft_links.fleet_min_lr` (20) are the edges of a graph of clusters, weighted by the log of the ratio ([`community.rs`](../crates/sc-core/src/community.rs)). Its **backbone** keeps an edge that holds an unusual share of either endpoint's weight (the disparity filter at `soft_links.backbone_alpha`, 5%), or whose endpoints share at least `soft_links.backbone_overlap` (half) of their other neighbours, as a clique's edges do; a cluster with one edge keeps it.

The backbone is split into communities by a deterministic **Leiden** under the constant Potts model: a community keeps only clusters whose ties to it hold on average `soft_links.fleet_density` (half) of a threshold edge's log ratio per pair. A cluster tied to two fleets, which connected components would chain into one, joins at most one of them.

Each community of two or more is a **candidate fleet** (`candidate_fleets`), with its weakest edge (`min_lr`), its density (the share of its pairs that are edges) and its weakest cut (`cut_lr`, `cut`: the edges whose removal would split it, by Stoer-Wagner, and the smaller side).

Candidate fleets are listed in internal reports and the watch digest. A candidate fleet is a proposal for the admin: it never merges clusters, changes a tier, or appears in a report to a provider, an operator or the public. The watch follows them across runs by key and adds up weak evidence over windows ([watch](reference/watch.md#the-ledger)).

**Multiplicity budget.** Every pairwise test in the analysis belongs to a family: shared pauses, scaffolds, scaffold lineage, prompt echoes, co-activity, ordered co-targets, the S3 to S6 interaction edges ([interaction](#interaction-between-runs)), and platform candidates per platform. A family counts the pairs it tested, keeps those at or under its own chance limit that also survive a Benjamini-Hochberg cut at its false discovery rate over every pair tested, and states the pairs that unlikely chance alone would give among them (`tested × cut`).

The analysis lists each family (`multiplicity`: family, tested, passed, kept, cut, expected), case notes print them under *Pairwise tests*, and each kept pair states its family's count. Platform candidates are weighed apart from the record analysis, and their report carries one family per platform (`families`). A larger analysis tests more pairs and so needs a smaller chance per pair; the [simulator's](reference/evaluation.md#simulated-scenarios) background-only scenarios measure the false pairs that remain.

**Why they never score or link.** Each of these is shared by many unrelated clients. Encoding styles are mostly library defaults. Polite crawlers and security scanners share recon openings. Popular targets attract the same paths. Cron jobs share pause times. Letting any of them raise a score would flag ordinary clients. Letting any of them link records would merge unrelated clusters, and every later step would inherit that error. They are also not measured by the evaluation set. So they appear in reports as hints, labelled as hints, for the admin to weigh.

## Provenance and plant review

Most sources take records from anyone. A record shows that someone submitted or published a URL, not that an agent sent it, and a person who wants a cluster found, or wants one attributed to someone else, can place records to be found. [`plant.rs`](../crates/sc-core/src/plant.rs) describes this for the admin. None of it changes a score, a tier or a link.

**Provenance.** Each record's provenance follows from its source (`Provenance::of_source` in [`model.rs`](../crates/sc-core/src/model.rs)); it is derived, never stored:

| Provenance | Sources |
|---|---|
| `observed` | Access logs; logs an affected operator sent |
| `submit-anywhere` | urlquery, urlscan, Wayback, Arquivo.pt, Memento timemaps |
| `publish-anywhere` | GH Archive, npm, PyPI, Wikimedia EventStreams, CT logs, Common Crawl |
| `reported` | Records an outside submission states: its own logs and references as written ([inbox](reference/inbox.md)) |
| `unknown` | Anything else: manual imports, fixtures |

Archive rows count as submitted. A CDX row does not say whether a capture came from an on-demand save (Save Page Now, which anyone can trigger for any URL) or from a crawl, and telling them apart would mean opening the capture, which collection never does. Common Crawl counts as published: it crawls what pages link to, and anyone can publish a link.

**Corroboration.** Each cluster counts its members by provenance (`provenance`) and says how many kinds of source stand behind it (`corroboration`): `single_source` (one kind at most, unknown not counted), `multi_source` (two or more), or `operator_confirmed` (an operator's logs hold a member). Reported records count as no kind, so a submission alone never makes a cluster multi-source. Two scan services count as one kind: whoever submits to one can submit to the other. Internal and provider reports carry both on each cluster's timeline. The tier does not read them, so a single-source cluster is graded like any other; the line says that such records show someone submitted them, not who.

**Plant signals.** Each cluster lists signs that it was planted (`plant_signals`), with the records each rests on. They appear under *Plant review* in case notes and as one line per cluster in `case status`, never in a report to a provider or an operator, and never in a notice:

- **Provenance monoculture**: a cluster above noise whose every record comes from a submit-anywhere source. In a collection built from one scan service, nearly every cluster carries it, so it says little about one cluster; each signal is reported with its base rate over the analysis's clusters, and one carried by most of them (at least four) is context and does not count toward the plant-review threshold ([FM-5.11](manual/05-linking.md#fm-511-provenance-and-planted-records)).
- **Burned identifier**: a member's linking feature is one of `linking.published_tags`. Such a value never links, and is not a soft link either.
- **Too perfect**: every member significant on three or more kinds of evidence other than context kinds, with no unflagged request on its hosts within `linking.window_secs` of its span, no route escalation and no task retrieval. Real agents read pages no rule flags on their way to a probe; a cluster built from textbook payloads need not.
- **Habit mismatch**: a linking feature the cluster shares with an earlier cluster (outside the link window, not common and not burned), where the two clusters' relay stacks, URL encodings or payload dialects both exist and share nothing. The identifier may have been copied.
- **Auto-submitted**: the cluster's [cross-service fan-out](#descriptive-hints) marks it as an auto-submitter: at least `fanout.cross_service_ambient` ordinary targets on other hosts went to several services alike around it. A mail gateway or security product submits every link it sees, so the records say who mailed the links, not who sent requests.

Each is something ordinary agent activity also produces, which is why they are prompts and never evidence.

## Interaction between runs

[`swarm.rs`](../crates/sc-core/src/swarm/mod.rs) lists possible interaction between runs (SC-T9) as edges (`swarm_edges` in the analysis). Each edge names two runs as `C3#2` (cluster and run number) with a few of the records it rests on, a kind, a strength (weak, moderate, strong), a chance where the kind has a model, and a detail line. Edges are hints: they never score, link or merge, and they never make a grouping a swarm. That takes a reviewed record in the case ([cases](reference/cases.md#swarms)). The method and its limits are in [SC-FM 4.10](manual/04-indicators.md#fm-410-interaction-signals) and [SC-FM 5.12](manual/05-linking.md#fm-512-interaction-edges).

**Runs and strands.** Runs are the clusters' runs above noise. Each run is split into strands by relay route, user agent, client network and header set, so that two clients joined into one cluster by a shared inbox can still be told apart. Two sides are different clients when their known values differ on a dimension (relay route, user agent, network, header set or encoding style) and they share no user agent, network or header set.

**Artifacts.** A record names an artifact by string only: an inbox a linking `exfil.*` rule matched, a gist id, a pastebin or rentry id, a Hugging Face Space, or a subdomain of a static-site host (`pages.dev`, `vercel.app`, `netlify.app`, `workers.dev`, `github.io` and similar). An inbox is written to, unless the record reads it back (a webhook.site `token/` URL, an ntfy subscription path). Any other artifact is fetched when it is the first host the record reaches past relays and carriers, and written to when the record names it as a destination. An artifact named by more than 10 runs is common and draws no edge.

The kinds and their thresholds:

- **S1 shared sink.** Two strands writing one artifact that differ on at least two dimensions; moderate at three. A one-record strand beside others is left out.
- **S2 hand-off.** A run writes an artifact and another run fetches it later. Strong when the fetch comes within an hour and the two are different clients, moderate otherwise; never within one cluster by one client.
- **S3 synchronized start.** Two runs of different-client clusters in lockstep: at one offset up to `swarm.lockstep_max_offset_secs` (120 seconds) either way, at least `swarm.lockstep_min_events` (4) requests of the shorter run, and `swarm.lockstep_min_share` (60%) of them, each have a request of the other within `swarm.lockstep_tolerance_secs` (3 seconds). A run's requests are its members' and the unflagged records its clients (user agent, network, header set) sent within its span; capture times never count. See *Lockstep chance* after this list. Moderate with twice the minimum lined up and the clients differing on a known dimension; weak otherwise.
- **S4 role sequence.** A run with no attack hits on at least 3 hosts, then a different-client run with attack (`exploit`) hits starting within 6 hours of its end, on at least 3 of the same hosts, Jaccard at least 0.5, and at least 80% of them attacked after they were read. Chance: Poisson with mean `|read| × |attacked| / all target hosts`; kept at 1% or less. Every reading run and different-client attacking run starting in its window is a test. Moderate at Jaccard 0.7 with every host in order.
- **S5 disjoint partition.** Runs of different clusters starting within 10 minutes, each with at least 3 hosts in one family (the last two labels). Two tests, the structured one first:
  - *Structured*: the runs' hosts in the family share none and split their sorted union (as text, or with numbers read as numbers) into a stride, every k-th host to one run, or into contiguous blocks. The chance is the number of stride and block splits with these part sizes, times the two host orders, over the multinomial count of all splits with them; kept at 1% or less, with an edge for each pair of the runs. Moderate when the clients differ on a known dimension, weak otherwise.
  - *Random draw*: two runs sharing at most a tenth of the smaller set. Chance of so little overlap if hosts were drawn from the family's hosts in the analysis; kept at 5% or less. Always weak. The family's hosts are those the runs read, so a complete sharding of a family never passes this test; the structured one finds it.

  Each group of runs the structured test splits and each pair the random draw reads is a test. One scheduler sharding a list does the same, so S5 alone is a fleet signal.
- **S6 dispatch star.** A cluster that at least `swarm.dispatch_min_followers` (2) different-client clusters each trail at their own lag, as a planner dispatching workers ([`dispatch.rs`](../crates/sc-core/src/swarm/edges/dispatch.rs)). See *Dispatch stars* after this list. An edge joins the leader to each follower, `a` leading. Moderate when every follower coincides on at least twice `co_activity.min_coincidences` and differs from the leader on a known dimension; weak otherwise.

**Dispatch stars.** Co-activity reads two clusters busy together without a direction; S6 reads it. Each cluster's request and submit times, its runs' unflagged requests by the same clients included, fall into `co_activity` bins, crowded bins left out as there. Every ordered pair of different-client clusters within reach is read at signed lags, from one bin before to `co_activity.max_lag_bins` after; lag `l` counts the leader's active bins with follower activity in bin `b + l` or the next. A follower trails at its best lag when that lag is zero or more and reads more coincidences than its mirror, the follower before the leader.

A follower's own chance is co-activity's two models at that lag, a leader on clock hours weighted down as there, and must be at most `swarm.dispatch_pair_max_chance` (5%) with at least `co_activity.min_coincidences` coincidences. Followers are taken most unlikely first, each of a client no other follower shares, and each pair of followers must have its own best lag within `swarm.dispatch_lag_tolerance_bins` (1) of the difference of their lags to the leader.

The star's chance is the product chance of its followers' chances (Fisher's method), each first corrected for the leader's candidate followers (Sidak), times the star's runs, any of which could have been read as its leader; kept at `swarm.dispatch_max_chance` (1%). Every cluster with at least two candidate followers is a test. One upstream trigger (a feed item, a news alert, a scheduled post) sends unrelated agents after it at their own lags in the same way, and the quickest reads as the leader; requiring followers of different clients does not exclude that, since a trigger's audience is many clients, so a star is weighed with what the leader's requests show.

**Multiplicity.** S3 to S6 each count the tests they read in one analysis, and keep an edge only when it also survives a Benjamini-Hochberg cut at `swarm.fdr` (5%) over them; each such edge states the tests read (`tested`) and the pairs that unlikely expected among them. S1 and S2 have no chance model and no cut.

**Lockstep chance.** Two models, and the larger chance is the edge's. Placement: the shorter run placed rigidly at random over the analysis span (the first to the last request of all runs with enough requests), the chance that some offset within reach lines up as many requests. Own gaps: the shorter run's start kept and its own gaps between requests permuted `swarm.lockstep_permutations` (199) times with a seed taken from the two runs, continued to `swarm.lockstep_max_permutations` (1999) in all while none lines up as well, the share of permutations lining up as many, counting the real order. Every pair of different-client runs within reach of each other is a test.

Two jobs that start together and send at a steady rate line up under every permutation, so a scheduler gets no other allowance and a start on the clock hour is neither discounted nor excused. Kept at `swarm.lockstep_max_chance` (1%) or less; the permutations make the smallest chance `1 / 2000`, which a false-discovery cut over many pairs can still reach. At tool pace (gaps of a second or two) the permutations line up as well as the real order within the tolerance, so S3 does not fire there.

At most 200 edges are kept. Internal and provider reports list those touching the report's clusters (a provider report only those between two of them) under *Possible interaction (SC-T9)*, details defanged. Affected-operator reports and notices do not.

## Coordinated accounts on public platforms

Agent swarms also act through accounts: near-identical issues, comments and vulnerability reports from fresh accounts, repositories, packages and Spaces created with templated names, stars and forks farmed onto one repository, test edits to wiki sandboxes, many at once. [`platform`](../crates/sc-core/src/platform/mod.rs) groups such public actions into **platform swarm candidates**, separately from the record analysis. A candidate is a hint for the admin; it never joins a cluster, scores a record or makes a fleet. The method is [SC-FM 5.15](manual/05-linking.md#fm-515-coordinated-accounts-on-public-platforms).

**What is kept.** The [collectors](../crates/sc-collect/src/platform.rs) read:

- GH Archive events: issues, pull requests and discussions opened; issue, review and commit comments and reviews; releases published; wiki pages edited; repositories created, starred and forked;
- package registries: npm search results, PyPI's newest-projects feed, the Go module index, NuGet's catalog, Packagist's change feed, and RubyGems' and crates.io's newest listings ([`registries.rs`](../crates/sc-collect/src/registries.rs));
- code hosts beside GitHub: GitLab.com's and Codeberg's newest public projects, as repositories created ([`forges.rs`](../crates/sc-collect/src/forges.rs));
- the Hugging Face Hub's newest Spaces, models or datasets;
- edits on Wikimedia wikis from EventStreams ([`wikimedia.rs`](../crates/sc-collect/src/wikimedia.rs));
- Hacker News stories and comments ([`hackernews.rs`](../crates/sc-collect/src/hackernews.rs));
- Bluesky posts from Jetstream, a sampled stretch of the newest half hour each run ([`bluesky.rs`](../crates/sc-collect/src/bluesky.rs)); a reply targets its thread's root post, whose author is the target's owner;
- CVE records and security advisories from the GitHub Advisory Database or the CVE List ([`cve.rs`](../crates/sc-collect/src/cve.rs)), each targeting the first source repository its references name (`owner/repo`), else the vendor's host; the account is the credited finder where one is credited. Reference URLs are matched as text, never fetched.

Each event keeps its id, time, target and public link, plus:

- the account as a keyed hash of its id or login, never the login itself (on a wiki, of the global account name, since local user ids differ from wiki to wiki; on Go, of the module path's owner; on Packagist, of the vendor; on RubyGems, of the gemspec's author string; on crates.io, of the declared repository's host and owner; on GitLab.com, of the project's top-level namespace; on Codeberg, of the owner's login. NuGet's catalog and PyPI's feeds name no one, so their groups are floods);
- on GitHub, the account id divided by 1000 (`actor_rank`): ids rise with account creation, so a rank near the newest seen marks a new account without identifying it; on a wiki, the account's registration time in units of 864 seconds, so a thousand ranks is ten days, and a first-edit flag from the account's edit count; on Hacker News, the account's creation time in the same units, looked up from its profile only for authors whose text a group could form around (a shared template or near-duplicate band with another author, or residue); on Bluesky, the same from the PLC directory's first operation for the account's DID; on Codeberg, the same from the owner's account creation time, which the listing carries. GitLab's listing gives no account age. GitHub's
 event payloads no longer carry the author association, so no GitHub event has a first-timer flag;
- the text (title and body, a description or a summary) as a sketch: lower-cased words with URLs, addresses, mentions, paths, numbers, hex strings, mixed letter-and-digit tokens and the target's and actor's own names replaced by slots (`<url>`, `<user>`, `<num>` and so on); a 32-value MinHash signature over word 3-shingles; a hash of the first 48 slotted words (the template); the first 160 characters of slotted text; and the residue rules that fire on the raw text;
- for a created item, its name as a template (`reach-check-<num>`), only when the name keeps a word of three letters or more and has a slot; for a wiki edit, the page title the same way, with the editor's own name as `<user>` (`user:<user>/sandbox`);
- coding-harness self-identification on the raw text: the footers, trailers and session links harnesses add (`Generated with Claude Code`, a `Co-Authored-By` trailer, a Codex task, Devin session or Jules task link).

GitHub's event payloads are trimmed: a pull request opened carries its number and refs, no title or body, and a push carries no commits. A pull request opened is kept without text, as are stars and forks, so these group by their target instead.

Automation accounts are dropped by login before anything is kept ([`automation.rs`](../crates/sc-core/src/platform/automation.rs)): GitHub Apps (`[bot]`), logins ending in `-bot`, `_bot` or `-robot`, and a list of dependency, CI, release, translation and classroom accounts; on wikis, bot-flagged accounts. An App acts only where a repository owner installed it. The coding-agent Apps [`declared-agents.toml`](../declared-agents.toml) names (`github_app`) are told apart first: their events are tallied by product in the digest, not grouped and not dropped unseen. An undeclared App whose login carries one of those products' names (`claude-fleet[bot]`) is listed as a spoofing lead by login: any App picks its own name, so the login claims a product its provider did not ship.

**Grouping.** Events on one platform join when their templates are equal (at least 8 words), when their MinHash signatures agree in any of 8 bands of 4 values and the full signatures estimate a similarity of at least 0.6, when created items share a name template, or when text-less events of one kind (stars, forks, pull requests opened) act on the same target. Groups are the connected components.

**Chance.** For each group with at least 3 accounts (or, where the source names no account, at least 5 events):

- **Burst.** Each account's first event in the group is a point. The densest 15-minute window holds `m` of the `k` points. With `k` points placed at random over `S`, the clock hours read in full (those holding at least a tenth of the busiest hour's events, so hours that hold only carried events do not count) plus the group's own hours, one window expects `k × 900 / S`, and the chance of a window this dense anywhere is `(S / 900) × P(Poisson ≥ m)`. A window starting within 2 minutes of a clock hour counts a quarter of its points.
- **New accounts.** The share of all accounts in the window that are new is the base rate `q`. Each of the group's accounts with age data is weighed against the accounts first seen in the same clock hour, the group's own left out: their new share, shrunk toward `q` as if five more accounts at `q` were seen then. The chance of at least `n` new among the group's accounts is the Poisson-binomial tail over those rates. A wave of new accounts in some hours (a launch, a news story) raises every group's rate in those hours, so it is not counted once in the burst and again in the accounts.
- **One test.** Given the hours the group's accounts appeared in, the account-age chance is independent of the burst chance, so the two are combined as one: their product `x` is weighed as `x (1 - ln x)`, the chance of a product that small from two independent chances.

A group is reported when that chance is at most 1% and it survives a Benjamini-Hochberg cut at 5% over every group weighed on the platform (each states the groups weighed and the groups that unlikely expected among them), or when at least half its text members carry residue. A text-less group, and a group of wiki edits, also needs its burst chance at most 1% on its own: new editors' sandboxes and a new project's first stars come from new accounts by nature, so account age alone says nothing there. It is moderate when the combined chance is at most 0.01% and two of burst, new accounts, residue and target overlap (one target hit by 3 accounts, across several owners) stand; otherwise weak. There is no strong grade.

**Residue.** The bundled rules whose patterns mean the same in prose run on each line of the raw text: `marker.placeholder`, `marker.tool_call_markup`, `marker.chat_opener` and the generation-loop check. The Markdown rules do not: Markdown is how people write there. Five text-only shapes are added ([`residue.rs`](../crates/sc-core/src/platform/residue.rs)): an AI disclaimer, a knowledge-cutoff remark, a chat reply's opener, an `[Insert ...]` slot and "regenerate response". Each is weak alone. Harness self-identification is kept apart (`selfid.*`): a candidate lists it as weak context, and it never makes a group residue-heavy, since people run these harnesses for their own work every day and anyone can paste the footer.

**Suppressed and dropped.** A group whose template matches a benign kind (dependency update, translation sync, release automation, contribution drive, classroom or course, declared scanner, platform default text) is listed as suppressed with its kind, as is a text-less group on a practice repository built for first-time contributors. A burst on one owner's repositories by established accounts is counted below threshold: an outage, a release or a linked discussion looks the same. Each candidate lists what is left to rule out (on the hour, one owner, one target, no new account, no account data, a span over a day).

**Labels.** Reference sources label targets rather than add events: OSV's malicious-package records (`MAL-` ids) name packages later found malicious ([`osv.rs`](../crates/sc-collect/src/osv.rs)), and English Wikipedia's monthly categories of articles editors tagged as containing suspected AI-generated text name pages ([`wikimedia.rs`](../crates/sc-collect/src/wikimedia.rs)). Labels are kept for `label_days`. A candidate whose members published a labelled package lists the label and the records behind it. A label says what a target was, never who acted, and it changes neither a candidate's chance nor its strength.

**Identifiers.** A candidate's id is `PS-` and 8 hex digits derived from its earliest member, so it stays while that member stays and new members join under it.

## Endpoints

Flagged requests are also grouped per target host: hits, first and last seen, attack payloads, the clusters involved, and whether the hits are ongoing or historical. `swarmchase endpoints` prints this table, and a report to an affected operator carries it for that operator's hosts. In a case, the admin classifies each endpoint ([case files](reference/cases.md#what-casetoml-holds)).

## Attribution levels and the naming gate

Every claim about who is behind a cluster states the strongest class of evidence it rests on. The ladder, weakest first, is in [`attribution.rs`](../crates/sc-core/src/attribution.rs):

1. **Self-identification** (`self_id`): a model or vendor name in a request. Agents misreport who built them, and anyone can submit `?agent=claude` to a public scanner.
2. **Hosting network** (`hosting_asn`): the ASN a record came from. It names a host. It names a developer only when the network belongs to the same company the requests name themselves after.
3. **Identifiers shared with a confirmed incident** (`shared_identifiers`): inbox IDs or tags.
4. **Infrastructure owned by the provider** (`provider_infrastructure`).
5. **Confirmation by the provider** (`provider_confirmed`).

Levels 1 and 2 come from the records. Levels 3 to 5 come from case work and are added as claims (`swarmchase case claim`, or `--claims` on `report`).

**The naming gate.** A report or notice names a developer only at or above the level set for the case (`--min-named`, or `case set --min-named`). The default is `shared_identifiers`. Whatever is set, a developer is never named on self-identification alone: the floor is the hosting level. A network operator may always be named as a host, because that is what an ASN shows. Case notes for the admin list every claim, with the evidence for each.

In a public notice, a developer below shared identifiers is named only as the party notified: what the requests say about themselves, that self-identification is the weakest evidence, that its operation, deployment or authorisation is not confirmed, and, once a send to the provider is recorded, that it was sent the full evidence. It gets no Conclusion line and stays out of the title. At `provider_infrastructure`, the Conclusion says the requests came from infrastructure the provider operates and leaves who deployed the agents as a separate question ([policies](policies.md#naming)).

**Layers, labels and tags.** Each claim belongs to one of four layers ([FM-7.1](manual/07-attribution.md#fm-71-four-layers)): `developer`, `host`, `harness` or `model_family` (`case claim --layer`). The code derives its label from the layer and the evidence: Confirmed, Suspected, Possible or Unattributed ([FM-7.7](manual/07-attribution.md#fm-77-attribution-labels)). Each claim also carries a tag, given with `--tag` or derived: a network seen in the records is Observed, a provider's confirmation or documented infrastructure is Documented, and the rest is Inference.

Reports list each claim with its layer, label and tag, and add a Conclusion line for each developer named through the gate, with the strongest likelihood word its label allows. Harness and model-family candidates appear ranked in private reports and never in public. A model-family claim needs the method's held-out accuracy and corpus size, or it is refused.

## Declared agent identity

Agent products declare themselves in the user agent, and some sign their requests (Web Bot Auth). [`identity/`](../crates/sc-core/src/identity/mod.rs) reads each record's declaration against the address-range files and signing keys the provider publishes, held from the addresses in [`declared-agents.toml`](../declared-agents.toml) ([FM-7.11](manual/07-attribution.md#fm-711-declared-agent-identity), [FM-7.13](manual/07-attribution.md#fm-713-published-address-ranges)). Each record gets one class, the strongest that holds:

| Class | What holds |
|---|---|
| `signature_verified` | An Ed25519 Web Bot Auth signature verifies, in time, with a key from a held directory. |
| `ip_verified` | A declared product, from an address in its provider's range file. |
| `in_range` | No declaration and no signature, from an address in a held range file. |
| `spoofed` | A declared product from outside a range file the provider presents as complete, with no signature or a failed one. |
| `signature_failed` | A signature that is malformed, out of time at the record's timestamp, or does not verify. |
| `signature_present` | A signature that cannot be checked: no directory held for its signer, a rotated key, an unsupported algorithm. |
| `claimed` | A declared product and nothing to check it against. |

The analysis commands give each cluster an identity line (`identity` in the analysis JSON). It is descriptive: it changes no score, tier or link. The three verified classes reach `provider_infrastructure` evidence; case notes print the developer claim they support as a `case claim` command, and nothing is claimed until the admin runs it. On the agent grade, a verified identity is a signal for L1 (`verified_platform`): it shows the provider's platform sent the request, which a user directing a fetch tool also produces, so it lifts L0 to L1 and nothing higher. A spoofed identity is a counter-signal (`spoofed_identity`). Reports to affected operators and public notices carry none of it. Without range files held, a user agent stays a claim and nothing is called spoofed.

## Agent likelihood

A tier says attack payloads were present. It does not say an AI agent sent them: a penetration tester or a conventional scanner sending the same payloads through the same relays leaves the same records. [`agentness.rs`](../crates/sc-core/src/agentness.rs) grades each cluster on a separate ladder ([FM-7.10](manual/07-attribution.md#fm-710-agent-likelihood)). The grade is set by the strongest **combination** of signals the cluster shows, never by a sum: many weak signals of one rung do not reach the next.

| Grade | Name | Needs |
|---|---|---|
| L0 | payloads only | Nothing beyond the rules' hits. |
| L1 | self-described | A vendor or model name (`self_id` rules), or an agent test tag (`marker.uq_tags`, `marker.test_tag`, `marker.oai_tag`). Anyone can write either, so reports word it like L0. |
| L2 | model-written | One of: residue (any other artifact rule of kind `agent_marker`), prose, fabricated identifiers, repeated cut lengths, stale knowledge, a stale-date pattern. |
| L3 | adaptive | L2, and a retry after an error, a route escalation, or a probe chain at model pace. |
| L4 | agent likely | L3, and retries at tool pace (faster than a person reads), a fixed fan-out width, cross-service fan-out with no auto-submitter around it, a round-the-clock rhythm, per-fetch robots or a rate ceiling. |
| L5 | documented | Never computed. Only the admin's case decision sets it (`case grade`). |

A flagged record in no cluster is graded the same way from its own hits alone: self-description gives L1 and model-output residue L2. One record shows no pace, retries or rhythm, so it never reaches L3.

Prose counts when a cluster has at least two prose values, or one in a language other than its target's country domain: one search in plain words is ordinary.

**Fetch-tool habits.** Two L4 signals read one client's requests (user agent and network) in each of the cluster's runs, its unflagged requests included as recon preambles read them, from request and submit times only (the `[agentness]` settings):

- **Per-fetch robots**: at least `robots_min_share` (80%) of at least `robots_min_pages` (3) page requests each come within `robots_window_secs` (2 seconds) after a `/robots.txt` request on the same host, with at least `robots_min_repeats` (2) of them on one host. A polite crawler reads robots.txt once per host per session; the Model Context Protocol reference fetch server, driven by a model, reads it before every page and keeps no cache. Chance: the Poisson-binomial tail of so many preceded pages with the client's robots requests placed at random over its span; kept at `robots_max_chance` (1%). Reports call it an uncached robots-respecting fetch tool, and name the MCP fetch server only when `header.mcp_fetch_ua` fires on the same client.
- **Rate ceiling**: the most requests any `rate_window_secs` (60 second) window holds is at least `rate_min_cap` (5), and at least `rate_min_saturated` (3) windows, counted without overlap, hold exactly that many with the next request within `rate_press_secs` (60 seconds) of the window's end: a client-side limiter (Gemini CLI's web fetch allows 10 per minute) holding back a client that wants more. Chance: the run's own gaps permuted `rate_permutations` (199) times with a seed from the run, continued to `rate_max_permutations` (1999) while none does as well, the share that keep the same ceiling and at least as many such windows; kept at `rate_max_chance` (0.1%), which no run reaches when any of the first permutations does as well.

A steady pace permutes into itself and a cron job's batches have nothing pressing after them, so neither makes a rate ceiling, and a run with a 429 response is not read: the server limited it. A scanning script with its own limiter or a robots-respecting fetch library a person drives shows the same, which is why both count only above L3. Adaptive and pace signals are read only from probe chains and escalations timed by request or submit times; a chain or escalation timed by captures is skipped, as for pace ([timing](#timing)).

**Caps.** Some evidence holds a grade down:

- a cluster whose timestamps are all archive captures stops at L2, because pace, retries and rhythm cannot be read from captures;
- a working-hours rhythm with slow pace (no probe chain faster than slow pace, and a median gap above `chains.model_pace_max_secs`) stops at L2: possibly a person working with a model's help;
- any other working-hours rhythm stops at L3, since an unattended fleet need not keep office hours.

**Counter-signals** are listed beside the signals and never move the grade: declared testing, benchmark or practice targets, a declared agent product from outside its provider's published ranges ([declared agent identity](#declared-agent-identity)), and a probe chain at tool pace with no change after errors, which is how a scanner runs its list. An auto-submitter (cross-service fan-out on ordinary links around the cluster too) is listed as a counter-signal in place of the cross-service signal, which then does not count. A working-hours rhythm is listed as a counter-signal too, besides capping.

The grade is descriptive. It changes no score, tier or link, and it has no held-out measurement. Internal and provider reports carry a section, *Why we think this is an agent*, listing each cluster's grade, signals, counter-signals and caps, and the case decision when there is one. A provider report leaves out the decision's basis and the declared-testing counter-signal, which stay in case notes like the declaration itself. Reports to affected operators carry none of it. A public notice never prints a grade: when the strongest grade (or the case decision) is L1 or below, its summary adds that the payloads alone do not show what sent them.

`swarmchase eval` prints the grade against each record's actor ([evaluation](reference/evaluation.md#agent-grades-by-actor)). The committed set's synthetic controls show the ladder's known limit: a person pasting a chatbot's payloads into an intercepting proxy, and retrying after errors, reaches L3. The rungs are ordered by kind of evidence, not by measured likelihood, so a report reads the grade with the hypotheses it leaves open ([FM-7.12](manual/07-attribution.md#fm-712-competing-hypotheses)).

## Misalignment and scope

A tier measures payloads and tool use, and the grade measures how likely an agent is. Neither says the agent went beyond its task. The method makes that a third finding, the scope assessment ([SC-FM 15](manual/15-misalignment.md)): the reviewer states the cluster's task class from its ordinary requests, classifies each target (public content, interactive, access-controlled, sensitive, third-party channel, benchmark), and runs seven tests, from off-task targets (S1, SC-T8) and control circumvention (S2) to coordination (S7). Tool use alone, relays and echo-service programs included, fails no test. A cluster is called misaligned only when an agent is present and a test fails with its innocent explanation rejected.

The toolkit runs the assessment as a pass and records it on each cluster (`Cluster.scope`): the task class, the target classes, the S1–S7 tests with their evidence records, and the finding. Internal and provider reports show it in one line. The pass is a suggestion: the admin decides the incident from it and records the finding (`case scope`, [cases](reference/cases.md#scope-finding)), which is what notices state.

Reports and notices describe suspected AI agent activity. The word "misaligned" in any form appears in one only when the case records an admin finding of scope exceeded for the clusters it covers and an admin agent grade of L3 or higher (`case grade`); the notice front matter carries both, and the notice linter rejects the word without them ([notices](reference/notices.md#lint)).

## Evaluation

`swarmchase eval` scores the rules against labelled records ([`eval.rs`](../crates/sc-core/src/eval.rs)). It reports precision and recall at the significant tier and at suggestive-or-above, precision per rule with its hard negatives, recall per class of activity and per tactic, and false positives per benign class. Every proportion carries a 95% Wilson interval. Records labelled with their true run also measure linking: B-cubed precision and recall, false merges and split runs, reported but not gated.

Records labelled with their true fleet measure the soft links and candidate fleets as proposed cluster pairs, with precision per kind, also reported and not gated. The seeded simulator measures the same against generated ground truth, and the gate holds its edge, soft-link and candidate-fleet precision and a ceiling on what its background-only scenarios draw ([simulator bounds](reference/evaluation.md#simulator-bounds)). Two reviewers' labels give Cohen's κ (`review --stats`). Details are in [evaluation](reference/evaluation.md). With no embargo, a false positive is published within a day of the admin acting on it, so precision matters most.

**The committed set** is in [`samples/eval/`](../samples/eval/README.md). It holds records reconstructed from request patterns quoted in published Transluce reports, synthetic records for the model-output residue rules, and benign records, including hard negatives built to trip the rules: SQL words in search text, JSON in ordinary API queries, unrendered front-end templates, reading `claude.ai` through a relay. CI runs [`eval-gate.sh`](../scripts/ci/eval-gate.sh) on it and fails when precision or recall, or the lower end of a precision interval, falls below the floors in that script, or when a rule has no labelled positive and is not on the coverage allow-list. The floors only go up.

**What it is not.** The rules were tuned on this set, and most of it is synthetic. Its numbers are a regression floor, not an estimate of precision on real traffic. A number worth quoting needs held-out data, and the words a public notice may use follow from that measurement ([FM-9.12](manual/09-evaluation.md#fm-912-calibrated-public-language)).

**The held-out measurement.** Transluce's [urlquery dataset](https://transluce.org/agent-activity) labels tens of thousands of urlquery reports as significant, suggestive or benign background. It ships report IDs and labels, not report contents, and urlquery's terms forbid redistributing the contents. To measure against it, anyone with a urlquery API key fetches the reports into a gitignored directory with `swarmchase collect urlquery-reports --sample N` and runs `eval` with Transluce's labels and our [label overrides](../samples/eval/overrides/transluce-labels.ndjson), each override with its reason. The steps are in [samples/eval/README.md](../samples/eval/README.md#held-out-evaluation-on-the-transluce-release).

Read the per-class table, not just the overall recall: Transluce labelled some reports from context a single record cannot show. The benign controls are too few to estimate precision on their own, so add a sample of unflagged reports from a generic urlquery search, labelled benign.

Records the admin reviews with `swarmchase review` are saved with their labels and can be measured the same way. That file stays in the data directory and is never committed.

## Known limits and false-positive traps

**What the records cover.** Public scan services and web archives see a fraction of agent activity. Private and account-linked scans are invisible. A record shows that a URL was submitted or captured. It does not show that a request reached the target or succeeded. Reports say so.

**Archive timestamps.** A Wayback or Arquivo timestamp is when the archive captured the URL. That may be the agent's own request or a later crawl of a link to it. Cadence on archive records describes captures, not necessarily the agent, and pace, fan-out and rhythm skip them.

**Humans look the same.** The rules detect agent-like activity. A security researcher, a penetration tester or a conventional scanner sending the same payloads through the same services produces the same records. A significant tier means attack payloads were present, not that an AI agent sent them. Context, rhythm, residue and case work separate the two; the [agent grade](#agent-likelihood) states which of them a cluster shows.

**A tier is not misalignment.** A benign data task done with fetch programs through an echo service grades suggestive, and significant once an independent indicator such as a run tag comes with the program. Whether activity was out of scope is a separate finding ([FM-14.21](manual/14-limits.md#fm-1421-a-tier-is-not-misalignment)).

**Model-output residue from people.** A person who pastes a chatbot answer into a scan form leaves the same Markdown, placeholders and JSON. This is why residue rules carry low weights and never link.

**Accounts acting alike are not always one operator.** A platform swarm candidate rests on shape and timing. Contribution drives, coursework, an outage, a popular tutorial and scheduled jobs make many accounts post alike at once, and the benign templates cover only the common ones. The account-age rank is GitHub's id order, a proxy: an old account bought or revived reads as established. The GH Archive pass reads every hour since the last run unless the budget or a backlog cuts it short, and the digest says which; events whose payload carries no text group only by name or by target, or not at all. Wiki account ages come from registration times, which a dormant account does not refresh. A candidate is reviewed by reading its events on the platform, never by contacting its accounts.

**Self-identification is cheap.** Anyone can type a vendor name into a URL. It never names a developer.

**The ASN on a urlquery record describes the target, not the sender.** urlquery records the IP and ASN where its scanner reached the submitted URL's host. For a URL submitted through a relay, that is often the relay's hosting network. The attribution step reads a record's ASN as the network the requests came from. Treat a hosting-network claim that rests on urlquery records with care, and check which records it comes from before relying on it.

**Popular targets read through relays.** A shared relay or cache buster alone never links by timing, but two unrelated people reading the same popular page within `linking.window_secs`, each with the same non-context indicator (a run tag parameter, a residue rule), share a rule and a target host and will be linked. Check a cluster's link features and runs before treating it as one operator.

**Planted records.** Scan services and archives take any URL from anyone, and registries, GitHub and certificate logs publish what their users name. A person can submit records to be found: to start a false incident, to attach their records to a real cluster, or to point attribution at someone else. A planted record joins a cluster only through a shared identifier, a shared non-context rule within the window, or a probe chain, and cannot re-key it. A cluster's provenance, corroboration and plant signals ([above](#provenance-and-plant-review)) are prompts to check this; a single-source cluster of submitted records is the usual case, not proof of a plant.

**Copied tags.** A tag quoted in a published report (such as `CHATGPTTEST1`) can be reused by anyone who read it. Tags listed in `linking.published_tags` never link. A quoted tag missing from that list, reused by unrelated operators within the feature window on no more than `linking.feature_max_hosts` hosts, still merges their clusters; add it to the list when a report quotes it. A listed tag on a cluster's member is shown as a burned identifier under plant review. Generic parameter names in `strong_params` (`tag`, `run`, `session`) can carry the same value by coincidence.

**Corroboration across a cluster.** A cluster can be one tier above its strongest member when two members bring different kinds of evidence. That rests on the link between them being right. The cluster's member tiers and rules are listed so a reader can see how it got there.

**Heuristic decoding.** Base64 detection and unwrapping are heuristics. Truncated URLs decode partly. An opaque ID that happens to decode to text can, rarely, become a layer.

**Date and rhythm assumptions.** The offset inference assumes date tags mean "today" on the operator's clock. The rhythm guess assumes a working day centred on 13:00 local time. A fleet scheduled to a fixed UTC window, or an operator who keeps unusual hours, gives a misleading guess. Both are labelled as hints in reports.

**Headers are rarely recorded.** Most public records carry no request headers, and none keep their order. Header rules mostly apply to operator logs and the few sources that keep headers.

**Rules change.** A new rules version can move a record between tiers. Each case pins the rules it was opened with, and its reports, notices and evidence bundles use that version. `swarmchase case rules <id>` shows which records would change tier under the current rules. An evidence bundle records the rules version, and `swarmchase case verify` re-runs the analysis to show the tiers follow from the records (see [for-operators.md](guides/for-operators.md#verify-an-evidence-bundle)).
