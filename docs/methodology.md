# Methodology

This page describes how swarmchasing turns public records into the claims in a report or notice. It is written for three readers: security teams at AI providers who receive a report, operators of affected sites, and researchers checking the method. Each section links to the code that does the work. Where a number is a setting, the page names the setting so you can check its current value.

The short version: the toolkit reads public indexes, redacts secrets, unwraps each recorded URL, matches indicator rules, grades each record, links flagged records into clusters, and describes their timing. The admin reviews the result, decides what is true, and sends and publishes. No step is automatic past drafting.

Policies (what we collect, how we name, what notices withhold) are in [policies.md](policies.md). Guidance for operators is in [for-operators.md](guides/for-operators.md).

This page is the toolkit's implementation. The method as a standard, which other groups can apply with their own tools and cite by section, is the [Swarmchasing Field Manual](manual/README.md).

## Collection

The collectors are in [`sc-collect`](../crates/sc-collect/src/lib.rs). They read:

| Source | What is read | Used for |
|---|---|---|
| Wayback Machine CDX | Index rows: capture time, captured URL, status, digest | Scheduled watch, per-case pulls |
| Arquivo.pt CDX | Index rows, as above | Per-case pulls only; its index lags too far for the watch window |
| Common Crawl CDX | Index rows of one crawl, never WARC content | Scheduled watch, per-case pulls |
| Memento timemaps | One URL's captures across archives | Per-case pulls |
| urlquery.net | Search results and reports by ID (needs an API key) | Scheduled watch; the held-out evaluation |
| urlscan.io | Public search results | Per-case lookups only; its terms need permission for systematic retrieval |
| GH Archive | Public GitHub events whose repository name or URLs match | Scheduled watch, as leads for review |
| npm, PyPI | Package names, versions and publish times matching run tags | Scheduled watch, as leads for review |
| CT logs, crt.sh | Certificate Transparency entries | Watch sample of one log (relay look-alikes); case work (`swarmchase certs`) |
| security.txt, RDAP | The affected organisation's published security contact, or its registrar's abuse address | Finding who to report to |

The scheduled watch pulls the sources in [`watchlist.toml`](../watchlist.toml). Each source there carries a rationale: which agent behaviour it catches, which rule it feeds, and what its noise looks like. The same file lists what is deliberately not watched, such as callback channels.

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

A rule's target says what it reads: the host of each layer (suffix match), each layer's decoded text, parameter names, parameter values, request headers, the user agent, or the final URL. Patterns are case-insensitive regular expressions unless a rule says otherwise. A parameter-value rule can also name a `check`, a test its matches must pass for what a regular expression cannot say: `repeated_token` ([`prose.rs`](../crates/sc-core/src/prose.rs)) wants a word of three characters or more, or a phrase of two or three words, repeated five or more times in a row. Short refrains (`na na na`) and one long run of a letter do not pass.

**Scoring.** Each rule counts at most once per record, whatever layer it matched in. A record's score is the sum of the weights of the distinct rules that fired. Weights are deliberately low for anything ordinary users also do: a relay is worth 1 or 2, a self-identification 1.

**Significant rules.** A rule marked `significant = true` puts a record in the top tier on its own. These are the unambiguous attack payloads (UNION SELECT, boolean and time-based SQL injection, multi-step traversal and sensitive files, XSS, template and command injection) and a small number of infrastructure fingerprints. Weaker exploit rules, such as a single traversal step or a lone quote, are not significant on their own.

**Linking rules.** A rule marked `link = true` turns its matched text into a linking feature (see [Linking](#linking-into-clusters)). Only identifiers one operator would hold are linking rules: per-user callback inboxes (webhook.site IDs, request-catcher subdomains, ntfy topics) and specific test tags. A rule that many unrelated users share scores but never links. For example, `exfil.oast_service` matches an OAST service named without an inbox subdomain; it scores like the inbox rule but does not link.

**Model-output residue.** Agents built on language models sometimes leave the model's formatting in the URL they send. The residue rules match text a model wrote around a URL: Markdown link and code syntax, unfilled placeholders, tool-call JSON and function-call markup, JSON string tails, escaped newlines, output cut off mid-escape or with an ellipsis, generation loops (one word or a phrase of up to three words repeated five or more times in a row, `marker.repeated_token`), and similar artefacts. A person pasting a chatbot answer into a scan form produces the same residue. These rules therefore carry low weights, and none of them links records.

**Tactics.** Each rule names what a match shows the agent doing, in the swarmchasing tactic vocabulary: `T1` task retrieval (relays, readers), `T2` tool escalation (carriers, programs, remote browsers), `T3` access-control circumvention (anti-bot, challenge outcomes), `T4` vulnerability probing, `T5` account or identity acquisition, `T6` credential reuse, `T7` callback or side channels, `T8` off-task targets, `T9` inter-agent coordination. A rules file naming `T8`, `T9` or any other id as a rule's tactic fails to load.

Each rule kind has a default tactic, the Field Manual's [FM-4.4](manual/04-indicators.md#fm-44-default-tactics-by-rule-kind) table; a rule on another tactic is listed with its reason in a test (`TACTIC_EXCEPTIONS` in [`rules.rs`](../crates/sc-core/src/rules.rs)). `T8` and `T9` are cluster-level judgments and never a rule's tactic. A rule marked `artifact = true` is a trace of how the agent was built, not an action: model-output residue, run tags, self-identification, client headers, sandbox hosts.

Every hit carries its rule's tactic and artifact flag, and each cluster counts hits per tactic (`tactics`) and members with an artifact hit (`artifacts`). Case notes and provider reports print the artifact count per cluster; affected-operator reports and public notices do not. Tactics describe; they never change a score.

**ASN hints.** The `[[asn]]` table maps autonomous system numbers to the organisations that run them. It is context for attribution, never proof.

## Tiers

Each record is graded by [`analyze.rs`](../crates/sc-core/src/analyze/mod.rs):

- **significant:** a significant rule fired, or the score reached `thresholds.significant`;
- **suggestive:** the score reached `thresholds.suggestive`;
- **noise:** anything else, including records with a score above zero.

Both thresholds are set in the rules file. A tier says the record looks like agent activity under the rules. It does not say who sent it.

**One relay hit is never enough.** People use relays, CORS proxies and echo services every day. No relay rule weighs as much as the suggestive threshold, so a single relay hit never flags a record. It needs another indicator first: a payload, a tag, a callback channel, a program, or residue.

A cluster gets its own tier: the highest tier among its members, raised one step only by corroboration. A suggestive cluster becomes significant when two of its suggestive-or-above members each carry a kind of evidence the other lacks: one record shows a callback channel and model residue, another the same channel and a carrier program. Context kinds, which ordinary clients produce too, do not count towards that: `relay`, `cache_buster`, `self_id`, `header` and `outcome`. A cluster of noise records stays noise, and weak rules collected across many members never add up to a higher tier.

The cluster's `score`, the sum of the weights of the distinct rules seen in any member, is listed for reference and does not set the tier. Code: `cluster_tier` in [`hints.rs`](../crates/sc-core/src/analyze/hints.rs).

## Linking into clusters

Only records with a score above zero are linked. Ordinary traffic to the same host is never swept into a cluster. Three things join two flagged records:

1. **A shared linking feature.** Two records that carry the same matched text from a linking rule, or the same value (three characters or more) of a parameter named in `linking.strong_params` (run tags such as `uqtag`, `tok`, `run`, `session`). The link is bounded in time: a feature's records, in time order, are joined while each is at most `linking.feature_link_window_secs` (3 days) after the last, and a longer gap starts a new group. The same inbox used again months later starts a new cluster. Records without a timestamp join the feature's only group, or form their own when it has several.

   A feature can also be too common to say anything about one operator: a tag copied from a published report, or a generic parameter value. A group whose feature appears on more than `linking.feature_max_hosts` target hosts does not link, and neither does one carrying more than `linking.feature_max_share` of all records in its time span (when that span holds at least `linking.feature_share_min_records` records; the share is off by default, because in a case file one fleet can be most of the records). Such a group is listed under `common_features` in the analysis and in internal reports, with the limit it passed.

   A tag quoted in a public report is common by definition, however few hosts carry it: anyone who read the report can copy it. `linking.published_tags` lists those tags, each with its source in a comment. A feature whose value is one of them (ignoring case) never links, and its group is listed as a common feature with the reason "quoted in a public report".
2. **Close timing against the same target.** Consecutive flagged records to the same target host, at most `linking.window_secs` apart, that share at least one rule. Only request and submit times link this way (and times of unknown kind, read as requests). Archive capture times say when a crawler saved a URL, not when a client sent it, so two captures minutes apart are not joined by timing.
3. **Probe chains.** A run of requests to one host and path, each at most 5 minutes after the last (`chains.max_gap_secs`), with at least 3 distinct parameter sets (`chains.min_variants`) and at least one parameter whose value changes. This is one client trying variants of a request. The flagged requests in a chain are linked even when different rules fired on each. Code: [`chains.rs`](../crates/sc-core/src/chains.rs).

Links are transitive: if A links to B and B to C, all three form one cluster. A cluster needs at least two records. Each cluster lists the linking features its members share, so a reader can see what joined them.

Within a cluster, a gap longer than `linking.run_gap_secs` starts a new **run**.

Probe chains also carry descriptive detail that changes nothing: their **pace** and the requests in them that no rule flagged. The pace is the chain's median gap. Under 2 seconds (`chains.tool_pace_below_secs`) reads as a scanner or script. From 2 seconds to 2 minutes (`chains.model_pace_max_secs`) is consistent with a model choosing each request. Slower is a person or a model that reasons longer. Chains also count **retries after an error**: a changed request sent right after a response with status 400 or above. A scanner working through a list keeps going regardless; a model reading the error tends to change course. Both are hints, not evidence.

## Timing

[`timing.rs`](../crates/sc-core/src/timing/mod.rs) describes each cluster and the whole analysis. None of it changes a score or links records.

**What the times measure.** Each record says what its timestamp is (`ts_kind`): a request or the event a public log recorded (access and operator logs; a GH Archive event, an npm or PyPI publication, a certificate log accepting an entry), a submission to a scan service (urlquery), or an archive capture (Wayback, Arquivo.pt, Common Crawl, Memento archives). Each cluster and probe chain carries the result as `time_basis`: `request`, `submit`, `capture`, or `mixed` when capture times sit alongside the others.

Hints that read request timing (chain pace, fan-out width and the hour-of-day rhythm) never use capture times: rhythm and fan-out leave capture-time records out, and a chain timed by captures reports "capture times, not request times: pace not read". Submit times are close to request times and are used, labelled "submit times". Cadence, bursts and pauses describe whatever the times are.

**Cadence, bursts and pauses.** The median and 90th-percentile gap between records. A burst is at least `linking.burst_min` records, each within `linking.burst_gap_secs` of the last. A pause is a gap at least `linking.pause_min_secs` long and at least ten times the median gap, so a slow but steady cadence does not read as a string of pauses. The analysis also reports how many cluster runs were active at the same instant.

**Rhythm.** An hour-of-day profile, counted in distinct active clock hours rather than records, so one burst does not outweigh a day of steady activity. It needs records on at least 3 UTC days, at least 20 records and at least 12 active clock hours (`RHYTHM_MIN_*`). With enough data, the narrowest circular window of the day holding 90% of active hours is found:

- a window of at most 12 hours reads as one time zone's working day. Its middle is placed at 13:00 local time to give a UTC offset guess (`LOCAL_MIDDAY`);
- a window of 20 hours or more with normalised entropy of at least 0.85 reads as round the clock. People sleep; automated fleets need not;
- anything else is reported as unclear.

**Operator offset from date tags.** Agents sometimes put "today's" date in a URL (`archive_test=20261004`). A tag one day ahead of the UTC date, late in the UTC day, means the operator's clock is east of UTC. A tag one day behind means west. Every tagged record narrows the range of UTC offsets consistent with all of them. The analysis reports that range when the records agree, and says so when they do not. Tags more than a day from the UTC date are not "today" tags and are ignored here.

**Stale dates.** A tag at least 7 days behind the day it was seen (`STALE_MIN_DAYS`) is stale. An agent with no clock that writes "today" writes the date it believes it is, often one from its training data. A cluster's stale tags are reported as a pattern only when there are at least 3, they are at least half of all its tags, and at least 60% name one date or lag by about the same amount (`STALE_MIN_TAGS`, `STALE_AGREE_SHARE`). Tags two or more days ahead are counted separately as a wrong clock or a typo.

**Shared pauses.** Two clusters that share no identifier but go quiet together may have one scheduler, quota or operator behind them. For each pair of clusters above noise, the pauses of each are compared over the time both were active. A pair of pauses matches when their starts and their ends each fall within 120 seconds (`SHARED_PAUSE_TOLERANCE_SECS`).

Matches can happen by chance, so each pair is tested against a chance model. For every pause pair whose lengths differ by less than twice the tolerance, the chance of a match is the width of the window in which its start could fall and still match, divided by the time both clusters were active. The sum over all pause pairs is the number of matches expected by chance. The probability of seeing at least the observed number is taken from a Poisson distribution. A pair of clusters is listed only when that probability is at most 1% (`SHARED_PAUSE_MAX_CHANCE`), and either it has at least 2 matches or one matching pause is at least 3 hours long.

Pauses that start or end on a clock hour are not random under this model: unrelated cron jobs stop and start on the hour together. A match within the tolerance of a clock hour counts as a quarter of a match (`SHARED_PAUSE_CLOCK_WEIGHT`), and never qualifies on its own as a long pause.

A shared pause is a link to check by hand. It never merges clusters.

## Descriptive hints

Several features describe a cluster without changing its score, its tier or its membership:

- **Encodings** ([`fingerprint.rs`](../crates/sc-core/src/fingerprint.rs)). How each URL was written: spaces as `%20` or `+`, hex case in escapes, double encoding, unescaped characters, trailing `&`, empty values, sorted parameter names. Only URLs that show at least one such choice are counted.
- **Recon preambles** ([`paths.rs`](../crates/sc-core/src/paths.rs)). The same opening sequence of well-known files (`/.well-known/security.txt`, `/.env`, `/llms.txt` and similar) on 3 or more hosts. An opening made only of what polite crawlers fetch (`/robots.txt`, `/sitemap.xml`) does not count. The path lists and thresholds are the `[paths]` settings. Unflagged requests on the cluster's hosts during its span are read too, because a recon opening is rarely flagged itself.
- **Unusual path sets.** The same set of at least 3 uncommon paths requested on 3 or more hosts (Jaccard similarity at least 0.6). Records rarely say whether a path existed, so this is "the same unusual path set", not "the same invented paths". Where records carry a status, 404 and 410 responses are counted.
- **Fabricated identifiers.** UUID-shaped values no generator produces (wrong version or variant digit, repeated groups, sequential or low-diversity digits) and hex "hashes" that are obviously typed by hand. Language models write such values when they invent a resource. The nil and max UUIDs are not reported.
- **Probe chain pace and retries**, as above.
- **Reruns** ([`recurrence.rs`](../crates/sc-core/src/recurrence.rs)), in the watch digest. A later run whose target hosts, and their order, repeat an earlier run in a different cluster on another day, at least 6 hours later. Runs must share at least 4 hosts, overlap with a weighted Jaccard of at least 0.5 (hosts common to many runs are down-weighted), and agree on order for at least 70% of shared hosts.
- **Archive bursts**, in the watch digest. Many archive captures of one target host within minutes, on a host the store otherwise holds few captures of (the `linking.archive_burst_*` settings). A capture with no target behind its relay or carrier (the service's own page) is left out, so a burst never names the relay.
- **Payload dialect.** Which canonical test payloads a cluster uses, such as `<script>alert(1)</script>` or `<svg onload>`, `' OR 1=1--` or `' OR '1'='1`, and how deep its `../` runs go. Clusters that use the same uncommon mix of payloads are listed as a link to check.
- **Route escalation** ([`escalation.rs`](../crates/sc-core/src/escalation.rs)). Requests for one host and path, each at most `escalation.window_secs` (30 minutes) after the last, whose route climbs: a direct request, then a relay (Jina Reader, allorigins, markdown.new, a translate proxy), then a program carrier (httpbin, a `data:` or base64 program), then a remote browser (a code playground). The route lists in `[escalation]` name the rules for each level. An agent that cannot read a page tends to try harder like this; two people reading the same page by different routes look the same. Capture-time records are left out, because their order is the archive's.
- **Parallel fan-out width.** How many alike requests land in the same second, as when an agent issues tool calls in parallel (the `[fanout]` settings).
- **Declared testing** ([`declared.rs`](../crates/sc-core/src/declared.rs)). Members that announce themselves as testing: a user agent, header or parameter saying "authorized security test", "for research purposes" or "this is a security test"; a bug-bounty header (`X-HackerOne-Research`, `X-Bug-Bounty` and similar); or words such as "pentest", "security research" or "bug bounty" next to an email address or bounty handle. Each cluster lists the declaring text and the contact it names (`declared`), in case notes only. It feeds the case's handling of authorised testing: the admin checks the claim with its owner. It never lowers or raises a score, because anyone can write it and an agent can copy it from its prompt.
- **Benchmark targets** ([`knowledge.rs`](../crates/sc-core/src/knowledge.rs)). Members hitting a public benchmark or practice target listed under `[[benchmark]]` in the rules file, each entry with its source: intentionally vulnerable demo sites (Acunetix's vulnweb hosts, Altoro Mutual, OWASP Juice Shop demos, Google Firing Range) and agent benchmark environments (WebArena, MiniWoB++, picoCTF hosts). Each cluster counts them per entry (`benchmarks`). Probing such a site is likely evaluation or training activity, not malice, and reports say so. It never lowers a score: an agent can be evaluated and misbehave in the same run.
- **Stale knowledge.** Retired API endpoints and old client versions listed under `[[stale]]`, each with its source (OpenAI's Engines endpoints, Twitter API v1.1, YQL, Graph API v2.x, query-string tokens on the GitHub API, old `openai-python` and `python-requests` user agents), plus API path versions (`/v1/`) below the newest one seen on the same host family anywhere in the input (`older_api_version`). An entry is reported per cluster (`stale_knowledge`: id, note, records, hosts) when at least two members carry it. A model writes requests from what its training data knew; old scripts and pinned clients do the same, so it is a hint.
- **Natural-language residue** ([`prose.rs`](../crates/sc-core/src/prose.rs)). Parameter values that are prose: at least 6 words with letters (`PROSE_MIN_WORDS`), or 12 characters in a script written without spaces. Each gets an offline language guess: the script first, then for Latin script the language whose common words it uses most (seven languages), or none when unclear. Each cluster counts distinct prose values and their languages (`prose`), and how many are in a language other than their target's country domain (`.de` German, `.jp` Japanese; `mismatched`). An agent prompted in one language often searches a foreign site in it. Searches by travellers and English-language sites abroad do the same, so it is a hint.
- **Relay stacks.** The relays and carriers each member went through, outermost first, ending at the target (`relay.jina → relay.translate_goog → target`), counted per cluster (`relay_stacks`). The order is the unwrapping order of the rule hits. A stack of two or more hops is listed in reports; one relay is every relay user's habit and is only counted.
- **Repeated cut lengths.** Truncated URLs cut at nearly the same length, as a model or tool output limit would (the `[cut_lengths]` settings). A scan service's own display limit can do the same.

**Soft links and candidate fleets** ([`fleets.rs`](../crates/sc-core/src/fleets.rs)). The hints that relate two clusters are collected as soft links (`soft_links` in the analysis). Each has a strength from 0 to 1: its weight in `[soft_links]`, times its own similarity where it has one. A value shared by more than `soft_links.max_shared` clusters links none of them. The kinds:

- timing and habit: shared pauses, payload dialects, reruns of one target list;
- how requests were written: the same recon opening, overlapping unusual path sets, one encoding style across every member, the same fan-out width, the same cut length, the same request header set;
- routes and features: steps of one route escalation, the same relay stack of two or more hops (`relay_stack`), inboxes on the same callback service (`callback_service`: different webhook.site inboxes, say; one inbox links outright), and a linking feature too common to link on;
- **captured secrets** (`shared_secret`): one `REDACTED-<hash>` value in records of both clusters. It is the strongest kind, because a token one client captured rarely reaches another by chance.

For each pair of clusters the strengths combine as `1 - Π(1 - strength)`, so several weak ties can add up and one cannot. Pairs that reach `soft_links.fleet_min_strength` are grouped into connected components, the **candidate fleets** (`candidate_fleets`), listed in internal reports. A candidate fleet is a proposal for the admin: it never merges clusters, changes a tier, or appears in a report to a provider, an operator or the public.

**Why they never score or link.** Each of these is shared by many unrelated clients. Encoding styles are mostly library defaults. Polite crawlers and security scanners share recon openings. Popular targets attract the same paths. Cron jobs share pause times. Letting any of them raise a score would flag ordinary clients. Letting any of them link records would merge unrelated clusters, and every later step would inherit that error. They are also not measured by the evaluation set. So they appear in reports as hints, labelled as hints, for the admin to weigh.

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

**Layers, labels and tags.** Each claim belongs to one of four layers ([FM-7.1](manual/07-attribution.md#fm-71-four-layers)): `developer`, `host`, `harness` or `model_family` (`case claim --layer`). The code derives its label from the layer and the evidence: Confirmed, Suspected, Possible or Unattributed ([FM-7.7](manual/07-attribution.md#fm-77-attribution-labels)). Each claim also carries a tag, given with `--tag` or derived: a network seen in the records is Observed, a provider's confirmation or documented infrastructure is Documented, and the rest is Inference.

Reports list each claim with its layer, label and tag, and add a Conclusion line for each developer named through the gate, with the strongest likelihood word its label allows. Harness and model-family candidates appear ranked in private reports and never in public. A model-family claim needs the method's held-out accuracy and corpus size, or it is refused.

## Evaluation

`swarmchase eval` scores the rules against labelled records ([`eval.rs`](../crates/sc-core/src/eval.rs)). It reports precision and recall at the significant tier and at suggestive-or-above, precision per rule with its hard negatives, recall per class of activity and per tactic, and false positives per benign class. Every proportion carries a 95% Wilson interval. Records labelled with their true run also measure linking: B-cubed precision and recall, false merges and split runs, reported but not gated. Two reviewers' labels give Cohen's κ (`review --stats`). Details are in [evaluation](reference/evaluation.md). With no embargo, a false positive is published the moment the admin acts on it, so precision matters most.

**The committed set** is in [`samples/eval/`](../samples/eval/README.md). It holds records reconstructed from request patterns quoted in published Transluce reports, synthetic records for the model-output residue rules, and benign records, including hard negatives built to trip the rules: SQL words in search text, JSON in ordinary API queries, unrendered front-end templates, reading `claude.ai` through a relay. CI runs [`eval-gate.sh`](../scripts/ci/eval-gate.sh) on it and fails when precision or recall, or the lower end of a precision interval, falls below the floors in that script, or when a rule has no labelled positive and is not on the coverage allow-list. The floors only go up.

**What it is not.** The rules were tuned on this set. Its numbers are a regression floor, not an estimate of precision on real traffic. A number worth quoting needs held-out data.

**The held-out measurement.** Transluce's [urlquery dataset](https://transluce.org/agent-activity) labels tens of thousands of urlquery reports as significant, suggestive or benign background. It ships report IDs and labels, not report contents, and urlquery's terms forbid redistributing the contents. To measure against it, anyone with a urlquery API key fetches the reports into a gitignored directory with `swarmchase collect urlquery-reports --sample N` and runs `eval` with Transluce's labels and our [label overrides](../samples/eval/overrides/transluce-labels.ndjson), each override with its reason. The steps are in [samples/eval/README.md](../samples/eval/README.md#held-out-evaluation-on-the-transluce-release).

Read the per-class table, not just the overall recall: Transluce labelled some reports from context a single record cannot show. The benign controls are too few to estimate precision on their own, so add a sample of unflagged reports from a generic urlquery search, labelled benign.

Records the admin reviews with `swarmchase review` are saved with their labels and can be measured the same way. That file stays in the data directory and is never committed.

## Known limits and false-positive traps

**What the records cover.** Public scan services and web archives see a fraction of agent activity. Private and account-linked scans are invisible. A record shows that a URL was submitted or captured. It does not show that a request reached the target or succeeded. Reports say so.

**Archive timestamps.** A Wayback or Arquivo timestamp is when the archive captured the URL. That may be the agent's own request or a later crawl of a link to it. Cadence on archive records describes captures, not necessarily the agent, and pace, fan-out and rhythm skip them.

**Humans look the same.** The rules detect agent-like activity. A security researcher, a penetration tester or a conventional scanner sending the same payloads through the same services produces the same records. A significant tier means attack payloads were present, not that an AI agent sent them. Context, rhythm, residue and case work separate the two.

**Model-output residue from people.** A person who pastes a chatbot answer into a scan form leaves the same Markdown, placeholders and JSON. This is why residue rules carry low weights and never link.

**Self-identification is cheap.** Anyone can type a vendor name into a URL. It never names a developer.

**The ASN on a urlquery record describes the target, not the sender.** urlquery records the IP and ASN where its scanner reached the submitted URL's host. For a URL submitted through a relay, that is often the relay's hosting network. The attribution step reads a record's ASN as the network the requests came from. Treat a hosting-network claim that rests on urlquery records with care, and check which records it comes from before relying on it.

**Popular targets read through relays.** Two unrelated people reading the same popular page through the same relay within `linking.window_secs`, each with one more indicator, share a rule and a target host and will be linked. Check a cluster's link features and runs before treating it as one operator.

**Copied tags.** A tag quoted in a published report (such as `CHATGPTTEST1`) can be reused by anyone who read it. Tags listed in `linking.published_tags` never link. A quoted tag missing from that list, reused by unrelated operators within the feature window on no more than `linking.feature_max_hosts` hosts, still merges their clusters; add it to the list when a report quotes it. Generic parameter names in `strong_params` (`tag`, `run`, `session`) can carry the same value by coincidence.

**Corroboration across a cluster.** A cluster can be one tier above its strongest member when two members bring different kinds of evidence. That rests on the link between them being right. The cluster's member tiers and rules are listed so a reader can see how it got there.

**Heuristic decoding.** Base64 detection and unwrapping are heuristics. Truncated URLs decode partly. An opaque ID that happens to decode to text can, rarely, become a layer.

**Date and rhythm assumptions.** The offset inference assumes date tags mean "today" on the operator's clock. The rhythm guess assumes a working day centred on 13:00 local time. A fleet scheduled to a fixed UTC window, or an operator who keeps unusual hours, gives a misleading guess. Both are labelled as hints in reports.

**Headers are rarely recorded.** Most public records carry no request headers, and none keep their order. Header rules mostly apply to operator logs and the few sources that keep headers.

**Rules change.** A new rules version can move a record between tiers. Each case pins the rules it was opened with, and its reports, notices and evidence bundles use that version. `swarmchase case rules <id>` shows which records would change tier under the current rules. An evidence bundle records the rules version, and `swarmchase case verify` re-runs the analysis to show the tiers follow from the records (see [for-operators.md](guides/for-operators.md#verify-an-evidence-bundle)).
