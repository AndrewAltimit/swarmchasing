# For operators

This page is for you if you run a website or service and either received a report from swarmchasing or found your host named in a published notice. It explains what the report means, what becomes public and when, how to check your own logs, how to send logs back, how to reply or ask for a correction, and how to check the evidence we sent.

How the analysis works is in [methodology.md](../methodology.md). The policies behind reports and notices are in [policies.md](../policies.md).

## What the report means

A report to an affected operator says that public records, from scan services and web archives, show automated agents sending requests to a host we believe you operate. It lists:

- the window of activity, the records and the clusters they were linked into;
- the indicators that matched, by rule, and whether attack payloads were present;
- an **Endpoints** table for your hosts: hits, first and last seen, payload rules, clusters, and whether the activity is ongoing or historical;
- links to the public records behind the hits (archive captures or scan reports, never the URLs the agents submitted).

**What it does not mean:**

- **It does not say you were compromised.** Public records show that a request was submitted or captured. We did not test whether any request reached you or succeeded, and we never contact the affected system to find out.
- **It does not say who sent the requests.** A report names an AI developer only when the evidence reaches the level set for the case. A model name inside a request never names one on its own. See [attribution levels](../methodology.md#attribution-levels-and-the-naming-gate).
- **It does not prove an AI agent sent every request.** The rules detect agent-like activity. A penetration tester or conventional scanner using the same payloads and services produces the same records. See [known limits](../methodology.md#known-limits-and-false-positive-traps).
- **It is not an accusation.** You are the target, not the subject.

## What happens after the report

You hear first, privately. What becomes public, and when, comes in two stages, and your report states both times:

1. **An indicator notice that does not name you.** Once every party has been sent its report, a public notice describes the activity and how to recognise it: relays, payload shapes, the kinds of callback service, the time window. It does not name or locate you: no organisation name, host, domain or address. Your endpoint appears only by class, such as "a national government data portal". If your endpoint was targeted, this can follow your report at once; if it was marked compromised, it waits at least 24 hours after your report.
2. **Your name, after a lead.** A dated update to the notice then names your organisation and its hosts, defanged: 3 working days after your report if your endpoint was targeted, 10 working days if it was marked compromised. Working days are Monday to Friday, counted in UTC. Use the time to check your logs, block the clients, fix the weakness and prepare your own statement.

**If you agree to be named earlier**, say so in writing in a reply; we record it, and your name can go in the next update with no wait. Consent is the only thing that shortens the lead.

**If you want more time**, ask; we record the request. We may lengthen the naming lead for the case, up to 20 working days, but are not bound to. Nothing you say or ask moves the indicator notice. It is not an embargo: a swarm is an active incident and others it targets need the indicators now; only names wait.

A statement you send is added to the notice verbatim ([right of reply](#right-of-reply-and-corrections)). Each notice and each naming update is reviewed by a second person before it is published. See [lead times](../policies.md#lead-times).

The naming update names your organisation as targeted or affected, never as the actor. It says your systems were compromised only when we have a basis beyond the requests themselves, such as your own confirmation. If every record we hold on your host comes from a public scan service, the update says that URLs targeting your hosts were submitted to public scan services, not that requests reached you. If an endpoint was marked compromised, the notice withholds the attack details and request URLs for it. What notices withhold is listed in [policies.md](../policies.md#reporting-and-publication).

## Check your own logs

Your access logs see requests the public records cannot. You can run the same rules over them yourself, without sending us anything. Two ways:

### In the browser toolkit

The browser toolkit runs the analysis entirely on your machine. Records are parsed and analysed in WebAssembly in the page; nothing is uploaded.

1. Open the toolkit's workbench (**Analyze**); its access-log preset sets the format for you.
2. Paste the log, or use **Load file**.
3. Pick **Access log** as the format (auto-detect usually finds it).
4. In the field map, name your host: `host=www.example.org`. Lines that do not name a virtual host are otherwise shown under `log.invalid`.
5. Press **Analyze**. The page shows flagged records, clusters, an hourly chart and the **Endpoints** table.

To run the toolkit locally instead of from the published site, build it with `scripts/ci/build-site.sh` and serve it with `python -m http.server -d _site 8080`.

### With the CLI

Build the CLI from this repository (`cargo build --release`), then run it on your log:

```sh
swarmchase scan access.log --map host=www.example.org         # flagged requests, strongest first
swarmchase clusters access.log --map host=www.example.org     # linked runs
swarmchase endpoints access.log --map host=www.example.org --from-now   # per host; "ongoing" measured from now
swarmchase report access.log --map host=www.example.org --audience affected -o my-report.md
swarmchase unwrap 'https://www.example.org/path?q=…'          # layers and rules for one URL
```

Through cargo, replace `swarmchase` with `cargo run --release -p swarmchase --`. Add `--format access_log` if auto-detection picks the wrong format.

### Log formats

- **Common and Combined Log Format**, as written by Apache, nginx and most proxies, optionally with a leading virtual host (`vhost_combined`). The client IP, time, method, request target, status, referer and user agent are read.
- **JSON or NDJSON** logs work if a field holds the full request URL. Name the fields with `--map`, for example `--map ts=time,url=request.url,ip=client.ip,ua=headers.user_agent`.

Secrets in query strings (session tokens, API keys) are replaced with hashes at ingest, as for every other source. See [redaction](../methodology.md#redaction-at-ingest).

### What to expect in your own logs

When an agent reached you through a relay (Jina Reader, a CORS proxy, a translate proxy), your log shows the relay's server as the client, not the agent. The relay rules match the relay's URL, which you never see, so they will not fire. Payload, tag, cache-buster, user-agent and model-output residue rules still match the path and query string you received. A log line with an attack payload and a status code tells you what the public record could not: whether the request reached you and how your server answered.

## Send logs back

If you choose to send us your logs, they help confirm what happened and link activity the public records missed. This is optional.

**What to send.** The access log for your host covering the window in the report, in one of the formats above. Tell us which host it belongs to.

**What we keep.** The admin adds your file to the case with `swarmchase case evidence add`. It keeps only:

- flagged requests (suggestive or above);
- every other request from a client IP that sent one of them;
- the requests in any probe chain around a flagged request (variants of one request to the same path, minutes apart).

Everyone else's traffic stays out of the case. What is kept is redacted at ingest. The toolkit does not copy your file into the case; it records only its SHA-256, the line count and how many records it kept.

**Where it is used.** Your logs become case evidence. They are used in:

- the case's internal notes and evidence bundles;
- private reports to the AI provider;
- private reports to you.

A report to another affected operator never carries your logs.

**The public notice uses your logs only with your agreement.** Until you agree, nothing from them appears in the notice. When you agree, the admin records how and when (`swarmchase case evidence consent`), and records used in the notice are marked as provided by the operator. You can withdraw your agreement. The admin records that with `case evidence withdraw`, and drafts made afterwards no longer use your logs. A notice already published changes only through a dated update, so ask us if you want one.

## Right of reply and corrections

Published notices are append-only. Each change is a dated entry; earlier entries are never rewritten. The notice also appears in the site's Atom feed, one entry per update.

- **Statements.** If you want a statement on the notice, send it. It is appended verbatim as a dated statement, with your name as its source. A statement never delays publication.
- **Corrections.** If something in a notice is wrong, tell us what and why. A correction is appended as a dated entry. If the evidence does not hold, the notice is retracted the same way.
- **Status.** A notice is `active`, `contained` or `historical`. If the activity has stopped for you, tell us. The watch also proposes marking an active notice contained after a quiet period, and reopening it if matching activity returns. The admin decides each change.
- **Endpoint classification.** Each endpoint in a case is classified as compromised, targeted, historical or not affected. If you can show an endpoint was not affected, or that a request did not succeed, tell us and we will review it.

## Verify an evidence bundle

A report sent by email carries an evidence bundle as attachments:

| File | What it holds |
|---|---|
| `records.ndjson` | The redacted records the report rests on |
| `analysis.json` | The analysis of those records |
| `stamp.json` | The rules version, the toolkit version and commit, and the tier of every flagged record and cluster when the report was made |
| `MANIFEST.sha256` | The SHA-256 of each file above |

Save the four files into one directory. Then check them in either of two ways.

**With the CLI.** From a checkout of this repository:

```sh
swarmchase case verify path/to/bundle
```

It checks each file against the manifest, re-runs the analysis on `records.ndjson`, and fails if any record's tier or any cluster differs from the stamp. On success it prints `verified (manifest, tiers and clusters match)`.

The check must use the rules the bundle was made with. If the rules version in `stamp.json` differs from your checkout's, the check says so. Check out the commit named in `stamp.json` (`toolkit_commit`, when present), or pass that commit's rules file with `--rules path/to/default.toml`.

**In the browser.** The toolkit's **Tools** page loads a bundle and re-runs the check locally.

**What verifying shows, and what it does not.** A bundle that verifies shows that the tiers and clusters in the report follow from the records under the stated rules, and that the files are the ones the manifest lists. It does not show that the records are genuine. For that, follow each record's `reference` link to the public record it was taken from: an archive capture or a scan report. The manifest is not signed, so it proves the files agree with each other, not who produced them.

## Contact

Reply to the address the report came from. Questions, logs, statements, corrections, consent to earlier naming and requests for more time all go there. If you found your host in a notice but received no report, contact the project through this repository and we will send you the full report.
