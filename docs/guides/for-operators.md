# For operators

This page is for you if you run a website or service and either received a report from swarmchasing or found your host named in a published notice. It explains what the report means, how to tell it is genuine, what becomes public and when, how to check your own logs, how to send logs back, how to reply or ask for a correction, how to check the evidence we sent, and how to [reach us privately](#contact).

If you work at an AI provider, [for-providers.md](for-providers.md) is the page for you.

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

## Check that a report is genuine

Anyone can write an email that claims to come from us, so check before you act on one. A genuine report:

- **carries a case id** in square brackets at the end of its subject. The public notice for the incident is published on this site under the same id, at `notices/<case id>/`, so once the notice is out you can match the two. Before then, ask us through the [private channel](#contact) and give the id.
- **comes with an evidence bundle** that you can check yourself on the site's [Tools page](../reference/browser-toolkit.md#evidence-bundles), in your browser, without installing anything or uploading the files ([verify an evidence bundle](#verify-an-evidence-bundle)).
- **links only to public records and this site.** Each record links to the archive capture or scan report it was taken from. A report never asks you to sign in, pay, install software or visit a host named in it.

If a message fails any of these, or you are unsure, do not act on it; ask us privately with the id it gave.

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

The short path is **Check my logs** (**Investigate**, then **Check my logs**): paste or drop the log once (or [many at once](#many-logs-at-once)), name your host, and the page runs the rules and the [agent identity](#agents-that-name-themselves) check on it, then says what it found and what to do next. For the full analysis, use the workbench:

1. Open the workbench (**Investigate**, then **Workbench**); its access-log preset sets the format for you.
2. Paste the log, or use **Load files** or **Load folder**.
3. Pick **Access log** as the format (auto-detect usually finds it).
4. In the field map, name your host: `host=www.example.org`. Lines that do not name a virtual host are otherwise shown under `log.invalid`.
5. Press **Analyse**. The page shows flagged records, clusters, an hourly chart and the **Endpoints** table.

### Many logs at once

Both pages take a whole set of logs and run one analysis over all of them, so a run that crosses a log rotation, or reaches several servers, shows as one cluster:

- pick several files with **Load files**, a folder with **Load folder**, or drop files and folders on the log area;
- archives are unpacked in the page: `.zip` (stored or deflate, ZIP64 included), `.tar`, `.tar.gz`, `.tgz` and `.gz`, and one archive inside another. The page tells an archive from a log by its first bytes, so a rotated `access.log.1` or a log without an extension reads as well.

Each file is read on its own, in its own format (an access log beside a JSON log reads as both), and your host applies to every file. Before the results, a table lists each file with the format it was read as, its lines, the records read and the lines skipped, and below it every entry the page did not read with the reason: binary content, an encrypted zip entry, a link or device in a tar, an archive nested deeper than one level. Each flagged record names its file; in the workbench the **File** filter narrows the records table to one file, and the CSV has a file column.

The page reads at most 512 MB of unpacked text and 10,000 files and entries in one set, 256 MB in one file, and skips an entry that unpacks to over 400 times its packed size past the first 8 MB. When a limit is hit it stops and says so. Above 50 MB of files it asks before it starts. Nothing leaves the browser: archives are unpacked by the browser's own decompressor, file names are only shown, never used as paths, and every line is read as text. **Check my logs** carries a set of up to about 4 MB of text to the workbench; for a larger one, load the same files there.

To run the toolkit locally instead of from the published site, build it with `scripts/ci/build-site.sh` and serve it with `python -m http.server -d _site 8080`.

### Agents that name themselves

Some requests say which AI provider's agent sent them: a user agent such as `ChatGPT-User` or `Claude-User`, or a Web Bot Auth signature. Anyone can write a user agent, so the toolkit's **Agent identity** page checks each one against the address ranges and signing keys the provider publishes ([how](../reference/identity.md)):

1. Paste the log or use **Load file**, and name your host in the field map as above.
2. Press **Check**. Each record gets a class: verified by signature or by address, from a provider's range without a declaration, a claim with nothing to check it against, a failed signature, or spoofed (a provider's product named from outside its published ranges). The page counts each class per provider product and lists spoofed records first.
3. The page starts with the providers' files the site was built with and says how old they are. For a recent log, download fresh copies from the addresses it lists and load them; the page itself never contacts a provider.

Signatures are checked only on JSON records that carry the request headers; Common and Combined logs have no signatures. With the CLI: `swarmchase identity refresh`, then `swarmchase identity check access.log --map host=www.example.org`.

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

## Share sightings

A swarm that reaches many sites is invisible to any one of them. If you found one in your logs, you can share what it left without sharing your logs or your visitors, so that we can tell whether other operators, or the public records, saw the same swarm. This is optional, and separate from [sending logs back](#send-logs-back).

**Make the file.** In the workbench, after **Analyse**, go to **Share sightings** and press **Prepare sightings**. The page shows the whole file before you save it; **Download** saves exactly that text. Or, with the CLI:

```sh
swarmchase sightings export access.log --map host=www.example.org -o sightings.json
```

**What it holds.** For each flagged cluster: keyed hashes of the run tags, inbox ids and captured secrets that linked it; how its requests were made (relays, payload variants, rule ids, tactics, a fingerprint of header names); the hours it was active, in UTC; its client networks as AS numbers; its tier and agent grade. Your host names go in only if you tick **Include my host names**, and then defanged.

**What it never holds.** URLs, paths, query values, IP addresses, user agents, cookies, or any request from an ordinary visitor.

**What the hashes hide, and what they do not.** The hashes use a key published for each quarter, so every operator's hashes of the same tag match. That keeps tags out of reach of a lookup table, but anyone with the key can test a guess, and short run tags are easy to guess. Long values such as inbox ids and captured secrets stay out of reach. Send the file only to us, privately. The details are in [SC-Sightings v1](../specs/sightings-v1.md#what-the-keyed-hash-protects-and-what-it-does-not).

**Sending it.** If you received a report, reply to it with the file attached and keep the case id in the subject: a file that comes back on the channel we reported to counts as yours. A file from anywhere else is welcome, but is treated as unverified until we can tie it to you.

**How we use it.** We match it against other operators' sightings and our own clusters from public records. A match is a lead for case work: it never merges clusters or changes a finding on its own, and an unverified file corroborates nothing. Your file is never published, and a report to another party never carries it or says it came from you. How long we keep it is in [policies](../policies.md#collection).

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
| `MANIFEST.sha256.sig` | The Ed25519 signature of the manifest, once a signing key is published |

Save the files into one directory. Then check them in either of two ways.

**With the CLI.** From a checkout of this repository:

```sh
swarmchase case verify path/to/bundle
```

It checks the signature against the published key (`keys/bundle-signing.pub` in the checkout, or `--key path`), checks each file against the manifest, re-runs the analysis on `records.ndjson`, and fails if the signature is invalid or any record's tier or any cluster differs from the stamp. It says whether the bundle is `signed by key <key id>` or `unsigned`. On success it prints `verified (signature, manifest, tiers and clusters match)`, or without `signature, ` for an unsigned bundle.

The check must use the rules the bundle was made with. If the rules version in `stamp.json` differs from your checkout's, the check says so. Check out the commit named in `stamp.json` (`toolkit_commit`, when present), or pass that commit's rules file with `--rules path/to/default.toml`.

**In the browser.** The site's [Tools page](../reference/browser-toolkit.md#evidence-bundles) loads a bundle and re-runs the check locally, the signature against the key the site publishes.

**What verifying shows, and what it does not.** A bundle that verifies shows that the tiers and clusters in the report follow from the records under the stated rules, and that the files are the ones the manifest lists. It does not show that the records are genuine. For that, follow each record's `reference` link to the public record it was taken from: an archive capture or a scan report. A valid signature shows who produced the bundle: the holder of the published key. Without one, the manifest proves the files agree with each other, not who produced them. The key id, what it means and where to compare it are in [for-providers.md](for-providers.md#check-who-sent-it).

## Contact

- **If you received a report,** reply to the address it came from and keep the case id in the subject. Questions, logs, statements, corrections, consent to earlier naming and requests for more time all go there.
- **If you received no report,** found your organisation in a notice, or want to reach us privately for any other reason, use [private vulnerability reporting](https://github.com/AndrewAltimit/swarmchasing/security/advisories/new) on this repository. Only the maintainers can read what you send. Give the case or notice id if you have one, and say how to reach you. If a notice concerns you and you received no report, we will send you the full report.
- **Do not open a public issue or discussion about an affected host or organisation.** Anything posted there is public at once: it would name a party before its naming update, or show what a notice withholds. Public issues are for the toolkit itself.
