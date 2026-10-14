# Declared agent identity

How the toolkit checks the identity agent products declare: a user agent naming the product, a Web Bot Auth signature, and the address ranges and signing keys the provider publishes. The method is [FM-7.11](../manual/07-attribution.md#fm-711-declared-agent-identity) and [FM-7.13](../manual/07-attribution.md#fm-713-published-address-ranges); the classes and how they feed attribution and the agent grade are in the [methodology](../methodology.md#declared-agent-identity).

This evidence comes from operator logs. Public records rarely carry a client address or request headers, so the watch does not use it.

## The catalog

[`declared-agents.toml`](../../declared-agents.toml) lists, for each provider:

| Table | Holds |
|---|---|
| `[[agent]]` | A product token as it appears in the user agent (`ChatGPT-User`), its provider, purpose, range files and signing directory. |
| `[[range_file]]` | A published address-range file: its URL, and `exhaustive = false` when the provider does not present it as complete. |
| `[[directory]]` | A Web Bot Auth key directory: the `Signature-Agent` URI the provider documents, and the directory's URL. |
| `[[github_app]]` | A coding-agent product's GitHub login (`claude[bot]`, `Copilot`), and the words that claim it in another App's login. |

The platform pass reads `[[github_app]]`: those Apps' events are tallied by product rather than grouped, and an undeclared App whose login carries one of the words is a spoofing lead ([platform swarms](watch.md#platform-swarms)).

Every entry cites the provider page (`source`) that names the file. Adding one is a review decision, as for a rule: cite the page, keep the URL the page gives (or the host it redirects to, said in a comment), and run the tests. The catalog is compiled into the CLI and the browser module.

A product whose provider publishes no range file, or publishes its addresses only as a web page the refresh cannot parse (Amazon's), is listed without ranges: its user agent stays a claim, never verified and never called spoofed. A key directory whose `Signature-Agent` value and URL the provider's public documentation does not give is left out.

### Candidates from the reference list

`swarmchase identity reference` fetches the community-maintained [ai.robots.txt](https://github.com/ai-robots-txt/ai.robots.txt) list (MIT) of AI crawler and agent user-agent tokens into `<data>/identity/reference/robots.json` and prints the tokens it lists that the catalog has no `[[agent]]` for, matched case-insensitively, with the operator and function the list gives (defanged). `--offline` reads the held copy. The command proposes and never edits the catalog: the list is a pointer to where to look, and an entry is added only with the provider's own page as its `source`.

## Passivity

`identity refresh` fetches only the catalog's URLs, over HTTPS, following redirects within the same host. These are the providers' own documents about their agents, read like a security.txt: no agent infrastructure is touched. A `Signature-Agent` URI in a request is an address the agent supplied and is never fetched, whatever it names ([FM-2.1](../manual/02-principles.md#fm-21-passive-only)). A signer whose directory is not in the catalog stays unverified.

## Commands

```bash
swarmchase identity refresh                        # fetch the catalog's files into <data>/identity/
swarmchase identity status                         # what is held, with fetch dates
swarmchase identity reference                      # tokens the ai.robots.txt list names that the catalog lacks
swarmchase identity check access.log --map host=www.example.org
swarmchase identity check records.ndjson --json --all
```

`check` prints one line per record with a declared identity: record id, client address, class, provider and product, and the reason for a spoof or a failure (hosts defanged). `--all` adds the records with none; `--json` prints the classification as JSON. With nothing held, user agents stay claims and nothing is called spoofed; the command says so.

Once files are held, the analysis commands fill each cluster's identity from `<data>/identity/` (the data directory is `SWARMCHASE_DATA`, else `data/`): `report` prints it and `analyze` writes it as `identity`.

## Data

| Path | Holds |
|---|---|
| `<data>/identity/<id>.json` | Each range file or directory as last fetched. A fetch that does not parse keeps the previous copy. |
| `<data>/identity/fetched.json` | Per file: URL, fetch date, SHA-256 and entry count, so a case can cite the version a verdict rests on. |
| `<data>/identity/reference/robots.json` | The ai.robots.txt list as last fetched by `identity reference`. |

The files stay in the data directory and are never committed. Providers change them; refresh before checking a log, and for an old log say how far apart the log and the file are.

## What a record needs

| Check | Needs |
|---|---|
| Product claim | A user agent: access logs in Combined format, or `user_agent` in JSON. |
| Address checks | The client address (`ip`). Behind a proxy, log the forwarded client address, not the proxy's. |
| Signatures | The `Signature`, `Signature-Input` and `Signature-Agent` headers in a JSON record's `headers`, as received. Common and Combined logs do not carry them. A covered `@method` needs a `:method` header on the record. |

Signature checks follow RFC 9421 for the signature base and the Web Bot Auth profile for the rest: the `web-bot-auth` tag, `created`, `expires` and `keyid` present, `@authority` or `@target-uri` covered, the record's time inside `created` (with five minutes' skew) and `expires`, the key found by its JWK thumbprint (or `kid`) in the directory and valid at that time, and Ed25519 (`alg="ed25519"` or none). A keyed dictionary member is tried as RFC 9421 serialises it, then as its bare string, the form the Web Bot Auth draft's own test vector is signed over. Other algorithms are reported as present and unverified.

## In reports

Case notes and provider reports carry a **Declared agent identity** section: one line per cluster with each class, provider and product and the file that decided it, the reason for any spoof, and the files checked with their fetch dates. Case notes add the claim a verified identity supports, as a command:

```bash
swarmchase case claim <case> --party "OpenAI" --layer developer --evidence provider_infrastructure --detail "..."
```

Nothing is recorded until the admin runs it. Reports to affected operators and public notices carry none of this. A spoofed identity also appears as a counter-signal in *Why we think this is an agent*, and a verified one as an L1 signal.

## In the browser

The site's **Agent identity** page (`/identity/`) runs `check` on an operator's own log in the page ([browser toolkit](browser-toolkit.md#agent-identity)). The tools module exposes `identity_catalog()` and `identity_check(input, format, map, files)`. `files` holds range files and directories by catalog id; the module fetches nothing. It is built with signature verification, so a signed JSON record is verified in the browser as in the CLI.

The page never fetches a provider's file at runtime: the site's policy allows requests to its own files only, and a request from the operator's browser would tell the provider who is checking. It starts from a snapshot the site build embeds, and the operator can load newer copies.

### The snapshot

`sc-site --identity-snapshot <dir>` (or `SITE_IDENTITY_SNAPSHOT` for `scripts/ci/build-site.sh`) embeds the files `identity refresh` wrote into `<dir>`, normally `<data>/identity`, as `assets/identity-snapshot.json` with their URLs and fetch dates. Only `fetched.json` and the files the catalog names are read. A file is embedded only when it parses and its SHA-256 matches `fetched.json`, so the date shown is that file's.

The deploy passes the runner's `<data>/identity` when it holds files and fetches nothing itself, so the snapshot is as old as the last `identity refresh` there. The scheduled watch workflow runs that refresh once a day, after its digest, as a step that never blocks the watch ([runner](runner.md#watchyml)); the admin can also run it by hand. Without one, or offline, the build embeds the catalog alone and the page says so.

The files are not committed: providers change them, and a copy in git would go stale between commits.
