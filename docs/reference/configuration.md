# Configuration

Local secrets, the environment variables the tools read, and the urlquery.net key and terms. The workflows' own settings are in [runner](runner.md).

## Local secrets

Copy [`env.list.example`](../../env.list.example) to `env.list` (gitignored) and fill in the keys you have. Run any command with them loaded, or load them into your shell:

```sh
scripts/with-env.sh cargo run -p swarmchase -- watch
source scripts/with-env.sh
```

[`with-env.sh`](../../scripts/with-env.sh) parses the file and never executes it: values are taken literally, and a variable already set in the environment wins. `SWARMCHASE_ENV_FILE` loads a different file. It prints how many variables it loaded, never their values. CI does not use it; the workflows read repository secrets.

The commit gate refuses `env.list` and `.env` even when force-added ([contributing](../../CONTRIBUTING.md#the-one-hard-rule-no-raw-data-no-live-secrets)).

## Environment variables

| Variable | Read by | Used for |
|---|---|---|
| `SWARMCHASE_DATA` | `swarmchase` | The data directory ([watch](watch.md#the-data-directory)). Unset, it is `data/` relative to the working directory. |
| `SWARMCHASE_ADMIN` | `swarmchase case new` | The admin name a new case records. Unset, `git config user.name` ([second review](cases.md#second-review)). |
| `URLQUERY_APIKEY` | `swarmchase` | urlquery.net collectors and watch sources. |
| `URLSCAN_APIKEY` | `swarmchase` | Optional: raises urlscan.io's search quota ([urlscan.io](#urlscanio)). |
| `SWARMCHASE_SITE_URL` | `swarmchase notice build`, `site build` | `--base-url`. |
| `SWARMCHASE_LLM_URL` | `swarmchase review --suggest`, `watch --triage` | A local OpenAI-compatible model server; loopback, private or link-local hosts only ([label suggestions](watch.md#label-suggestions)). |
| `SWARMCHASE_LLM_MODEL` | `swarmchase review --suggest`, `watch --triage` | The model name sent to that server. |
| `SWARMCHASE_WATCH_TRIAGE` | `swarmchase watch` | The [model triage](watch.md#model-triage) backend, as `--triage=` sets it: `local` (also `1`, `true`, `yes`) or `claude`. |
| `SWARMCHASE_CLAUDE_MODEL` | `watch --triage=claude`, `review suggest-claude` | The model Claude Code is asked for. Default `claude-opus-5-5`. |
| `CLAUDE_PATH` | `watch --triage=claude`, `review suggest-claude` | The `claude` binary. Unset, it is found on `PATH` or in the usual install locations. |
| `SWARMCHASE_TRIAGE_MAX`, `SWARMCHASE_TRIAGE_SECS` | `swarmchase watch` | Leads triage asks about per run (default 20) and seconds it may spend (default 600). |
| `SWARMCHASE_UA` | collectors | Overrides the collectors' user agent. |
| `SWARMCHASE_BACKUP_DIR` | `swarmchase backup` | Where encrypted backups go, one subdirectory per host ([backups](#backups)). |
| `SWARMCHASE_BACKUP_RECIPIENT` | `swarmchase backup create` | The age public key backups are encrypted to. |
| `SWARMCHASE_BACKUP_PASSPHRASE` | `swarmchase backup` | A passphrase instead of a recipient; also what `verify --passphrase` and `restore --passphrase` read. |
| `SWARMCHASE_CANARY_SEED` | `sc-site`, `site build`, `swarmchase canary` | The secret seed [canary tokens](#canary-tokens) derive from; set, the build embeds them. |
| `SWARMCHASE_SIGNING_KEY` | `swarmchase case bundle`, `case draft`, `key public` | The secret seed [bundle signing](#bundle-signing) uses; set, every bundle is signed. |
| `SWARMCHASE_SIGNING_PUBLIC` | `swarmchase case verify`, `key public` | Another published key file. Unset, `keys/bundle-signing.pub`. |
| `SOURCE_DATE_EPOCH` | `sc-site`, `site build` | The build's time, for the canary month and `security.txt` `Expires`; else the clock. |
| `SWARMCHASE_EVAL_DIR` | `swarmchase case bundle`, `case draft` | The evaluation set whose figures go into bundle stamps. Unset, `samples/eval/` ([evidence bundles](cases.md#evidence-bundles)). |
| `SMTP_URL`, `SMTP_USER`, `SMTP_PASSWORD`, `MAIL_FROM`, `MAIL_TO` | [`send-mail.sh`](../../scripts/ci/send-mail.sh) | Digest and alert email to the admin. |
| `SWARMCHASE_ENV_FILE` | `with-env.sh` | Another file to load instead of `env.list`. |
| `SWARMCHASE_SKIP_PRECOMMIT` | pre-commit hook | `1` skips the hook for one command. |

## urlquery.net

urlquery's search API needs a key from a urlquery account, read from `URLQUERY_APIKEY` (the same variable `urlquery-cli` uses). Without one, `watch` skips urlquery sources and says so at the top of the digest: urlquery is the only scheduled source with submission times, so timing links, pace, agent grades above L2 and interaction edges are lost ([health](watch.md#health)). A urlquery export (search response or report JSON) can still be loaded with any command or in the browser.

urlquery's terms allow personal, non-commercial research use and forbid redistributing their content without permission. So reports and notices link to urlquery reports and quote only the indicators derived from them, and urlquery content is never committed: not in `samples/`, not in test fixtures, not in a notice. It may go to a hosted model for private label suggestions ([hosted suggestions](watch.md#hosted-suggestions)).

## urlscan.io

`swarmchase collect urlscan` searches urlscan.io's public scans. It works without a key; `URLSCAN_APIKEY` raises the quota. Only result metadata and the report link are kept, never page content or screenshots.

[urlscan's terms](https://urlscan.io/terms/) license personal, non-commercial use and need written permission for systematic retrieval into a database. So urlscan is a per-case lookup, not a watch source, and its records are cited by report link, as for urlquery.

## Collector cache

`watch` keeps collector responses in `<data>/cache/http/` and reuses them for `http_cache_ttl_secs` (in [`watchlist.toml`](../../watchlist.toml)), then revalidates them. `swarmchase collect … --cache` does the same for one command, under `SWARMCHASE_DATA` or `./data`. The cache is outside git and safe to delete.

## IP-to-ASN table

`swarmchase asn fetch` downloads [iptoasn.com](https://iptoasn.com/)'s IPv4 table (`ip2asn-v4.tsv.gz`, a few MB) into `<data>/asn/`. The data is public domain (PDDL 1.0) and updated hourly; refreshing weekly is enough. It is never committed.

Once it is there, `watch` and the commands that read record files fill the network of records that carry an IP but no ASN. A scan service's IP is the target's, so it fills `target_asn`; any other record's IP fills `asn`. `swarmchase asn lookup <ip>…` shows single addresses.

## Backups

Cases, reviewed labels and pinned rules cannot be collected again, so `swarmchase backup` keeps encrypted copies of them, with `state.json`, the cross-run history (`ledger.json`, `summary.json`, `autonomy.ndjson`) and the canary registry. The record store is left out: the sources refill it.

```sh
swarmchase backup keygen --out swarmchase-backup.key   # once, on the admin's own machine
swarmchase backup create --keep 30                      # SWARMCHASE_BACKUP_DIR, _RECIPIENT
swarmchase backup list
swarmchase backup verify <file> [--identity swarmchase-backup.key]
swarmchase backup restore <file> --identity swarmchase-backup.key --to restored/
```

- `create` writes `<SWARMCHASE_BACKUP_DIR>/<hostname>/swarmchase-<UTC stamp>.tar.age`, a tar encrypted with [age](https://age-encryption.org/), and a `.sha256` sidecar. `--keep N` deletes all but this host's newest N.
- It encrypts to `SWARMCHASE_BACKUP_RECIPIENT`, a public key, so the machine making backups holds no secret; `SWARMCHASE_BACKUP_PASSPHRASE` is the alternative.
- `keygen` writes the identity file and prints the public key. Keep the identity off the runner and away from the backup drive: anyone holding it reads every backup, and without it none can be restored.
- `verify` checks the hash; with the identity it also decrypts and reads the archive through, writing nothing.
- `restore` refuses a directory that is not empty unless `--force`, and holds the directory's lock while it writes. Restored without a record store, every source's cursor, seen list, resume key and stream checkpoint in `state.json` are reset, so the next watch fetches the analysis window again; health history is kept.

## Bundle signing

Evidence bundles carry an Ed25519 signature of their manifest when `SWARMCHASE_SIGNING_KEY` is set, and none when it is unset or empty ([signed bundles](cases.md#signed-bundles)). A value that is not a key fails the bundle.

```sh
swarmchase key generate --out ~/swarmchase-signing.key --public-out keys/bundle-signing.pub   # once, on the admin's machine
swarmchase key public                                                                          # key id of SWARMCHASE_SIGNING_KEY, and whether it is published
```

- The value is the 32-byte secret seed, as 64 hex digits or base64. It lives in `env.list` on the machine that drafts reports; it is never committed, printed or written anywhere but the file `key generate` makes.
- `key generate` writes the seed to `--out` as a `SWARMCHASE_SIGNING_KEY=` line, never over an existing file, readable by its owner only where the system has Unix permissions. It refuses a path inside a git checkout unless git ignores it. It prints only the public key and key id.
- Publishing a key is the maintainer's decision: committing `keys/bundle-signing.pub` publishes it. The site build then serves it at the same path and names it on the providers page, in `security.txt` and in `swarm-report.json`; without the file they say bundles are not signed yet. The build reads only the committed public key.
- Whoever holds the seed can sign bundles as this project. If it leaks, publish a new key and remove the old line from `keys/bundle-signing.pub`, so bundles signed with it stop verifying. To retire a key that did not leak, add the new line and keep the old one.
- The secret-scan gate refuses a committed `SWARMCHASE_SIGNING_KEY=` line with a value.

## Canary tokens

The site carries a reference token per page and per month ([page references](browser-toolkit.md#page-references)) when `SWARMCHASE_CANARY_SEED` is set, and none when it is unset or empty. A seed shorter than 16 bytes fails the build.

- The seed is a secret of at least 16 bytes (for example 32 random bytes as hex). It lives in `env.list` and, for a deploy, in a repository secret; it is never committed, printed or written to a file.
- The Pages deploy embeds tokens only when the repository secret `SWARMCHASE_CANARY_SEED` is set ([runner](runner.md#secrets-and-variables)); after a deploy it registers them in `$SWARMCHASE_DATA` on the runner.
- Whoever holds the seed can make tokens for any page and month, so a leaked seed voids every sighting; rotate it, and tokens made under the old seed stop matching new builds.
- `swarmchase canary register _site` records a built site's tokens in `<data>/canary/registry.json` after checking each against the seed. The deploy runs it on the runner; run it by hand only for a site deployed some other way.
- `swarmchase canary token <path> [--period YYMM]` prints one token; `canary list` the registry; `canary scan <records>` the copies in record files.
