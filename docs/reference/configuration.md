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
| `URLQUERY_APIKEY` | `swarmchase` | urlquery.net collectors and watch sources. |
| `SWARMCHASE_SITE_URL` | `swarmchase notice build` | `--base-url`. |
| `SWARMCHASE_UA` | collectors | Overrides the collectors' user agent. |
| `SWARMCHASE_EVAL_DIR` | `swarmchase case bundle`, `case draft` | The evaluation set whose figures go into bundle stamps. Unset, `samples/eval/` ([evidence bundles](cases.md#evidence-bundles)). |
| `SMTP_URL`, `SMTP_USER`, `SMTP_PASSWORD`, `MAIL_FROM`, `MAIL_TO` | [`send-mail.sh`](../../scripts/ci/send-mail.sh) | Digest and alert email to the admin. |
| `SWARMCHASE_ENV_FILE` | `with-env.sh` | Another file to load instead of `env.list`. |
| `SWARMCHASE_SKIP_PRECOMMIT` | pre-commit hook | `1` skips the hook for one command. |

## urlquery.net

urlquery's search API needs a key from a urlquery account, read from `URLQUERY_APIKEY` (the same variable `urlquery-cli` uses). Without one, `watch` skips urlquery sources and says so in the digest, and a urlquery export (search response or report JSON) can still be loaded with any command or in the browser.

urlquery's terms allow personal, non-commercial research use and forbid redistributing their content without permission. So reports and notices link to urlquery reports and quote only the indicators derived from them, and urlquery content is never committed: not in `samples/`, not in test fixtures, not in a notice.
