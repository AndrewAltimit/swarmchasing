## What this changes

<!-- One or two sentences: what the change does and why. -->

## Checks

- [ ] No raw data, case files or live secrets. Committed records are redacted at ingest, and fake credentials carry `secret-scan: fixture`.
- [ ] Passive only. Nothing fetches a URL an agent submitted, touches a callback channel, or probes agent infrastructure.
- [ ] The gates in [CONTRIBUTING.md](../CONTRIBUTING.md#the-gates) pass locally. CI runs only the repo gates and a lint pass on pull requests, and nothing on forks, so say which you ran.

## Rule changes

Delete this section if `rules/default.toml` is unchanged. See [Contributing a rule](../CONTRIBUTING.md#contributing-a-rule).

- [ ] Public reference for each new or changed rule, linked in the rule:
- [ ] Labelled eval records in `samples/eval/` that the rule should catch.
- [ ] Hard negatives in `samples/eval/`: benign records built to trip the rule.
- [ ] `scripts/ci/eval-gate.sh` passes, and no floor was lowered.
- [ ] Before and after `swarmchase eval` numbers are in the commit message.
- [ ] `[meta] version` in `rules/default.toml` is bumped.
- [ ] Any `significant = true` or `link = true` flag is justified below.

| | Before | After |
|---|---|---|
| Significant precision | | |
| Significant recall | | |
| Suggestive precision | | |
| Suggestive recall | | |
| New rule's precision | | |
