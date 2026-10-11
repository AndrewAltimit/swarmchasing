# Notices

A notice is the public page for one incident. It is drafted inside its case and published by committing it to `notices/<id>.md`. The policy behind what a notice says and withholds is in [policies](../policies.md#reporting-and-publication).

## From draft to published

1. After the reports are sent and recorded, `case notice <id>` renders the public notice into `<data>/cases/<id>/notice.md` and records its hash and time. It prints each thing it withheld, each thing it could not classify (withheld until the admin decides), and anything that got through the withholding anyway.
2. The admin reviews and edits the draft, and an hour or more after it was written re-reads it and records that (`case reread`).
3. `notice add <id>` runs the self-review checklist ([cases](cases.md#self-review-checklist)) and prints it as a pass/fail list. Once every item passes, including the lead time ([cases](cases.md#lead-time)), it copies the draft to `notices/<id>.md`, with front matter that holds the status and the dated updates. Before the lead time has run it refuses and prints the time it runs until; there is no override. It never overwrites a notice that exists. The case moves to `reported` and is marked *publish pending*.
   - The first update and the draft's summary name only the parties the case's recorded sends reached (`case sent`) and say the reports went before publication; the first update also names the parties no contact was found for.
   - The withholding scan uses the case's pinned rules, and the current rules too when they differ.
4. The admin commits and pushes the file, which publishes it.
5. `notice published <id>` finds the file on the remote (`origin/HEAD` or `origin/main`, from local refs only: it never fetches or pushes) and moves the case to `published`. `--force` marks it without the check.

## Front matter

| Field | Holds |
|---|---|
| `id`, `title` | The slug the file is named after, and the headline. |
| `status` | `active`, `contained` or `historical`. |
| `published`, `updated` | Dates; `updated` is the last update's date. |
| `providers` | Developers named, at or above the case's naming threshold. May be empty. |
| `affected` | Affected hosts, shown defanged. |
| `sector` | Optional: the affected operators' sector, one of `government`, `health`, `education`, `research`, `finance`, `energy`, `water`, `telecom`, `transport`, `technology`, `media`, `nonprofit`, `retail`, `manufacturing`, `other`. Any other value fails the lint. |
| `rules_version`, `toolkit` | What the analysis ran with. |
| `[[update]]` | The dated updates, oldest first. |

The notices index filters on status, provider, sector, affected host and update date.

## Updates

Later changes go through `notice update <id> --kind update|status|correction|reply|retraction --text …`.

- `--status contained` (or another status) with `--kind status` changes the notice status, and the case's too.
- `--from` and `--text-file` carry a statement quoted verbatim, such as a reply.

Each update appends a dated entry and never rewrites an earlier one.

## What a notice withholds

| Withheld | Detail |
|---|---|
| Records that reach a callback channel | Webhook, request-bin and notification-topic identifiers, paste links, disposable inboxes: the whole URL and its record link. |
| Linking parameters that could be credentials | `tok`, `sid`, `session`, `nonce`. Run tags such as `uqtag` stay. |
| E-mail addresses | The local part of every address. |
| Compromised endpoints | Their attack details and request URLs. |
| Hosts not classified as affected | Not named: the summary and endpoint table give a count, and their records, chains and escalations are left out. |
| Operator-supplied logs | Everything from them, until the operator agrees to publication ([operator evidence](cases.md#operator-evidence)). |

A report to one operator never carries another operator's logs. Records used with agreement are marked as provided by the operator.

## Lint

`notice lint` checks every committed notice for:

- callback channel identifiers;
- e-mail addresses other than role mailboxes;
- credential shapes;
- valid front matter and update order;
- attribution statements without a layer, a label (`Label: …`, or a Conclusion line's leading label) or a tag;
- likelihood words stronger than their label allows: in the attribution section, each line's own label; in the summary, the strongest label the notice states; anywhere, off-table words of certainty ([SC-FM 8](../manual/08-confidence.md));
- a title naming a model provider from the [provider directory](cases.md#the-provider-directory) that `providers` does not list.

CI runs it on every pull request and push, and so does the pre-commit hook when `notices/` is staged ([scripts](../../scripts/README.md)).

## Burned tags

A run tag or marker a notice prints is public: anyone can copy it, so it no longer identifies one operator. [`check-published-tags.py`](../../scripts/ci/check-published-tags.py) fails when a committed notice shows a linking tag (`uqtag`, `run` and the other tag parameters notices keep) or a linking marker value that `[linking] published_tags` in [`rules/default.toml`](../../rules/default.toml) does not list. A listed value never links; its records appear as a common feature instead. Add each value with the notice as its source when the notice is added. The rules change passes the eval gate like any other.

## Build

`notice build --out <dir> --base-url <url>` turns `notices/` into the notice data: an index, one JSON page per notice and an Atom feed with one entry per update. It refuses to build if any notice fails the lint. At deploy the site build writes the same files under `notices/`, plus a static page per notice and the filterable index ([browser toolkit](browser-toolkit.md#pages)).
