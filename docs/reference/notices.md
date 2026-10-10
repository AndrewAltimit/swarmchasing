# Notices

A notice is the public page for one incident. It is drafted inside its case and published by committing it to `notices/<id>.md`. The policy behind what a notice says and withholds is in [policies](../policies.md#reporting-and-publication).

## From draft to published

1. `case notice <id>` renders the public notice into `<data>/cases/<id>/notice.md`. It prints each thing it withheld, each thing it could not classify (withheld until the admin decides), and anything that got through the withholding anyway.
2. The admin reviews and edits the draft.
3. `notice add <id>` checks the draft and copies it to `notices/<id>.md`, with front matter that holds the status and the dated updates. The check uses the case's pinned rules, and the current rules too when they differ. It refuses while any endpoint is unreviewed, and it never overwrites a notice that exists.
4. The admin commits and pushes the file, which publishes it.

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
| Operator-supplied logs | Everything from them, until the operator agrees to publication ([operator evidence](cases.md#operator-evidence)). |

A report to one operator never carries another operator's logs. Records used with agreement are marked as provided by the operator.

## Lint

`notice lint` checks every committed notice for:

- callback channel identifiers;
- e-mail addresses other than role mailboxes;
- credential shapes;
- valid front matter and update order.

CI runs it on every pull request and push, and so does the pre-commit hook when `notices/` is staged ([scripts](../../scripts/README.md)).

## Build

`notice build --out <dir> --base-url <url>` turns `notices/` into the notice data: an index, one JSON page per notice and an Atom feed with one entry per update. It refuses to build if any notice fails the lint. At deploy the site build writes the same files under `notices/`, plus a static page per notice and the filterable index ([browser toolkit](browser-toolkit.md#pages)).
