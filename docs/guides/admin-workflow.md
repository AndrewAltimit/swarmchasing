# Admin workflow

The day-to-day path from a watch digest to a published notice. Tools draft at every step; the admin decides, sends and publishes ([policies](../policies.md#reporting-and-publication)). Each step links to its reference page.

Run the commands from a checkout, with the data directory set the way the runner has it (`SWARMCHASE_DATA`) and secrets loaded from `env.list` ([configuration](../reference/configuration.md)). With `cargo run -p swarmchase --` in place of `swarmchase`, they also run without installing.

```sh
source scripts/with-env.sh
```

## 1. Read the digest

The scheduled watch runs every 6 hours on the runner and emails the digest when something changed, or an alert when the run failed ([runner](../reference/runner.md)). To run one by hand:

```sh
swarmchase watch                      # watchlist.toml, $SWARMCHASE_DATA (or data/)
```

Read it top down:

- **Health.** A starved or failing source, or a rule whose hit rate jumped. Fix the source or the key before trusting the rest.
- **New clusters, tier changes, first-time endpoints.** The leads.
- **Possible reruns and archive bursts.** Leads to check, never merged automatically.
- **Case status.** Proposals for existing cases; see [step 8](#8-keep-the-notice-current).

Details: [watch runs](../reference/watch.md#the-digest).

## 2. Review the leads

```sh
swarmchase review --unflagged 20
```

Label each lead agent, benign or unsure, strongest cluster first. The unflagged sample keeps the benign baseline honest. Labels feed the evaluation ([evaluation](../reference/evaluation.md#reviewed-records)). Press `c` on a lead worth pursuing to open a case from its cluster, or `c <case-id>` to add it to an open one.

Details: [reviewing leads](../reference/watch.md#reviewing-leads).

## 3. Open a case

```sh
swarmchase case new 2026-10-portal --title "Portal SQLi" --cluster C1 --host-hits
swarmchase case status 2026-10-portal
```

The case copies its records out of the watch store, so retention cannot delete them, and pins the current rules. `case status` lists what the case still needs.

Details: [case files](../reference/cases.md#opening-a-case).

## 4. Classify endpoints and record claims

```sh
swarmchase case endpoint 2026-10-portal portal.example.gov targeted --note "payloads reflected, no sign of success"
swarmchase case claim 2026-10-portal --party … --evidence provider_confirmed --detail …
swarmchase case claim 2026-10-portal --layer harness --party … --detail …
swarmchase case note 2026-10-portal "Rerun of C4 from last week; same host order."
```

Every endpoint needs a decision (`compromised`, `targeted`, `historical`, `not-affected`) before a notice can be added. Attribution claims carry their layer, evidence level and tag; a developer is named only at or above the case's naming threshold, and harness and model-family candidates never ([attribution claims](../reference/cases.md#attribution-claims)).

## 5. Find contacts and draft reports

```sh
swarmchase case contacts 2026-10-portal
swarmchase case draft 2026-10-portal --audience affected --to security@example.gov
swarmchase case draft 2026-10-portal --audience provider --to <provider contact>
```

`case contacts` adds the provider's channels from the [provider directory](../reference/cases.md#the-provider-directory) when a claim names it, then reads security.txt, then RDAP abuse addresses. Add anything else by hand with `case contact add` (a CSIRT, a declared owner). `case draft` writes an unsent `.eml` with a fresh evidence bundle into `outbox/`, or paste-ready text for a web form. Read every draft before sending it.

Details: [contacts](../reference/cases.md#contacts), [drafts](../reference/cases.md#drafts).

## 6. Draft the notice

```sh
swarmchase case notice 2026-10-portal
```

This writes `notice.md` in the case and prints what it withheld, what it could not classify and anything that got through. Edit the draft until nothing needs a decision.

Details: [notices](../reference/notices.md#from-draft-to-published).

## 7. Send and publish together

There is no embargo: the reports and the notice go out at the same time.

1. Send each draft from your own mail client (or the organisation's form), then record it:
   ```sh
   swarmchase case sent 2026-10-portal --to security@example.gov --channel email
   ```
2. Add the notice and publish it by committing:
   ```sh
   swarmchase notice add 2026-10-portal
   git add notices/2026-10-portal.md && git commit && git push
   swarmchase notice published 2026-10-portal
   ```

`notice add` refuses while any endpoint is unreviewed, and leaves the case `reported` with its publication pending; `notice published` checks the pushed file is on the remote and marks the case `published`. The pre-commit hook and CI lint the notice; the deploy on `main` builds it into the site and the feed.

## 8. Keep the notice current

- **Replies and corrections** are appended, never rewritten:
  ```sh
  swarmchase notice update 2026-10-portal --kind reply --from "Example Agency" --text-file reply.txt
  ```
- **Status.** When the digest's *Case status* section proposes contained or reopened, and you agree:
  ```sh
  swarmchase notice update 2026-10-portal --kind status --status contained
  ```
- **Operator logs.** When an operator sends logs back, add them and record consent before the notice may use them:
  ```sh
  swarmchase case evidence add 2026-10-portal access.log --org "Example Agency" --host portal.example.gov
  ```
- **Rules changes.** `case rules <id>` shows records whose tier would change under the current rules; `--update` re-pins.

Close the case with `case set <id> --status closed` when nothing is left to do. Its records stay with the case for the retention period in [policies](../policies.md#collection).
