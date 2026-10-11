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
- **Case status.** Proposals for existing cases; see [step 9](#9-keep-the-notice-current).

Details: [watch runs](../reference/watch.md#the-digest).

The same picture across runs is on a local page: what is new since you last looked, each source's health, the review queue, open cases and their clocks, and the command for each next step. Press `s` there once you have read a run, and later runs show as new.

```sh
swarmchase dashboard                  # http://127.0.0.1:8767/
```

Details: [the dashboard](../reference/watch.md#the-dashboard).

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

The case copies its records out of the watch store, so retention cannot delete them, pins the current rules and records you as its admin (from `SWARMCHASE_ADMIN`, else `git config user.name`; `case set --admin` changes it). `case status` lists what the case still needs.

Details: [case files](../reference/cases.md#opening-a-case).

## 4. Classify endpoints and record claims

```sh
swarmchase case endpoint 2026-10-portal portal.example.gov targeted --note "payloads reflected, no sign of success" --sector "a national government data portal"
swarmchase case endpoint 2026-10-portal shop.example.org compromised --basis "operator confirmed a web shell: <link>"
swarmchase case scope 2026-10-portal --cluster C1 --finding exceeded --tests S2,S4 --note "relays after a challenge, then SQLi: <links>"
swarmchase case grade 2026-10-portal L3 --note "retries after errors at model pace: <links>"
swarmchase case claim 2026-10-portal --party … --evidence provider_confirmed --detail …
swarmchase case claim 2026-10-portal --layer harness --party … --detail …
swarmchase case note 2026-10-portal "Rerun of C4 from last week; same host order."
```

Every endpoint needs a decision (`compromised`, `targeted`, `historical`, `not-affected`) before a notice can be added. `compromised` needs a basis beyond the requests the endpoint received. An endpoint seen only in records anyone could have submitted to a scan service is named only with `--single-source-reason "…"`. Attribution claims carry their layer, evidence level and tag; a developer is named only at or above the case's naming threshold, and harness and model-family candidates never ([attribution claims](../reference/cases.md#attribution-claims)).

The indicator notice describes each target by class; `--sector` gives a description when the class is not enough. Record the scope finding for each cluster from the scope pass's suggestion ([scope finding](../reference/cases.md#scope-finding)). A notice or report may call the activity misaligned only with a finding of `exceeded` and an admin grade of L3 or higher; otherwise it describes suspected AI agent activity.

Then rule out the innocent and misleading explanations, one by one, and review any cluster `case status` marks for plant review:

```sh
swarmchase case alternative 2026-10-portal honeypot --rejected "portal is the agency's production site: <link>"
swarmchase case plant-review 2026-10-portal C1 --note "tag also in a published report, but the payload dialect matches the earlier runs"
```

## 5. Find contacts and draft reports

```sh
swarmchase case contacts 2026-10-portal
swarmchase case draft 2026-10-portal --audience affected --to security@example.gov
swarmchase case draft 2026-10-portal --audience provider --to <provider contact>
```

`case contacts` adds the provider's channels from the [provider directory](../reference/cases.md#the-provider-directory) when a claim names it, then reads security.txt, then RDAP abuse addresses. Add anything else by hand with `case contact add` (a CSIRT, a declared owner). `case draft` writes an unsent `.eml` with a fresh evidence bundle into `outbox/`, or paste-ready text for a web form. Each report states when the indicator notice is scheduled, that it will not name the recipient, and when the recipient may be named. Read every draft before sending it.

Details: [contacts](../reference/cases.md#contacts), [drafts](../reference/cases.md#drafts).

## 6. Send the reports

The reports go first. The indicator notice follows once every party is sent or recorded without a contact: at once for the provider and the operators of targeted or historical endpoints, 24 hours after the report for a compromised one. Operators are named 3 working days after their report, 10 for a compromised endpoint, or earlier with their written consent ([lead times](../policies.md#lead-times)). Nothing a recipient says changes the indicator clock.

Send each draft from your own mail client (or the organisation's form), then record it, with the time when you record it later:

```sh
swarmchase case sent 2026-10-portal --to security@example.gov --channel email
swarmchase case sent 2026-10-portal --to abuse@provider.example --at 2026-10-12T14:05:00Z
swarmchase case no-contact 2026-10-portal old.example.org --searched "security.txt, RDAP: nothing"
swarmchase case set 2026-10-portal --naming-days 5         # optional, 3 to 20 working days
```

Record a party with no contact rather than leaving it out; the notice then says contact was attempted, and the party's naming clock runs from the record. `case status` shows every party's clocks, when the indicator notice may be added and when each operator may be named.

Details: [lead times](../reference/cases.md#lead-times).

## 7. Draft, review and publish the indicator notice

1. Draft the notice once the sends are recorded:
   ```sh
   swarmchase case notice 2026-10-portal
   ```
   This writes `notice.md` in the case and prints what it withheld, what it could not classify and anything that got through. Edit the draft until nothing needs a decision, and check it names and locates no affected party: no organisation, host, domain or address of a target.
2. An hour or more later, read the whole draft again and record it. An edit after that needs another re-read:
   ```sh
   swarmchase case reread 2026-10-portal
   swarmchase case checklist 2026-10-portal
   ```
3. Hand the draft to a second reviewer, and record their verdict. You cannot review your own draft; an edit after the review needs a new one, and an objection blocks until a later approval:
   ```sh
   swarmchase case review-packet 2026-10-portal              # outbox/review/
   swarmchase case review 2026-10-portal --reviewer "R. Reviewer" --verdict approve
   ```
4. Once the indicator clock has run, add the notice and publish it by committing:
   ```sh
   swarmchase notice add 2026-10-portal
   git add notices/2026-10-portal.md && git commit && git push
   swarmchase notice published 2026-10-portal
   ```

`notice add` prints the [self-review checklist](../reference/cases.md#self-review-checklist) and refuses while any item fails, including before the clock has run and without an approved [second review](../reference/cases.md#second-review) of the current draft; with no reviewer available, nothing is published. It leaves the case `reported` with its publication pending. `notice published` checks the pushed file is on the remote and marks the case `published`. The pre-commit hook and CI lint the notice; the deploy on `main` builds it into the site and the feed.

Details: [notices](../reference/notices.md#from-draft-to-published).

## 8. Name the operators

Once an operator's naming lead has run, or it consented in writing to earlier naming, name it in a naming update. Operators are named independently; one update may name some while others are still pending.

```sh
swarmchase case consent 2026-10-portal --party portal.example.gov --note "agreed by email: <date and sender role>"
swarmchase case naming 2026-10-portal --party old.example.org --withhold --reason "…"    # only to never name one
swarmchase case notice 2026-10-portal --naming
swarmchase case reread 2026-10-portal
swarmchase case review-packet 2026-10-portal --naming
swarmchase case review 2026-10-portal --reviewer "R. Reviewer" --verdict approve
swarmchase notice update 2026-10-portal --naming
git add notices/2026-10-portal.md && git commit && git push
```

`notice update --naming` runs the checklist for the naming stage and needs an approved review of the current `naming.md`. A recipient's request to delay naming is recorded with `case note`; you may lengthen the lead with `case set --naming-days` but are not bound by it.

Details: [naming updates](../reference/notices.md#naming-updates).

## 9. Keep the notice current

- **Replies and corrections** are appended, never rewritten, and need no second review:
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
- **Exports.** For a recipient's tooling, `case export <id> --format stix|misp --audience provider|affected|public` writes a STIX bundle or a MISP event; after the notice is public, `--format oecd|aiid` drafts an incident-framework submission (the OECD draft with an EU AI Act Article 73 section). Each is a file to review and pass on by hand ([exports](../reference/cases.md#stix-export)).

Close the case with `case set <id> --status closed` when nothing is left to do. Its records stay with the case for the retention period in [policies](../policies.md#collection).

## Backups

Run `swarmchase backup create --keep 30` after case work, or on a schedule, and `swarmchase backup verify <file> --identity <key file>` now and then from your own machine. The key file never goes on the runner ([backups](../reference/configuration.md#backups)).
