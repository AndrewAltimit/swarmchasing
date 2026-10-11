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
swarmchase case endpoint 2026-10-portal shop.example.org compromised --basis "operator confirmed a web shell: <link>"
swarmchase case claim 2026-10-portal --party … --evidence provider_confirmed --detail …
swarmchase case claim 2026-10-portal --layer harness --party … --detail …
swarmchase case note 2026-10-portal "Rerun of C4 from last week; same host order."
```

Every endpoint needs a decision (`compromised`, `targeted`, `historical`, `not-affected`) before a notice can be added. `compromised` needs a basis beyond the requests the endpoint received. An endpoint seen only in records anyone could have submitted to a scan service is named only with `--single-source-reason "…"`. Attribution claims carry their layer, evidence level and tag; a developer is named only at or above the case's naming threshold, and harness and model-family candidates never ([attribution claims](../reference/cases.md#attribution-claims)).

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

`case contacts` adds the provider's channels from the [provider directory](../reference/cases.md#the-provider-directory) when a claim names it, then reads security.txt, then RDAP abuse addresses. Add anything else by hand with `case contact add` (a CSIRT, a declared owner). `case draft` writes an unsent `.eml` with a fresh evidence bundle into `outbox/`, or paste-ready text for a web form. Each report states when the notice is scheduled. Read every draft before sending it.

Details: [contacts](../reference/cases.md#contacts), [drafts](../reference/cases.md#drafts).

## 6. Send the reports

The reports go first; the notice follows on a fixed lead time: none for the provider, 4 to 12 hours for the operator of a targeted endpoint (6 unless you set the case otherwise), 24 hours for a compromised one ([lead times](../policies.md#lead-times)). Nothing a recipient says extends it.

Send each draft from your own mail client (or the organisation's form), then record it, with the time when you record it later:

```sh
swarmchase case sent 2026-10-portal --to security@example.gov --channel email
swarmchase case sent 2026-10-portal --to abuse@provider.example --at 2026-10-12T14:05:00Z
swarmchase case no-contact 2026-10-portal old.example.org --searched "security.txt, RDAP: nothing"
swarmchase case set 2026-10-portal --lead-hours 8          # optional, 4 to 12
```

Record a party with no contact rather than leaving it out; the notice then says contact was attempted. `case status` shows every party's clock and when the notice may be added.

Details: [lead time](../reference/cases.md#lead-time).

## 7. Draft, re-read and publish the notice

1. Draft the notice once the sends are recorded:
   ```sh
   swarmchase case notice 2026-10-portal
   ```
   This writes `notice.md` in the case and prints what it withheld, what it could not classify and anything that got through. Edit the draft until nothing needs a decision.
2. An hour or more later, read the whole draft again and record it. An edit after that needs another re-read:
   ```sh
   swarmchase case reread 2026-10-portal
   swarmchase case checklist 2026-10-portal
   ```
3. Once the lead time has run, add the notice and publish it by committing:
   ```sh
   swarmchase notice add 2026-10-portal
   git add notices/2026-10-portal.md && git commit && git push
   swarmchase notice published 2026-10-portal
   ```

`notice add` prints the [self-review checklist](../reference/cases.md#self-review-checklist) and refuses while any item fails, before the lead time has run included; it leaves the case `reported` with its publication pending. `notice published` checks the pushed file is on the remote and marks the case `published`. The pre-commit hook and CI lint the notice; the deploy on `main` builds it into the site and the feed.

Details: [notices](../reference/notices.md#from-draft-to-published).

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
- **Exports.** For a recipient's tooling, `case export <id> --format stix|misp --audience provider|affected|public` writes a STIX bundle or a MISP event; after the notice is public, `--format oecd|aiid` drafts an incident-framework submission (the OECD draft with an EU AI Act Article 73 section). Each is a file to review and pass on by hand ([exports](../reference/cases.md#stix-export)).

Close the case with `case set <id> --status closed` when nothing is left to do. Its records stay with the case for the retention period in [policies](../policies.md#collection).

## Backups

Run `swarmchase backup create --keep 30` after case work, or on a schedule, and `swarmchase backup verify <file> --identity <key file>` now and then from your own machine. The key file never goes on the runner ([backups](../reference/configuration.md#backups)).
