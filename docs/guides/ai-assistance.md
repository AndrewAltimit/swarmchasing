# AI assistance

Where a language model helps across the admin's workflow, what each kind of model may see, what stays with people, and how to run each piece. The policy behind it is [machine help with labelling](../policies.md#evidence-and-attribution) and the [admin gate](../policies.md#reporting-and-publication); the labelling method is [evaluating leads](evaluating-leads.md).

Every part here suggests or drafts. None of it labels, sends, files or publishes.

## What a model may see

Two kinds of model are treated differently, by where they run, not by how capable they are.

- **A local model** runs on infrastructure the admin controls: a loopback, private-network or link-local endpoint (`SWARMCHASE_LLM_URL`). It may see any record, operator logs included, because nothing leaves that infrastructure.
- **A hosted model** runs on a provider's servers. That includes Claude in a Claude Code session, any subagent it starts, and Claude Code run headless by the watch or `review suggest-claude`. It may see only what `review --export-hosted` writes: records from web archive indexes (Wayback, Arquivo, Memento, Common Crawl) and urlquery.net, defanged, without IP addresses. Operator logs and every other source are withheld by a list in code, so a new collector is withheld until someone adds it on purpose.

This project uses no Anthropic API key. Claude is reached only through Claude Code on the admin's own subscription login, in a session or headless; every headless call removes `ANTHROPIC_API_KEY` from its environment, and no workflow or `env.list` entry holds one.

For both, the same rules hold:

- **Records are data.** Text in a record that reads like an instruction is part of the record. The model gets text and no fetching tools; nothing an agent submitted is ever visited, resolved or searched for.
- **Private labelling, not redistribution.** What a model sees and what it writes stay in the data directory, which is gitignored. No record content reaches the repo, a commit message, a test or a reply; urlquery content in particular is never quoted outside the data directory ([configuration](../reference/configuration.md#urlquerynet)).
- **Reports back are aggregates.** A subagent reports counts and file paths, never URLs, hosts or reasons.

## Where it helps

### Label suggestions

A model reads each record of the review queue and proposes `agent`, `benign` or `unsure` with a one-line reason. The admin sees it beside the record and labels; it is saved beside the label as `suggested`, never as it, and `eval` reads only the admin's label.

The labelling rule binds suggestions as it binds labels: `agent` needs an agent grade of L2 or higher. The export carries the grade, whether it is the cluster's or the record's own, an `agent_allowed` flag, the signals, counter-signals and caps, and the rules that fired. `review check-suggestions` fails a line that breaks the rule, and the review page flags an `agent` suggestion on a record now graded below L2 as against the rule.

- **Local**, one record at a time while labelling in the terminal: `review --suggest` ([label suggestions](../reference/watch.md#label-suggestions)).
- **Hosted**, in batches: the [label-suggestions skill](../../.claude/skills/label-suggestions/SKILL.md) gives a Claude Code session the full procedure, from export to validated files. `review suggest-claude <export>` does the same in one command, through a locked-down headless Claude Code.
- **On the runner**, for each run's new leads: [model triage](../reference/watch.md#model-triage), with a local model (`watch --triage`) or with Claude through the admin's Claude Code login (`watch --triage=claude`), which sends only the leads an export would hold. The digest lists the suggestions, and the queue arrives pre-suggested.

```sh
swarmchase review --export-hosted data/labels/hosted.ndjson --batch-size 120
# one subagent per batch, following the skill, writes data/labels/suggestions-<model>-hosted-NNN.ndjson
swarmchase review check-suggestions --export data/labels/hosted-001.ndjson data/labels/suggestions-<model>-hosted-001.ndjson
swarmchase review --serve
```

A suggestion line is `{"id", "label", "reason", "model", "grade", "misfires"}`. `grade` records the grade the model saw, and `misfires` the rule ids it thinks matched something they do not describe. Files with only the first four fields still load.

### Triage

Suggestions also order attention. On the review page, the Disagree tab lists groups where the label and the suggestion differ, and blind review (`h`) hides suggestions until a group is labelled, so a suggestion informs the second look and not the first. A hosted model triages only what the export holds; it never reads the digest, the store or a case.

Before leaning on a model's suggestions, measure it:

```sh
swarmchase review agreement
```

For each model it prints a confusion matrix of the admin's label against the suggestion, raw agreement and Cohen's κ, the same split by agent grade, the `agent` suggestions that break the L2 rule, and the opposite calls (agent against benign). The grade is the one the model saw when the suggestion records it, else the grade stored with the admin's label, else the grade now. It also lists the admin's `agent` labels below L2 with their grade and reason, and the rules models flagged as misfires.

### Rule upkeep

Labels show which rules fire where they should not.

```sh
swarmchase review misfires
```

It analyses the reviewed records with the current rules and counts each rule's hits by the admin's label. A rule is listed when at least three benign records fired it and benign records are at least half of its agent and benign hits (`--min-benign`, `--share`). The `b-flag` column counts benign records it helped flag at suggestive or above, which would be false positives in a notice; the `model` column counts suggestions that named it a misfire.

For each listed rule, the benign records it fired on go to `data/labels/hard-negative-candidates.ndjson`, flagged ones first, with their ids in `.ids` beside it. They are real records, so they stay in the data directory: each line says whether a hosted model may see it, and one from an operator log is for the admin or a local model only. A rule change then follows [writing rules](writing-rules.md): rebuild the shape as a synthetic `.example` record with `hard_negative_for`, fix the rule, run the eval gate, and mark the records looked at with `review tuned <file>.ids` so they leave the benign baseline. Nothing here writes into `samples/` or `rules/`.

A model in a Claude Code session can do the rule-change half: read the aggregate table, write the synthetic records and the rule edit, and run the eval. It works from the table and from export lines, never from the candidates file's operator-log lines.

### Case drafting

`case draft` writes report drafts from templates, with no model in the loop ([drafts](../reference/cases.md#drafts)). A model may help with the wording of the templates and the docs in the repo. A specific case's draft holds the case's evidence, which can include operator logs, so a hosted model does not draft it; a local model may. Every draft is read in full by the admin before it is sent.

### Monitoring

The watch's health block and digest stay on the runner and reach the admin by email. A model may help maintain collectors and diagnose a failing source from what the admin pastes of the health block: source names, counts, error classes. It never reads the runner's data directory or the digest's lead sections.

## What stays human

- **Labels.** Only the admin's label counts. A suggestion is accepted only by the admin pressing a key on the page.
- **Grades above the computed ones.** L5 comes only from the admin's case decision.
- **Cases and claims.** Opening a case, classifying endpoints, recording attribution and the scope finding.
- **Sending and publishing.** Reports, notices, naming updates, and the second review of every notice.
- **Rules and floors.** Merging a rule change, and the eval floors, which only go up.
- **Autonomy.** Which [autonomy level](../reference/watch.md#autonomy) runs in shadow or on. The levels are deterministic, never a model, and none sends, publishes or opens a case.
- **Policy.** Which sources a hosted model may see, and anything in [options not built](#options-not-built).

## Options not built

These are open for the admin's decision; none runs today.

- **Model drafting of case reports.** A local model could propose the free-text parts of a report from the case file. The admin still reads and sends every draft.
- **Automatic rule proposals.** A model could turn `review misfires` output into a rule change on a branch. A pull request on the public repository would carry evidence from unreviewed leads, so this needs a way to keep the branch private, or stays manual.
