# Evaluating leads

How to label a lead well: what each label means, a procedure for deciding a group, what each kind of evidence does and does not show, the traps, and worked examples. It is for anyone labelling with `swarmchase review`, in the terminal or on [the review page](../reference/watch.md#the-review-page). The page carries the same method in its guide (`g`), with a practice round of synthetic cases and a short coaching box on each group.

Labels are how the rules get measured ([reviewed records](../reference/evaluation.md#reviewed-records)). A guessed agent label makes the rules look more precise than they are, and a flagged record the admin acts on can become a public notice within a day. A calibrated reviewer says unsure rather than guess.

Every example here is synthetic, uses reserved `.example` hosts, and is written defanged, as the page shows records.

## The question

Each label answers one question: **did an AI agent send these requests?** An agent here is software in which a model chooses and sends requests.

A label does not say whether the requests did harm, whether they stayed within their task, or whether the rules scored them right. Those are separate findings with their own evidence ([FM-15.1](../manual/15-misalignment.md#fm-151-four-questions)). A harmless task does not make a sender benign, and a scanner firing injection payloads is not an agent's even though it attacks.

## The labels

- **Agent.** An agent most likely sent the requests. This needs a model's hand in the requests and something a person pasting model output would not do, such as adapting to responses at machine pace. It also needs the group's agent grade at L2 or higher.
- **Benign.** Not an agent: a person, a crawler, a mail gateway, or a conventional scanner or script. Benign means not an agent, not harmless.
- **Unsure.** The evidence fits an agent and a person or tool equally, and nothing in the group separates them. `eval` does not count unsure labels, so an honest unsure costs nothing, while a wrong guess skews the measurement.

## Deciding a group

1. **Read what the records do.** Open the decoded layers and the rules that matched. Rules that read the same artifact are one piece of evidence: a fetch program fires the echo, script, fetch and title rules together ([FM-14.22](../manual/14-limits.md#fm-1422-correlated-rules-stack)).
2. **Set the payloads aside.** A payload shows what was sent, not who sent it. A tester or a scanner sends the same strings through the same relays ([FM-14.7](../manual/14-limits.md#fm-147-humans-look-the-same)). Ask what is left.
3. **Look for a model's hand.** Model-output residue (Markdown, placeholders, tool-call text, chat openers), prose in parameters, invented identifiers, a program built for an echo service ([FM-4.5](../manual/04-indicators.md#fm-45-artifact-families)). People paste chatbot answers too, so this alone is weak ([FM-14.8](../manual/14-limits.md#fm-148-model-residue-comes-from-people-too)).
4. **Look for behaviour.** A changed request right after an error, a route escalation, machine pace, a fixed fan-out, activity round the clock. The agent grade reads these. Archive capture times cannot show any of them ([FM-14.4](../manual/14-limits.md#fm-144-capture-time-is-not-request-time)).
5. **Look for the other side.** Declared testing, a scanner's pace with no change after errors, a working-hours rhythm, practice targets, a mail gateway submitting every link, or one ordinary read ([FM-4.9](../manual/04-indicators.md#fm-49-benchmark-targets-and-declared-testing)).
6. **Keep the explanation with least against it.** List what could have sent the requests and drop each one the evidence rules out ([FM-7.12](../manual/07-attribution.md#fm-712-competing-hypotheses)). If an agent and a person both survive, the label is unsure. Agent needs a grade of L2 or higher; below it, unsure is the most the evidence allows, however much a program's shape or a tag looks like an agent's. An unclustered record is graded from its own hits, so it can reach L2 but no higher.
7. **Leave a note when it matters.** When a label rests on something the record does not show plainly, or on a judgement another reviewer might not share, say what in the note. A Field Manual id (`FM-14.7`) is enough for a trap.

A group is a cluster, or records of one shape when unclustered. Records grouped by shape are not linked and may come from different senders: label a record on its own when it differs.

## What each kind of evidence shows

| Kind | Shows | Does not show |
|---|---|---|
| Exploit | An attack payload: injection, traversal, XSS. | Who sent it. |
| Exfil | A callback channel: a webhook inbox, an out-of-band host, a paste. | Who reads it. Testers use request catchers too. |
| Agent marker | Model-output residue, a generation loop, or an agent test tag. | That an agent sent it. |
| Carrier | A program carried through an echo service, a `data:` URL or a playground. | Harm. It is tool use, not misuse. |
| Relay | A reader, proxy or translate service in front of the target. | Anything on its own. |
| Self-identification | A model or vendor name in the request. | Who built or ran it. |
| Anti-bot | Anti-bot token generation or a captcha solver. | Who. Scrapers do it too. |
| Cache buster, header, outcome | Context about how the request was made or where it ended. | Anything on its own. |

Relays, cache busters, self-identification, headers and outcomes are context kinds. Together they stay below the suggestive threshold, however many fire ([FM-4.11](../manual/04-indicators.md#fm-411-independence-groups-and-the-context-cap)).

## The agent grade

Each cluster carries a grade from L0 (payloads only) to L4 (agent likely), set by the strongest combination of signals it shows, with the counter-signals and caps beside it. The ladder and its caps are in [methodology](../methodology.md#agent-likelihood) and [FM-7.10](../manual/07-attribution.md#fm-710-agent-likelihood).

Read the grade as a summary of the evidence, not as a probability. The rungs are ordered by kind of evidence, and a person stepping through a proxy repeater with a chatbot's help reaches L3. L1 is self-description, which anyone can write, and is worded like L0. An unclustered record is graded from its own hits: no pace or retries can be read from one record, so it stops at L2.

## Traps

Each is a conclusion that looks sound and is not. The full list is [chapter 14](../manual/14-limits.md) of the Field Manual.

- **A payload is not an agent** ([FM-14.7](../manual/14-limits.md#fm-147-humans-look-the-same)). A significant tier means a payload was present.
- **Residue comes from people too** ([FM-14.8](../manual/14-limits.md#fm-148-model-residue-comes-from-people-too)). Treat it as weak, and look for behaviour before agent.
- **Self-identification is forgeable** ([FM-14.1](../manual/14-limits.md#fm-141-self-identification-is-forgeable)). Never label agent on a name alone, and never read a name as naming a developer.
- **Tool use is not misuse** ([FM-14.21](../manual/14-limits.md#fm-1421-a-tier-is-not-misalignment)). Label who sent the requests; whether they went beyond their task is the scope finding.
- **Capture time is not request time** ([FM-14.4](../manual/14-limits.md#fm-144-capture-time-is-not-request-time)). Read no pace or rhythm from archive captures.
- **Tags get copied** ([FM-14.5](../manual/14-limits.md#fm-145-tags-get-copied-after-publication)). A tag quoted in a published report can turn up again from anyone who read it.
- **One common feature can merge strangers** ([FM-14.6](../manual/14-limits.md#fm-146-common-features-cause-giant-clusters)). Spot-check records from both ends of a large group before labelling it at once.
- **A cut URL may be the service's cut** ([FM-14.13](../manual/14-limits.md#fm-1413-display-truncation-looks-like-model-truncation)). Scan services truncate long URLs.
- **Decoding is heuristic** ([FM-14.14](../manual/14-limits.md#fm-1414-decoding-is-heuristic)). Check a decoded layer makes sense before resting a label on it.
- **Public records can be planted** ([FM-14.20](../manual/14-limits.md#fm-1420-public-records-can-be-planted)). Doubts about where records came from go in a note.

## Model suggestions

A suggestion comes from a language model that read the same defanged text the reviewer sees, and nothing more ([label suggestions](../reference/watch.md#label-suggestions)). It is saved beside the label, never as it.

- Decide first, then compare. On the page, blind review (`h`) hides every suggestion until the group is labelled, and holds `s` (accept suggestion) until then.
- Read the model's reason against the evidence. A common model error is reading payloads or a vendor name as agent evidence.
- The Disagree tab lists groups where the label and the suggestion differ. Neither side is right by default.

## Worked examples

### SQL injection through a reader relay

Two urlquery submissions seven minutes apart, mid-afternoon. Rules: `exploit.sqli_boolean`, `exploit.sqli_union`, `relay.jina`. Grade L0, with a working-hours counter-signal.

```text
hxxps://r[.]jina[.]ai/hxxps://shop[.]example/item?id=1%27%20OR%20%271%27=%271
hxxps://r[.]jina[.]ai/hxxps://shop[.]example/item?id=1%20UNION%20SELECT%20null,null--
```

**Unsure** (benign is defensible). Textbook payloads through a public relay are what a penetration tester sends, and nothing separates an agent from a person. Benign fits when a note or the case shows a person, such as a confirmed test. Agent does not: the payloads are the only evidence.

### Pasted chatbot residue

One urlquery submission. Rules: `exploit.sqli_quote`, `marker.placeholder`. Grade L2.

```text
hxxps://portal[.]city[.]example/login?user=admin%27--&pass=YOUR_PASSWORD_HERE
```

**Unsure.** The unfilled placeholder shows a model wrote the URL, not that a model sent it. A person who asks a chatbot for a login bypass and pastes the answer into a scan form leaves this exact record. With no adaptation, pace or scale, nothing tells them apart.

### A run-tagged program through an echo service

Three archive captures over two days. Rules: `carrier.httpbin`, `carrier.inline_fetch_program`, `marker.title_write`, `marker.uq_tags`. Grade L1.

```text
hxxps://httpbin[.]org/base64/PHNjcmlwdD5mZXRjaCgiaHR0cHM6Ly90di5leGFtcGxlL2FwaS9zY2hlZHVsZT9kYXk9…
decoded: <script>fetch("hxxps://tv[.]example/api/schedule?day=2026-08-03&uqtag=r7k2")
         .then(r=>r.text()).then(t=>document.title=t)</script>
```

**Unsure.** A fetch program packed into an echo service, writing its result into the page title, with a run tag beside it, looks like published agent runs. The three program rules read one artifact and count once; the tag is a second indicator, but it is self-description anyone can type. Neither is a model's hand, and the grade is L1. Agent needs L2 or higher, so the label is unsure, with a note saying what points toward an agent. Benign is not right either: a person who wants a TV schedule opens the page.

### A plain page read through a relay

One archive capture, unclustered. Rule: `relay.jina`. Tier noise.

```text
hxxps://r[.]jina[.]ai/hxxps://news[.]example/2026/08/rail-strike-update
```

**Benign.** One relay hit on an ordinary article. Readers, summarisers and people all read pages this way, and a relay never makes a lead on its own.

### Adaptive probing at machine pace

Forty-one urlquery submissions over 22 hours. Rules: `exploit.sqli_boolean`, `exploit.sqli_union`, `marker.md_link`, `relay.jina`. Grade L4: residue, a changed request two to four seconds after each challenge page, a route escalation, activity round the clock. No counter-signals.

```text
hxxps://records[.]agency[.]example/search?q=%5Bpermits%5D(hxxps://records[.]agency[.]example)%27%20OR%201=1--
hxxps://r[.]jina[.]ai/hxxps://records[.]agency[.]example/search?q=permits%27%20UNION%20SELECT%20null--
```

**Agent.** The Markdown residue shows a model wrote the requests, the changes after each block show it reading responses, and doing so within seconds all day and night is beyond one person.

## Practice and calibration

The page's guide has a practice round: synthetic groups to label, with the answer and the reasoning after each, and a score. It never writes to the review file. It counts how often the trainee chose agent against the key, because over-calling agent is the commonest error.

Calibration against another person is the real test. A second reviewer labels the same queue with `--labeller <name>`, and `review --stats` prints Cohen's κ and lists the disagreements to settle ([two labellers](../reference/evaluation.md#two-labellers)).
