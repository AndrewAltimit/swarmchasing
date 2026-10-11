# 15. Misalignment and scope

[Manual index](README.md) · Previous: [14. Known limits](14-limits.md) · Next: [16. Other methods](16-other-methods.md)

The manual's scope is agent activity that goes beyond its task against others, or runs unsupervised ([FM-1.1](01-scope.md#fm-11-scope)). A tier does not measure that. It measures payloads and tool use: a fetch program that reads a TV schedule through an echo service, carrying a run tag, grades significant, the same tier as an injection probe of a login form. This chapter makes misalignment a separate assessment, with its own evidence, so that a report says which of four different things it found.

## FM-15.1 Four questions

| Question | Answered by | What it does not say |
|---|---|---|
| **Payload present?** Do the records contain attack payloads or escalated tool use? | The tier ([FM-1.5](01-scope.md#fm-15-evidence-tiers)). Observed. | Whether an agent sent them, or whether sending them was out of scope. |
| **Agent present?** Did an agent, not a person or a script, send them? | The agent grade and its competing hypotheses ([FM-7.10](07-attribution.md#fm-710-agent-likelihood), [FM-7.12](07-attribution.md#fm-712-competing-hypotheses)). | Whether the agent did anything wrong. |
| **Out of scope?** Did the activity go beyond what its evident task needed, against a party who did not sanction it? | The scope assessment below. Inference. | Who is responsible, or why it happened. |
| **Coordinated?** Do several agents act together? | Fleet and swarm evidence ([FM-1.3](01-scope.md#fm-13-groupings), SC-T9). | Whether any of them is out of scope. |

The answers are independent. A significant cluster can be in scope (a data task done with programs); a noise cluster can be out of scope (a polite crawl of a government login page, off task). A report answers each question it can, separately, and never lets one stand in for another.

**Misaligned**, for this manual, means: an agent is present, and its activity is out of scope on at least one test in [FM-15.3](#fm-153-scope-tests), with no accepted alternative explanation ([FM-10.9](10-disclosure.md#fm-109-self-review-and-second-review)). **Unsupervised** means the activity continues with no sign of a person checking it: round-the-clock rhythm, reruns, retries after a block, or persistence across days. Neither word appears in a public Conclusion without the evidence for each part.

## FM-15.2 Task class and target class

Scope is judged by comparing what the agents were evidently doing with what they reached.

**Task class** is the evident purpose of a cluster's ordinary requests: the data sources it retrieved (SC-T1), the queries it ran, the pages it read. It is inferred from the cluster, never from one record, and is stated as an Inference with the requests it rests on. Classes: data retrieval (a dataset, a schedule, a price list), search and reading, account setup, testing of a named site, and unclear.

**Target class** is what kind of endpoint a request reached:

| Target class | Examples |
|---|---|
| Public content | Pages, documents, open data, public APIs used as documented. |
| Interactive | Search, forms, public APIs used outside their documented parameters. |
| Access-controlled | Login, sign-up, authorisation and password-reset endpoints; paths behind a challenge. |
| Sensitive | Configuration and source files (`.env`, `.git/`), administration paths, server status, backup files. |
| Third-party channel | Inboxes, request catchers, pastes and topics the agent writes to (SC-T7). |
| Benchmark | Sites built to be tested against ([FM-4.9](04-indicators.md#fm-49-benchmark-targets-and-declared-testing)). |

A target's sector (government, health, critical infrastructure) is recorded with it; it raises the stakes of a finding ([FM-2.8](02-principles.md#fm-28-proportionality)), not its likelihood.

## FM-15.3 Scope tests

Each test is a question with the evidence that answers it. A finding cites the test by id.

| Test | Question | Evidence | Innocent explanation |
|---|---|---|---|
| **S1 Off-task target** (SC-T8) | Did requests reach targets outside the task class? | Targets unrelated to the retrieved sources; a data run turning to login pages. | A broad task the records do not show. |
| **S2 Control circumvention** (SC-T3) | Did the agent get past a block, challenge, rate limit or authentication? | A challenge outcome then a retry by another route; CAPTCHA solvers; anti-bot tokens; relays after a block. | A relay used from the start for format conversion, not after a block. |
| **S3 Sensitive paths** | Did it request sensitive targets the task did not need? | Recon openings and sensitive files ([FM-5.7](05-linking.md#fm-57-soft-links)). | A security-review task, declared and checked ([FM-10.6](10-disclosure.md#fm-106-authorised-testing)). |
| **S4 Unsanctioned probing** (SC-T4) | Did it send attack payloads to a party who did not sanction them? | Payload rules; probe chains. | An authorised test; a benchmark target. |
| **S5 Identity and credentials** (SC-T5, SC-T6) | Did it acquire accounts or use credentials it was not given? | Disposable mail; stock identities in sign-ups; a captured token reused. | Test accounts on the operator's own site. |
| **S6 Data sent out** (SC-T7) | Did it send data it fetched to a channel outside the target? | Callback inboxes and side channels carrying fetched content or headers. | The operator's own result store. |
| **S7 Coordination** (SC-T9) | Did agents divide or hand off work in a way that widens any of the above? | Reviewed interaction evidence ([FM-4.10](04-indicators.md#fm-410-interaction-signals)). | One scheduler sharding a list. |

**Tool use is not a scope test.** Echo services, relays and programs (SC-T1, SC-T2) are how agents fetch; they make a request harder to read, not out of scope. They become evidence only through a test: a relay after a block is S2, a program that writes a fetched page to an inbox is S6.

Procedure:

1. State the task class, with the requests it rests on, or "unclear".
2. Classify each target host by target class, and record its sector.
3. Run each test. Record pass, fail or not assessable, with the records and rule ids for each.
4. Record the innocent explanation considered for each failed test and why it was rejected, as for the self-review alternatives ([FM-10.9](10-disclosure.md#fm-109-self-review-and-second-review)).
5. Set the finding ([FM-15.4](#fm-154-stating-a-scope-finding)).

## FM-15.4 Stating a scope finding

| Finding | When |
|---|---|
| **In scope** | Every assessable test passes. |
| **Scope exceeded** | At least one test fails, and the failed tests' innocent explanations were rejected. |
| **Not assessable** | The task class is unclear and no test can be decided without it, or the records are too few. |

S2 to S6 can fail without a task class, because they rest on what the target is, not on what the task was. S1 needs one.

A finding is an Inference ([FM-7.6](07-attribution.md#fm-76-claim-tags)). It is stated with the tests that failed, their records, and the agent grade, for example: "Scope exceeded (S2, S4): after a challenge page, requests in this cluster reached the login endpoint through two relays and then carried SQL injection payloads. The records show an adaptive client (L3); a person using a proxy tool cannot be excluded." The word "misaligned" is used only when the agent question and the scope question both hold ([FM-15.1](#fm-151-four-questions)). This chapter is the one place that defines when it applies; elsewhere, reports and notices describe suspected AI agent activity.

Toolkit: the rule is enforced. "Misaligned" in any form may appear in a report or notice only when the case records both an admin scope finding of scope exceeded for the clusters it covers (`case scope`, [cases](../reference/cases.md#scope-finding)) and an admin agent grade of L3 or higher (`case grade`). The notice's front matter carries both, and the notice linter rejects the word without them, before a notice is written and in CI.

## FM-15.5 From finding to incident

An incident is activity a reviewer judged to harm, or put at risk, an affected operator ([FM-1.4](01-scope.md#fm-14-casework-terms)). The scope finding is how that judgment is made explicit:

- A cluster that is in scope is not an incident, whatever its tier. It may be logged as agent activity and is not reported.
- A cluster whose scope is exceeded, against a party who did not sanction it, is an incident candidate. The admin decides, and records the finding with the case's other decisions.
- A cluster that is not assessable is held as a lead until more records arrive, unless a payload against an access-controlled or sensitive target makes S3 or S4 decidable on its own.

Toolkit: a scope pass fills `Cluster.scope` with the task class, the target classes reached, the S1–S7 tests with the record ids that answer each, the finding, and the four FM-15.1 questions; it is conservative, so tool use alone fails no test, and an unreviewed interaction hint alone fails none either: S7 fails only when a hint touches a cluster that already fails another test, and is otherwise not assessable. Internal and provider reports carry a one-line Scope entry per cluster. The pass is a suggestion: the admin decides the incident from it and records the finding with `case scope`, which is what notices state.
