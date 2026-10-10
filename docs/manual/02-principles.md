# 2. Principles

[Manual index](README.md) · Previous: [1. Scope](01-scope.md) · Next: [3. Sources](03-sources.md)

Eight principles govern every later chapter. Where a later section and a principle seem to conflict, the principle wins and the conflict is a defect in the manual.

## FM-2.1 Passive only

Practitioners read public indexes and records. They **must not** fetch a URL an agent submitted, read from or post to an agent's callback channels, interact with an agent, or probe infrastructure suspected of running agents. The only request to an affected organisation's own host is for its published security contact.

Why: a submitted URL can carry a live payload or tell the operator they were seen; a callback inbox is the swarm's channel, and reading it is joining it; probing turns observation into an incident of its own. The test every source passes is in [FM-3.2](03-sources.md#fm-32-passivity-test).

## FM-2.2 Evidence over narrative

Every claim traces to a record link and the rule that matched it, or to a cited public document. A report reads as a chain of evidence, not a story with evidence attached. Claims are tagged by kind ([FM-7.6](07-attribution.md#fm-76-claim-tags)), so a reader can see where observation ends and judgment begins. This is the distinction [ICD 203](references.md#standards-and-guidance) draws between underlying information and an analyst's assumptions and judgments.

## FM-2.3 Calibrated attribution

Every attribution states the strongest class of evidence it rests on ([FM-7.2](07-attribution.md#fm-72-developer-and-operator-ladder)), a label ([FM-7.7](07-attribution.md#fm-77-attribution-labels)), and likelihood words from a fixed table ([chapter 8](08-confidence.md)). Weak evidence is reported as weak. A self-identification never names a developer, and an ASN names a host.

## FM-2.4 Admin gate

Tools and assistants collect, grade, link, draft reports, find contacts and prepare notices. Only a named person, the admin, decides that evidence is sufficient, classifies endpoints, merges clusters into fleets, sends reports and publishes notices. No step past drafting is automatic, and unreviewed leads never leave the collection host except to reach the admin privately.

## FM-2.5 Publish what informs, withhold what enables

A notice tells the public what happened, to whom, by whose agents (at the stated strength) and what to check. It withholds what would let a reader take over or reuse the swarm's channels, use captured secrets, or exploit an unfixed weakness ([FM-11.4](11-notices.md#fm-114-what-a-notice-withholds)). Private reports to the affected parties carry everything they need.

## FM-2.6 Correct in public

A published notice is never rewritten. Corrections, retractions, replies and status changes are appended as dated updates, and the feed carries each one ([FM-11.6](11-notices.md#fm-116-corrections-and-retractions)). A withdrawn claim stays visible as withdrawn.

## FM-2.7 Minimise sensitive data

Secrets in records are replaced at ingest with a short hash that still links records but does not reveal the secret. Raw collection stays out of public repositories, and is deleted on a published retention schedule. Records a case needs are copied into the case, which is kept private. Operator-supplied logs are the operator's to publish ([FM-10.7](10-disclosure.md#fm-107-operator-supplied-logs)).

## FM-2.8 Proportionality

The effort and exposure of a step match what is at stake. A single suggestive record does not justify a report; a significant cluster against a public body's login endpoint justifies prompt disclosure. Naming an organisation in public is the most consequential act in the method, so it has the strictest gate ([FM-7.8](07-attribution.md#fm-78-the-naming-gate)). Retention is as short as the casework allows.
