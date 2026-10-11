# For providers

This page is for trust and safety, security and abuse teams at an AI provider or agent host that received a report from swarmchasing, or found its platform mentioned in a published notice. It covers what the report holds, how to check its evidence, what the STIX and MISP exports carry, when the notice is published and how you are named in it, and how to reply.

How the analysis works is in [methodology.md](../methodology.md). The policies behind reports and notices are in [policies.md](../policies.md). Operators of the targeted sites have their own page, [for-operators.md](for-operators.md).

## Why you received a report

A case lists as contacts the providers its attribution claims name at the developer or hosting layer, and the admin sends each of them a report. The address comes from the [provider directory](../../contacts/providers.toml), which records the page each channel was read from and when. If the report reached the wrong team, tell us the right channel.

**What it does not mean:**

- **It does not say you operated the agents.** Each claim states the strongest class of evidence it rests on, weakest first: self-identification, hosting network, identifiers shared with a confirmed incident, infrastructure the provider owns, confirmation by the provider. A model or vendor name inside a request is the weakest: agents misreport who built them, and anyone can submit such a string to a public scanner. See [attribution](../policies.md#evidence-and-attribution).
- **It does not prove an AI agent sent every request.** The rules detect agent-like activity, and a person or a conventional scanner using the same payloads leaves the same records. The report grades how likely an agent is, separately from the payloads.
- **It does not say any request succeeded.** Public records show that a request was submitted or captured. We never contact the affected systems to find out more.

## What a provider report holds

Its subject is "Suspected AI agent activity: <case title> [<case id>]", and its title "Report of suspected AI agent activity". It holds:

- a **summary**, the **indicators** that matched by rule, and the window of activity;
- **attribution**: every claim, by layer (developer, hosting network, harness, model family), with its label, tag and evidence class. Harness and model-family candidates are ranked here and never named in public;
- **why we think this is an agent**: each cluster's agent-likelihood grade from L0 to L5, with its signals, counter-signals and caps, and the case decision when there is one;
- each cluster's **scope assessment** in one line, and its **timeline**: runs, sources by provenance and corroboration, and how many records carry model-written artifacts;
- **possible interaction** between the report's clusters (SC-T9), as hints for review;
- **representative records**, each linked to the public record it was taken from;
- the **method and its limits**, the **requested action**, and a **publication** section with the times described [below](#when-the-notice-is-published).

It leaves out the operators' **Endpoints** table, the basis of the case's agent-grade decision, and any declaration of authorised testing, which stay in the case notes. Logs an affected operator sent us may be part of its evidence.

The requested action is to check whether the patterns match agents or sandboxes on your platform during the window, to stop the runs if they do, and to tell us whether you can confirm or rule out involvement.

## Check the evidence

A report sent by email carries an evidence bundle: the redacted records, their analysis, a stamp (rules version, toolkit version and commit, method version, and the tier of every flagged record and cluster) and a SHA-256 manifest. Two ways to check it:

- **In the browser.** The site's **Tools** page loads the bundle and re-runs the check in the page. Nothing is uploaded and nothing needs installing.
- **With the CLI.** From a checkout of this repository, `swarmchase case verify path/to/bundle`. It checks the manifest, re-runs the analysis and fails if any tier or cluster differs from the stamp.

The check needs the rules the bundle was made with; the stamp names them. A bundle that verifies shows that the tiers and clusters follow from the records under those rules. It does not show that the records are genuine, and the manifest is not signed. Follow each record's link to the archive capture or scan report it came from. The full procedure is in [for-operators.md](for-operators.md#verify-an-evidence-bundle).

The URLs in `records.ndjson` are as they were recorded, with secrets replaced by hashes. They can carry attack payloads and live callback channels. We never open them; treat them the same way, and open them only in an isolated environment if you must.

The case id in the subject is the id the public notice carries (`notices/<case id>/` on this site), so a report and its notice can be matched.

## STIX and MISP exports

For your own tooling, the admin can send the same case as a STIX 2.1 bundle or a MISP event; ask for either in your reply. Both are scoped like your report, and the tool that builds them never connects to anything ([STIX export](../reference/cases.md#stix-export), [MISP export](../reference/cases.md#misp-export)).

**The STIX bundle** holds:

- indicators as STIX patterns for run tags, callback channels, agent markers and flagged user agents;
- `observed-data` for each cluster, relationships between the objects, and a `report`;
- each cluster as an `x-sc-agent-run` object (span, tactics, artifact families, batch width, tier, attribution per layer), with the `extension-definition` that defines it and a [JSON Schema](../../schemas/stix/x-sc-agent-run.json);
- each SC-T tactic as external references to the MITRE ATLAS and ATT&CK techniques and OWASP agentic entries the Field Manual maps it to, and as kill chain phases;
- each merged fleet as a `grouping` of its runs.

Ids are UUIDv5 of the content, so an export made again from the same case is identical byte for byte and two versions can be compared directly. A private export carries the TLP:AMBER marking.

**The MISP event** carries the same content as attributes (run tags, agent markers, callback domains and user agents marked for IDS; observed URLs, domains, client addresses and networks not for IDS), one `swarmchasing-agent-run` object per run, and tags for the TLP, the tactics and their mapped techniques. It is unpublished, with distribution "your organisation only".

## When the notice is published

Every confirmed incident gets a public notice, in two stages ([two stages](../policies.md#two-stages)):

1. **The indicator notice** describes the activity and how to recognise it, and names and locates no affected organisation.
2. **Naming updates** add the affected organisations, each after its own naming clock or with its consent.

Your clock for the indicator notice is 0 hours: it may follow your report as soon as every party has been sent its report and every operator's indicator clock has run (24 hours when an endpoint was compromised). The publication section of your report gives the time. Nothing you say, ask or offer moves it; it is not an embargo, because others the agents target can protect themselves only once the indicators are out. Each notice and each naming update is approved by a second reviewer before it is published. See [lead times](../policies.md#lead-times).

## How you are named

The operators' naming clock does not apply to you. How you appear follows the attribution rules from the indicator notice on ([naming](../policies.md#naming)):

- **Below shared identifiers,** you are named only as the party notified, never as the operator, and never in a notice title. The notice says: "Requests in this cluster identify themselves as using <model> from <provider>. Self-identification is the weakest evidence we use. We have not confirmed that <provider> operated, deployed or authorised them. <provider> has been sent the full evidence."
- **On your own infrastructure,** the notice says the requests came from infrastructure you operate, and treats who deployed the agents as a separate question.
- **As a developer,** only when the evidence reaches the level the admin set for the case (by default, identifiers shared with a confirmed incident), and never on self-identification alone.

Harness and model-family candidates are never named in public. A notice calls activity misaligned only when the case records that it went beyond its task and an agent grade of L3 or higher.

## Reply, confirm or send a statement

Reply to the address the report came from and keep the case id in the subject.

- **Confirm or rule out.** A confirmation is the strongest evidence class, and the case records it. If you rule out involvement, say on what basis; we correct the record the same way.
- **Statements.** A statement you send for publication is appended to the notice verbatim, as a dated update with your organisation as its source. It never delays publication.
- **Corrections.** If an attribution is wrong, tell us what and why. A correction is appended as a dated update, and a notice whose evidence does not hold is retracted the same way. Earlier entries are never rewritten, and every update appears in the site's Atom feed.
- **Authorised testing.** If the activity was an authorised red-team exercise or evaluation, say who owns it. We contact the declared owner; if it confirms the activity was authorised and in scope, the notice is published as "authorised test, closed". It is not withheld.
- **Without a report.** If you found your platform in a notice but received no report, or want to reach us privately for any other reason, use [private vulnerability reporting](https://github.com/AndrewAltimit/swarmchasing/security/advisories/new) on this repository. Do not open a public issue about an affected host or organisation: anything posted there is public at once.
