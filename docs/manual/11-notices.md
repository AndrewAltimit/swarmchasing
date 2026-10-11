# 11. Notice standard

[Manual index](README.md) · Previous: [10. Disclosure](10-disclosure.md) · Next: [12. Interoperability](12-interoperability.md)

## FM-11.1 Purpose

A notice is the public page for one incident. It lets anyone targeted by the same agents recognise the activity in their own logs, tells the public whose agents were involved at the stated strength and, once their naming lead has run, which organisations were affected, and keeps a permanent, dated record of what was known when. One incident has one notice.

## FM-11.2 Structure

A notice is published in two stages ([FM-10.2](10-disclosure.md#fm-102-lead-times)): the indicator notice, then naming updates appended to it.

**Front matter:** the notice id, the status ([FM-11.3](#fm-113-status-lifecycle)), the providers named (with label), the affected hosts named so far, the scope finding and agent grade of the clusters it covers ([FM-15.4](15-misalignment.md#fm-154-stating-a-scope-finding)), and the dated updates.

**Body** of the indicator notice, in this order:

1. **Summary.** What happened, to what classes of target, when, and the attribution Conclusion with its label and likelihood words.
2. **Targets.** Each affected endpoint by target class and sector only ([FM-15.2](15-misalignment.md#fm-152-task-class-and-target-class)), with what it saw: compromised, targeted or historical.
3. **Attribution.** Each layer that has a claim ([FM-7.1](07-attribution.md#fm-71-four-layers)), with tagged claims ([FM-7.6](07-attribution.md#fm-76-claim-tags)).
4. **Timeline.** Clusters and runs with first and last seen, naming the timestamp kind.
5. **What to look for.** Indicators safe to publish: relays, carriers, tactics, payload families and shapes, run tags already published elsewhere that are not credentials, the kinds of callback service used.
6. **Withheld.** What was withheld, by category, and why ([FM-11.4](#fm-114-what-a-notice-withholds)).
7. **Method and limits.** The method version (cite this manual), the rules version, the limits that bear on the claims ([chapter 14](14-limits.md)), and that the notice was reviewed by a second reviewer before publication ([FM-10.9](10-disclosure.md#fm-109-self-review-and-second-review)).
8. **Updates.** Dated entries, oldest first, never rewritten.

The indicator notice names and locates no affected party: no organisation name, host (defanged or not), registrable domain, IP address or network of a target, and no target URL or path that contains an affected host.

A **naming update** names the affected organisations whose naming lead has run or who consented, each with its defanged hosts and what its endpoints saw. Later naming updates name the rest; an operator the practitioner decided never to name is not named.

Hosts are defanged (`a[.]b`) and no URL from a record is a link.

**Who is named, and how.**

- An affected organisation is described as targeted or affected, never as the actor. "Compromised" appears only for an endpoint classified so on a recorded basis beyond the requests it received.
- An endpoint seen only in records anyone could have submitted is named only with the practitioner's logged reason, as "URLs targeting <organisation>'s hosts were submitted to public scan services".
- A provider below shared identifiers is the party notified, in these words: "Requests in this cluster identify themselves as using <model> from <provider>. Self-identification is the weakest evidence we use. We have not confirmed that <provider> operated, deployed or authorised them. <provider> has been sent the full evidence." The title never names it.
- At provider infrastructure, the notice says the requests came from infrastructure that the provider operates, and keeps who deployed them separate.
- The activity is described as suspected AI agent activity. "Misaligned" appears only where [FM-15.4](15-misalignment.md#fm-154-stating-a-scope-finding) allows it.

Toolkit: `case notice` drafts the indicator notice from the case, and the admin edits it. The draft's attribution section gives each host claim, and each developer claim that passes the naming gate, with its layer, label, claim tag and evidence, and a Conclusion line for each named developer; a developer below shared identifiers gets the notified-party line, with its label and tag, and the sentence about the evidence only when a send to the provider is recorded; harness and model-family candidates are left out. Claim tags outside the attribution section are added by hand. The naming update is drafted into the case's `naming.md` and appended with `notice update --naming` ([notices](../reference/notices.md#naming-updates)).


## FM-11.3 Status lifecycle

| Status | Meaning | Moves to |
|---|---|---|
| **Active** | Matching activity seen recently, or no evidence it stopped. | Contained, when no matching record has been seen for a set period and the admin agrees. |
| **Contained** | No matching activity for the set period, or the provider confirms it stopped the agents. | Active, if matching activity returns; historical, when the case closes. |
| **Historical** | Activity ended before discovery, or the case is closed. | Active, if matching activity returns. |

Every status change is a dated update with its reason. Toolkit: the watch matches new records against each case's indicators and proposes status changes; the admin applies them ([watch](../reference/watch.md#case-status)).

## FM-11.4 What a notice withholds

| Withheld | Why |
|---|---|
| Live callback channel identifiers: inbox, webhook, request-catcher, topic and paste identifiers | A reader could take over, read or feed the swarm's channel. |
| Captured credentials and cookies, and linking values that could be credentials (`tok`, `session`) | They are secrets, even when redacted to a hash. |
| Attack details and request URLs for endpoints marked compromised | They describe how to exploit a weakness that may still be open. |
| The local part of e-mail addresses, except role mailboxes | Personal data with no public value. |
| Operator-supplied logs without consent | They are the operator's to publish ([FM-10.7](10-disclosure.md#fm-107-operator-supplied-logs)). |
| Every affected party's name and location, until its naming update | The indicator notice warns others without pointing readers at one organisation's systems ([FM-10.2](10-disclosure.md#fm-102-lead-times)). |
| Anything the drafting tool cannot classify | Withheld until the admin decides. |

Content from a source whose terms forbid redistribution is never quoted; the notice links the record and gives derived indicators ([FM-3.4](03-sources.md#fm-34-terms-of-use)). Private reports carry what the recipient needs, including what the notice withholds ([FM-10.1](10-disclosure.md#fm-101-parties)).

## FM-11.5 Lint

Every notice is checked by a program before publication and on every later change, for: callback channel identifiers, e-mail addresses other than role mailboxes, credential shapes, well-formed front matter with updates in date order, attribution statements without a layer, label or tag, likelihood words stronger than their labels allow, a title naming a provider the notice does not name as a developer, an affected host in the indicator notice, and the word "misaligned" without the scope finding and agent grade that [FM-15.4](15-misalignment.md#fm-154-stating-a-scope-finding) requires. A notice that fails is not published.

Before publication, the self-review checklist and the second review cover what the notice alone cannot show ([FM-10.9](10-disclosure.md#fm-109-self-review-and-second-review)). The lint is a last check, not the withholding itself: the draft is built from a withholding view, and the lint catches what got through ([notices](../reference/notices.md#lint)).

## FM-11.6 Corrections and retractions

A published notice is never rewritten. Each change is an appended, dated update of one kind:

| Kind | Use |
|---|---|
| **Update** | New facts: more clusters, a provider statement summarised. |
| **Naming** | Names affected organisations and their hosts once their naming lead has run or they consented. Needs both reviews. |
| **Status** | A lifecycle change ([FM-11.3](#fm-113-status-lifecycle)). |
| **Correction** | A published claim was wrong. States the claim, what is now believed, and why. |
| **Reply** | A party's statement, verbatim ([FM-10.5](10-disclosure.md#fm-105-right-of-reply)). |
| **Retraction** | The notice's central claim no longer holds. The notice stays, marked retracted, with the reason. |

The feed carries every update, so a reader who saw the original sees the correction. A withdrawn attribution stays visible as withdrawn ([FM-2.6](02-principles.md#fm-26-correct-in-public)).

## FM-11.7 Permanence

A notice id, once published, keeps its address. Notices are published from a version-controlled repository, so every state of every notice is recoverable. Committing a notice publishes it; nothing else does ([notices](../reference/notices.md#from-draft-to-published)). A notice is published, and each operator named, no earlier than the lead times allow ([FM-10.2](10-disclosure.md#fm-102-lead-times)), and its first update says who was reported before it and for whom no contact could be found.
