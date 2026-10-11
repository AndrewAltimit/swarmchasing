# Adopting the method

[Specs index](README.md)

This page is for a group that wants to apply swarmchasing with its own data, tools or reporting, and be comparable with others who do. It lists what to take, what to state, and how to show that the result follows the method. Nothing here needs this repository's toolkit; the toolkit is one implementation.

## What to take

| Part | Take it as | Where |
|---|---|---|
| The method | The Field Manual, cited by version and section id. | [Field Manual](../manual/README.md) |
| Indicator rules | A rules file in the SC-Rules v1 format, this project's or your own. | [SC-Rules v1](rules-v1.md) |
| Incident records | One SC-Incident v1 document per published incident. | [SC-Incident v1](incident-v1.md) |
| Threat-intelligence export | The STIX 2.1 profile and its `x-sc-agent-run` object. | [FM-12.1](../manual/12-interoperability.md#fm-121-stix-21-export-profile), [FM-12.2](../manual/12-interoperability.md#fm-122-the-x-sc-agent-run-extension) |
| Evaluation | The three kinds of evaluation and what to publish with a number. | [FM-9.1](../manual/09-evaluation.md#fm-91-three-kinds-of-evaluation), [FM-9.9](../manual/09-evaluation.md#fm-99-what-to-publish-with-a-number) |
| A benchmark | Record ids, labels, derived features and split, never restricted content. | [FM-9.10](../manual/09-evaluation.md#fm-910-benchmark-publication-rules) |

## Steps

1. **Pass the passivity test** for every source you collect from, and record each source's terms ([FM-3.2](../manual/03-sources.md#fm-32-passivity-test), [FM-3.4](../manual/03-sources.md#fm-34-terms-of-use)). This is not optional: a group that reads agents' channels or fetches their URLs is not following the method, whatever else it does.
2. **Use a rules file that validates** against [`schemas/sc-rules-v1.json`](../../schemas/sc-rules-v1.json), with a version. If you run your own engine, pass the [conformance vectors](rules-v1.md#conformance) with the rules version they name.
3. **Grade, link and assess separately.** A tier, an agent grade, a scope finding and a coordination finding are four results ([FM-15.1](../manual/15-misalignment.md#fm-151-four-questions)). Report each you made, and say which you did not.
4. **Attribute by layer and ladder**, with labels, tags and the likelihood table ([chapter 7](../manual/07-attribution.md), [chapter 8](../manual/08-confidence.md)). Keep the competing-hypotheses worksheet with the case ([FM-7.12](../manual/07-attribution.md#fm-712-competing-hypotheses)).
5. **Disclose before publishing**, on lead times fixed in advance ([FM-10.2](../manual/10-disclosure.md#fm-102-lead-times)), and publish notices that withhold what enables harm ([FM-11.4](../manual/11-notices.md#fm-114-what-a-notice-withholds)).
6. **Measure before you claim.** Quote precision only from held-out or prospective evaluation, with its interval and context, and choose public words by the calibration rule ([FM-9.12](../manual/09-evaluation.md#fm-912-calibrated-public-language)).

## Stating conformance

A report, paper or notice that follows the method says so in one line, with its departures:

> Method: SC-FM 1.1. Rules: SC-Rules v1, rules version `<version>`. Departures: FM-9.3 (no held-out split; regression numbers only).

Name each section you depart from and what you did instead ([how to cite](../manual/README.md#how-to-cite)). A departure stated is a method followed; one hidden is not.

## Sharing rules and results

- **Rules.** A rule you share carries its public basis, its labelled positives and hard negatives, and its before and after numbers ([FM-4.7](../manual/04-indicators.md#fm-47-rule-writing-standard)). To contribute one to this project, see [writing rules](../guides/writing-rules.md).
- **Tags you publish.** When your report quotes a run tag or marker, other groups add it to their published-tags list, and it stops being a hard link everywhere ([FM-14.5](../manual/14-limits.md#fm-145-tags-get-copied-after-publication)). Quote only what readers need.
- **Fleet identifiers.** Refer to another group's fleet by its identifier, and record the overlap as a soft link until the evidence for a merge is reviewed ([FM-5.13](../manual/05-linking.md#fm-513-cluster-lifecycle-and-identifiers)).
- **Corrections.** When you correct a finding another group cited, tell them; corrections are appended, never rewritten ([FM-2.6](../manual/02-principles.md#fm-26-correct-in-public)).

## Comparing with other groups

Two findings compare only when they share the rules version, the unit (record or cluster) and the evaluation kind. Tier names match the Transluce release, so labels compare directly; most other terms map through [chapter 16](../manual/16-other-methods.md) and the crosswalk in [FM-12.4](../manual/12-interoperability.md#fm-124-crosswalk-to-agent-security-frameworks).
