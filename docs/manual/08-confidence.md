# 8. Confidence language

[Manual index](README.md) · Previous: [7. Attribution](07-attribution.md) · Next: [9. Evaluation](09-evaluation.md)

Readers act on the words a report uses. If one practitioner's "likely" is another's "almost certain", reports cannot be compared or checked. Every report and notice that follows this manual uses the table below.

## FM-8.1 Likelihood table

The terms and ranges are those of US Intelligence Community Directive 203, *Analytic Standards* ([ICD 203](references.md#standards-and-guidance)). A report uses the terms in the first column; the second column is ICD 203's alternative set, and a report **should not** mix the two.

| Term | Alternative | Probability |
|---|---|---|
| almost no chance | remote | 1–5% |
| very unlikely | highly improbable | 5–20% |
| unlikely | improbable | 20–45% |
| roughly even chance | roughly even odds | 45–55% |
| likely | probable | 55–80% |
| very likely | highly probable | 80–95% |
| almost certain | nearly certain | 95–99% |

Certainty is reserved for Observed and Documented claims ([FM-7.6](07-attribution.md#fm-76-claim-tags)): a record shows a URL, or it does not. Likelihood words belong to Inferences and Conclusions.

## FM-8.2 Confidence levels

A confidence level (**high**, **moderate**, **low**) describes the basis for a judgment: the quantity and quality of the evidence and how much the judgment rests on assumptions. It is not a probability. The three levels are this manual's definitions:

- **High**: several independent lines of evidence, at least one costly to forge ([FM-7.9](07-attribution.md#fm-79-false-flag-reasoning)), and no unresolved inconsistency.
- **Moderate**: credible evidence with gaps, or lines that are not independent.
- **Low**: thin, single-source or easily forged evidence.

Following ICD 203, a sentence carries either a likelihood word or a confidence level, never both. Write "We assess with moderate confidence that the clusters share an operator." or "The clusters very likely share an operator.", not "We have moderate confidence the clusters very likely share an operator."

## FM-8.3 Usage rules

- A Conclusion carries a likelihood word or a confidence level, and an attribution label where it attributes ([FM-7.7](07-attribution.md#fm-77-attribution-labels)).
- The likelihood word never exceeds what the label allows.
- Model-family rankings give a likelihood word per family, with the method's held-out accuracy ([FM-7.5](07-attribution.md#fm-75-model-family-layer)).
- Hedges outside the table ("may", "could", "appears", "possibly") are not used for Conclusions. "Possible" appears only as the attribution label.
- A report says what would change the judgment: the evidence that would raise or lower the likelihood.

Toolkit: a draft's Conclusion line for each developer named through the gate uses the strongest likelihood word its label allows ([FM-7.7](07-attribution.md#fm-77-attribution-labels)); the admin lowers it where the evidence warrants. Other Conclusions are written by the admin. `notice lint` and the self-review of `notice add` ([FM-10.9](10-disclosure.md#fm-109-self-review)) refuse a notice whose summary or attribution uses a table term stronger than the strongest label it states, or an attribution line stronger than its own label, and any off-table word of certainty ("certainly", "definitely") anywhere.
