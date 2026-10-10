# Saved evaluation results

Measured results, written by `swarmchase eval --save-result`. Each file is JSON with numbers only: counts, proportions with 95% Wilson intervals, rule ids, class and tactic names. It also carries the rules version, the toolkit commit and the SHA-256 of every input and label file. The format is in [evaluation](../../../docs/reference/evaluation.md#saved-results).

## Convention

- **Never record content.** No record ids, URLs or quoted text. Inputs are named by their description and hash, so a reader holding the same files can check they measured the same thing, and nobody else learns what is in them.
- **One file per measurement**, named `<kind>-<what>-rules-<rules version>.json`, for example `held_out-transluce-rules-2026-10-15.json`. A new measurement is a new file; an old one is never edited.
- **The kind is in the file** (`regression`, `held_out` or `prospective`; [FM-9.1](../../../docs/manual/09-evaluation.md#fm-91-three-kinds-of-evaluation)). Only held-out and prospective results may be quoted as performance.
- **Quote with its context**: the kind, the counts behind each ratio, the interval, the rules and toolkit version, the label source and the class mix ([FM-9.9](../../../docs/manual/09-evaluation.md#fm-99-what-to-publish-with-a-number)).
- **Commit the toolkit first.** A result whose `toolkit.commit` ends in `-dirty` was measured with uncommitted code; measure again from a clean checkout.

## Results

| File | Kind | What |
|---|---|---|
| [`held_out-transluce-rules-2026-10-15.json`](held_out-transluce-rules-2026-10-15.json) | held out | A sample of Transluce's labelled urlquery reports, fetched by id, with this repository's label overrides. |

The Transluce sample holds agent-labelled reports only, so its precision says nothing: with no benign records there can be no false positive. Its recall is the useful number, and the per-class table explains it. Reports Transluce labelled `source_request` are judged from context a single record does not show, and the rules flag few of them.
