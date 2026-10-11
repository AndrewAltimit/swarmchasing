# Saved evaluation results

Measured results, written by `swarmchase eval --save-result`. Each file is JSON with numbers only: counts, proportions with 95% Wilson intervals, rule ids, class and tactic names. It also carries the rules version and hash, the toolkit version and commit, and the path, SHA-256 and size of every input and label file. The format is in [evaluation](../../../docs/reference/evaluation.md#saved-results).

## Convention

- **Never record content.** No record ids, URLs or quoted text. Inputs are named by their path in the data directory and their hash, so a reader holding the same files can check they measured the same thing, and nobody else learns what is in them.
- **One file per measurement**, named `<kind>-<what>-rules-<rules version>.json`. A new measurement is a new file; an old one is never edited.
- **The kind is in the file** (`regression`, `held_out` or `prospective`; [FM-9.1](../../../docs/manual/09-evaluation.md#fm-91-three-kinds-of-evaluation)). Only held-out and prospective results may be quoted as performance.
- **Precision needs benign records.** A held-out or prospective result with none is saved only with `--allow-no-benign`, says so in the file, and is quoted for recall only.
- **Quote with its context**: the kind, the counts behind each ratio, the interval, the rules and toolkit version, the label source and the class mix ([FM-9.9](../../../docs/manual/09-evaluation.md#fm-99-what-to-publish-with-a-number)).
- **Commit the toolkit first.** A result whose `toolkit.commit` ends in `-dirty` was measured with uncommitted code; measure again from a clean checkout.
- **It must reproduce.** `swarmchase eval repro <file>` measures it again from the same inputs and diffs every number. The eval gate runs `swarmchase eval check-results` on this directory: a result whose rules version is newer than the committed rules, whose precision is vacuous without saying so, or that came from uncommitted code fails, and is withdrawn rather than edited.

## Results

| File | Kind | What |
|---|---|---|
| [`held_out-transluce-rules-2026-10-10.json`](held_out-transluce-rules-2026-10-10.json) | held out, recall only | A sample of Transluce's agent-labelled urlquery reports, fetched by id, with this repository's label overrides. |
| [`held_out-urlquery-com-presumed-benign-rules-2026-10-10.json`](held_out-urlquery-com-presumed-benign-rules-2026-10-10.json) | held out, false-positive rate only | Recent urlquery reports from a generic search, outside Transluce's catalogue, presumed benign and not reviewed. |

The Transluce sample holds agent-labelled reports only, so it was saved with `--allow-no-benign` and its precision says nothing. Its recall is the useful number, and the per-class table explains it: reports Transluce labelled `source_request` are judged from context a single record does not show, and the rules flag few of them.

The generic-search sample holds no agent label, so it gives a false-positive rate and nothing else. Its labels are a presumption, not a review: a flagged record in it would need review before it counted against the rules, and an agent among the unflagged ones would go unseen. A reviewed baseline replaces it ([a reviewed benign baseline](../../../docs/reference/evaluation.md#a-reviewed-benign-baseline)).

Both were measured on the same rules and can be measured again with `swarmchase eval repro` by anyone holding the same inputs; the inputs stay in the data directory.
