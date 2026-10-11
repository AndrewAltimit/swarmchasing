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
