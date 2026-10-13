# sc-inbox

Outside reports of AI agent activity, in the [SC-Submission v1](../../docs/specs/submission-v1.md) format, without I/O. The [`swarmchase`](../swarmchase/README.md) CLI's `inbox` commands read and write the files and run the lookups; this crate decides what a submission is and how much it is worth ([the inbox](../../docs/reference/inbox.md)).

Every submission is untrusted and a way to plant records. The crate assumes all of it may be fabricated, grades only the records the toolkit found itself, and asks of every item what it would have cost to make up. Nothing here fetches anything, and no string from a submission is ever treated as an instruction.

## Use

```rust
use sc_inbox::{Checks, Prior, Settings, assess, corroborate, intake};

let i = intake(&text, received, "email", Some(sender), &prior, &settings.intake)?;
let held = corroborate(&i, &watch_store, &rules, &settings.triage);
let a = assess(&i, Checks { verifications: &v, found: &found, held: &held, signatures: &sigs }, &rules, &settings.triage);
```

## Modules

| Module | Covers |
|---|---|
| [`spec`](src/spec.rs) | The document, validation as the [schema](../../schemas/sc-submission-v1.json) states it, and the size caps. |
| [`intake`](src/intake.rs) | Redaction at ingest, fingerprints, duplicates and repeats, rate limits per submitter key. |
| [`inert`](src/inert.rs) | Instruction-shaped and hidden text flagged by field; every string shown inert. |
| [`evidence`](src/evidence.rs) | Evidence classes by fabrication cost, record identities, and a submission's own records as `reported`. |
| [`verify`](src/verify.rs) | Whether a lookup shows a referenced record exists, matches and predates the submission. |
| [`triage`](src/triage.rs) | Corroboration against the watch store, the grade of the records found, inflated claims, the verdict and its settings. |

## Tests

```sh
cargo test -p sc-inbox
```

The triage tests are scenarios: fabricated submissions (assertions only, scan-service records made minutes before, inflated claims, references that do not exist or postdate the report, the submitter's own logs) that must not reach examine, and ones that must (archive captures weeks older, an indicator the watch already held, a checked third-party signature).
