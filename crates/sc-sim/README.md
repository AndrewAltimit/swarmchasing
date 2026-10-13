# sc-sim

Swarm and fleet detection measured against ground truth. It reads, from labelled records, who sent each record, its true run, and the swarm and fleet that run belongs to, then scores an analysis's interaction edges (S1 to S5), soft links, candidate fleets and agent grades against them. The [`swarmchase`](../swarmchase/README.md) CLI runs it as `swarmchase sim score` ([evaluation](../../docs/reference/evaluation.md#swarm-and-fleet-measurement)).

No I/O. Report only: no gate reads it.

## Use

```rust
use sc_sim::{Truth, measure, render};

let truth = Truth::from_ndjson(&labelled_text);
let m = measure(&analysis, &truth);
print!("{}", render(&m));
```

## Modules

| Module | Covers |
|---|---|
| [`truth`](src/truth.rs) | `TruthRow` per record id from `label`, `actor`, `class`, `run`, `swarm` and `fleet`; the operator a run belongs to. |
| [`measure`](src/measure.rs) | Pair-level precision and recall per edge kind, soft-link kind and candidate fleet; the grade table by actor and class. |
| [`render`](src/render.rs) | The measurement as text tables, with Wilson intervals. |

Kinds are keyed by their serialised names, so a kind added to `SwarmEdgeKind` or `SoftLinkKind` is measured without a change here.

## Tests

```sh
cargo test -p sc-sim
```
