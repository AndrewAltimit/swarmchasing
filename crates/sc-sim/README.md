# sc-sim

A seeded swarm simulator with ground truth, and swarm and fleet detection measured against it. The generator turns a scenario file into labelled records: request content is copied from the committed evaluation records, and what it simulates is who sends them, when, from which client and in what order. The measurement reads, from labelled records, who sent each record, its true run, and the swarm and fleet that run belongs to, then scores an analysis's interaction edges (S1 to S5), soft links, candidate fleets and agent grades against them. The [`swarmchase`](../swarmchase/README.md) CLI runs it as `swarmchase sim write`, `sim bench` and `sim score` ([evaluation](../../docs/reference/evaluation.md#swarm-and-fleet-measurement)).

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
| [`scenario`](src/scenario.rs) | Scenario files: actors (swarms by mode, fleets, schedulers, single agents, background and planters), pace, retries, time basis, seeds. |
| [`palette`](src/palette.rs) | The committed records the generator copies, sorted by use (attack, read, callback inbox, benign, person, tool). |
| [`generate`](src/generate.rs) | Labelled records from a scenario and a seed: clients, times, hosts, per-run identifiers. |
| [`rng`](src/rng.rs) | A small seeded generator, the same on every platform. |
| [`truth`](src/truth.rs) | `TruthRow` per record id from `label`, `actor`, `class`, `run`, `swarm` and `fleet`; the operator a run belongs to. |
| [`measure`](src/measure.rs) | Pair-level precision and recall per edge kind, soft-link kind and candidate fleet; the grade table by actor and class. |
| [`render`](src/render.rs) | The measurement as text tables, with Wilson intervals. |

`bench` generates each scenario under its seeds, analyses each run on its own and sums the measurements.

Kinds are keyed by their serialised names, so a kind added to `SwarmEdgeKind` or `SoftLinkKind` is measured without a change here.

## Tests

```sh
cargo test -p sc-sim
```
