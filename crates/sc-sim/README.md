# sc-sim

A seeded swarm simulator with ground truth, and swarm and fleet detection measured against it. The generator turns a scenario file into labelled records: request content is copied from the committed evaluation records, and what it simulates is who sends them, when, from which client and in what order. The measurement reads, from labelled records, who sent each record, its true run, and the swarm and fleet that run belongs to, then scores an analysis's interaction edges (S1 to S6), soft links, candidate fleets and agent grades against them. The [`swarmchase`](../swarmchase/README.md) CLI runs it as `swarmchase sim write`, `sim bench`, `sim calibrate` and `sim score` ([evaluation](../../docs/reference/evaluation.md#swarm-and-fleet-measurement)).

No I/O. The eval gate holds `sim bench`'s precision floors, grade and null-scenario ceilings and per-scenario expectations ([simulator bounds](../../docs/reference/evaluation.md#simulator-bounds)).

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
| [`scenario`](src/scenario.rs) | Scenario files: actors (swarms by mode, fleets, schedulers, target lists, news spikes, hubs, single agents, background, benign look-alikes, planters, mimics, escalators, prompt fleets, framework users, link checkers, SEO crawlers) and their options ([simulated scenarios](../../docs/reference/evaluation.md#simulated-scenarios)), tag styles, seeds, null scenarios, expectations, defaults, the calibration allow-list. |
| [`palette`](src/palette.rs) | The committed records the generator copies, sorted by use (attack, read, callback inbox, benign, person, tool). |
| [`generate`](src/generate.rs) | Labelled records from a scenario and a seed: clients, times, hosts, per-run identifiers, a fleet harness's own parameters, synthetic prose from prompt templates, tags from a node id, clock or counter. |
| [`rng`](src/rng.rs) | A small seeded generator, the same on every platform. |
| [`truth`](src/truth.rs) | `TruthRow` per record id from `label`, `actor`, `class`, `run`, `swarm` and `fleet`; the operator a run belongs to. |
| [`measure`](src/measure.rs) | Pair-level precision and recall per edge kind, soft-link kind and candidate fleet; onset groups against swarm pairs and seams against false merges; split runs rejoined; the grade table by actor and class; B-cubed and adjusted Rand index of clusters against runs; time to detect, and by prefix re-analysis time to L2 or a candidate fleet. |
| [`render`](src/render.rs) | The measurement as text tables, with Wilson intervals. |
| [`gate`](src/gate.rs) | Precision floors over every scenario, grade ceilings, ceilings on what the null scenarios draw, per-scenario expectations. |
| [`calibrate`](src/calibrate.rs) | Each soft-link kind's and family pair's likelihood ratio from simulated truth, pooled and stratified by scenario, and the check of the bundled ratios and joint caps. |

`bench` generates each scenario under its seeds, analyses each run on its own and sums the measurements. `bench_with` does the same and, from the same generated records, the calibration counts and the prefix analyses for time to L2.

Kinds are keyed by their serialised names. Every edge kind, soft-link kind, `any` and `candidate_fleet` is listed in every measurement with its recall denominator, fired or not, so a sum over seeds and scenarios counts the true pairs a kind missed where it drew nothing. A soft-link kind added to `SoftLinkKind` fails to compile in `measure` until it is listed there.

## Tests

```sh
cargo test -p sc-sim
```
