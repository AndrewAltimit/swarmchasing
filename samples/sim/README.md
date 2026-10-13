# Simulated scenarios

[`scenarios.toml`](scenarios.toml) is the scenario file `swarmchase sim bench` reads: swarms of each interaction mode, fleets, schedulers, planted records, escalating agents, hard negatives and benign background, each under several seeds, and null scenarios of background alone. The eval gate holds floors and ceilings on what it measures ([simulator bounds](../../docs/reference/evaluation.md#simulator-bounds)).

Scenario names other work can read by: `null-background` and `null-crowd` (nothing related), `planted-timing` (a planter copying tags, inbox and timing), `xbow-swarm` (many short agents on one inbox), `hub-two-fleets` (an agent of another operator sending two fleets' shapes), `fleet-crowd` (a fleet among hundreds of agents), `fleet-slow` (one agent every four days), `fleet-upgrade` (a harness changed halfway), `sync-loose` (a dispatch beyond the lockstep tolerance), `news-spike` (unrelated agents on one target at once), `escalation` (route climbs across clusters of one run), `target-list` (one operator's agents on one host list), `news-spike-list` (its hard negative) and `hub` (one agent tied to two target lists). The records it produces are synthetic. Their request content is copied from [`samples/eval`](../eval/README.md); only senders, clients, times and order are simulated, and every target host is a reserved `.example` name.

```sh
cargo run -p swarmchase -- sim bench samples/sim/scenarios.toml
cargo run -p swarmchase -- sim calibrate samples/sim/scenarios.toml       # soft-link likelihood ratios
cargo run -p swarmchase -- sim write samples/sim/scenarios.toml -o data/sim   # the records, for eval or sim score
```

What the numbers mean and what the simulator leaves out: [simulated scenarios](../../docs/reference/evaluation.md#simulated-scenarios). Generated records are never committed; the eval gate reads only `samples/eval`.
