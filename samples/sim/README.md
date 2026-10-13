# Simulated scenarios

[`scenarios.toml`](scenarios.toml) is the scenario file `swarmchase sim bench` reads: swarms of each interaction mode, fleets, schedulers, planted records and benign background, each under several seeds. The records it produces are synthetic. Their request content is copied from [`samples/eval`](../eval/README.md); only senders, clients, times and order are simulated, and every target host is a reserved `.example` name.

```sh
cargo run -p swarmchase -- sim bench samples/sim/scenarios.toml
cargo run -p swarmchase -- sim write samples/sim/scenarios.toml -o data/sim   # the records, for eval or sim score
```

What the numbers mean and what the simulator leaves out: [simulated scenarios](../../docs/reference/evaluation.md#simulated-scenarios). Generated records are never committed; the eval gate reads only `samples/eval`.
