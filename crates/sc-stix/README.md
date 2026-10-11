# sc-stix

A case's analysis as a STIX 2.1 bundle, and as a MISP event, for the tooling of the providers and operators it is reported to. The [`swarmchase`](../swarmchase/README.md) CLI's `case export --format stix|misp` reads the case, scopes its records to the audience, and writes what this crate builds ([STIX export](../../docs/reference/cases.md#stix-export), [MISP export](../../docs/reference/cases.md#misp-export)).

No I/O, and nothing is ever sent. Every id is a UUIDv5 of the content, so the same case exports byte for byte the same. A public export withholds what the public notice withholds and is refused when the leak scan finds anything in it.

## Use

```rust
use sc_stix::{Options, build, misp};

let bundle = build(&analysis, &rules, &Options { case_id, title, audience, reporter, today,
    exposed: &compromised, affected: &affected, claims: &c.claims, min_named: c.min_named, fleets: &c.fleets })?;
let event = misp::event(&bundle, title, today);
```

## Modules

| Module | Covers |
|---|---|
| [`lib`](src/lib.rs) | `Options` and `build`: the bundle from its parts. |
| [`observed`](src/observed.rs) | Each cluster's records as observables, indicator drafts and `observed-data`. |
| [`indicators`](src/indicators.rs) | STIX patterns for run tags, callback channels, agent markers and flagged user agents. |
| [`objects`](src/objects.rs) | One function per object type. |
| [`agent_run`](src/agent_run.rs) | The `x-sc-agent-run` object and its extension definition ([schema](../../schemas/stix/x-sc-agent-run.json)). |
| [`fleet`](src/fleet.rs) | A case fleet as a `grouping`. |
| [`mapping`](src/mapping.rs) | The SC-T cross-walk to MITRE ATLAS, ATT&CK and the OWASP agentic top 10, as references, kill chain phases and MISP tags. |
| [`misp`](src/misp.rs) | A bundle as a MISP event. |
| [`ids`](src/ids.rs) | Deterministic ids, TLP markings, timestamps. |

The rules carry each indicator's SC-T tactic only; the cross-walk to other frameworks is the table in `mapping`, following the Field Manual's ([SC-FM 4.6](../../docs/manual/04-indicators.md#fm-46-cross-walk-to-mitre-atlas-and-attck) and [SC-FM 12.4](../../docs/manual/12-interoperability.md#fm-124-crosswalk-to-agent-security-frameworks)). A test reads both manual tables and fails when the table differs from them.

## Tests

```sh
cargo test -p sc-stix
```
