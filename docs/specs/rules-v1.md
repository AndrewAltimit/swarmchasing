# SC-Rules v1: indicator rules format

[Specs index](README.md) · Schema: [`schemas/sc-rules-v1.json`](../../schemas/sc-rules-v1.json) · Conformance vectors: [`conformance/rules-v1.json`](conformance/rules-v1.json)

This page specifies the format of a swarmchasing rules file, such as [`rules/default.toml`](../../rules/default.toml), and the semantics an engine gives it. A group that writes its own rules, or its own engine, can exchange rules with this project and check its engine against the same vectors. The method the rules serve is the [Field Manual](../manual/README.md) ([FM-4.1](../manual/04-indicators.md#fm-41-grading-records) to [FM-4.8](../manual/04-indicators.md#fm-48-rule-versions-and-pinning)).

**Must**, **must not**, **should** and **may** in bold carry their [RFC 2119](../manual/references.md#standards-and-guidance) meanings.

## Status

| Part | Status |
|---|---|
| File structure, rule fields, matching and scoring | Normative; the toolkit implements it. |
| The `group` field and in-group scoring | Normative; see [Independence groups](#independence-groups). |
| The context cap | Normative; see [Context cap](#context-cap). |

An engine that does not implement groups or the context cap **must** reject a file that sets `group`, so a file never scores differently on two engines without saying so.

## File

A rules file is TOML. Its JSON value (the TOML read as JSON) **must** validate against [`schemas/sc-rules-v1.json`](../../schemas/sc-rules-v1.json). The schema checks structure and value domains. It cannot check that patterns compile or that rule ids are unique; an engine **must** reject a file with a duplicate rule id or a pattern that does not compile.

| Table | Holds | Required |
|---|---|---|
| `[meta]` | `version`: the rules version. | **should** |
| `[thresholds]` | `suggestive` and `significant` scores. | **should**; defaults 3 and 6 |
| `[linking]` | Link features, time windows, run gaps, published tags ([FM-5.2](../manual/05-linking.md#fm-52-shared-link-features)). | no |
| `[chains]`, `[fanout]`, `[escalation]`, `[soft_links]`, `[scaffold]`, `[co_activity]`, `[cut_lengths]`, `[paths]` | Settings for linking and descriptive hints. | no |
| `[[rule]]` | The indicator rules. | no |
| `[[asn]]` | Network number to organisation, for hosting context. | no |
| `[[benchmark]]`, `[[stale]]` | Benchmark targets and stale knowledge ([FM-4.9](../manual/04-indicators.md#fm-49-benchmark-targets-and-declared-testing), [FM-4.5](../manual/04-indicators.md#fm-45-artifact-families)). | no |

A missing settings table takes the defaults the toolkit's bundled file carries, so a case pinned to an older file renders the same. The meaning of each setting is in [methodology](../methodology.md); this spec fixes only its name and type.

The version is an opaque string. This project uses a date. Two files with the same version **must** be byte-identical in their rules; a change to any rule, threshold or setting takes a new version.

## Rule fields

| Field | Type | Required | Meaning |
|---|---|---|---|
| `id` | string | yes | Unique, dotted, `<family>.<name>`, lower case. Reports cite it. |
| `kind` | enum | yes | One of the kinds below. |
| `target` | enum | yes | What the rule reads; see [Targets](#targets). |
| `pattern` | string | yes | A host suffix for `host`; otherwise a regular expression. |
| `weight` | integer ≥ 0 | no, 1 | Contribution to the record's score. |
| `significant` | boolean | no, false | A match puts the record in the top tier on its own. |
| `link` | boolean | no, false | The matched text is a link feature. |
| `tactic` | `T1`–`T7` | one of these two | The SC-T tactic a match is evidence of. |
| `artifact` | boolean | one of these two | A match is a trace of how the agent was built. |
| `check` | enum | no | A test a `param_value` match must also pass. |
| `group` | string | no | An independence group ([Independence groups](#independence-groups)). |
| `description` | string | no | One line for people. |

A rule **must** carry a `tactic`, or `artifact = true`, or both. `T8` and `T9` are cluster-level judgments and **must not** be a rule's tactic ([FM-4.3](../manual/04-indicators.md#fm-43-the-sc-t-tactic-taxonomy)). A `check` **must** sit on a `param_value` rule. The only check in v1 is `repeated_token`: one word of three characters or more with a letter, or a phrase of two or three words, repeated five or more times in a row.

A rule carries no framework ids of its own: its MITRE ATLAS techniques and OWASP Top 10 for Agentic Applications risks are derived from its `tactic` through the FM-12.4 crosswalk, so the verified ids live in one table rather than on every rule.

**Kinds.** `relay`, `carrier`, `exploit`, `agent_marker`, `cache_buster`, `self_id`, `exfil`, `header`, `outcome`, `anti_bot`, `infra`. Five of them are **context kinds**, which ordinary clients produce too: `relay`, `cache_buster`, `self_id`, `header`, `outcome`. Context kinds never join records by timing ([FM-5.3](../manual/05-linking.md#fm-53-close-timing-on-the-same-target)) and never corroborate a cluster tier ([FM-14.9](../manual/14-limits.md#fm-149-stacking-across-a-cluster)). The default tactic of each kind is [FM-4.4](../manual/04-indicators.md#fm-44-default-tactics-by-rule-kind).

## Layers

Before rules run, an engine unwraps each record's URL into **layers**: the submitted URL, the inner URL of each relay or translate proxy, URL-valued parameters, `data:` bodies and base64 values that decode to text or a URL. The toolkit's rules for unwrapping, and its limits, are in [methodology](../methodology.md#unwrapping). An engine **should** unwrap at least relay paths, translate-proxy hosts, URL-valued parameters, `data:` URLs and base64 path or parameter values, because the default rules assume it; the conformance vectors exercise each.

The **target host** is the host of the innermost layer whose host is not itself matched by a `relay`, `carrier` or `exfil` rule.

## Targets

| Target | Reads | Match |
|---|---|---|
| `host` | The host of each layer. | Suffix on a label boundary: `jina.ai` matches `r.jina.ai`, not `notjina.ai`. |
| `url` | Each layer's decoded text: its URL, a `data:` body, a decoded payload. | Regular expression. |
| `param_name` | Each query parameter name of each layer. | Regular expression. |
| `param_value` | Each query parameter value of each layer, decoded. | Regular expression, then the `check`. |
| `header` | Each request header as `name: value`. | Regular expression. |
| `user_agent` | The user agent. | Regular expression. |
| `final_url` | Where a scan ended. | Regular expression. |

Regular expressions are case-insensitive and use the syntax of the Rust `regex` crate: no look-around and no back-references, inline flags such as `(?-i:…)`, and `\x{…}` escapes. An engine in another language **must** use a compatible syntax or translate the patterns, and **must** pass the conformance vectors.

## Scoring

For one record:

1. Each rule counts at most once, whichever layer or target it matched.
2. The score is the sum of the weights of the distinct rules that fired, with the [independence groups](#independence-groups) and the [context cap](#context-cap) below applied.
3. The tier is **significant** when a rule marked `significant` fired or the score reaches `thresholds.significant`; else **suggestive** when the score reaches `thresholds.suggestive`; else **noise**.

A cluster's tier is not a summed score: it is its strongest member's tier, raised one step only by corroboration between members ([FM-14.9](../manual/14-limits.md#fm-149-stacking-across-a-cluster)).

### Independence groups

Rules that read the same artifact on the same layer are not independent evidence: one fetch program carried through an echo service fires the echo rule, the script rule and the fetch rule at once. Under groups, step 2 becomes: the score is the sum, over groups, of the largest weight among the group's rules that fired, plus the weights of ungrouped rules that fired. `significant` is unchanged: any significant rule still sets the top tier. The method and the default groups are in [FM-4.11](../manual/04-indicators.md#fm-411-independence-groups-and-the-context-cap).

### Context cap

Rules of context kinds together contribute at most `thresholds.suggestive − 1` to a record's score, so a record whose only hits are context kinds stays noise ([FM-4.11](../manual/04-indicators.md#fm-411-independence-groups-and-the-context-cap)). A `significant` context rule still sets the top tier on its own. A group counts as context when the heaviest of its rules that fired is a context kind, a non-context rule winning a tie; its weight then falls under the cap with the ungrouped context rules.

## Conformance

An engine conforms to SC-Rules v1 when, with the rules file at the corpus's `rules_version`, it gives every vector in [`conformance/rules-v1.json`](conformance/rules-v1.json) the same target host, the same set of rule ids, the same score and the same tier. Layer order and numbering are the engine's own. Each vector is a single synthetic URL on a reserved example domain or a public relay or echo service, analysed alone. This repository's own engine is held to the file by a test in `sc-core` (`tests/conformance.rs`), which also regenerates the vectors' scores and tiers after an intended scoring change.

The corpus covers each layer type, each tier, the hard negatives the default rules are built to avoid (payload words in a search, a relay tried on the example domain), and the records whose tier the independence groups and the context cap decide:

| Vector | Rules | Score | Tier | Why |
|---|---|---|---|---|
| `two-relays` | `relay.jina`, `relay.translate_goog` | 2 | noise | context cap |
| `relay-selfid` | `relay.jina`, `selfid.vendor_name` | 2 | noise | context cap |
| `context-cap` | `relay.jina`, `marker.uq_tags`, `cache.buster` | 5 | suggestive | run tag, context capped |
| `httpbin-program` | echo, script, fetch, title write | 3 | suggestive | program group, the echo in it |
| `echo-script-page` | echo, script | 2 | noise | program group, no request |
| `data-url-program` | echo script, script, fetch | 3 | suggestive | program group |
| `run-tag` | `marker.uq_tags`, `marker.test_tag` | 3 | suggestive | run-tag group |
| `oai-prefix-tag` | `marker.oai_prefix` | 3 | suggestive | run-tag group |
| `traversal` | `exploit.traversal`, `exploit.traversal_single` | 5 | significant | traversal group, a `significant` rule |
| `double-encoded-path` | `exploit.double_encoded_path` | 4 | significant | a `significant` rule |
| `double-encoded-meta` | `exploit.double_encoded_meta` | 4 | significant | a `significant` rule |
| `httpbin-data-exfil` | `carrier.httpbin`, `exfil.httpbin_data` | 5 | significant | a `significant` rule |

The full set, with its scores and tiers, is [`conformance/rules-v1.json`](conformance/rules-v1.json), regenerated from the rules at `rules_version`.

## Validating a rules file

The JSON value of the TOML is validated with any JSON Schema 2020-12 validator. With Python 3.11 or later and the `jsonschema` package:

```sh
python -c "import tomllib, json, jsonschema; jsonschema.validate(tomllib.load(open('rules/default.toml', 'rb')), json.load(open('schemas/sc-rules-v1.json')))"
```

No output means the file is valid. This repository's gate, [`scripts/ci/check-rules-schema.py`](../../scripts/ci/check-rules-schema.py), does the same with the standard library alone (`tomllib`, `json`, `re`), so it needs no third-party package. The engine's own load (`swarmchase scan --rules <file>`) then checks what the schema cannot: unique ids and patterns that compile.

## Versioning

This is version 1. A minor version adds optional fields or makes a reserved one normative; a file valid under 1.0 stays valid. A major version may change the meaning of a field. A rules file does not declare which spec version it follows; the schema it validates against does.
