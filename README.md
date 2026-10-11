# swarmchasing

Rust tools for finding misaligned AI agent swarms and fleets in public records, linking their activity into runs and fleets, and reporting each incident to the AI provider responsible and to the operators of affected systems, then publishing a notice after a short fixed lead time. The methods follow published incident work: [swarmcha.se — agent fleet report](https://swarmcha.se/posts/chinese-agent-fleet), [Transluce — agent activity](https://transluce.org/agent-activity) and [Transluce — US/Canada government](https://transluce.org/us-canada-gov). Agents leave traces in public scan services and web archives: they wrap targets in relays, run fetch programs in remote browsers, call back to throwaway inboxes and tag their requests. Those traces can be extracted, linked, timed and attributed.

## What it does

1. **Collect** passively from scan services and web archive indexes, or read an operator's own access log ([collection](docs/methodology.md#collection)).
2. **Redact** secrets at ingest, so captured cookies and tokens are never stored ([redaction](docs/methodology.md#redaction-at-ingest)).
3. **Unwrap** relays, carriers and encodings down to the real target ([unwrapping](docs/methodology.md#unwrapping)).
4. **Match and grade** each record against the [rules](rules/default.toml): significant, suggestive or noise ([rules](docs/methodology.md#rules), [tiers](docs/methodology.md#tiers)).
5. **Link** records into clusters by shared identifiers, timing and probe chains ([linking](docs/methodology.md#linking-into-clusters)).
6. **Describe** each cluster's timing and habits as hints to check, never as evidence ([timing](docs/methodology.md#timing), [hints](docs/methodology.md#descriptive-hints)).
7. **Report** per audience: Markdown drafts for the provider, the affected operator, internal notes and the public notice, with defanged URLs and an evidence-graded attribution section ([attribution](docs/methodology.md#attribution-levels-and-the-naming-gate)).
8. **Watch** the sources every 6 hours, keep case files, and draft the reports and notices the admin sends and publishes ([admin workflow](docs/guides/admin-workflow.md)).

The same analysis runs in the browser: the [toolkit](docs/reference/browser-toolkit.md) on GitHub Pages works client-side, so an operator can check its own logs without sending anything.

## Quick start

```sh
cargo build --release
scripts/ci/install-hooks.sh                                   # once per clone
cargo run -p swarmchase -- scan records.ndjson                # flagged records, strongest first
cargo run -p swarmchase -- clusters records.ndjson            # linked runs
cargo run -p swarmchase -- report access.log --map host=www.example.org --audience affected   # your own server's log
cargo run -p swarmchase -- unwrap 'https://r.jina.ai/https://…'
cargo run -p swarmchase -- collect wayback 'r.jina.ai/*' --from 20260901 -o data/jina.ndjson
scripts/ci/build-site.sh && python -m http.server -d _site 8080  # the public site
```

The [CLI README](crates/swarmchase/README.md) covers input formats and every command. Keys and SMTP settings go in `env.list` ([configuration](docs/reference/configuration.md)).

## Layout

| Path | What |
|---|---|
| [`crates/sc-core`](crates/sc-core/README.md) | Platform-independent analysis. No I/O, so it compiles to WASM. |
| [`crates/sc-collect`](crates/sc-collect/README.md) | Passive collectors: archive CDX indexes, scan services, CT logs, registries, security.txt, well-known footprints, the MCP registry. |
| [`crates/swarmchase`](crates/swarmchase/README.md) | The CLI: analysis, collection, watch, review, cases and notices. |
| [`crates/sc-case`](crates/sc-case/README.md) | What a case is and may do, without I/O; shared by the CLI, the site build and the browser. |
| [`crates/sc-stix`](crates/sc-stix/README.md) | A case as a STIX 2.1 bundle or a MISP event. |
| [`crates/sc-publish`](crates/sc-publish/README.md) | Notice files, their Markdown blocks, the Atom feed and the generated site pages. |
| [`crates/sc-wasm`](crates/sc-wasm/README.md) | wasm-bindgen bindings for the browser toolkit. |
| [`crates/sc-rules-wasm`](crates/sc-rules-wasm/README.md) | Edited rules (TOML) to JSON in the browser, loaded only when needed. |
| [`rules/default.toml`](rules/default.toml) | Indicator rules, compiled into the CLI and the browser. |
| [`samples/eval/`](samples/eval/README.md) | Labelled evaluation set behind the CI eval gate. |
| [`samples/showcase/`](samples/showcase/README.md) | Synthetic records the site's landing page walks through. |
| [`schemas/`](docs/specs/README.md) | JSON Schemas for the specs, SC-Bench and the STIX extension. |
| [`site/`](site/js/site.js) | The site's styles and page scripts; the pages are generated into `_site/` at deploy. |
| `notices/` | Published notices, one `<id>.md` per incident. |
| [`watchlist.toml`](watchlist.toml) | Sources the scheduled watch pulls, each with its rationale. |
| [`scripts/`](scripts/README.md) | CI gates, the pre-commit hook and helpers. |
| [`docs/`](docs/README.md) | Guides, reference, methodology, policies, the Field Manual and the specs. |

## Docs

- [Admin workflow](docs/guides/admin-workflow.md): from watch digest to published notice.
- [For operators](docs/guides/for-operators.md): what a report means, checking your own logs, sending logs back, replies, verifying a bundle.
- [Methodology](docs/methodology.md): how records become tiers, clusters and claims, and the known limits.
- [Policies](docs/policies.md): collection, attribution, reporting and publication.
- [Reference](docs/README.md#reference): watch runs, cases, notices, evaluation, the browser toolkit, configuration, the CI runner.
- [Contributing](CONTRIBUTING.md): gates, conventions and rule contributions.

## Ground rules

- **Passive only.** Read indexes and public records. Never open the URLs agents submitted, since they may carry live payloads or alert the operator. Never read from or post to their inboxes or notification topics.
- **Attribution is evidence-weighted.** Model names inside requests are weak, because agents misreport who built them. An ASN names a host, not a developer. A developer is named outside case notes only at or above the case's naming threshold.
- **Report, then publish on a fixed clock.** Swarms are active incidents. Reports go to the provider and affected operators first; the public notice follows after a fixed lead time (none for the provider, 4 to 12 hours for a targeted operator, 24 for a compromised one) that nothing a recipient says extends. Tools only draft and check. The admin sends and publishes, after a written self-review.
- **Raw data stays out of git.** The data directory (watch data and case files) is gitignored. Only notices and curated, redacted samples are committed.

The full set is in [docs/policies.md](docs/policies.md).

## License

Released under the [Unlicense](LICENSE) (public-domain dedication). For jurisdictions that do not recognise the public domain, it is also available under the [MIT License](LICENSE-MIT). [NOTICE](NOTICE) covers what the licenses do not extend to: quoted third-party records and trademarks.
