# SC-Sightings v1: sharing what a swarm left in your logs

[Specs index](README.md) · Schema: [`schemas/sc-sightings-v1.json`](../../schemas/sc-sightings-v1.json)

A swarm that reaches many sites is invisible to any one of them. This page specifies a file an operator makes from its own access logs, after checking them in the [browser toolkit](../reference/browser-toolkit.md#sharing-sightings) or the CLI, that lets the same swarm be recognised across operators without anyone sharing their logs or their visitors. One file holds one operator's sightings: one entry per flagged cluster.

**Must**, **must not**, **should** and **may** in bold carry their [RFC 2119](../manual/references.md#standards-and-guidance) meanings.

## Status

| Part | Status |
|---|---|
| The format and its schema | Normative. |
| Export | The workbench's *Share sightings* and `swarmchase sightings export`. |
| Matching | `swarmchase sightings match`, run by the admin. |
| Private set intersection | Not implemented; see [the alternative](#the-alternative-private-set-intersection). |

## What a file carries

| Carried | Form |
|---|---|
| Linking features | The values that joined the cluster's records: strong parameters (`uqtag`, `run`) and `link = true` rule matches (inbox and topic ids, model tags). Kind and name in the clear; the value only as a [keyed hash](#the-keyed-hash). |
| Captured secrets | Secrets the records carried, by their `REDACTED-` replacement, re-keyed as a feature of kind `secret`. Stock passwords are left out. |
| Scaffold | Relay stacks (rule ids ending at `target`), canonical payload variant ids, hits per rule id, hits per tactic, header-name fingerprints. |
| Client networks | Members per client ASN. Never an address or a prefix. |
| Time | UTC hour buckets with at least one record, the epochs they fall in, and what the times measure (`request` for an access log). |
| Grades | The cluster tier (suggestive or significant) and its computed agent grade, L0 to L4. |
| Hosts | The operator's own hosts the cluster reached, defanged, **only** when the operator opts in (`shares_hosts`). |
| Operator | Free text the sender may add to describe itself. It is shown to the recipient and never read as proof of who sent the file. |

## What a file never carries

- **URLs, paths and query values.** Not even of flagged requests. A query value goes in only as the keyed hash of a value the rules already treat as linking.
- **Addresses.** No client IP, no network prefix, no address of any ordinary visitor; client networks are ASNs of the cluster's own records.
- **User agents, cookies, headers.** Header names reach the file only as a fingerprint hash of the set of names; values never do.
- **Plain or unkeyed hashes.** No value appears in the clear or under a hash anyone can compute without the epoch key. The redaction hash (`REDACTED-` plus unkeyed SHA-256) is never copied; it is re-keyed.
- **Cluster keys or record ids.** A cluster key is a hash of a record id; a sighting is numbered `S1`, `S2` instead.
- **Unflagged clusters.** Only clusters at the suggestive tier or above.

A producer **must not** add fields to a v1 file. A recipient **should** reject a file the schema refuses.

## The keyed hash

Each feature value is hashed as the first 16 bytes, in lower-case hex, of HMAC-SHA256 under the epoch key, over `sc-sightings-v1`, the kind (`param`, `rule` or `secret`), the name and the value, joined by a NUL byte. Rule matches are lower-cased; parameter values are kept as written.

**Epochs.** An epoch is a calendar quarter in UTC (`2026Q4`). A cluster's features are hashed under the key of every epoch its hours fall in, so a swarm that crosses a quarter boundary still matches on either side. A feature in an epoch with no published key is left out, and the file names that epoch in `missing_epochs`.

**Keys.** Each epoch has one random 32-byte key, published in [`keys.rs`](../../crates/sc-core/src/sightings/keys.rs) and compiled into the CLI and the browser toolkit, no later than the day the epoch starts. A key is never changed or removed. A group running its own exchange **may** use its own table, as long as every party uses the same one.

### What the keyed hash protects, and what it does not

Run tags are low-entropy: `zz9` is guessed in seconds. The key is public, because every operator needs it to make matching hashes. So:

- **It does** keep values out of the file in the clear, and out of reach of any precomputed table of plain or unkeyed hashes. A table built for one quarter is useless for the next, and none can be built before a key is published.
- **It does not** stop anyone who holds the epoch key from testing a guess: hash the guessed tag under the key and compare. A low-entropy tag in a sighting is as good as public to a determined reader. An inbox id or a captured secret, being long and random, stays out of reach.
- **It does not** hide that two files share a feature. That is its purpose.

An operator who would not publish a value **should not** share a file containing its hash with a party it does not trust. Sightings go to the admin privately; they are never published ([policies](../policies.md#collection)).

## The alternative: private set intersection

A private set intersection (PSI) protocol lets two parties learn only which values they share, and nothing about the rest, with no public key that turns a guess into a test. Its costs, and why v1 does not use it:

- **It is interactive.** Each pair of parties runs a protocol together, online, or through a server that sees every exchange. A file an operator downloads and sends once cannot do that, and the workbench sends nothing.
- **It is pairwise.** Matching many operators means a run per pair, or a multi-party protocol with heavier machinery and a coordinator.
- **It still leaks what is shared,** and a dishonest party can submit guessed values as its own set and learn which are in the other's. PSI raises the cost of a guess from free to one run, which a rate limit then bounds.
- **It needs cryptography** (elliptic-curve or oblivious-transfer based) that the browser module would carry, against its size budget.

A later version **may** add an OPRF-based mode, where a coordinator holds the key and answers hashing requests one at a time, so guesses are rate-limited instead of free. The format then keeps its fields and changes how `hash` is made.

## Matching

`swarmchase sightings match` reads sightings files and, with `--store`, the watch store's clusters as party `watch`, and lists:

- **pairs**: two sightings of different parties sharing at least one linking feature or captured secret, with the shared kinds and names, hours in common or the gap between them, and the scaffold both carry;
- **groups**: sightings joined by pairs, with how many parties and how many independent parties they span;
- **scaffold pairs**: sightings active in the same hours on alike scaffold with no shared feature, as hints only.

### Who a party is

A sighting is `observed` provenance only if its sender is who it says it is. The file cannot vouch for itself, so the admin sets each file's standing, and the matcher never reads it from the file:

| Standing | Set by | Counts toward corroboration |
|---|---|---|
| `unverified` | A file with nothing tying it to a known operator. | No. |
| `claimed` | `--vouch FILE=CASE` for a case with no report sent to an affected operator's contact. | No. |
| `contacted` | `--vouch FILE=CASE` for a case whose affected operator we reported to; the file came back on that channel. | Yes. |
| `watch` | The watch store's own clusters, from public records. | Yes. |

A group is **corroborated** when two parties that count share a feature. One name is one party, at the weakest standing it was given, so naming a party twice never raises it, and a party's sightings never match each other.

### Planted sightings

Anyone holding the epoch key can hash a value read from a public record. An unverified sighting that matches the watch therefore shows only that its sender can read public records. The design assumes a submitter may plant sightings:

- **Sightings propose, never merge.** No match changes a cluster, a tier, a grade or a case. It is a lead for case work.
- **Only vouched parties corroborate.** An unverified or claimed file can appear in a group but never makes it corroborated.
- **Bridges are flagged.** A sighting joined to two others that share nothing with each other, through different features, is the shape a planted file needs to make two swarms look like one. The matcher lists it as a bridge for the admin to check.
- **Limits.** A file over 500 sightings, 400 features or 2,000 hours per sighting, or with a malformed hash or epoch, is refused whole.

## Carrying a file

A sightings file is a JSON document with media type `application/json` and `spec` `sc-sightings-v1`. It is a valid attachment kind for an outside submission; the admin decides its standing when it arrives, as above.

## Mapping to STIX

Each pair maps naturally to a STIX 2.1 `sighting` of the watch cluster's indicator, with the operator as `where_sighted_refs` and the hour buckets as `first_seen` and `last_seen`. The toolkit's STIX export does not emit sightings yet.

## Versioning

A minor version adds optional fields; a file valid under 1.0 stays valid. A major version may change a field's meaning or how `hash` is made. A consumer **should** ignore a file whose `spec` names a major version it does not know.
