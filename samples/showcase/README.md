# Showcase set

`showcase.ndjson` is the synthetic record set the site's landing page walks through, one step of the method at a time (unwrap, match, link, time, grade, attribute, report), and the workbench's "Try the showcase" button loads. None of it was collected. Every record is marked `"synthetic": true`, every target host is a reserved placeholder (`*.example`), every network a documentation ASN (RFC 5398), and the relays and carriers are the public services the rules name.

The records are taken from the labelled sets in [`samples/eval/`](../eval/README.md), with their label fields removed, re-timed into one two-day window and given sources that vary their provenance. The site build refuses a record here that is not marked synthetic.

What each group of records shows:

- **Disjoint partition (S5):** two clients split one host list between them and start together. They send at one steady rate, so their lockstep is what any two steady jobs show and draws no synchronized start (S3).
- **Shared sink (S1):** two strands of one run, sent different ways, write to one inbox.
- **Hand-off (S2):** one run writes an artifact that a later run fetches.
- **Role sequence (S4):** a reader maps a set of hosts from archive captures, then a striker attacks them in the same order; its timestamps are capture times, so its grade is capped.
- **Rerun and candidate fleet:** the striker's host list is attacked again the next day under another tag, which the engine proposes as a candidate fleet.
- **Model-written requests:** model-output residue on its own.
- **Escalation:** one page asked for directly, then through a relay, with model residue: an adaptive grade.

Records here are not part of the evaluation set and are never scored by the eval gate.
