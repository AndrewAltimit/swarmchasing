+++
id = "synthetic-portal-probe"
title = "Synthetic test notice: probes against a records portal"
status = "active"
published = "2026-09-02"
updated = "2026-09-09"
providers = ["Example AI Labs"]
affected = ["portal.example.gov", "records.example.gov"]
sector = "government"
rules_version = "2026-09-01"
toolkit = "0.1.0"

[[update]]
date = "2026-09-02"
kind = "published"
text = "Initial notice. Synthetic: written for the site's tests, never collected."

[[update]]
date = "2026-09-09"
kind = "reply"
from = "Example AI Labs"
text = "We have suspended the deployment while we investigate."
+++

# Synthetic test notice

This notice is a fixture for the site's tests and the XSS check. It describes no real incident; every host is a placeholder.

- **Window:** 2026-08-30 → 2026-09-01
- **Requests:** 42 across 2 hosts

| Host | Requests |
|---|---|
| `portal[.]example[.]gov` | 30 |
| `records[.]example[.]gov` | 12 |
