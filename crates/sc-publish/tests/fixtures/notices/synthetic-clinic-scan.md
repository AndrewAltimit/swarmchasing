+++
id = "synthetic-clinic-scan"
title = "Synthetic test notice: scanning of a clinic booking site"
status = "contained"
published = "2026-08-11"
updated = "2026-08-20"
providers = ["Placeholder Models"]
affected = ["booking.clinic.example"]
sector = "health"
rules_version = "2026-08-01"
toolkit = "0.1.0"

[[update]]
date = "2026-08-11"
kind = "published"
text = "Initial notice. Synthetic: written for the site's tests, never collected."

[[update]]
date = "2026-08-20"
kind = "status"
text = "No activity for seven days; the provider reports the run stopped."
+++

# Synthetic test notice

A fixture for the site's tests. It describes no real incident.

1. Reconnaissance of the booking pages.
2. Repeated form submissions with test payloads.
