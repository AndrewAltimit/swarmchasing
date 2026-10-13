//! How long a run's phases and sources took: `durations_ms` in `run.json`
//! and the digest's "Run time" line.

use super::digest::SourceReport;
use serde::Serialize;
use std::collections::BTreeMap;
use std::time::Instant;

/// Phase durations in the order the run went through them.
#[derive(Debug)]
pub struct Phases {
    start: Instant,
    mark: Instant,
    done: Vec<(&'static str, u64)>,
}

impl Default for Phases {
    fn default() -> Self {
        Self::new()
    }
}

impl Phases {
    pub fn new() -> Self {
        let now = Instant::now();
        Self {
            start: now,
            mark: now,
            done: Vec::new(),
        }
    }

    /// The phase that ran since the last mark ended now.
    pub fn end(&mut self, phase: &'static str) {
        let now = Instant::now();
        self.done.push((phase, ms(now - self.mark)));
        self.mark = now;
    }

    /// Milliseconds since the run began.
    pub fn total_ms(&self) -> u64 {
        ms(self.start.elapsed())
    }

    /// `run.json`'s `durations_ms`: each phase, and `total` so far.
    pub fn summary(&self) -> Durations {
        Durations {
            phases: self.done.iter().copied().collect(),
            total: self.total_ms(),
        }
    }

    /// The digest's line: the run so far, each phase, and the slowest
    /// sources.
    pub fn digest_section(&self, sources: &[SourceReport]) -> String {
        let phases: Vec<String> = self
            .done
            .iter()
            .map(|(p, t)| format!("{p} {}", human(*t)))
            .collect();
        let mut slow: Vec<&SourceReport> = sources.iter().filter(|s| s.duration_ms > 0).collect();
        slow.sort_by(|a, b| b.duration_ms.cmp(&a.duration_ms).then(a.name.cmp(&b.name)));
        let slow: Vec<String> = slow
            .iter()
            .take(3)
            .map(|s| format!("{} {}", s.name, human(s.duration_ms)))
            .collect();
        let mut t = format!(
            "\n## Run time\n\n{} ({})",
            human(self.total_ms()),
            phases.join(", ")
        );
        if !slow.is_empty() {
            t.push_str(&format!("; slowest sources: {}", slow.join(", ")));
        }
        t.push_str(".\n");
        t
    }
}

/// `durations_ms` in `run.json`.
#[derive(Debug, Serialize)]
pub struct Durations {
    #[serde(flatten)]
    pub phases: BTreeMap<&'static str, u64>,
    pub total: u64,
}

fn ms(d: std::time::Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// `850 ms`, `12.3 s`, `4 min 05 s`.
pub fn human(ms: u64) -> String {
    match ms {
        0..1_000 => format!("{ms} ms"),
        1_000..60_000 => format!("{:.1} s", ms as f64 / 1000.0),
        _ => format!("{} min {:02} s", ms / 60_000, (ms % 60_000) / 1000),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_read_as_people_say_them() {
        assert_eq!(human(850), "850 ms");
        assert_eq!(human(12_340), "12.3 s");
        assert_eq!(human(245_000), "4 min 05 s");
    }

    #[test]
    fn the_digest_line_names_phases_and_the_slowest_sources() {
        let mut p = Phases::new();
        p.end("collect");
        p.end("analysis");
        let sources = [
            SourceReport {
                duration_ms: 70_000,
                ..SourceReport::new("slow", "wayback")
            },
            SourceReport {
                duration_ms: 2_000,
                ..SourceReport::new("fast", "npm")
            },
            SourceReport::new("skipped", "urlquery"),
        ];
        let t = p.digest_section(&sources);
        assert!(t.starts_with("\n## Run time\n\n"), "{t}");
        assert!(t.contains("(collect "), "{t}");
        assert!(t.contains(", analysis "), "{t}");
        assert!(
            t.contains("slowest sources: slow 1 min 10 s, fast 2.0 s."),
            "{t}"
        );
        let v = serde_json::to_value(p.summary()).unwrap();
        assert!(v["collect"].is_u64() && v["analysis"].is_u64() && v["total"].is_u64());
    }
}
