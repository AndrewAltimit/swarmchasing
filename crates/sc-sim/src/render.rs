//! A [`Measurement`] as plain text tables.

use crate::measure::{KindStat, Measurement};
use sc_core::eval::stats::Proportion;
use std::fmt::Write;

fn prop(p: Proportion) -> String {
    match (p.value, p.lo, p.hi) {
        (Some(v), Some(lo), Some(hi)) => format!(
            "{:>5.1}% [{:.0}-{:.0}%] ({}/{})",
            v * 100.0,
            lo * 100.0,
            hi * 100.0,
            p.k,
            p.n
        ),
        _ => "-".into(),
    }
}

fn table(s: &mut String, rows: &std::collections::BTreeMap<String, KindStat>, edges: bool) {
    let _ = writeln!(
        s,
        "  {:<22} {:>5} {:>5} {:>5} {:>5}  {:<28} recall",
        "kind",
        "pairs",
        "right",
        "run",
        if edges { "fleet" } else { "" },
        "precision",
    );
    for (k, v) in rows {
        let label = match k.parse::<sc_core::SwarmEdgeKind>() {
            Ok(e) if edges => format!("{} {k}", e.id()),
            _ => k.clone(),
        };
        let _ = writeln!(
            s,
            "  {:<22} {:>5} {:>5} {:>5} {:>5}  {:<28} {}",
            label,
            v.pairs,
            v.correct,
            v.same_run,
            if edges {
                v.same_operator.to_string()
            } else {
                String::new()
            },
            prop(v.precision()),
            prop(v.recall()),
        );
    }
}

pub fn render(m: &Measurement) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "Records with truth: {}", m.records);
    let _ = writeln!(
        s,
        "\nInteraction edges against true swarm pairs ({} reachable of {}). Right: distinct runs in one swarm; run: both sides one run; fleet: one operator, no interaction. Precision, then recall over reachable pairs.",
        m.swarm_pairs.reachable, m.swarm_pairs.total
    );
    table(&mut s, &m.edges, true);
    let _ = writeln!(
        s,
        "\nSoft links and candidate fleets against true operator pairs ({} reachable of {}, {} already in one cluster). Right: one operator. Recall over reachable pairs in different clusters.",
        m.operator_pairs.reachable, m.operator_pairs.total, m.operator_pairs.joined
    );
    table(&mut s, &m.links, false);
    if m.unplaced > 0 {
        let _ = writeln!(s, "\nUnplaced (a side with no truth): {}", m.unplaced);
    }
    let cols = sc_core::eval::grades::COLUMNS;
    let _ = writeln!(s, "\nAgent grade by actor/class (records):");
    let _ = write!(s, "  {:<32}", "");
    for c in cols {
        let _ = write!(s, " {c:>11}");
    }
    s.push('\n');
    for (row, counts) in &m.grades {
        let _ = write!(s, "  {row:<32}");
        for c in cols {
            let _ = write!(s, " {:>11}", counts.get(c).copied().unwrap_or(0));
        }
        s.push('\n');
    }
    s
}
