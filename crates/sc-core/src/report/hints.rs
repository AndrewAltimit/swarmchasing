//! One-line descriptions of a cluster's hints (payload dialect, fan-out,
//! cut lengths, date tags, daily rhythm), or nothing when there is too
//! little to say. Every line says it is a hint, not evidence.

use super::dur;
use crate::dialect::{CutGroup, CutLengths, Dialect};
use crate::fanout::FanOut;
use crate::timing::{Rhythm, RhythmVerdict, STALE_AGREE_SHARE, STALE_MIN_DAYS, StaleDates};

/// The cluster's canonical test payloads, or nothing for fewer than two
/// records (one person pasting one payload is no habit).
pub(super) fn dialect_line(d: &Dialect) -> Option<String> {
    if d.records < 2 {
        return None;
    }
    let fams: Vec<String> = d
        .families()
        .into_iter()
        .map(|(fam, vs)| {
            let vs: Vec<String> = vs.iter().map(|(v, n)| format!("{v} ×{n}")).collect();
            format!("{fam} ({})", vs.join(", "))
        })
        .collect();
    let order = if d.first_seen.len() > 1 {
        let shown: Vec<&str> = d.first_seen.iter().take(8).map(String::as_str).collect();
        format!("; first seen {}", shown.join(" → "))
    } else {
        String::new()
    };
    Some(format!(
        "payload dialect `{}` over {} records: {}{order}. Which canonical test payloads a client reaches for is consistent with one model or tool, not evidence on its own",
        d.signature,
        d.records,
        fams.join("; ")
    ))
}

/// The modal batch width, when one width holds for most batches.
pub(super) fn fanout_line(f: &FanOut) -> Option<String> {
    let w = f.modal_width?;
    let widths: Vec<String> = f.widths.iter().map(|(w, n)| format!("{w}×{n}")).collect();
    Some(format!(
        "parallel fan-out: {} of {} one-second batches were {w} alike requests wide (width×batches: {}), like an agent issuing tool calls in parallel; a scanner submitting a list in bulk looks the same (a hint, not evidence)",
        f.widths.get(&w).copied().unwrap_or(0),
        f.batches,
        widths.join(", ")
    ))
}

/// Truncated URLs cut at nearly one length.
pub(super) fn cut_line(c: &CutLengths) -> Option<String> {
    let span = |g: &CutGroup| {
        if g.min == g.max {
            format!("{}", g.min)
        } else {
            format!("{}–{}", g.min, g.max)
        }
    };
    let mut parts = Vec::new();
    if let Some(g) = &c.url {
        parts.push(format!(
            "{} of {} truncated URLs were cut at {} characters",
            g.records,
            c.truncated,
            span(g)
        ));
    }
    if let Some(g) = &c.value {
        parts.push(format!(
            "{} of {} cut parameter values were {} characters long",
            g.records,
            c.truncated,
            span(g)
        ));
    }
    if parts.is_empty() {
        return None;
    }
    Some(format!(
        "cut lengths: {}, consistent with a model or tool output limit, not evidence on its own (rule out the source's own display limit first)",
        parts.join("; ")
    ))
}

/// The hour-of-day profile as a hint, or nothing when there is too little to say.
/// Date tags far behind when they were seen, or nothing when they agree with
/// the clock.
pub(super) fn stale_dates_line(d: &StaleDates) -> Option<String> {
    if !d.consistent {
        return None;
    }
    let named = match d.modal_date {
        Some(date) if d.same_date_share >= STALE_AGREE_SHARE => {
            format!(", {:.0}% naming {date}", d.same_date_share * 100.0)
        }
        _ => String::new(),
    };
    Some(format!(
        "date tags: {} of {} name a day at least {STALE_MIN_DAYS} days before they were seen (median lag {} days{named}), like a model with no clock writing the date it believes is today (a hint, not evidence)",
        d.behind,
        d.tags,
        d.median_lag_days.unwrap_or(0)
    ))
}

pub(super) fn rhythm_line(r: &Rhythm) -> Option<String> {
    let over = format!(
        "over {} days (hour-of-day entropy {:.2}, longest idle {})",
        r.days,
        r.entropy,
        dur((r.longest_idle_hours * 3600.0) as i64)
    );
    Some(match r.verdict {
        RhythmVerdict::TooShort => return None,
        RhythmVerdict::RoundTheClock => format!(
            "daily rhythm: active around the clock {over}; people sleep, automated fleets need not (a hint, not evidence)"
        ),
        RhythmVerdict::Daytime {
            utc_offset_guess,
            start_hour,
            hours,
        } => format!(
            "daily rhythm: active {start_hour:02}:00–{:02}:00 UTC {over}, like a working day near UTC{utc_offset_guess:+} (a hint, not evidence of where the operator is)",
            (start_hour as u32 + hours as u32) % 24
        ),
        RhythmVerdict::Unclear => format!("daily rhythm: no clear pattern {over}"),
    })
}
