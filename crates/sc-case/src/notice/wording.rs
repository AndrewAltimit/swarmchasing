//! Wording checks on a notice's text: what the linter checks from a notice
//! alone ([`super::lint`]), and what the self-review checklist checks
//! against its case ([`crate::checklist`]).
//!
//! - every attribution statement carries a layer, a label and a tag
//!   (SC-FM 7.6, 7.7);
//! - no likelihood word is stronger than its label allows (SC-FM 8);
//! - a title names no provider the notice does not name as a developer;
//! - "compromised" only for endpoints classified so with a basis;
//! - an affected organisation is described as a target, never as the actor.

use crate::providers::Directory;
use crate::text::short;

/// ICD 203 likelihood terms and their strength (SC-FM 8.1), with the
/// off-table words of certainty, which no attribution statement uses.
/// Longer phrases first, so `very likely` is not read as `likely`.
const TERMS: &[(&str, u8)] = &[
    ("almost no chance", 1),
    ("very unlikely", 2),
    ("highly improbable", 2),
    ("roughly even chance", 4),
    ("roughly even odds", 4),
    ("almost certainly", 7),
    ("almost certain", 7),
    ("nearly certainly", 7),
    ("nearly certain", 7),
    ("very likely", 6),
    ("highly probable", 6),
    ("unlikely", 3),
    ("improbable", 3),
    ("likely", 5),
    ("probable", 5),
    ("probably", 5),
    ("certainly", 8),
    ("definitely", 8),
    ("undoubtedly", 8),
];

/// The attribution labels, weakest first, with the strongest term each
/// allows (SC-FM 7.7). Unattributed allows none.
const LABELS: &[(&str, u8)] = &[
    ("Unattributed", 0),
    ("Possible", 5),
    ("Suspected", 6),
    ("Confirmed", 7),
];

fn words(text: &str) -> Vec<String> {
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(str::to_lowercase)
        .collect()
}

/// The likelihood terms in `text`, with their strength.
pub fn terms(text: &str) -> Vec<(&'static str, u8)> {
    let w = words(text);
    let mut out = Vec::new();
    let mut i = 0;
    while i < w.len() {
        let hit = TERMS.iter().find(|(t, _)| {
            let parts: Vec<&str> = t.split(' ').collect();
            w.len() >= i + parts.len() && parts.iter().enumerate().all(|(k, p)| w[i + k] == *p)
        });
        match hit {
            Some(&(t, n)) => {
                out.push((t, n));
                i += t.split(' ').count();
            }
            None => i += 1,
        }
    }
    out
}

/// The label a line states (`Label: Suspected`, or a Conclusion line
/// `- Suspected: …`), if any.
fn line_label(line: &str) -> Option<(&'static str, u8)> {
    let t = line.trim_start_matches(['-', ' ', '*']);
    LABELS.iter().copied().find(|(l, _)| {
        line.contains(&format!("Label: {l}"))
            || line.contains(&format!("label: {l}"))
            || t.starts_with(&format!("{l}:"))
    })
}

/// The lines of the section under `## heading`.
fn section<'a>(body: &'a str, heading: &str) -> Vec<&'a str> {
    let mut inside = false;
    let mut out = Vec::new();
    for l in body.lines() {
        if let Some(h) = l.strip_prefix("## ") {
            inside = h.trim().eq_ignore_ascii_case(heading);
            continue;
        }
        if l.starts_with("# ") {
            inside = false;
        }
        if inside {
            out.push(l);
        }
    }
    out
}

/// The strongest label the notice states anywhere.
fn strongest_label(body: &str) -> (&'static str, u8) {
    body.lines()
        .filter_map(line_label)
        .max_by_key(|(_, n)| *n)
        .unwrap_or(LABELS[0])
}

/// Attribution statements without a layer, a label or a tag.
pub fn claim_problems(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    for l in section(body, "Attribution") {
        let t = l.trim_start();
        if !t.starts_with("- ") {
            continue;
        }
        let conclusion = line_label(t).is_some_and(|(lab, _)| {
            t.trim_start_matches(['-', ' '])
                .starts_with(&format!("{lab}:"))
        }) && t.contains("Tag: Conclusion");
        if conclusion {
            continue;
        }
        let layer =
            t.contains("(developer)") || t.contains("(hosting network)") || t.contains("Layer: ");
        let label = line_label(t).is_some();
        let tag = t.contains("tag: ") || t.contains("Tag: ");
        if !(layer && label && tag) {
            let missing: Vec<&str> = [(layer, "layer"), (label, "label"), (tag, "tag")]
                .into_iter()
                .filter_map(|(ok, what)| (!ok).then_some(what))
                .collect();
            out.push(format!(
                "attribution statement without a {}: `{}`",
                missing.join(", "),
                short(t)
            ));
        }
    }
    out
}

/// Likelihood words stronger than their label allows: in an attribution
/// line, the line's own label (else the strongest the notice states); in the
/// summary, the strongest the notice states; anywhere, an off-table word of
/// certainty, or a Confirmed-strength term without a Confirmed label.
pub fn likelihood_problems(body: &str) -> Vec<String> {
    let (top, cap) = strongest_label(body);
    let mut out = Vec::new();
    let mut check = |line: &str, (label, cap): (&str, u8)| {
        for (t, n) in terms(line) {
            if n > cap {
                out.push(format!(
                    "`{t}` is stronger than {label} allows: `{}`",
                    short(line)
                ));
            }
        }
    };
    for l in section(body, "Attribution") {
        check(l, line_label(l).unwrap_or((top, cap)));
    }
    for l in section(body, "Summary") {
        check(l, (top, cap));
    }
    let scoped: Vec<&str> = section(body, "Attribution")
        .into_iter()
        .chain(section(body, "Summary"))
        .collect();
    for l in body.lines().filter(|l| !scoped.contains(l)) {
        check(l, (top, cap.max(6)));
    }
    out.sort();
    out.dedup();
    out
}

/// Whether `text` names `name` as a whole word or phrase.
pub fn names(text: &str, name: &str) -> bool {
    let w = words(text);
    let n = words(name);
    !n.is_empty() && w.windows(n.len()).any(|win| win == n.as_slice())
}

/// Providers a title names that the notice does not name as a developer:
/// every model provider in the directory whose name or alias the title
/// holds, unless the front matter's `providers` lists it. Hosts and clouds
/// may be named as hosts.
pub fn title_problems(title: &str, named: &[String], dir: &Directory) -> Vec<String> {
    let mut out = Vec::new();
    for p in dir.models() {
        let listed = named
            .iter()
            .any(|n| p.names().any(|a| n.eq_ignore_ascii_case(a)));
        let hit = p.names().find(|a| names(title, a));
        if let (false, Some(a)) = (listed, hit) {
            out.push(format!(
                "the title names `{a}` ({}), which the notice does not name as a developer; below shared identifiers a provider stays out of the title",
                p.name
            ));
        }
    }
    out
}

/// "compromised" where the case has no compromised endpoint with a basis,
/// or next to a host not classified compromised.
pub fn compromised_problems(text: &str, compromised: &[String], other: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for l in text.lines().filter(|l| names(l, "compromised")) {
        if compromised.is_empty() {
            out.push(format!(
                "says `compromised` but no endpoint is classified compromised with a basis: `{}`",
                short(l)
            ));
            continue;
        }
        for h in other {
            if l.contains(&sc_core::defang_host(h)) || l.contains(h.as_str()) {
                out.push(format!(
                    "says `compromised` next to {}, which is not classified compromised",
                    sc_core::defang_host(h)
                ));
            }
        }
    }
    out
}

/// Words that cast a target as the actor.
const ACCUSING: &[&str] = &[
    "attacker",
    "perpetrator",
    "operated the agents",
    "ran the agents",
    "deployed the agents",
    "is responsible",
    "are responsible",
    "was responsible",
    "were responsible",
];

/// Lines naming an affected host that describe it as anything but a target.
pub fn accusation_problems(body: &str, affected: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for l in body.lines() {
        let lower = l.to_lowercase();
        for h in affected {
            if !(l.contains(&sc_core::defang_host(h)) || l.contains(h.as_str())) {
                continue;
            }
            if let Some(w) = ACCUSING.iter().find(|w| lower.contains(*w)) {
                out.push(format!(
                    "{} is affected (a target), but the notice says `{w}` next to it",
                    sc_core::defang_host(h)
                ));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terms_read_the_longest_phrase() {
        let t: Vec<&str> = terms("Very likely, not unlikely; almost certainly likely.")
            .into_iter()
            .map(|x| x.0)
            .collect();
        assert_eq!(t, ["very likely", "unlikely", "almost certainly", "likely"]);
        assert!(terms("likelihood remotely certain").is_empty());
    }

    #[test]
    fn a_term_may_not_exceed_its_label() {
        let ok = "## Attribution\n\n- **X** (developer). Evidence: e. d. Label: Suspected; tag: Inference.\n\n**Conclusion.**\n- Suspected: very likely operated by **X** (e). Tag: Conclusion.\n";
        assert!(
            likelihood_problems(ok).is_empty(),
            "{:?}",
            likelihood_problems(ok)
        );
        assert!(claim_problems(ok).is_empty(), "{:?}", claim_problems(ok));
        let strong = ok.replace("very likely", "almost certain");
        assert_eq!(likelihood_problems(&strong).len(), 1);
        // A line without a label is held to the strongest the notice states.
        let summary = format!("## Summary\n\nThe agents are almost certainly X's.\n\n{ok}");
        assert_eq!(likelihood_problems(&summary).len(), 1);
        // With no label at all, no likelihood word attributes anything.
        let bare = "## Summary\n\nLikely X's agents.\n";
        assert_eq!(likelihood_problems(bare).len(), 1);
        // Outside the summary and attribution, only words of certainty count.
        let hint = "## Timeline\n\n- Evaluation is likely, not malice. It is definitely X.\n";
        assert_eq!(likelihood_problems(hint).len(), 1);
    }

    #[test]
    fn claims_need_a_layer_label_and_tag() {
        let body = "## Attribution\n\n- **X** (developer). Evidence: e. Label: Suspected.\n- X did it.\n- Requests identify themselves as `m` from X. Layer: developer. Label: Unattributed; tag: Inference.\n\n## Timeline\n\n- a line\n";
        let p = claim_problems(body);
        assert_eq!(p.len(), 2, "{p:?}");
        assert!(p[0].contains("without a tag"), "{p:?}");
        assert!(p[1].contains("layer, label, tag"), "{p:?}");
    }

    #[test]
    fn titles_compromise_and_accusations() {
        let dir = Directory::builtin();
        assert_eq!(
            title_problems("Claude agents probe a portal", &[], &dir).len(),
            1
        );
        assert!(
            title_problems("Claude agents probe a portal", &["Anthropic".into()], &dir).is_empty()
        );
        assert!(title_problems("Agents probe a portal", &[], &dir).is_empty());

        let text = "| `a[.]example` | withheld (endpoint compromised) |\n| `b[.]example` | compromised |\n";
        assert_eq!(compromised_problems(text, &[], &[]).len(), 2);
        let p = compromised_problems(text, &["a.example".into()], &["b.example".into()]);
        assert_eq!(p.len(), 1, "{p:?}");

        let p = accusation_problems("The attacker at `a[.]example` …\n", &["a.example".into()]);
        assert_eq!(p.len(), 1);
        assert!(
            accusation_problems("`a[.]example` was targeted\n", &["a.example".into()]).is_empty()
        );
    }
}
