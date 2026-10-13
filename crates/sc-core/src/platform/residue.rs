//! Model-output residue in free text (issue, comment and package text).
//!
//! The bundled `marker.*` rules are written for request URLs. Those whose
//! pattern means the same in prose are reused here as they stand: unfilled
//! placeholders, tool-call markup, a chat reply's opener and a generation
//! loop. The Markdown rules are not: Markdown is how people write on these
//! platforms. A few text-only shapes no URL carries are added below, each
//! one weak alone: people paste chatbot answers too.

use crate::rules::{Matcher, Rules};
use regex::{Regex, RegexBuilder};
use std::sync::OnceLock;

/// Bundled rules reused on text.
pub const REUSED_RULES: [&str; 3] = [
    "marker.placeholder",
    "marker.tool_call_markup",
    "marker.chat_opener",
];

/// Text-only residue: (id, pattern). Case-insensitive.
pub const TEXT_RESIDUE: [(&str, &str); 5] = [
    (
        "text.ai_disclaimer",
        r"\bas an ai(\s+language)?\s+model\b|\bi(\s+am|'m)\s+an\s+ai\s+(language\s+model|assistant)\b",
    ),
    (
        "text.knowledge_cutoff",
        r"\bmy\s+(knowledge|training(\s+data)?)\s+(cutoff|cut-off)\b|\bas\s+of\s+my\s+last\s+(knowledge\s+|training\s+)?update\b",
    ),
    (
        "text.chat_opener",
        r"^\W*(certainly|sure|absolutely|of\s+course)[!,.]\s+(here(['\x{2019}]s|\s+is|\s+are)|below\s+is|i(['\x{2019}]ve|\s+have|['\x{2019}]ll))\b",
    ),
    (
        "text.unfilled_slot",
        r"\[insert[\s_-]+(your[\s_-]+)?(name|github[\s_-]*(username|handle)|e-?mail|contact(\s+information)?|company|title|project[\s_-]*name|repository[\s_-]*name)\]",
    ),
    ("text.regenerate", r"\bregenerate\s+response\b"),
];

fn text_set() -> &'static [(&'static str, Regex)] {
    static SET: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();
    SET.get_or_init(|| {
        TEXT_RESIDUE
            .iter()
            .map(|(id, p)| {
                let re = RegexBuilder::new(p)
                    .case_insensitive(true)
                    .build()
                    .expect("text residue patterns compile");
                (*id, re)
            })
            .collect()
    })
}

/// Residue rule ids that fire on `text`, sorted.
pub fn text_residue(text: &str, rules: &Rules) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    // The URL rules expect one value; a long body is read a line at a time
    // so `^` anchors at each line, as it would at each value.
    let lines: Vec<&str> = text.lines().take(400).collect();
    for r in rules.compiled.iter() {
        if !REUSED_RULES.contains(&r.def.id.as_str()) {
            continue;
        }
        if let Matcher::Re(re) = &r.matcher
            && lines.iter().any(|l| re.is_match(l.trim()))
        {
            out.push(r.def.id.clone());
        }
    }
    if crate::prose::repeated_token(text) {
        out.push("marker.repeated_token".into());
    }
    for (id, re) in text_set() {
        if lines.iter().any(|l| re.is_match(l.trim())) {
            out.push((*id).to_string());
        }
    }
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn residue_in_prose() {
        let r = Rules::default_rules();
        let hit = |t: &str| text_residue(t, &r);
        assert_eq!(
            hit("Certainly! Here's the security report you asked for."),
            ["text.chat_opener"]
        );
        assert_eq!(
            hit("Reported by [Your Name]. Contact YOUR_API_KEY owner."),
            ["marker.placeholder"]
        );
        assert_eq!(
            hit("As an AI language model, I cannot verify this."),
            ["text.ai_disclaimer"]
        );
        assert!(
            hit("Regards,\n[Insert GitHub username]").contains(&"text.unfilled_slot".to_string())
        );
        assert!(
            hit("<tool_call>{\"name\": \"open_issue\"}</tool_call>")
                .contains(&"marker.tool_call_markup".to_string())
        );
    }

    #[test]
    fn ordinary_prose_carries_none() {
        let r = Rules::default_rules();
        for t in [
            "Sure, I can take a look at this tomorrow.",
            "See [the docs](https://docs.example/x) for the setup steps.",
            "Fixed in #123, thanks for the report!",
            "The template uses {{ name }} which renders empty on Windows.",
        ] {
            assert!(
                text_residue(t, &r).is_empty(),
                "{t}: {:?}",
                text_residue(t, &r)
            );
        }
    }
}
