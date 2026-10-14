//! Model-output residue in free text (issue, comment and package text).
//!
//! The bundled `marker.*` rules are written for request URLs. Those whose
//! pattern means the same in prose are reused here as they stand: unfilled
//! placeholders, tool-call markup, a chat reply's opener and a generation
//! loop. The Markdown rules are not: Markdown is how people write on these
//! platforms. A few text-only shapes no URL carries are added below, each
//! one weak alone: people paste chatbot answers too.
//!
//! [`self_id`] is a separate list: the footers, trailers and session links
//! coding-agent harnesses add. It is weaker still, context for the admin and
//! never part of a group's residue.

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

/// Coding-harness self-identification: the footers, trailers and session
/// links agent harnesses add to what they write. (id, pattern),
/// case-insensitive. Weak context, never strong evidence: people run these
/// harnesses for their own work every day, and anyone can paste the text.
/// Kept apart from residue so it never makes a group residue-heavy.
/// Patterns read the whole text; `(?m:^...)` anchors a trailer at a line.
pub const SELF_ID: [(&str, &str); 13] = [
    (
        "selfid.claude_code",
        r"generated with \[?claude code\]?|co-authored-by:\s*claude\b|claude\.ai/code\b",
    ),
    (
        "selfid.codex",
        r"chatgpt\.com/codex/tasks/|co-authored-by:\s*(chatgpt\s+)?codex\b",
    ),
    ("selfid.devin", r"app\.devin\.ai/sessions/"),
    (
        "selfid.copilot",
        r"co-authored-by:\s*copilot\b|copilot-swe-agent\b",
    ),
    // The cloud agent's commit identity `Cursor Agent <cursoragent@cursor.com>`
    // and the `Made-with: Cursor` trailer the editor's agent adds (both
    // described by Cursor staff on forum.cursor.com).
    (
        "selfid.cursor",
        r"cursor\.com/(background-agent|agents)\b|co-authored-by:\s*cursor\s+agent\b|<cursoragent@cursor\.com>|(?m:^\s*made-with:\s*cursor\b)",
    ),
    ("selfid.jules", r"jules\.google(\.com)?/task/"),
    ("selfid.aider", r"co-authored-by:\s*aider\b"),
    // Amp's default trailers: a thread link (https://ampcode.com/threads/T-...)
    // and `Co-authored-by: Amp <amp@ampcode.com>`.
    (
        "selfid.amp",
        r"amp-thread-id:\s*https://ampcode\.com/threads/T-|co-authored-by:\s*amp\s*<amp@ampcode\.com>",
    ),
    // OpenHands' default git identity (github.com/OpenHands/OpenHands,
    // `openhands <openhands@all-hands.dev>`) as a co-author.
    (
        "selfid.openhands",
        r"co-authored-by:\s*openhands\s*<openhands@all-hands\.dev>",
    ),
    // Factory's Droid GitHub App (https://github.com/apps/factory-droid).
    ("selfid.factory", r"factory-droid\[bot\]"),
    // Crush's `Generated with Crush` line and `Assisted-by: Crush:<model>`
    // trailer (github.com/charmbracelet/crush, README "attribution").
    (
        "selfid.crush",
        r"generated with crush\b|assisted-by:\s*crush:",
    ),
    // The hidden markers GitHub Agentic Workflows append to what they post
    // (github.com/github/gh-aw, docs reference/footers.md).
    (
        "selfid.gh_aw",
        r"<!--\s*gh-aw-(workflow-id|tracker-id|execution):",
    ),
    // The generic `Assisted-by:` trailer the Linux kernel asks AI-assisted
    // patches to carry (https://docs.kernel.org/process/coding-assistants.html),
    // which other harnesses adopt. Any harness, so it names none.
    ("selfid.assisted_by", r"(?m:^\s*assisted-by:\s*\S)"),
];

fn self_id_set() -> &'static [(&'static str, Regex)] {
    static SET: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();
    SET.get_or_init(|| {
        SELF_ID
            .iter()
            .map(|(id, p)| {
                let re = RegexBuilder::new(p)
                    .case_insensitive(true)
                    .build()
                    .expect("self-identification patterns compile");
                (*id, re)
            })
            .collect()
    })
}

/// Self-identification ids that fire on `text`, in [`SELF_ID`] order.
pub fn self_id(text: &str) -> Vec<String> {
    let head: String = text.chars().take(64 * 1024).collect();
    self_id_set()
        .iter()
        .filter(|(_, re)| re.is_match(&head))
        .map(|(id, _)| (*id).to_string())
        .collect()
}

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
    fn harness_self_identification_is_its_own_list() {
        let r = Rules::default_rules();
        let t = "Fix the parser.\n\nGenerated with [Claude Code](https://claude.com/claude-code)\n\nCo-Authored-By: Claude <noreply@anthropic.com>";
        assert_eq!(self_id(t), ["selfid.claude_code"]);
        assert!(text_residue(t, &r).is_empty(), "self-id is not residue");
        assert_eq!(
            self_id("Codex task: https://chatgpt.com/codex/tasks/task_e_0123"),
            ["selfid.codex"]
        );
        assert_eq!(
            self_id("Devin session: https://app.devin.ai/sessions/abc123"),
            ["selfid.devin"]
        );
        assert_eq!(
            self_id("See https://jules.google.com/task/123"),
            ["selfid.jules"]
        );
        for t in [
            "I asked Claude about this and it agreed.",
            "The cursor jumps to the end of the line.",
            "Our code review found a copilot setting.",
        ] {
            assert!(self_id(t).is_empty(), "{t}: {:?}", self_id(t));
        }
    }

    #[test]
    fn harness_trailers_and_markers() {
        let one = |t: &str, id: &str| assert_eq!(self_id(t), [id], "{t}");
        one(
            "Fix flaky test\n\nCo-authored-by: Cursor Agent <cursoragent@cursor.com>",
            "selfid.cursor",
        );
        one("Tidy imports\n\nMade-with: Cursor", "selfid.cursor");
        one(
            "Add retries\n\nAmp-Thread-ID: https://ampcode.com/threads/T-0199aa11-2233-7444-8555-666677778888",
            "selfid.amp",
        );
        one(
            "Add retries\n\nCo-authored-by: Amp <amp@ampcode.com>",
            "selfid.amp",
        );
        one(
            "Bump deps\n\nCo-authored-by: openhands <openhands@all-hands.dev>",
            "selfid.openhands",
        );
        one(
            "Reviewed by factory-droid[bot] on this pull request.",
            "selfid.factory",
        );
        one("Fix the parser.\n\nGenerated with Crush", "selfid.crush");
        one(
            "Weekly triage summary.\n\n<!-- gh-aw-workflow-id: issue-triage -->",
            "selfid.gh_aw",
        );
        one("Done.\n<!--gh-aw-tracker-id: triage-7 -->", "selfid.gh_aw");
        one(
            "mm: fix a leak\n\nAssisted-by: LLM coccinelle sparse",
            "selfid.assisted_by",
        );
        // Crush's trailer is both its own and the generic convention.
        assert_eq!(
            self_id("Fix.\n\nAssisted-by: Crush:model-x"),
            ["selfid.crush", "selfid.assisted_by"]
        );
        for t in [
            "The amp in the lab hums when the cursor moves.",
            "I made this with Cursor and it works: made with cursor.",
            "Assisted-by is a trailer the kernel documents.",
            "We crush the image before upload; generated with crushed ice.",
            "<!-- workflow-id: build -->",
            "Our droid factory ships on Friday.",
            "Co-authored-by: Amp Lee <amp.lee@mail.example>",
        ] {
            assert!(self_id(t).is_empty(), "{t}: {:?}", self_id(t));
        }
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
