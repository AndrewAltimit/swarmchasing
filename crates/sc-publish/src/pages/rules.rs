//! The rules explorer: one card per rule in `rules/default.toml`, read as
//! plain TOML so a field the analysis does not use yet (a `tactic`, say)
//! still shows. The editor and the in-browser evaluation sit behind
//! "Edit & test".

use super::html::{esc, slug_class};
use sc_core::eval::RuleStat;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;

/// One rule as the explorer shows it.
#[derive(Debug, Clone, Default)]
pub struct RuleCard {
    pub id: String,
    pub kind: String,
    pub target: String,
    pub pattern: String,
    pub weight: i64,
    pub significant: bool,
    pub link: bool,
    pub description: String,
    pub tactic: Option<String>,
}

/// The rules of a rules file, in file order.
pub fn parse_rules(toml_text: &str) -> Result<(String, i64, i64, Vec<RuleCard>), String> {
    let v: toml::Value = toml::from_str(toml_text).map_err(|e| format!("rules: {e}"))?;
    let str_of =
        |t: &toml::Value, k: &str| t.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
    let version = v
        .get("meta")
        .map(|m| str_of(m, "version"))
        .unwrap_or_default();
    let th = |k: &str| {
        v.get("thresholds")
            .and_then(|t| t.get(k))
            .and_then(|x| x.as_integer())
            .unwrap_or(0)
    };
    let mut cards = Vec::new();
    for r in v
        .get("rule")
        .and_then(|r| r.as_array())
        .into_iter()
        .flatten()
    {
        cards.push(RuleCard {
            id: str_of(r, "id"),
            kind: str_of(r, "kind"),
            target: str_of(r, "target"),
            pattern: str_of(r, "pattern"),
            weight: r.get("weight").and_then(|x| x.as_integer()).unwrap_or(1),
            significant: r
                .get("significant")
                .and_then(|x| x.as_bool())
                .unwrap_or(false),
            link: r.get("link").and_then(|x| x.as_bool()).unwrap_or(false),
            description: str_of(r, "description"),
            tactic: r
                .get("tactic")
                .and_then(|x| x.as_str())
                .filter(|s| !s.is_empty())
                .map(String::from),
        });
    }
    Ok((version, th("suggestive"), th("significant"), cards))
}

fn kind_label(k: &str) -> String {
    k.replace('_', " ")
}

/// The explorer page body.
pub fn body(toml_text: &str, stats: &[RuleStat]) -> Result<String, String> {
    let (version, sug, sig, cards) = parse_rules(toml_text)?;
    let stats: BTreeMap<&str, &RuleStat> = stats.iter().map(|r| (r.rule_id.as_str(), r)).collect();
    let kinds: BTreeSet<&str> = cards.iter().map(|c| c.kind.as_str()).collect();
    let targets: BTreeSet<&str> = cards.iter().map(|c| c.target.as_str()).collect();
    let tactics: BTreeSet<&str> = cards.iter().filter_map(|c| c.tactic.as_deref()).collect();
    let mut s = String::new();
    let _ = writeln!(
        s,
        "<header class=\"page-head\"><h1>Rules</h1>\
<p class=\"lede\">The indicator rules every analysis on this site and in the CLI runs: rules version <code>{}</code>. A record's score is the sum of the weights of the distinct rules it matches; a score of {sug} or more is <em>suggestive</em>, {sig} or more is <em>significant</em>, and a rule marked <em>significant alone</em> is enough for that tier by itself. A single relay hit is never enough: people use those services too.</p>\
<p class=\"lede\">Rules marked <em>links records</em> join the records they match into one cluster, because only one operator would share that value. How each kind is read is in the <a href=\"../methodology/\">methodology</a>; how the rules score on the labelled set is on the <a href=\"../eval/\">evaluation</a> page.</p></header>",
        esc(&version)
    );
    s.push_str("<form class=\"filters card\" data-rule-filters role=\"search\" aria-label=\"Filter rules\">");
    s.push_str("<label class=\"grow\">Search<input name=\"q\" type=\"search\" spellcheck=\"false\" placeholder=\"id, pattern or description\"></label>");
    s.push_str("<label>Kind<select name=\"kind\"><option value=\"\">Any</option>");
    for k in &kinds {
        let _ = write!(
            s,
            "<option value=\"{}\">{}</option>",
            esc(k),
            esc(&kind_label(k))
        );
    }
    s.push_str(
        "</select></label><label>Target<select name=\"target\"><option value=\"\">Any</option>",
    );
    for t in &targets {
        let _ = write!(s, "<option value=\"{0}\">{0}</option>", esc(t));
    }
    s.push_str("</select></label>");
    if !tactics.is_empty() {
        s.push_str("<label>Tactic<select name=\"tactic\"><option value=\"\">Any</option>");
        for t in &tactics {
            let _ = write!(s, "<option value=\"{0}\">{0}</option>", esc(t));
        }
        s.push_str("</select></label>");
    }
    s.push_str("<label class=\"check\"><input type=\"checkbox\" name=\"significant\"> significant alone</label>");
    s.push_str(
        "<label class=\"check\"><input type=\"checkbox\" name=\"link\"> links records</label>",
    );
    let _ = write!(
        s,
        "<p class=\"hint\" data-rule-count aria-live=\"polite\">{} rules</p></form>\n<div class=\"rule-grid\">",
        cards.len()
    );
    for c in &cards {
        let st = stats.get(c.id.as_str());
        let _ = write!(
            s,
            "<article class=\"rule-card\" id=\"rule-{}\" data-kind=\"{}\" data-target=\"{}\" data-tactic=\"{}\" data-significant=\"{}\" data-link=\"{}\" data-text=\"{}\">\
<header><h2><code>{}</code></h2><span class=\"badge kind-{}\">{}</span></header>",
            esc(&c.id),
            esc(&c.kind),
            esc(&c.target),
            esc(c.tactic.as_deref().unwrap_or("")),
            c.significant,
            c.link,
            esc(&format!("{} {} {}", c.id, c.pattern, c.description).to_lowercase()),
            esc(&c.id),
            esc(&slug_class(&c.kind)),
            esc(&kind_label(&c.kind)),
        );
        if !c.description.is_empty() {
            let _ = write!(s, "<p>{}</p>", esc(&c.description));
        }
        let _ = write!(
            s,
            "<dl class=\"rule-meta\"><div><dt>Weight</dt><dd>+{}</dd></div><div><dt>Matches</dt><dd>{}</dd></div>",
            c.weight,
            esc(&c.target.replace('_', " "))
        );
        if let Some(t) = &c.tactic {
            let _ = write!(s, "<div><dt>Tactic</dt><dd>{}</dd></div>", esc(t));
        }
        s.push_str("</dl>");
        if c.significant || c.link {
            s.push_str("<p class=\"flags\">");
            if c.significant {
                s.push_str("<span class=\"flag sig\">significant alone</span>");
            }
            if c.link {
                s.push_str("<span class=\"flag link\">links records</span>");
            }
            s.push_str("</p>");
        }
        let _ = write!(
            s,
            "<pre class=\"pattern\" aria-label=\"Pattern\"><code>{}</code></pre>",
            esc(&c.pattern)
        );
        match st {
            Some(r) => {
                let _ = write!(
                    s,
                    "<p class=\"hint\">Labelled set: {} agent, {} benign record(s){}</p>",
                    r.on_agent,
                    r.on_benign,
                    r.precision
                        .map(|p| format!(" · precision {:.0}%", p * 100.0))
                        .unwrap_or_default()
                );
            }
            None => s.push_str("<p class=\"hint\">Labelled set: no hits</p>"),
        }
        s.push_str("</article>");
    }
    s.push_str(
        "</div>\n<p class=\"hint\" data-rule-none hidden>No rule matches these filters.</p>\n",
    );
    let _ = writeln!(
        s,
        "<section class=\"card editor\" id=\"edit\" aria-labelledby=\"edit-h\"><h2 id=\"edit-h\">Edit &amp; test</h2>\
<p class=\"hint\">Edit the rules and test them here. Edits are kept in this browser only and apply to the workbench and the unwrap tool on this site; they never leave the page. The analysis engine loads when you open the editor.</p>\
<details data-rules-editor><summary>Open the rules editor</summary>\
<label for=\"rules-text\">Rules (TOML)</label>\
<textarea id=\"rules-text\" rows=\"24\" spellcheck=\"false\">{}</textarea>\
<div class=\"row\"><button type=\"button\" class=\"primary\" data-act=\"validate\" data-needs-engine disabled>Validate</button>\
<button type=\"button\" data-act=\"save\" data-needs-engine disabled>Use for this browser</button>\
<button type=\"button\" data-act=\"eval\" data-needs-engine disabled>Test against labelled set</button>\
<button type=\"button\" data-act=\"reset\">Reset to bundled</button>\
<span class=\"hint\" data-engine-status aria-live=\"polite\"></span></div>\
<p class=\"hint\" id=\"rules-status\" aria-live=\"polite\"></p><div id=\"eval-out\" class=\"detail\"></div></details></section>",
        esc(toml_text)
    );
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_every_rule_and_escapes_it() {
        let toml = r#"
[meta]
version = "v<1>"
[thresholds]
suggestive = 3
significant = 6
[[rule]]
id = "a.<script>"
kind = "relay"
target = "url"
pattern = '''<img src=x onerror="alert(1)">'''
tactic = "recon"
[[rule]]
id = "b"
kind = "exfil"
target = "host"
pattern = "x.example"
weight = 4
link = true
"#;
        let (v, sug, sig, cards) = parse_rules(toml).unwrap();
        assert_eq!((v.as_str(), sug, sig, cards.len()), ("v<1>", 3, 6, 2));
        assert_eq!(cards[0].weight, 1);
        assert_eq!(cards[0].tactic.as_deref(), Some("recon"));
        let b = body(toml, &[]).unwrap();
        assert!(!b.contains("<script") && !b.contains("<img"), "{b}");
        assert!(b.contains("Tactic</dt><dd>recon"));
        assert!(b.contains("data-link=\"true\""));
    }

    #[test]
    fn the_bundled_rules_parse() {
        let (_, _, _, cards) = parse_rules(sc_core::DEFAULT_RULES).unwrap();
        assert_eq!(cards.len(), sc_core::Rules::default_rules().set.rules.len());
        assert!(
            cards
                .iter()
                .all(|c| !c.id.is_empty() && !c.pattern.is_empty())
        );
    }
}
