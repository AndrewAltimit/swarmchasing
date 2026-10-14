//! The rules explorer: one card per rule in `rules/default.toml`, grouped
//! by kind, read as plain TOML so a field the analysis does not use yet (a
//! `tactic`, say) still shows. A card is a row (id, weight, flags, a line
//! of description) that opens; rows start closed, and the page script opens
//! them on a wide screen, so on a phone the list is a list. Each card links its Field Manual section and tactic, and
//! can test a URL in the page (the engine's unwrap, output defanged). The
//! editor and the in-browser evaluation sit behind "Edit & test".

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
    pub artifact: bool,
    /// The independence group: rules in one group count once per record.
    pub group: Option<String>,
}

/// `T2 tool escalation`: a tactic id with its name, or the id alone when
/// the vocabulary does not know it.
pub fn tactic_label(id: &str) -> String {
    sc_core::model::Tactic::ALL
        .iter()
        .find(|t| t.id() == id)
        .map_or_else(|| id.to_string(), |t| format!("{} {}", t.id(), t.label()))
}

/// Fewer labelled hits than this and a rule's precision is not printed:
/// one benign hit would read as "precision 0%".
pub const MIN_HITS_FOR_PRECISION: usize = 5;

fn plural(n: usize, one: &str, many: &str) -> String {
    match n {
        0 => format!("no {many}"),
        1 => format!("1 {one}"),
        n => format!("{n} {many}"),
    }
}

/// A rule's hits on the labelled set: the counts, then its precision only
/// when there are enough hits to estimate it.
pub fn hit_counts(agent: usize, benign: usize, precision: Option<f64>) -> String {
    let total = agent + benign;
    if total == 0 {
        return "no hits".into();
    }
    let counts = format!(
        "{}, {}",
        plural(agent, "agent hit", "agent hits"),
        plural(benign, "benign hit", "benign hits")
    );
    match precision {
        Some(p) if total >= MIN_HITS_FOR_PRECISION => {
            format!("{counts} · precision {:.0}%", p * 100.0)
        }
        _ => format!("{counts}; too few to estimate precision"),
    }
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
            artifact: r.get("artifact").and_then(|x| x.as_bool()).unwrap_or(false),
            group: r
                .get("group")
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

/// A link from the rules page to a Field Manual section or tactic
/// (`fm` holds hrefs relative to the site root), or the id as text.
fn fm_link(fm: &BTreeMap<String, String>, id: &str, text: &str) -> String {
    match fm.get(id) {
        Some(h) => format!("<a href=\"../{}\">{}</a>", esc(h), esc(text)),
        None => esc(text),
    }
}

/// The explorer page body. `fm` maps Field Manual section and tactic ids
/// (`FM-4.4`, `SC-T4`) to their pages, relative to the site root.
pub fn body(
    toml_text: &str,
    stats: &[RuleStat],
    fm: &BTreeMap<String, String>,
) -> Result<String, String> {
    let (version, sug, sig, cards) = parse_rules(toml_text)?;
    let stats: BTreeMap<&str, &RuleStat> = stats.iter().map(|r| (r.rule_id.as_str(), r)).collect();
    let kinds: BTreeSet<&str> = cards.iter().map(|c| c.kind.as_str()).collect();
    let targets: BTreeSet<&str> = cards.iter().map(|c| c.target.as_str()).collect();
    let mut tactic_n: BTreeMap<&str, usize> = BTreeMap::new();
    for t in cards.iter().filter_map(|c| c.tactic.as_deref()) {
        *tactic_n.entry(t).or_insert(0) += 1;
    }
    let ctx = (sug - 1).max(0);
    let mut s = String::new();
    let _ = writeln!(
        s,
        "<header class=\"page-head\"><h1>Rules</h1>\
<p class=\"lede\">The indicator rules every analysis on this site and in the CLI runs, grouped by kind: rules version <code>{}</code>. A record scoring {sug} or more is <em>suggestive</em>, {sig} or more <em>significant</em>. Each rule can test a URL in this page: it is decoded, never opened.</p>\
<details class=\"explain\"><summary>How a score adds up</summary>\
<p>Each rule counts once per record. Rules that read the same artifact share an <em>independence group</em>, which counts once, at the largest weight among its rules that fired; other rules add their weight. Context hits (relays, cache-busters, self-identification, headers, outcomes) together count at most {ctx}, so context alone stays below suggestive: people use those services too ({}). A rule marked <em>significant alone</em> is enough for that tier by itself.</p>\
<p>Rules marked <em>links records</em> join the records they match into one cluster, because only one operator would share that value. How each kind is read is in the <a href=\"../methodology/\">methodology</a> and the Field Manual ({}, {}); how the rules score on the labelled set is on the <a href=\"../eval/\">evaluation</a> page.</p></details></header>",
        esc(&version),
        fm_link(fm, "FM-4.11", "FM-4.11"),
        fm_link(fm, "FM-4.2", "rule anatomy"),
        fm_link(fm, "FM-4.3", "tactics")
    );
    // `details.filters-fold`: open, and closed by the page script on a
    // phone, as the notice filters are.
    s.push_str("<details class=\"filters-fold\" open><summary>Filter rules</summary><form class=\"filters card\" data-rule-filters role=\"search\" aria-label=\"Filter rules\">");
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
    // Every tactic of the taxonomy, with how many rules carry it; SC-T8
    // and SC-T9 are cluster-level judgments no rule makes.
    s.push_str("<label>Tactic<select name=\"tactic\"><option value=\"\">Any</option>");
    for t in sc_core::model::Tactic::ALL {
        let n = tactic_n.get(t.id()).copied().unwrap_or(0);
        let _ = write!(
            s,
            "<option value=\"{}\">{} ({})</option>",
            esc(t.id()),
            esc(&tactic_label(t.id())),
            if n == 0 {
                "no rule".to_string()
            } else {
                n.to_string()
            }
        );
    }
    for t in tactic_n.keys() {
        if !sc_core::model::Tactic::ALL.iter().any(|x| x.id() == *t) {
            let _ = write!(s, "<option value=\"{0}\">{0}</option>", esc(t));
        }
    }
    s.push_str("</select></label>");
    s.push_str("<label class=\"check\"><input type=\"checkbox\" name=\"significant\"> significant alone</label>");
    s.push_str(
        "<label class=\"check\"><input type=\"checkbox\" name=\"link\"> links records</label><label class=\"check\"><input type=\"checkbox\" name=\"artifact\"> model artifact</label>",
    );
    let _ = writeln!(
        s,
        "<p class=\"hint\" data-rule-count aria-live=\"polite\">{} rules</p>\
<p class=\"hint note\" data-tactic-note hidden>SC-T8 (off-task targets) and SC-T9 (inter-agent coordination) are judgments about a cluster or a fleet, made with the task in view or from several runs together ({}), so no rule matches them. The workbench's Swarm view shows the interaction hints behind SC-T9.</p></form></details>",
        cards.len(),
        fm_link(fm, "FM-4.3", "FM-4.3")
    );
    for kind in &kinds {
        let mine: Vec<&RuleCard> = cards.iter().filter(|c| c.kind == *kind).collect();
        let _ = write!(
            s,
            "<section class=\"rule-kind\" data-rule-kind=\"{0}\" aria-labelledby=\"kind-{0}\"><h2 id=\"kind-{0}\">{1} <span class=\"hint\">{2}</span></h2><div class=\"rule-grid\">",
            esc(&slug_class(kind)),
            esc(&kind_label(kind)),
            plural(mine.len(), "rule", "rules"),
        );
        for c in mine {
            s.push_str(&card(c, stats.get(c.id.as_str()).copied(), fm));
        }
        s.push_str("</div></section>\n");
    }
    s.push_str("<p class=\"hint\" data-rule-none hidden>No rule matches these filters.</p>\n");
    editor(&mut s, toml_text);
    Ok(s)
}

/// One rule: a compact row (id, weight, flags, and the description cut to
/// a line while it is closed) that opens on its description, facts,
/// pattern, URL test and labelled-set hits. Closed in the markup, so a
/// phone lays out a list of rows; the page script opens them on a wide
/// screen.
fn card(c: &RuleCard, st: Option<&RuleStat>, fm: &BTreeMap<String, String>) -> String {
    let mut s = String::new();
    let _ = write!(
        s,
        "<article class=\"rule-card\" id=\"rule-{}\" data-kind=\"{}\" data-target=\"{}\" data-tactic=\"{}\" data-significant=\"{}\" data-link=\"{}\" data-artifact=\"{}\" data-text=\"{}\">\
<details class=\"rule-fold\"><summary><span class=\"rule-head\"><h3><code>{}</code></h3><span class=\"rule-w\" title=\"Weight\">+{}</span>{}</span>{}</summary><div class=\"rule-body\">",
        esc(&c.id),
        esc(&c.kind),
        esc(&c.target),
        esc(c.tactic.as_deref().unwrap_or("")),
        c.significant,
        c.link,
        c.artifact,
        esc(&format!(
            "{} {} {} {}",
            c.id,
            c.pattern,
            c.description,
            c.group.as_deref().unwrap_or("")
        )
        .to_lowercase()),
        esc(&c.id),
        c.weight,
        flags(c),
        if c.description.is_empty() {
            String::new()
        } else {
            format!("<span class=\"rule-gist\">{}</span>", esc(&c.description))
        },
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
    if let Some(g) = &c.group {
        let _ = write!(
            s,
            "<div><dt>Group</dt><dd><code>{}</code> <span class=\"hint\">counts once per record ({})</span></dd></div>",
            esc(g),
            fm_link(fm, "FM-4.11", "FM-4.11")
        );
    }
    if let Some(t) = &c.tactic {
        let _ = write!(
            s,
            "<div><dt>Tactic</dt><dd>{}</dd></div>",
            fm_link(fm, &format!("SC-{t}"), &tactic_label(t))
        );
    }
    let section = if c.artifact { "FM-4.5" } else { "FM-4.4" };
    let _ = write!(
        s,
        "<div><dt>Manual</dt><dd>{}</dd></div></dl>",
        fm_link(fm, section, section)
    );
    let _ = write!(
        s,
        "<pre class=\"pattern\" aria-label=\"Pattern\"><code>{}</code></pre>",
        esc(&c.pattern)
    );
    let _ = write!(
        s,
        "<details class=\"rule-test\" data-rule-test=\"{0}\"><summary>Test a URL</summary>\
<div class=\"row\"><label class=\"sr-only\" for=\"rt-{0}\">URL to test against {0}</label><input id=\"rt-{0}\" class=\"grow\" spellcheck=\"false\" autocomplete=\"off\" placeholder=\"https://r.jina.ai/https://...\">\
<button type=\"button\" data-test-run data-needs-engine disabled>Test</button></div><div class=\"rt-out\" aria-live=\"polite\"></div></details>",
        esc(&c.id)
    );
    let (agent, benign, precision) =
        st.map_or((0, 0, None), |r| (r.on_agent, r.on_benign, r.precision));
    let _ = write!(
        s,
        "<p class=\"hint\">Labelled set: {} (<a href=\"../eval/#per-rule\">hits per rule</a>)</p>",
        hit_counts(agent, benign, precision)
    );
    s.push_str("</div></details></article>");
    s
}

/// A rule's flags, in its row: significant alone, links records, model
/// artifact.
fn flags(c: &RuleCard) -> String {
    let mut s = String::new();
    if c.significant {
        s.push_str("<span class=\"flag sig\">significant alone</span>");
    }
    if c.link {
        s.push_str("<span class=\"flag link\">links records</span>");
    }
    if c.artifact {
        s.push_str("<span class=\"flag artifact\" title=\"The match only shows that a model wrote the request\">model artifact</span>");
    }
    s
}

/// The rules editor, after the rules.
fn editor(s: &mut String, toml_text: &str) {
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
group = "oast"
"#;
        let (v, sug, sig, cards) = parse_rules(toml).unwrap();
        assert_eq!((v.as_str(), sug, sig, cards.len()), ("v<1>", 3, 6, 2));
        assert_eq!(cards[0].weight, 1);
        assert_eq!(cards[0].tactic.as_deref(), Some("recon"));
        let mut fm = BTreeMap::new();
        fm.insert(
            "FM-4.4".to_string(),
            "docs/manual/04-indicators/#fm-44-x".to_string(),
        );
        let b = body(toml, &[], &fm).unwrap();
        assert!(!b.contains("<script") && !b.contains("<img"), "{b}");
        assert!(b.contains("Tactic</dt><dd>recon"));
        assert!(b.contains("href=\"../docs/manual/04-indicators/#fm-44-x\""));
        assert!(
            b.contains("<option value=\"T9\">T9 inter-agent coordination (no rule)</option>"),
            "{b}"
        );
        assert!(b.contains("data-rule-test=\"a.&lt;script&gt;\""));
        assert_eq!(tactic_label("T2"), "T2 tool escalation");
        assert!(b.contains("data-link=\"true\""));
        assert_eq!(cards[1].group.as_deref(), Some("oast"));
        assert!(b.contains("<dt>Group</dt><dd><code>oast</code>"));
        assert!(!b.contains("the sum of the weights"));
        // Grouped by kind, each rule a row that opens, the scoring folded.
        assert!(b.contains("<section class=\"rule-kind\" data-rule-kind=\"exfil\""));
        assert!(b.find("data-rule-kind=\"exfil\"") < b.find("data-rule-kind=\"relay\""));
        assert!(b.contains(
            "<details class=\"rule-fold\"><summary><span class=\"rule-head\"><h3><code>b</code></h3><span class=\"rule-w\" title=\"Weight\">+4</span><span class=\"flag link\">"
        ));
        assert!(b.contains("<details class=\"explain\"><summary>How a score adds up</summary>"));
    }

    #[test]
    fn a_rule_with_few_hits_shows_counts_not_a_precision() {
        assert_eq!(
            hit_counts(0, 1, Some(0.0)),
            "no agent hits, 1 benign hit; too few to estimate precision"
        );
        assert_eq!(
            hit_counts(4, 2, Some(4.0 / 6.0)),
            "4 agent hits, 2 benign hits · precision 67%"
        );
        assert_eq!(hit_counts(0, 0, None), "no hits");
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
