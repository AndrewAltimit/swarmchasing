//! What a public notice may carry.
//!
//! - What a public notice withholds ([`PublicView`]): callback channels (inbox,
//!   webhook and topic identifiers, paste links), e-mail addresses, run
//!   identifiers that cannot be told apart from credentials, and the request
//!   details for endpoints the admin marked compromised. Anything the view
//!   cannot classify is withheld and flagged for the admin.
//! - A last check over finished text ([`lint_public`]), run on every notice
//!   before it is published and on every committed notice in CI.
//!
//! The notice file format, the site pages and the feed are in `sc-publish`.

use crate::analyze::{Analysis, ObsResult};
use crate::model::{IndicatorKind, LinkFeature};
use crate::rules::{Matcher, Rules, Target};
use regex::Regex;
use std::collections::{BTreeSet, HashMap};
use std::fmt::Write;
use std::sync::OnceLock;

/// Linking parameters that carry a run or scan tag. Other linking parameters
/// (`tok`, `session`, `sid`, `nonce`) may be credentials and are withheld.
pub const TAG_PARAMS: &[&str] = &[
    "uqtag", "uqscan", "uq_tag", "tag", "run", "runid", "run_id", "cb_tag",
];

pub const WITHHELD: &str = "[withheld]";

fn email_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"(?i)\b([a-z0-9._%+-]+)(@|%40)([a-z0-9-]+(\.[a-z0-9-]+)+)\b").unwrap()
    })
}

/// Role mailboxes that may appear in a notice (contacts, corrections).
const ROLE_MAILBOXES: &[&str] = &[
    "security",
    "abuse",
    "cert",
    "csirt",
    "psirt",
    "soc",
    "info",
    "contact",
    "press",
    "disclosure",
    "trustandsafety",
    "safety",
    "noreply",
    "no-reply",
];

/// Replace the local part of every e-mail address: a disposable inbox is a
/// callback channel.
pub fn mask_emails(s: &str) -> String {
    email_re()
        .replace_all(s, |c: &regex::Captures| {
            format!("{WITHHELD}{}{}", &c[2], &c[3])
        })
        .into_owned()
}

/// A pattern for `value` as it may be written in a URL: each character as
/// itself, percent-encoded or double percent-encoded, a space also as `+`,
/// ignoring case.
fn written_forms(value: &str) -> Option<Regex> {
    let mut p = String::from("(?i)");
    for c in value.chars() {
        let mut buf = [0u8; 4];
        let lit = regex::escape(c.encode_utf8(&mut buf));
        let bytes = c.encode_utf8(&mut buf).as_bytes();
        let enc: String = bytes.iter().map(|b| format!("%{b:02x}")).collect();
        let enc2: String = bytes.iter().map(|b| format!("%25{b:02x}")).collect();
        let plus = if c == ' ' { r"|\+" } else { "" };
        let _ = write!(p, "(?:{lit}|{enc}|{enc2}{plus})");
    }
    Regex::new(&p).ok()
}

/// Decides what a public notice may show, and remembers what it withheld.
pub struct PublicView {
    kinds: HashMap<String, IndicatorKind>,
    exposed: BTreeSet<String>,
    /// Values withheld from the output, so a finished text can be checked
    /// for any that survived ([`PublicView::leaks`]). Never shown.
    hidden: BTreeSet<String>,
    /// What was withheld, for the admin.
    pub withheld: BTreeSet<String>,
    /// What could not be classified (also withheld), for the admin.
    pub flags: BTreeSet<String>,
}

impl PublicView {
    pub fn new(a: &Analysis, exposed_hosts: &[String]) -> Self {
        let mut kinds = HashMap::new();
        for r in &a.results {
            for h in &r.hits {
                kinds.insert(h.rule_id.clone(), h.kind);
            }
        }
        Self {
            kinds,
            exposed: exposed_hosts
                .iter()
                .map(|h| h.to_ascii_lowercase())
                .collect(),
            hidden: BTreeSet::new(),
            withheld: BTreeSet::new(),
            flags: BTreeSet::new(),
        }
    }

    /// An endpoint whose request details are withheld (compromised, so the
    /// weakness may still be open).
    pub fn exposed(&self, host: &str) -> bool {
        self.exposed.contains(&host.to_ascii_lowercase())
    }

    pub fn note_exposed(&mut self, host: &str) {
        self.withheld.insert(format!(
            "attack details for {} (endpoint marked compromised)",
            host.replace('.', "[.]")
        ));
    }

    /// Whether a notice may show a linking feature; a withheld one's value
    /// is remembered for [`PublicView::leaks`].
    fn shown(&mut self, f: &LinkFeature) -> bool {
        let shown = self.classify(f);
        if !shown && !f.value().is_empty() {
            self.hidden.insert(f.value().to_string());
        }
        shown
    }

    fn classify(&mut self, f: &LinkFeature) -> bool {
        match f {
            LinkFeature::Param { name, value } => {
                if TAG_PARAMS.contains(&name.as_str()) {
                    return true;
                }
                self.withheld
                    .insert(format!("value of linking parameter `{name}`"));
                self.flags.insert(format!(
                    "linking parameter `{name}` (value {} chars) could be a credential, so it was withheld; if it is a plain run tag, add it back by hand",
                    value.chars().count()
                ));
                false
            }
            LinkFeature::Rule { rule, .. } => match self.kinds.get(rule) {
                Some(IndicatorKind::AgentMarker) => true,
                Some(IndicatorKind::Exfil) => {
                    self.withheld
                        .insert(format!("callback channel identifiers (`{rule}`)"));
                    false
                }
                _ => {
                    self.withheld.insert(format!("linking identifier `{rule}`"));
                    self.flags.insert(format!(
                        "linking identifier from `{rule}` is neither a tag nor a callback channel, so it was withheld"
                    ));
                    false
                }
            },
        }
    }

    /// A linking feature as a notice may show it.
    pub fn feature(&mut self, f: &LinkFeature) -> String {
        if self.shown(f) {
            return mask_emails(&f.to_string());
        }
        match f {
            LinkFeature::Param { name, .. } => format!("param:{name}={WITHHELD}"),
            LinkFeature::Rule { rule, .. } => format!("{rule}:{WITHHELD}"),
        }
    }

    /// A record's URL as a notice may show it, or `None` when it must be
    /// withheld entirely: it reaches a callback channel, it targets an exposed
    /// endpoint, or a withheld identifier in it could not be located.
    pub fn record_url(&mut self, r: &ObsResult) -> Option<String> {
        if let Some(h) = r.hits.iter().find(|h| h.kind == IndicatorKind::Exfil) {
            self.withheld
                .insert(format!("callback channel identifiers (`{}`)", h.rule_id));
            return None;
        }
        if let Some(h) = r.target_host.as_deref()
            && self.exposed(h)
        {
            self.note_exposed(h);
            return None;
        }
        let mut url = r.obs.url.clone();
        for f in &r.features {
            if self.shown(f) {
                continue;
            }
            // Every occurrence, in whatever encoding it was written.
            let value = f.value();
            match written_forms(value) {
                Some(re) if !value.is_empty() && re.is_match(&url) => {
                    url = re.replace_all(&url, WITHHELD).into_owned();
                }
                _ => return None,
            }
        }
        Some(mask_emails(&url))
    }

    /// Withheld values that survive in finished text, one line per value.
    /// The lines name the problem, not the value.
    pub fn leaks(&self, text: &str) -> Vec<String> {
        let plain = refang(text);
        self.hidden
            .iter()
            .filter(|v| written_forms(v).is_some_and(|re| re.is_match(&plain)))
            .map(|v| {
                format!(
                    "a withheld linking value ({} chars) survives in the text",
                    v.chars().count()
                )
            })
            .collect()
    }

    /// [`lint_public`] plus [`PublicView::leaks`]: everything wrong with a
    /// text this view produced.
    pub fn lint(&self, text: &str, rules: &Rules) -> Vec<String> {
        let mut out = lint_public(text, rules);
        out.extend(self.leaks(text));
        out
    }
}

/// Undo `defang` so the lint sees what a reader could rebuild.
fn refang(s: &str) -> String {
    s.replace("hxxp", "http")
        .replace("[.]", ".")
        .replace("[:]", ":")
}

/// Check finished public text for anything a notice must not carry: callback
/// channel identifiers (the linking callback rules), e-mail addresses other
/// than role mailboxes, and credential shapes. Returns one line per problem.
pub fn lint_public(text: &str, rules: &Rules) -> Vec<String> {
    let plain = refang(text);
    let mut out = Vec::new();
    for r in rules.of_target(Target::Url) {
        if r.def.kind != IndicatorKind::Exfil || !r.def.link {
            continue;
        }
        if let Matcher::Re(re) = &r.matcher {
            for m in re.find_iter(&plain) {
                out.push(format!(
                    "callback channel identifier ({}): {}",
                    r.def.id,
                    crate::model::truncate(m.as_str(), 60)
                ));
            }
        }
    }
    for c in email_re().captures_iter(&plain) {
        let local = c[1].to_ascii_lowercase();
        if local != "withheld" && !ROLE_MAILBOXES.contains(&local.as_str()) {
            out.push(format!("e-mail address: {}", &c[0]));
        }
    }
    for m in crate::redact::secret_value().find_iter(&plain) {
        out.push(format!(
            "credential-shaped value: {}…",
            m.as_str().chars().take(8).collect::<String>()
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze::analyze;
    use crate::model::Observation;

    fn obs(id: &str, ts: i64, url: &str) -> Observation {
        Observation {
            id: id.into(),
            ts,
            url: url.into(),
            ..Default::default()
        }
    }

    #[test]
    fn view_withholds_channels_credentials_and_exposed_hosts() {
        let rules = Rules::default_rules();
        let a = analyze(
            vec![
                obs(
                    "a",
                    1_791_000_000,
                    "https://r.jina.ai/https://portal.example.gov/q?id=1%20UNION%20SELECT%201&uqtag=zz9&tok=abcdef123",
                ),
                obs(
                    "b",
                    1_791_000_030,
                    "https://r.jina.ai/https://portal.example.gov/q?id=2%20UNION%20SELECT%201&uqtag=zz9&cb=https://webhook.site/0f8fad5b-d9cb-469f-a165-70867728950e",
                ),
                obs(
                    "c",
                    1_791_000_060,
                    "https://r.jina.ai/https://hit.example.org/q?id=3%20UNION%20SELECT%201",
                ),
            ],
            &rules,
        );
        let mut v = PublicView::new(&a, &["HIT.example.org".into()]);
        let by = |id: &str| a.results.iter().find(|r| r.obs.id == id).unwrap();

        let url = v.record_url(by("a")).unwrap();
        assert!(url.contains("uqtag=zz9"), "{url}");
        assert!(
            url.contains("tok=[withheld]") && !url.contains("abcdef123"),
            "{url}"
        );
        assert!(v.record_url(by("b")).is_none(), "callback channel");
        assert!(v.record_url(by("c")).is_none(), "exposed endpoint");

        let f = |s: &str| s.parse::<LinkFeature>().unwrap();
        assert_eq!(v.feature(&f("param:uqtag=zz9")), "param:uqtag=zz9");
        assert_eq!(v.feature(&f("param:tok=abcdef123")), "param:tok=[withheld]");
        assert!(
            v.feature(&f(
                "exfil.webhook_site:webhook.site/0f8fad5b-d9cb-469f-a165-70867728950e"
            ))
            .ends_with(WITHHELD)
        );
        assert!(v.flags.iter().any(|f| f.contains("`tok`")), "{:?}", v.flags);
        assert!(v.withheld.iter().any(|w| w.contains("hit[.]example[.]org")));
        assert_eq!(
            mask_emails("write to x9q2@mail.tm or a%40b.example"),
            "write to [withheld]@mail.tm or [withheld]%40b.example"
        );
    }

    #[test]
    fn view_withholds_every_occurrence_in_any_encoding() {
        let rules = Rules::default_rules();
        let a = analyze(
            vec![
                obs(
                    "twice",
                    1_791_000_000,
                    "https://r.jina.ai/https://portal.example.gov/q?id=1%20UNION%20SELECT%201&tok=Abc123xyz&next=/x?tok=abc123XYZ",
                ),
                obs(
                    "encoded",
                    1_791_000_030,
                    "https://r.jina.ai/https://portal.example.gov/q?id=2%20UNION%20SELECT%201&tok=a%2Fb+c%3D1&back=a%252Fb%2520c%253D1&again=A%2fB+C%3d1",
                ),
            ],
            &rules,
        );
        let mut v = PublicView::new(&a, &[]);
        let by = |id: &str| a.results.iter().find(|r| r.obs.id == id).unwrap();

        let url = v.record_url(by("twice")).unwrap();
        assert_eq!(url.matches(WITHHELD).count(), 2, "{url}");
        assert!(!url.to_ascii_lowercase().contains("abc123xyz"), "{url}");

        let url = v.record_url(by("encoded")).unwrap();
        assert_eq!(url.matches(WITHHELD).count(), 3, "{url}");
        assert!(!url.contains("2Fb") && !url.contains("2fB"), "{url}");

        // A value that survives in finished text is a lint problem.
        assert!(v.leaks(&url).is_empty(), "{:?}", v.leaks(&url));
        let bad = format!("{url}\nsee hxxps://x[.]example/?t=ABC123XYZ");
        assert_eq!(v.leaks(&bad).len(), 1, "{:?}", v.leaks(&bad));
        assert_eq!(v.lint(&bad, &rules).len(), 1);
        assert!(!v.leaks(&bad)[0].contains("ABC"), "names no value");
    }

    #[test]
    fn lint_finds_what_a_notice_must_not_carry() {
        let rules = Rules::default_rules();
        let key = "AKIAABCDEFGHIJKLMNOP"; // secret-scan: fixture (fake key)
        let bad = format!(
            "see hxxps://webhook[.]site/0f8fad5b-d9cb-469f-a165-70867728950e and ntfy.sh/agent-run-77, mail x9q2@mail.tm, key {key}"
        );
        let l = lint_public(&bad, &rules);
        assert_eq!(l.len(), 4, "{l:?}");
        let good = "Contact security@example.org. Inbox: [withheld]@mail.tm. Channel `exfil.ntfy:[withheld]`. ntfy.sh is a notification service.";
        assert!(
            lint_public(good, &rules).is_empty(),
            "{:?}",
            lint_public(good, &rules)
        );
    }
}
