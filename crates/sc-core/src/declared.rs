//! Requests that announce themselves as testing: "authorized security
//! test", "for research purposes", a bug-bounty header, a contact address in
//! the user agent.
//!
//! A declaration is a hint for the case's handling of authorised testing,
//! never a score: anyone can write one, and an agent can copy it from a
//! prompt. What is kept is the text that declared it and the contact it
//! names (an email address or a bug-bounty handle), so the admin can check
//! the claim with its owner.

use crate::model::Observation;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

/// One declaration seen on a cluster's members.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Declared {
    /// The text that declared it: a user agent, a `header: value` line or a
    /// `param=value` pair, cut to 160 characters.
    pub text: String,
    /// An email address or bug-bounty handle it names.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contact: Option<String>,
    /// Members carrying it.
    pub records: usize,
}

/// Phrases that declare testing on their own.
fn strong() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(concat!(
            r"(?i)\bauthori[sz]ed[\s_-]+(security[\s_-]+|pen(etration)?[\s_-]*)?(test|testing|scan|scanning|assessment|research)\b",
            r"|\bfor[\s_-]+(security[\s_-]+|academic[\s_-]+)?research[\s_-]+purposes\b",
            r"|\bthis[\s_-]+is[\s_-]+an?[\s_-]+(authori[sz]ed[\s_-]+)?(security[\s_-]+)?test\b",
        ))
        .unwrap()
    })
}

/// Words that declare testing only next to a contact: a search for
/// "pentest tools" is not a declaration.
fn weak() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"(?i)\b(security[\s_-]+research(er)?|pen[\s_-]?test(ing|er)?|penetration[\s_-]+test(ing)?|bug[\s_-]?bounty|responsible[\s_-]+disclosure|vulnerability[\s_-]+disclosure|hackerone|bugcrowd|intigriti|yeswehack)\b").unwrap()
    })
}

/// Headers bug-bounty programmes ask researchers to send; the value is the
/// researcher's handle.
fn bounty_header() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"(?i)^x-(hackerone(-research)?|bug-?bounty|intigriti(-username)?|yeswehack|bugcrowd|security-research(er)?)$").unwrap()
    })
}

/// An email address, or a handle on a bug-bounty platform.
fn contact_in(text: &str) -> Option<String> {
    static EMAIL: OnceLock<Regex> = OnceLock::new();
    static HANDLE: OnceLock<Regex> = OnceLock::new();
    let email = EMAIL.get_or_init(|| {
        Regex::new(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}").unwrap()
    });
    let handle = HANDLE.get_or_init(|| {
        Regex::new(r"(?i)\b(?:hackerone|bugcrowd|intigriti|yeswehack|h1)(?:\.com)?[\s:/=]+@?([A-Za-z0-9_.-]{2,40})").unwrap()
    });
    if let Some(m) = email.find(text) {
        return Some(m.as_str().to_string());
    }
    handle
        .captures(text)
        .map(|c| c[1].trim_end_matches('.').to_string())
}

fn cut(s: &str) -> String {
    crate::model::truncate(s, 160)
}

/// The declaration one record makes, if any: the declaring text and the
/// contact it names. `params` are the decoded query parameters of all its
/// layers.
pub fn declared<'a>(
    obs: &Observation,
    params: impl IntoIterator<Item = &'a (String, String)>,
) -> Option<(String, Option<String>)> {
    for (k, v) in &obs.headers {
        if bounty_header().is_match(k) && !v.trim().is_empty() {
            return Some((
                cut(&format!("{}: {}", k.to_ascii_lowercase(), v.trim())),
                Some(cut(v.trim())),
            ));
        }
    }
    let ua = obs.user_agent.iter().cloned();
    let headers = obs
        .headers
        .iter()
        .map(|(k, v)| format!("{}: {}", k.to_ascii_lowercase(), v.trim()));
    let pairs = params.into_iter().map(|(k, v)| format!("{k}={v}"));
    for text in ua.chain(headers).chain(pairs) {
        let contact = contact_in(&text);
        if strong().is_match(&text) || (contact.is_some() && weak().is_match(&text)) {
            return Some((cut(&text), contact));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(ua: Option<&str>, headers: &[(&str, &str)]) -> Observation {
        Observation {
            url: "https://a.example/".into(),
            user_agent: ua.map(str::to_string),
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            ..Default::default()
        }
    }

    fn p(k: &str, v: &str) -> (String, String) {
        (k.into(), v.into())
    }

    #[test]
    fn declarations_and_their_contacts() {
        let ua = "Mozilla/5.0 (compatible; AcmeScan/1.0; authorized security test; contact sec@acme.example)";
        let (text, contact) = declared(&obs(Some(ua), &[]), &[]).unwrap();
        assert_eq!(text, ua);
        assert_eq!(contact.as_deref(), Some("sec@acme.example"));

        let (text, contact) =
            declared(&obs(None, &[("X-HackerOne-Research", "alice_h1")]), &[]).unwrap();
        assert_eq!(text, "x-hackerone-research: alice_h1");
        assert_eq!(contact.as_deref(), Some("alice_h1"));

        let (text, contact) =
            declared(&obs(None, &[]), &[p("note", "for research purposes only")]).unwrap();
        assert_eq!(text, "note=for research purposes only");
        assert_eq!(contact, None);

        let (_, contact) = declared(
            &obs(None, &[]),
            &[p("q", "1"), p("by", "bug bounty hackerone.com/bob-sec")],
        )
        .unwrap();
        assert_eq!(contact.as_deref(), Some("bob-sec"));
    }

    #[test]
    fn ordinary_requests_declare_nothing() {
        for (ua, params) in [
            (Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64)"), vec![]),
            (None, vec![p("q", "pentest tools for beginners")]),
            (None, vec![p("q", "bug bounty programs list")]),
            (None, vec![p("email", "jane@shop.example"), p("q", "shoes")]),
            (None, vec![p("q", "is this an unauthorized test")]),
        ] {
            assert_eq!(declared(&obs(ua, &[]), &params), None, "{ua:?} {params:?}");
        }
    }
}
