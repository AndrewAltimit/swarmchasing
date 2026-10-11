//! Reading published contact files: a host's candidate domains, the
//! contacts a security.txt lists, and the abuse addresses in an RDAP record.

use crate::case::{Contact, ContactRole};
use sc_core::SecurityTxt;
use serde_json::Value;

/// The host, then each parent down to the registered domain (by the Public
/// Suffix List: `aihw.gov.au`, `agency.gov.uk`, `foo.co.jp`).
pub fn domain_candidates(host: &str) -> Vec<String> {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    let labels: Vec<&str> = host.split('.').filter(|l| !l.is_empty()).collect();
    let n = labels.len();
    if n < 2 {
        return vec![host];
    }
    let min = sc_collect::psl::registrable_domain(&host)
        .map_or(2, |d| d.split('.').count())
        .clamp(1, n);
    (min..=n).rev().map(|k| labels[n - k..].join(".")).collect()
}

/// The registered domain: the last of [`domain_candidates`].
pub fn registered_domain(host: &str) -> String {
    domain_candidates(host).pop().unwrap_or_default()
}

/// Contacts listed in a security.txt.
pub fn from_security_txt(org: &str, url: &str, s: &SecurityTxt, today: &str) -> Vec<Contact> {
    let expired = s
        .expires
        .as_deref()
        .and_then(sc_core::parse_ts)
        .zip(sc_core::parse_ts(today))
        .is_some_and(|(exp, now)| exp < now);
    let confidence = match (expired, s.signed) {
        (true, _) => "low",
        (false, true) => "high",
        (false, false) => "medium",
    };
    s.contact
        .iter()
        .map(|c| {
            let (channel, address) = match c.strip_prefix("mailto:") {
                Some(a) => ("email", a.to_string()),
                None if c.starts_with("tel:") => ("phone", c.to_string()),
                None => ("web_form", c.to_string()),
            };
            Contact {
                org: org.to_string(),
                role: ContactRole::Affected,
                endpoint: None,
                channel: channel.into(),
                address,
                source: if expired {
                    format!("{url} (expired)")
                } else {
                    url.to_string()
                },
                confidence: confidence.into(),
                found_on: today.to_string(),
                purpose: None,
            }
        })
        .collect()
}

/// Abuse e-mail addresses in an RDAP domain response, with the name of the
/// entity that lists them (usually the registrar).
pub fn rdap_abuse(json: &str) -> Vec<(String, String)> {
    let Ok(v) = serde_json::from_str::<Value>(json) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    walk(&v, None, &mut out);
    out.sort();
    out.dedup();
    out
}

fn walk(v: &Value, parent: Option<String>, out: &mut Vec<(String, String)>) {
    let Some(entities) = v.get("entities").and_then(Value::as_array) else {
        return;
    };
    for e in entities {
        let name = vcard(e, "fn")
            .into_iter()
            .find(|n| !n.trim().is_empty())
            .or_else(|| parent.clone());
        let abuse = e
            .get("roles")
            .and_then(Value::as_array)
            .is_some_and(|r| r.iter().any(|x| x == "abuse"));
        if abuse {
            for email in vcard(e, "email") {
                out.push((name.clone().unwrap_or_else(|| "registrar".into()), email));
            }
        }
        walk(e, name, out);
    }
}

/// Text values of one vCard property in an RDAP entity.
fn vcard(e: &Value, prop: &str) -> Vec<String> {
    e.get("vcardArray")
        .and_then(|a| a.get(1))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|p| p.get(0).and_then(Value::as_str) == Some(prop))
        .filter_map(|p| p.get(3).and_then(Value::as_str))
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidates_stop_at_the_registered_domain() {
        assert_eq!(
            domain_candidates("amap-pc-ssr.amap.com"),
            ["amap-pc-ssr.amap.com", "amap.com"]
        );
        assert_eq!(
            domain_candidates("vizprod.aihw.gov.au"),
            ["vizprod.aihw.gov.au", "aihw.gov.au"]
        );
        assert_eq!(domain_candidates("example.co.uk"), ["example.co.uk"]);
        // Multi-label public suffixes, from the Public Suffix List.
        assert_eq!(
            domain_candidates("www.agency.gov.uk"),
            ["www.agency.gov.uk", "agency.gov.uk"]
        );
        assert_eq!(
            domain_candidates("a.foo.co.jp"),
            ["a.foo.co.jp", "foo.co.jp"]
        );
        assert_eq!(registered_domain("x.y.foo.co.jp"), "foo.co.jp");
        assert_eq!(registered_domain("a.b.example.org"), "example.org");
        assert_eq!(domain_candidates("localhost"), ["localhost"]);
    }

    #[test]
    fn security_txt_contacts() {
        let s = sc_core::parse_security_txt(
            "Contact: mailto:security@example.org\nContact: https://example.org/vdp\nExpires: 2027-01-01T00:00:00Z\n",
        );
        let c = from_security_txt(
            "example.org",
            "https://example.org/.well-known/security.txt",
            &s,
            "2026-10-12",
        );
        assert_eq!(c.len(), 2);
        assert_eq!(
            (
                c[0].channel.as_str(),
                c[0].address.as_str(),
                c[0].confidence.as_str()
            ),
            ("email", "security@example.org", "medium")
        );
        assert_eq!(c[1].channel, "web_form");
        let late = from_security_txt("example.org", "u", &s, "2027-02-01");
        assert_eq!(late[0].confidence, "low");
        assert!(late[0].source.ends_with("(expired)"));
    }

    #[test]
    fn rdap_abuse_contacts_are_found_in_nested_entities() {
        let json = r#"{"entities":[{"roles":["registrar"],
            "vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Example Registrar"]]],
            "entities":[{"roles":["abuse"],
              "vcardArray":["vcard",[["fn",{},"text",""],["email",{},"text","abuse@registrar.example"]]]}]}]}"#;
        // The abuse entity has no name of its own, so it takes the registrar's.
        assert_eq!(
            rdap_abuse(json),
            [(
                "Example Registrar".to_string(),
                "abuse@registrar.example".to_string()
            )]
        );
        assert!(rdap_abuse("not json").is_empty());
    }
}
