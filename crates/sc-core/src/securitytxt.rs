//! RFC 9116 `security.txt` parsing, for finding who to notify at an affected organisation.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SecurityTxt {
    pub contact: Vec<String>,
    pub expires: Option<String>,
    pub encryption: Vec<String>,
    pub policy: Vec<String>,
    pub acknowledgments: Vec<String>,
    pub preferred_languages: Option<String>,
    pub canonical: Vec<String>,
    pub hiring: Vec<String>,
    pub signed: bool,
    pub other: Vec<(String, String)>,
}

pub fn parse_security_txt(text: &str) -> SecurityTxt {
    let mut s = SecurityTxt {
        signed: text.contains("-----BEGIN PGP SIGNED MESSAGE-----"),
        ..Default::default()
    };
    let mut in_sig = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with("-----BEGIN PGP SIGNATURE") {
            in_sig = true;
        }
        if line.starts_with("-----END PGP SIGNATURE") {
            in_sig = false;
            continue;
        }
        if in_sig || line.is_empty() || line.starts_with('#') || line.starts_with("-----") {
            continue;
        }
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let v = v.trim().to_string();
        match k.trim().to_ascii_lowercase().as_str() {
            "contact" => s.contact.push(v),
            "expires" => s.expires = Some(v),
            "encryption" => s.encryption.push(v),
            "policy" => s.policy.push(v),
            "acknowledgments" | "acknowledgements" => s.acknowledgments.push(v),
            "preferred-languages" => s.preferred_languages = Some(v),
            "canonical" => s.canonical.push(v),
            "hiring" => s.hiring.push(v),
            "hash" if s.signed => {}
            other => s.other.push((other.to_string(), v)),
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses() {
        let t = "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\n# hi\nContact: mailto:security@example.org\nContact: https://example.org/vdp\nExpires: 2027-01-01T00:00:00Z\nPolicy: https://example.org/policy\n-----BEGIN PGP SIGNATURE-----\nabc: def\n-----END PGP SIGNATURE-----\n";
        let s = parse_security_txt(t);
        assert!(s.signed);
        assert_eq!(s.contact.len(), 2);
        assert_eq!(s.expires.as_deref(), Some("2027-01-01T00:00:00Z"));
        assert!(s.other.is_empty());
    }
}
