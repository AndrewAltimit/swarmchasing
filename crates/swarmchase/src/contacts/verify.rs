//! Re-checking the provider directory: each entry's source re-read, and
//! a draft of the changes for the admin. The directory file itself is never
//! changed.

use super::Directory;

/// Whether a fetched page still lists `address`.
fn lists(body: &str, address: &str) -> bool {
    let body = body.to_ascii_lowercase();
    let a = address.to_ascii_lowercase();
    let bare = a
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/');
    body.contains(&a) || body.contains(bare)
}

/// What a re-read of one directory contact found.
#[derive(Debug, PartialEq)]
pub enum Check {
    /// The source still lists the address.
    Listed,
    /// The source was read but no longer lists the address.
    Missing,
    /// The source could not be read.
    Unreachable(String),
}

/// Check every directory contact against `fetch(source)`, each source read
/// once. Returns (provider, address, result) in directory order, and any
/// Contact lines of a security.txt source that the directory lacks.
pub fn verify_directory(
    dir: &Directory,
    mut fetch: impl FnMut(&str) -> std::result::Result<String, String>,
) -> (Vec<(String, String, Check)>, Vec<String>) {
    let mut bodies: std::collections::BTreeMap<String, std::result::Result<String, String>> =
        Default::default();
    let mut out = Vec::new();
    let mut new = Vec::new();
    for p in &dir.providers {
        for c in &p.contacts {
            let body = bodies
                .entry(c.source.clone())
                .or_insert_with(|| fetch(&c.source));
            let check = match body {
                Ok(b) if lists(b, &c.address) => Check::Listed,
                Ok(_) => Check::Missing,
                Err(e) => Check::Unreachable(e.clone()),
            };
            out.push((p.name.clone(), c.address.clone(), check));
        }
        for c in p
            .contacts
            .iter()
            .filter(|c| c.source.ends_with("security.txt"))
        {
            if let Some(Ok(b)) = bodies.get(&c.source) {
                for listed in sc_core::parse_security_txt(b).contact {
                    let a = listed.trim_start_matches("mailto:").to_string();
                    let known = p.contacts.iter().any(|x| lists(&a, &x.address))
                        || new.iter().any(|n: &String| n.ends_with(&format!(" {a}")));
                    if !known {
                        new.push(format!("{}: {} also lists {a}", p.name, c.source));
                    }
                }
            }
        }
    }
    (out, new)
}

/// The directory text with `verified` set to `today` for every contact whose
/// address was confirmed, and a comment above each one that was not. A
/// draft for the admin to review and commit; the file itself is not touched.
pub fn draft_update(text: &str, checks: &[(String, String, Check)], today: &str) -> String {
    let mut out = String::new();
    let mut current: Option<&Check> = None;
    let mut pending = String::new();
    for line in text.lines() {
        let t = line.trim();
        if t == "[[provider.contact]]" || t == "[[provider]]" || t == "[[csirt]]" {
            out.push_str(&pending);
            pending.clear();
            current = None;
            pending.push_str(line);
            pending.push('\n');
            continue;
        }
        if let Some(a) = t
            .strip_prefix("address = \"")
            .and_then(|r| r.strip_suffix('"'))
        {
            current = checks.iter().find(|(_, x, _)| x == a).map(|(_, _, c)| c);
            if let Some(c) = current
                && *c != Check::Listed
            {
                let why = match c {
                    Check::Missing => "the source no longer lists this address".to_string(),
                    Check::Unreachable(e) => format!("the source could not be read: {e}"),
                    Check::Listed => unreachable!(),
                };
                pending.push_str(&format!("# NOT CONFIRMED {today}: {why}\n"));
            }
        }
        if t.starts_with("verified = ") && current == Some(&Check::Listed) {
            pending.push_str(&format!("verified = \"{today}\"\n"));
        } else {
            pending.push_str(line);
            pending.push('\n');
        }
    }
    out.push_str(&pending);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_reports_changes_and_drafts_an_update() {
        let text = "[[provider]]\nname = \"A\"\nkind = \"model\"\n[[provider.contact]]\nchannel = \"email\"\naddress = \"security@a.example\"\npurpose = \"security\"\nsource = \"https://a.example/.well-known/security.txt\"\nverified = \"2026-01-01\"\n[[provider.contact]]\nchannel = \"form\"\naddress = \"https://a.example/abuse\"\npurpose = \"abuse\"\nsource = \"https://a.example/policy\"\nverified = \"2026-01-01\"\n";
        let d = Directory::parse(text).unwrap();
        let mut fetched = Vec::new();
        let (checks, new) = verify_directory(&d, |u| {
            fetched.push(u.to_string());
            match u {
                "https://a.example/.well-known/security.txt" => Ok(
                    "Contact: mailto:security@a.example\nContact: mailto:psirt@a.example\n".into(),
                ),
                _ => Err("HTTP 404".into()),
            }
        });
        assert_eq!(fetched.len(), 2);
        assert_eq!(checks[0].2, Check::Listed);
        assert_eq!(checks[1].2, Check::Unreachable("HTTP 404".into()));
        assert_eq!(
            new,
            ["A: https://a.example/.well-known/security.txt also lists psirt@a.example"]
        );
        let draft = draft_update(text, &checks, "2026-10-13");
        assert_eq!(
            draft.matches("verified = \"2026-10-13\"").count(),
            1,
            "{draft}"
        );
        assert!(draft.contains("# NOT CONFIRMED 2026-10-13: the source could not be read: HTTP 404\naddress = \"https://a.example/abuse\""), "{draft}");
        assert!(Directory::parse(&draft).is_ok());
    }
}
