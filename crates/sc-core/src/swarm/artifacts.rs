//! The artifacts a record names (inboxes, gists, pastes, Spaces, static
//! sites), read from its identifier strings only.

use crate::analyze::ObsResult;
use crate::rules::Rules;

/// The artifacts one record names: (id, written). An inbox named by a
/// linking rule is written to unless the record reads it back (a
/// webhook.site token URL, an ntfy subscription). A gist, paste, Space or
/// static-site subdomain is fetched when it is the first host the record
/// reaches past relays and carriers, and written to (named as a destination)
/// otherwise.
pub(super) fn artifacts(r: &ObsResult, rules: &Rules, out: &mut Vec<(String, bool)>) {
    let url = r.obs.url.to_ascii_lowercase();
    for f in &r.features {
        if f.name().starts_with("exfil.") {
            let v = f
                .value()
                .trim_start_matches(|c: char| !c.is_ascii_alphanumeric());
            let read = v.contains("/token/")
                || ["/json", "/sse", "/raw", "/ws"]
                    .iter()
                    .any(|s| url.contains(&format!("{v}{s}")));
            out.push((v.replace("/token/", "/"), !read));
        }
    }
    let mut fetched = None;
    for l in &r.layers {
        let Some(h) = l.host.as_deref() else {
            continue;
        };
        if fetched.is_none() && !rules.is_intermediary_host(h) {
            fetched = Some(h);
        }
        if let Some(id) = site_artifact(h, &l.text) {
            out.push((id, Some(h) != fetched));
        }
    }
}

/// Static-site hosts whose subdomain is one user's site.
const SITE_SUFFIXES: [&str; 12] = [
    "pages.dev",
    "vercel.app",
    "netlify.app",
    "workers.dev",
    "github.io",
    "glitch.me",
    "onrender.com",
    "fly.dev",
    "replit.app",
    "surge.sh",
    "herokuapp.com",
    "hf.space",
];

pub(super) fn site_artifact(host: &str, text: &str) -> Option<String> {
    let h = host.to_ascii_lowercase();
    let rest = text.split_once("://").map_or(text, |(_, r)| r);
    let path = rest.find('/').map_or("", |i| &rest[i..]);
    let path = path.split(['?', '#']).next().unwrap_or("");
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let seg = |i: usize| segs.get(i).copied().unwrap_or("");
    let word = |s: &str| {
        s.len() >= 3
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    };
    let hex = |s: &str| s.len() >= 20 && s.bytes().all(|b| b.is_ascii_hexdigit());
    let (family, id) = match h.as_str() {
        "gist.github.com" | "gist.githubusercontent.com" => (
            "gist",
            if hex(seg(1)) { seg(1) } else { seg(0) }.to_ascii_lowercase(),
        ),
        "pastebin.com" => (
            "pastebin",
            if seg(0) == "raw" { seg(1) } else { seg(0) }.to_string(),
        ),
        "rentry.co" | "rentry.org" => ("rentry", seg(0).to_ascii_lowercase()),
        "huggingface.co" if seg(0) == "spaces" && !seg(2).is_empty() => (
            "hf_space",
            format!("{}-{}", seg(1), seg(2))
                .to_ascii_lowercase()
                .replace(['_', '.'], "-"),
        ),
        _ => {
            let s = SITE_SUFFIXES.iter().find(|s| {
                h.len() > s.len() && h.ends_with(*s) && h.as_bytes()[h.len() - s.len() - 1] == b'.'
            })?;
            let sub = &h[..h.len() - s.len() - 1];
            if sub == "www" {
                return None;
            }
            match *s {
                "hf.space" => ("hf_space", sub.to_string()),
                _ => ("site", h.clone()),
            }
        }
    };
    let ok = match family {
        "gist" => hex(&id),
        "pastebin" => id.len() == 8 && word(&id),
        "rentry" => word(&id) && !matches!(id.as_str(), "api" | "static" | "what" | "raw"),
        _ => true,
    };
    ok.then(|| format!("{family}/{id}"))
}
