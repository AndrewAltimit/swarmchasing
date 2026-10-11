//! A small URL reader: scheme, host, path and query of one absolute URL,
//! read the way the WHATWG URL standard reads them for the parts unwrapping
//! needs.
//!
//! It replaces a full URL parser so the browser module does not carry an
//! IDNA and Unicode normalisation stack. What it does not do: convert a
//! Unicode host to punycode (the host is kept in Unicode, lower-cased),
//! validate or normalise IP addresses, or keep the port. Unit tests hold it
//! to the `url` crate's results on the shapes records carry.

use std::fmt::Write;

/// The parts of an absolute URL.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct WebUrl<'a> {
    /// Lower case.
    pub scheme: String,
    /// The host, percent-decoded and lower-cased (ASCII), with quotes and
    /// punctuation a writer left around it trimmed. `None` when the URL has
    /// no authority, or an empty host.
    pub host: Option<String>,
    /// The path as a serialised URL carries it: for `http`, `https` and the
    /// other special schemes, backslashes read as slashes, dot segments
    /// removed and the characters a path may not hold percent-encoded.
    pub path: String,
    /// The query after `?`, without the fragment, as written.
    pub query: Option<&'a str>,
}

/// Schemes whose URLs always have a host and a hierarchical path.
fn is_special(scheme: &str) -> bool {
    matches!(scheme, "http" | "https" | "ws" | "wss" | "ftp" | "file")
}

/// Code points that end a parse when they appear in a host.
fn forbidden_in_host(c: char) -> bool {
    matches!(
        c,
        '\0' | '\t'
            | '\n'
            | '\r'
            | ' '
            | '#'
            | '/'
            | ':'
            | '<'
            | '>'
            | '?'
            | '@'
            | '['
            | '\\'
            | ']'
            | '^'
            | '|'
            | '%'
            | '\u{7f}'
    ) || c.is_ascii_control()
}

/// A host as reports and links read it: lower case, and without the quotes,
/// brackets and punctuation a model or a Markdown writer left around a URL
/// (`a.example%60` and `a.example%60%29` are `a.example`). A bracketed IPv6
/// address is kept as written.
pub(crate) fn normalise_host(host: &str) -> String {
    if host.starts_with('[') && host.ends_with(']') {
        return host.to_ascii_lowercase();
    }
    host.trim_matches(|c: char| !(c.is_alphanumeric() || c == '-' || c == '_'))
        .to_ascii_lowercase()
}

impl<'a> WebUrl<'a> {
    /// Read `input`, or `None` when it is not an absolute URL this reader
    /// accepts (no scheme, or a host the standard rejects).
    pub(crate) fn parse(input: &'a str) -> Option<Self> {
        let input = input.trim_matches(|c: char| c <= ' ');
        let colon = input.find(':')?;
        let scheme = &input[..colon];
        let mut chars = scheme.chars();
        if !chars.next()?.is_ascii_alphabetic()
            || !chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
        {
            return None;
        }
        let scheme = scheme.to_ascii_lowercase();
        // The standard drops tabs and newlines anywhere in the input.
        let rest = &input[colon + 1..];
        let (rest, _fragment) = rest.split_once('#').unwrap_or((rest, ""));
        let (before_query, query) = match rest.split_once('?') {
            Some((b, q)) => (b, Some(q)),
            None => (rest, None),
        };
        let special = is_special(&scheme);
        let (host, path) = if special {
            // Any run of slashes or backslashes opens the authority.
            let after = before_query.trim_start_matches(['/', '\\']);
            let end = after.find(['/', '\\']).unwrap_or(after.len());
            let host = read_host(&after[..end], true)?;
            if host.is_empty() && scheme != "file" {
                return None;
            }
            (Some(host), normalise_path(&after[end..]))
        } else if let Some(after) = before_query.strip_prefix("//") {
            let end = after.find('/').unwrap_or(after.len());
            let host = read_host(&after[..end], false)?;
            (Some(host), after[end..].to_string())
        } else {
            (None, before_query.to_string())
        };
        let host = host.map(|h| normalise_host(&h)).filter(|h| !h.is_empty());
        Some(WebUrl {
            scheme,
            host,
            path,
            query,
        })
    }

    /// The query as `(name, value)` pairs, `+` read as a space and
    /// percent-escapes decoded (`application/x-www-form-urlencoded`).
    pub(crate) fn query_pairs(&self) -> Vec<(String, String)> {
        self.query.map(form_pairs).unwrap_or_default()
    }

    /// The path's segments after the leading slash; none for a path that
    /// does not start with one.
    pub(crate) fn path_segments(&self) -> Vec<&str> {
        match self.path.strip_prefix('/') {
            Some(p) => p.split('/').collect(),
            None => Vec::new(),
        }
    }
}

/// The host of an authority (`user:pass@host:port`), percent-decoded for a
/// special scheme; `None` when the standard would reject it.
fn read_host(authority: &str, special: bool) -> Option<String> {
    let hostport = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = if hostport.starts_with('[') {
        let close = hostport.find(']')?;
        let (h, port) = hostport.split_at(close + 1);
        check_port(port.strip_prefix(':').unwrap_or(port))?;
        return Some(h.to_string());
    } else {
        match hostport.rsplit_once(':') {
            Some((h, port)) => {
                check_port(port)?;
                h
            }
            None => hostport,
        }
    };
    if !special {
        return Some(host.to_string());
    }
    let decoded = percent_encoding::percent_decode_str(host)
        .decode_utf8()
        .ok()?
        .into_owned();
    if decoded.chars().any(forbidden_in_host) {
        return None;
    }
    Some(decoded)
}

/// An empty port or one of up to five digits within range.
fn check_port(port: &str) -> Option<()> {
    if port.is_empty() {
        return Some(());
    }
    if !port.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    (port.trim_start_matches('0').len() <= 5 && port.parse::<u32>().ok()? <= 65_535).then_some(())
}

/// A special scheme's path: backslashes as slashes, `.` and `..` segments
/// (also percent-encoded) resolved, and the path percent-encode set encoded.
fn normalise_path(raw: &str) -> String {
    if raw.is_empty() {
        return "/".into();
    }
    let raw = raw.replace('\\', "/");
    let segs: Vec<&str> = raw.strip_prefix('/').unwrap_or(&raw).split('/').collect();
    let mut out: Vec<&str> = Vec::new();
    let last = segs.len() - 1;
    for (i, s) in segs.iter().enumerate() {
        let lower = s.to_ascii_lowercase();
        let single = matches!(lower.as_str(), "." | "%2e");
        let double = matches!(lower.as_str(), ".." | ".%2e" | "%2e." | "%2e%2e");
        if double {
            out.pop();
            if i == last {
                out.push("");
            }
        } else if single {
            if i == last {
                out.push("");
            }
        } else {
            out.push(s);
        }
    }
    let mut path = String::with_capacity(raw.len() + 1);
    for s in out {
        path.push('/');
        encode_path_segment(s, &mut path);
    }
    if path.is_empty() {
        path.push('/');
    }
    path
}

/// Percent-encode what the path percent-encode set holds: controls, space,
/// `"`, `<`, `>`, `` ` ``, `{`, `}` and everything outside ASCII.
fn encode_path_segment(s: &str, out: &mut String) {
    for c in s.chars() {
        if c.is_ascii() && !(c <= ' ' || matches!(c, '"' | '<' | '>' | '`' | '{' | '}' | '\u{7f}'))
        {
            out.push(c);
        } else {
            let mut buf = [0u8; 4];
            for b in c.encode_utf8(&mut buf).bytes() {
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
}

/// `application/x-www-form-urlencoded` pairs: split on `&`, then on the
/// first `=`; `+` is a space; empty sequences are skipped.
pub(crate) fn form_pairs(query: &str) -> Vec<(String, String)> {
    let decode = |s: &str| {
        percent_encoding::percent_decode_str(&s.replace('+', " "))
            .decode_utf8_lossy()
            .into_owned()
    };
    query
        .split('&')
        .filter(|s| !s.is_empty())
        .map(|s| {
            let (k, v) = s.split_once('=').unwrap_or((s, ""));
            (decode(k), decode(v))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Inputs the reader and the `url` crate must read alike.
    const CASES: &[&str] = &[
        "https://a.example/",
        "https://A.Example/Path?Q=1",
        "https://r.jina.ai/https://data.portal.example/q?id=5",
        "https://r.jina.ai/https://https://records.a.example/staff?uqtag=r7k2",
        "https://https//c.example/x",
        "https://api.microlink.io/?url=http%3A%2F%2Fhttps%3A%2F%2Fdata.b.example%2Fapi",
        "https://www-stats--office-example.translate.goog/t?a=1",
        "https://user:pw@a.example:8443/p?x=1#frag",
        "https://a.example:443",
        "https://a.example/a/b/../c/./d",
        "https://a.example/a/%2e%2E/c",
        "https://a.example/x/..%2Fy/z.asp",
        "https://a.example/a b/\"q\"/<x>/`y`/{z}",
        "https://a.example/caf\u{e9}?q=caf\u{e9}",
        "https://a.example\\path\\to?x",
        "https:///triple.example/x",
        "https://a.example/?q=a+b&r=%26&&s&=t&u=%zz",
        "https://a.example/?",
        "https://a.example/search?q=1%20OR%201=1",
        "https://httpbin.org/base64/PHNjcmlwdD5mZXRjaCgnaHR0cHM6Ly9hLmV4YW1wbGUvJyk8L3NjcmlwdD4",
        "https://corsproxy.io/?https://a.example/x?y=1",
        "hxxps://A.example/c",
        "mailto:someone@a.example",
        "javascript:alert(1)",
        "localhost:8080/x",
        "https://a.example%60",
        "https://a.example%22/x",
        "https://a.example'",
        "https://a.example/..",
        "https://a.example/a/.",
        "HTTPS://A.EXAMPLE/",
        "https://[::1]:8080/x",
        "ftp://files.a.example/pub/",
    ];

    /// Inputs both reject.
    const REJECTED: &[&str] = &[
        "www.a.example/x",
        "/relative/path",
        "https://",
        "https://a b.example/",
        "https://a.example:99999/",
        "https://a.example:port/",
        "https://a<b.example/",
        "Sure, here is the page: https://a.example/",
        "1http://a.example/",
        "http://https%3A//d.example/",
    ];

    #[test]
    fn reads_urls_as_the_url_crate_does() {
        for &input in CASES {
            let ours = WebUrl::parse(input).unwrap_or_else(|| panic!("rejected {input}"));
            let theirs = url::Url::parse(input).unwrap_or_else(|e| panic!("{input}: {e}"));
            assert_eq!(ours.scheme, theirs.scheme(), "{input}");
            let host = theirs
                .host_str()
                .map(normalise_host)
                .filter(|h| !h.is_empty());
            assert_eq!(ours.host, host, "host of {input}");
            assert_eq!(ours.path, theirs.path(), "path of {input}");
            let pairs: Vec<(String, String)> = theirs
                .query_pairs()
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect();
            assert_eq!(ours.query_pairs(), pairs, "query of {input}");
            // The query text itself is kept as written; it decodes alike.
            let dec = |q: Option<&str>| {
                q.map(|q| {
                    percent_encoding::percent_decode_str(q)
                        .decode_utf8_lossy()
                        .into_owned()
                })
            };
            assert_eq!(dec(ours.query), dec(theirs.query()), "query of {input}");
            let segs: Vec<String> = theirs
                .path_segments()
                .map(|s| s.map(str::to_string).collect())
                .unwrap_or_default();
            assert_eq!(ours.path_segments(), segs, "segments of {input}");
        }
        for &input in REJECTED {
            assert!(url::Url::parse(input).is_err(), "url accepts {input}");
            assert!(WebUrl::parse(input).is_none(), "accepted {input}");
        }
    }

    #[test]
    fn hosts_lose_the_punctuation_around_them() {
        for (input, host) in [
            ("https://a.example%60", "a.example"),
            ("https://a.example%60%29/x", "a.example"),
            ("https://a.example%22%2C", "a.example"),
            ("https://(a.example)/", "a.example"),
            ("https://a.example./", "a.example"),
            ("https://*a.example*/", "a.example"),
        ] {
            assert_eq!(
                WebUrl::parse(input).and_then(|u| u.host).as_deref(),
                Some(host),
                "{input}"
            );
        }
        // A Unicode host stays in Unicode, lower-cased in ASCII only.
        assert_eq!(
            WebUrl::parse("https://B\u{fc}cher.example/")
                .and_then(|u| u.host)
                .as_deref(),
            Some("b\u{fc}cher.example")
        );
    }
}
