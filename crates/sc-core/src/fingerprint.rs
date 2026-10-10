//! Client fingerprints: how a request was encoded, independent of what it says.
//!
//! Two HTTP libraries asked to fetch the same thing write it differently: a
//! space as `%20` or `+`, escapes as `%2F` or `%2f`, parameters sorted or in
//! insertion order, a stray trailing `&`. [`encoding`] reduces a recorded URL
//! to those choices. Requests from one client share them, so a cluster whose
//! members all show one unusual style is consistent with one client; a style is
//! never evidence on its own, because popular libraries share their defaults.
//!
//! [`header_set`] does the same for request headers. Every source keeps
//! headers as a name-to-value map, so the order a client sent them in is not
//! recorded; only the set of names and how they were capitalised survive.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// How spaces were written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpaceStyle {
    #[default]
    None,
    /// `%20` only.
    Percent,
    /// `+` in the query only.
    Plus,
    Both,
}

/// Case of the hex digits in percent escapes. Escapes whose digits are all
/// numeric (`%20`, `%25`) say nothing about case and are ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HexCase {
    #[default]
    None,
    Upper,
    Lower,
    Mixed,
}

/// How the path ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathEnd {
    /// No path at all: `https://host` or `https://host?q`.
    #[default]
    Bare,
    Slash,
    NoSlash,
}

/// The encoding choices visible in one URL.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Encoding {
    pub space: SpaceStyle,
    pub hex_case: HexCase,
    /// `%25` followed by two hex digits: an escape that was escaped again.
    pub double_encoded: bool,
    /// A literal space or non-ASCII byte the client did not escape.
    pub unescaped: bool,
    /// The query ends with `&`.
    pub trailing_amp: bool,
    /// A `?` with nothing after it.
    pub empty_query: bool,
    /// `&&` inside the query.
    pub empty_pairs: bool,
    /// `name=` with no value.
    pub empty_values: bool,
    /// `name` with no `=`.
    pub bare_keys: bool,
    /// Whether the parameter names are in sorted order; `None` with fewer than
    /// two distinct names.
    pub names_sorted: Option<bool>,
    pub path_end: PathEnd,
    /// Query parameter names in the order they were sent, as written.
    pub param_names: Vec<String>,
    /// Compact label of the encoding choices alone, comparable across
    /// endpoints, e.g. `sp20.hexU.amp.sorted.noslash`.
    pub style: String,
    /// 8 hex digits over `style` and `param_names`: one request shape.
    pub hash: String,
}

impl Encoding {
    /// True when the URL shows at least one encoding choice beyond the path
    /// ending and parameter order, which nearly every URL has.
    pub fn informative(&self) -> bool {
        self.space != SpaceStyle::None
            || self.hex_case != HexCase::None
            || self.double_encoded
            || self.unescaped
            || self.trailing_amp
            || self.empty_query
            || self.empty_pairs
            || self.empty_values
            || self.bare_keys
    }
}

/// Fingerprint the encoding of a recorded request URL. The fragment is ignored.
pub fn encoding(url: &str) -> Encoding {
    let head = url.split_once('#').map_or(url, |(h, _)| h);
    let (base, query) = match head.split_once('?') {
        Some((b, q)) => (b, Some(q)),
        None => (head, None),
    };
    let mut e = Encoding::default();

    let b = head.as_bytes();
    let (mut upper, mut lower, mut pct20) = (false, false, false);
    for i in 0..b.len() {
        if b[i] == b' ' || !b[i].is_ascii() {
            e.unescaped = true;
        }
        if b[i] != b'%' || i + 2 >= b.len() {
            continue;
        }
        let (h1, h2) = (b[i + 1], b[i + 2]);
        if !h1.is_ascii_hexdigit() || !h2.is_ascii_hexdigit() {
            continue;
        }
        upper |= h1.is_ascii_uppercase() || h2.is_ascii_uppercase();
        lower |= h1.is_ascii_lowercase() || h2.is_ascii_lowercase();
        pct20 |= h1 == b'2' && h2 == b'0';
        if h1 == b'2'
            && h2 == b'5'
            && b.get(i + 3).is_some_and(u8::is_ascii_hexdigit)
            && b.get(i + 4).is_some_and(u8::is_ascii_hexdigit)
        {
            e.double_encoded = true;
        }
    }
    e.hex_case = match (upper, lower) {
        (true, true) => HexCase::Mixed,
        (true, false) => HexCase::Upper,
        (false, true) => HexCase::Lower,
        (false, false) => HexCase::None,
    };

    let plus = query.is_some_and(|q| q.contains('+'));
    e.space = match (pct20, plus) {
        (true, true) => SpaceStyle::Both,
        (true, false) => SpaceStyle::Percent,
        (false, true) => SpaceStyle::Plus,
        (false, false) => SpaceStyle::None,
    };

    let path = base
        .split_once("://")
        .map_or(base, |(_, rest)| rest)
        .split_once('/')
        .map(|(_, p)| p);
    e.path_end = match path {
        None => PathEnd::Bare,
        Some(p) if p.is_empty() || p.ends_with('/') => PathEnd::Slash,
        Some(_) => PathEnd::NoSlash,
    };

    if let Some(q) = query {
        e.empty_query = q.is_empty();
        e.trailing_amp = q.ends_with('&');
        e.empty_pairs = q.contains("&&") || q.starts_with('&');
        for pair in q.split('&').filter(|p| !p.is_empty()) {
            match pair.split_once('=') {
                Some((k, v)) => {
                    e.empty_values |= v.is_empty();
                    e.param_names.push(k.to_string());
                }
                None => {
                    e.bare_keys = true;
                    e.param_names.push(pair.to_string());
                }
            }
        }
    }
    let mut distinct: Vec<&str> = Vec::new();
    for n in &e.param_names {
        if !distinct.contains(&n.as_str()) {
            distinct.push(n);
        }
    }
    if distinct.len() >= 2 {
        e.names_sorted = Some(distinct.windows(2).all(|w| w[0] <= w[1]));
    }

    e.style = style_label(&e);
    e.hash = short_hash(&format!("{}|{}", e.style, e.param_names.join("&")));
    e
}

fn style_label(e: &Encoding) -> String {
    let mut parts: Vec<&str> = Vec::new();
    parts.push(match e.space {
        SpaceStyle::None => "",
        SpaceStyle::Percent => "sp20",
        SpaceStyle::Plus => "sp+",
        SpaceStyle::Both => "sp20+",
    });
    parts.push(match e.hex_case {
        HexCase::None => "",
        HexCase::Upper => "hexU",
        HexCase::Lower => "hexL",
        HexCase::Mixed => "hexM",
    });
    for (on, tag) in [
        (e.double_encoded, "dbl"),
        (e.unescaped, "raw"),
        (e.trailing_amp, "amp"),
        (e.empty_query, "q0"),
        (e.empty_pairs, "pair0"),
        (e.empty_values, "val0"),
        (e.bare_keys, "bare"),
    ] {
        parts.push(if on { tag } else { "" });
    }
    parts.push(match e.names_sorted {
        None => "",
        Some(true) => "sorted",
        Some(false) => "unsorted",
    });
    parts.push(match e.path_end {
        PathEnd::Bare => "nopath",
        PathEnd::Slash => "slash",
        PathEnd::NoSlash => "noslash",
    });
    parts.retain(|p| !p.is_empty());
    parts.join(".")
}

/// Capitalisation of header names as the source recorded them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HeaderCasing {
    /// `user-agent` (HTTP/2, many proxies, or a source that lowercases).
    Lower,
    /// `User-Agent`.
    Canonical,
    Mixed,
}

/// The set of request header names, without the order they were sent in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeaderSet {
    /// Lowercased and sorted.
    pub names: Vec<String>,
    pub casing: HeaderCasing,
    /// 8 hex digits over `names` and `casing`.
    pub hash: String,
}

/// Fingerprint the header names of a record. Headers a collector adds itself
/// (`x-urlquery-*`) are not the client's and are skipped. `None` when no
/// client header is left.
pub fn header_set(headers: &BTreeMap<String, String>) -> Option<HeaderSet> {
    let raw: Vec<&str> = headers
        .keys()
        .map(String::as_str)
        .filter(|k| !k.to_ascii_lowercase().starts_with("x-urlquery-"))
        .collect();
    if raw.is_empty() {
        return None;
    }
    let canonical = |k: &str| {
        k.split('-').all(|seg| {
            let mut c = seg.chars();
            c.next().is_none_or(|f| !f.is_ascii_lowercase()) && c.all(|x| !x.is_ascii_uppercase())
        })
    };
    let all_lower = raw
        .iter()
        .all(|k| !k.bytes().any(|b| b.is_ascii_uppercase()));
    let casing = if all_lower {
        HeaderCasing::Lower
    } else if raw.iter().all(|k| canonical(k)) {
        HeaderCasing::Canonical
    } else {
        HeaderCasing::Mixed
    };
    let mut names: Vec<String> = raw.iter().map(|k| k.to_ascii_lowercase()).collect();
    crate::sort::sort(&mut names);
    names.dedup();
    let hash = short_hash(&format!("{casing:?}|{}", names.join(",")));
    Some(HeaderSet {
        names,
        casing,
        hash,
    })
}

/// First 8 hex digits of FNV-1a 64: stable across platforms and runs.
pub(crate) fn short_hash(s: &str) -> String {
    let h = s.bytes().fold(0xcbf2_9ce4_8422_2325_u64, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3)
    });
    format!("{:08x}", h >> 32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spaces_hex_case_and_path() {
        let e = encoding("https://a.example/search?q=a%20b&lang=en");
        assert_eq!(e.space, SpaceStyle::Percent);
        assert_eq!(e.hex_case, HexCase::None);
        assert_eq!(e.path_end, PathEnd::NoSlash);
        assert_eq!(e.param_names, ["q", "lang"]);
        assert_eq!(e.names_sorted, Some(false));
        assert_eq!(e.style, "sp20.unsorted.noslash");
        assert!(e.informative());

        let e = encoding("https://a.example/x/?q=a+b&u=https%3a%2f%2fb.example%2F");
        assert_eq!(e.space, SpaceStyle::Plus);
        assert_eq!(e.hex_case, HexCase::Mixed);
        assert_eq!(e.path_end, PathEnd::Slash);
        assert_eq!(e.names_sorted, Some(true));

        let e = encoding("https://a.example?u=https%3A%2F%2Fb.example");
        assert_eq!(e.hex_case, HexCase::Upper);
        assert_eq!(e.path_end, PathEnd::Bare);
        assert_eq!(e.names_sorted, None);
        assert_eq!(e.style, "hexU.nopath");
    }

    #[test]
    fn plus_in_path_is_not_a_space() {
        let e = encoding("https://a.example/c++/guide");
        assert_eq!(e.space, SpaceStyle::None);
        assert!(!e.informative());
        assert_eq!(e.style, "noslash");
    }

    #[test]
    fn double_encoding_and_empty_parts() {
        let e = encoding("https://a.example/p?next=%252Fadmin&x=&flag&&y=1&");
        assert!(e.double_encoded);
        assert!(e.empty_values && e.bare_keys && e.empty_pairs && e.trailing_amp);
        assert_eq!(e.param_names, ["next", "x", "flag", "y"]);
        assert_eq!(e.hex_case, HexCase::None);
        assert_eq!(e.style, "dbl.amp.pair0.val0.bare.unsorted.noslash");

        let e = encoding("https://a.example/?");
        assert!(e.empty_query && !e.trailing_amp);
        assert_eq!(e.style, "q0.slash");

        let e = encoding("https://a.example/a b?q=ü");
        assert!(e.unescaped);
        // A trailing `%2` is not an escape and must not panic.
        let e = encoding("https://a.example/a%2");
        assert_eq!(e.hex_case, HexCase::None);
    }

    #[test]
    fn style_ignores_content_but_hash_pins_the_shape() {
        let a = encoding("https://one.example/a?q=hello%20world&page=2#frag");
        let b = encoding("https://two.example/b?q=other%20words&page=9");
        let c = encoding("https://two.example/b?page=9&q=other%20words");
        assert_eq!(a.style, b.style);
        assert_eq!(a.hash, b.hash);
        assert_ne!(a.hash, c.hash);
        assert_eq!(a.hash.len(), 8);
    }

    #[test]
    fn header_sets() {
        let mut h = BTreeMap::new();
        h.insert("User-Agent".to_string(), "x".to_string());
        h.insert("Accept-Encoding".to_string(), "gzip".to_string());
        h.insert("x-urlquery-useragent".to_string(), "x".to_string());
        let s = header_set(&h).unwrap();
        assert_eq!(s.names, ["accept-encoding", "user-agent"]);
        assert_eq!(s.casing, HeaderCasing::Canonical);

        let mut l = BTreeMap::new();
        l.insert("user-agent".to_string(), "x".to_string());
        l.insert("accept-encoding".to_string(), "gzip".to_string());
        let t = header_set(&l).unwrap();
        assert_eq!((t.casing, &t.names), (HeaderCasing::Lower, &s.names));
        assert_ne!(t.hash, s.hash);

        l.insert("X-Foo".to_string(), "1".to_string());
        assert_eq!(header_set(&l).unwrap().casing, HeaderCasing::Mixed);

        let mut only = BTreeMap::new();
        only.insert("x-urlquery-useragent".to_string(), "x".to_string());
        assert_eq!(header_set(&only), None);
    }
}
