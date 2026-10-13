//! Published address ranges: the files providers publish listing the
//! addresses their agents and crawlers send from.
//!
//! The providers in the catalog all use one JSON shape (`{"creationTime":
//! ..., "prefixes": [{"ipv4Prefix": "a.b.c.d/n"}, {"ipv6Prefix": ...}]}`).
//! The parser takes any string in the document that reads as a CIDR prefix,
//! so a provider that renames a key still loads, and a plain list (one
//! prefix per line) loads too.

use std::net::IpAddr;

/// One prefix, held as IPv6 (IPv4 as IPv4-mapped) so one type holds both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Prefix {
    net: u128,
    /// Prefix length in the 128-bit space.
    len: u8,
}

fn key(ip: IpAddr) -> u128 {
    match ip {
        IpAddr::V4(v4) => u128::from(v4.to_ipv6_mapped()),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => u128::from(v4.to_ipv6_mapped()),
            None => u128::from(v6),
        },
    }
}

fn mask(len: u8) -> u128 {
    if len == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(len))
    }
}

impl Prefix {
    /// `a.b.c.d/n`, `x::/n`, or a bare address (a host prefix).
    pub fn parse(s: &str) -> Option<Prefix> {
        let s = s.trim();
        let (addr, len) = match s.split_once('/') {
            Some((a, l)) => (a, Some(l.parse::<u8>().ok()?)),
            None => (s, None),
        };
        let ip: IpAddr = addr.parse().ok()?;
        let len = match (ip, len) {
            (IpAddr::V4(_), Some(l)) if l <= 32 => l + 96,
            (IpAddr::V6(_), Some(l)) if l <= 128 => l,
            (IpAddr::V4(_), None) | (IpAddr::V6(_), None) => 128,
            _ => return None,
        };
        Some(Prefix {
            net: key(ip) & mask(len),
            len,
        })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        key(ip) & mask(self.len) == self.net
    }
}

/// One provider's range file as fetched.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RangeTable {
    /// The catalog's id for the file (`openai.chatgpt-user`).
    pub id: String,
    /// The file's own `creationTime`, when it has one.
    pub created: Option<String>,
    /// When it was fetched (`yyyy-mm-dd`), set by the caller: core has no clock.
    pub fetched: Option<String>,
    prefixes: Vec<Prefix>,
}

impl RangeTable {
    /// Parse a range file: JSON with prefixes anywhere in it, or one prefix
    /// per line. Errors when nothing in it reads as a prefix.
    pub fn parse(id: &str, text: &str) -> Result<RangeTable, String> {
        let mut t = RangeTable {
            id: id.to_string(),
            ..Default::default()
        };
        match serde_json::from_str::<serde_json::Value>(text) {
            Ok(v) => {
                t.created = v
                    .get("creationTime")
                    .and_then(|c| c.as_str())
                    .map(str::to_string);
                walk(&v, &mut t.prefixes);
            }
            Err(_) => t.prefixes.extend(
                text.lines()
                    .map(|l| l.split('#').next().unwrap_or("").trim())
                    .filter(|l| l.contains('/'))
                    .filter_map(Prefix::parse),
            ),
        }
        t.prefixes.sort();
        t.prefixes.dedup();
        if t.prefixes.is_empty() {
            return Err(format!("{id}: no address prefixes in the file"));
        }
        Ok(t)
    }

    pub fn len(&self) -> usize {
        self.prefixes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.prefixes.is_empty()
    }

    /// Whether `ip` (an address as a log writes it) is in the file.
    pub fn contains(&self, ip: &str) -> bool {
        parse_ip(ip).is_some_and(|ip| self.prefixes.iter().any(|p| p.contains(ip)))
    }
}

/// An address as logs write it: bare, bracketed IPv6, or with a port.
pub fn parse_ip(s: &str) -> Option<IpAddr> {
    let s = s.trim();
    if let Ok(ip) = s.parse() {
        return Some(ip);
    }
    let inner = s.strip_prefix('[').and_then(|r| r.split(']').next());
    if let Some(ip) = inner.and_then(|i| i.parse().ok()) {
        return Some(ip);
    }
    s.rsplit_once(':').and_then(|(a, _)| a.parse().ok())
}

fn walk(v: &serde_json::Value, out: &mut Vec<Prefix>) {
    match v {
        serde_json::Value::String(s) if s.contains('/') => out.extend(Prefix::parse(s)),
        serde_json::Value::Array(a) => a.iter().for_each(|x| walk(x, out)),
        serde_json::Value::Object(m) => m.values().for_each(|x| walk(x, out)),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_json_and_plain_lists() {
        let json = r#"{"creationTime": "2026-10-07T16:05:32", "prefixes": [
            {"ipv4Prefix": "192.0.2.0/28"}, {"ipv6Prefix": "2001:db8:c::/124"},
            {"ipv4Prefix": "not a prefix"}]}"#;
        let t = RangeTable::parse("x", json).unwrap();
        assert_eq!(t.len(), 2);
        assert_eq!(t.created.as_deref(), Some("2026-10-07T16:05:32"));
        assert!(t.contains("192.0.2.15"));
        assert!(!t.contains("192.0.2.16"));
        assert!(t.contains("::ffff:192.0.2.1"), "IPv4-mapped IPv6");
        assert!(t.contains("[2001:db8:c::f]:443"));
        assert!(!t.contains("2001:db8:c::10"));
        assert!(!t.contains("garbage"));

        let plain = "# test\n198.51.100.0/24\n203.0.113.7/32 # one host\n";
        let t = RangeTable::parse("y", plain).unwrap();
        assert!(t.contains("198.51.100.200") && t.contains("203.0.113.7:8080"));
        assert!(!t.contains("203.0.113.8"));
        assert!(RangeTable::parse("z", "{}").is_err());
        assert!(Prefix::parse("10.0.0.0/33").is_none());
        assert!(
            Prefix::parse("0.0.0.0/0")
                .unwrap()
                .contains("8.8.8.8".parse().unwrap())
        );
    }
}
