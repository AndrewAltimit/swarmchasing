//! Registrable domains from the Public Suffix List (the `psl` crate embeds
//! the list, ICANN and private sections, at build time; it is MIT or
//! Apache-2.0). Used to stop contact discovery at the domain an organisation
//! registered: `aihw.gov.au`, `example.co.uk`, `someone.github.io`.

/// The registrable domain of `host` (public suffix plus one label),
/// lowercased, or `None` when the host is itself a public suffix, an IP
/// address, or not a domain name.
pub fn registrable_domain(host: &str) -> Option<String> {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if h.is_empty() || h.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    let d = psl::domain_str(&h)?;
    // `psl` falls back to the last label for unknown TLDs; require a dot so
    // a bare label is never taken for a domain.
    d.contains('.').then(|| d.to_string())
}

/// The public suffix of `host` (`co.uk`, `gov.au`, `github.io`).
pub fn public_suffix(host: &str) -> Option<String> {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    psl::suffix_str(&h).map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registrable_domains() {
        let r = |h| registrable_domain(h);
        assert_eq!(r("www.aihw.gov.au").as_deref(), Some("aihw.gov.au"));
        assert_eq!(r("a.b.example.co.uk").as_deref(), Some("example.co.uk"));
        assert_eq!(r("Example.COM.").as_deref(), Some("example.com"));
        assert_eq!(r("someone.github.io").as_deref(), Some("someone.github.io"));
        // An exception rule (`!city.kawasaki.jp`).
        assert_eq!(r("x.city.kawasaki.jp").as_deref(), Some("city.kawasaki.jp"));
        assert_eq!(r("co.uk"), None);
        assert_eq!(r("203.0.113.7"), None);
        assert_eq!(r("localhost"), None);
        assert_eq!(public_suffix("a.example.co.uk").as_deref(), Some("co.uk"));
    }
}
