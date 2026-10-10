//! Offline IP-to-ASN lookup: a sorted table of address ranges, each with its
//! origin AS number and the AS's name, searched by binary search.
//!
//! The table is loaded from the iptoasn.com TSV format (`ip2asn-v4.tsv`,
//! `ip2asn-v6.tsv` or the combined file): `range_start range_end AS_number
//! country_code AS_description`, tab-separated. The data is published under
//! the Public Domain Dedication and License (PDDL 1.0) and updated hourly.
//! The CLI downloads it into the data directory; it is never committed.
//!
//! IPv4 addresses are stored as IPv4-mapped IPv6 so one table holds both.

use crate::model::{Observation, TsKind};
use std::net::IpAddr;

/// One AS's address ranges, sorted by start.
#[derive(Debug, Default, Clone)]
pub struct AsnTable {
    starts: Vec<u128>,
    ends: Vec<u128>,
    asns: Vec<u32>,
    /// Index into `orgs` per range.
    org_of: Vec<u32>,
    orgs: Vec<String>,
}

/// The result of one lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AsnEntry<'a> {
    pub asn: u32,
    pub org: &'a str,
}

fn key(ip: IpAddr) -> u128 {
    match ip {
        IpAddr::V4(v4) => u128::from(v4.to_ipv6_mapped()),
        IpAddr::V6(v6) => u128::from(v6),
    }
}

impl AsnTable {
    /// Parse iptoasn.com TSV. Unrouted ranges (AS 0) and malformed lines are
    /// skipped; overlapping ranges keep the first by start.
    pub fn from_tsv(text: &str) -> Self {
        let mut rows: Vec<(u128, u128, u32, &str)> = text
            .lines()
            .filter_map(|l| {
                let mut f = l.split('\t');
                let start: IpAddr = f.next()?.trim().parse().ok()?;
                let end: IpAddr = f.next()?.trim().parse().ok()?;
                let asn: u32 = f.next()?.trim().parse().ok()?;
                let _country = f.next();
                let org = f.next().unwrap_or("").trim();
                let (s, e) = (key(start), key(end));
                (asn != 0 && s <= e).then_some((s, e, asn, org))
            })
            .collect();
        rows.sort_by_key(|r| r.0);
        let mut t = Self::default();
        let mut org_ids = std::collections::HashMap::new();
        for (s, e, asn, org) in rows {
            if t.ends.last().is_some_and(|&prev| s <= prev) {
                continue;
            }
            let id = *org_ids.entry(org).or_insert_with(|| {
                t.orgs.push(org.to_string());
                (t.orgs.len() - 1) as u32
            });
            t.starts.push(s);
            t.ends.push(e);
            t.asns.push(asn);
            t.org_of.push(id);
        }
        t
    }

    pub fn len(&self) -> usize {
        self.starts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.starts.is_empty()
    }

    /// The AS announcing `ip` (an address literal), if the table covers it.
    pub fn lookup(&self, ip: &str) -> Option<AsnEntry<'_>> {
        let k = key(ip.trim().parse().ok()?);
        let i = self.starts.partition_point(|&s| s <= k).checked_sub(1)?;
        (k <= self.ends[i]).then(|| AsnEntry {
            asn: self.asns[i],
            org: &self.orgs[self.org_of[i] as usize],
        })
    }

    /// Fill the network of records that carry an IP but no ASN. A scan
    /// service's IP is the target's (`ts_kind` submit), so it fills
    /// `target_asn`; any other record's IP is the client's and fills `asn`.
    /// Returns how many records were filled.
    pub fn enrich(&self, records: &mut [Observation]) -> usize {
        let mut n = 0;
        for o in records.iter_mut() {
            if o.asn.is_some() || o.target_asn.is_some() {
                continue;
            }
            let Some(e) = o.ip.as_deref().and_then(|ip| self.lookup(ip)) else {
                continue;
            };
            if o.ts_kind == TsKind::Submit {
                o.target_asn = Some(e.asn);
            } else {
                o.asn = Some(e.asn);
            }
            n += 1;
        }
        n
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TSV: &str = "1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n\
        1.0.1.0\t1.0.3.255\t0\tNone\tNot routed\n\
        198.51.100.0\t198.51.100.255\t64500\tZZ\tEXAMPLE-NET\n\
        203.0.113.0\t203.0.113.127\t64501\tZZ\tDOC-NET\n\
        203.0.113.128\t203.0.113.255\t64501\tZZ\tDOC-NET\n\
        2001:db8::\t2001:db8::ffff\t64502\tZZ\tV6-NET\n\
        garbage line\n";

    #[test]
    fn lookups() {
        let t = AsnTable::from_tsv(TSV);
        assert_eq!(t.len(), 5);
        assert_eq!(
            t.lookup("1.0.0.7"),
            Some(AsnEntry {
                asn: 13335,
                org: "CLOUDFLARENET"
            })
        );
        assert_eq!(t.lookup("1.0.2.1"), None, "unrouted");
        assert_eq!(t.lookup("203.0.113.200").unwrap().asn, 64501);
        assert_eq!(t.lookup("198.51.101.1"), None);
        assert_eq!(t.lookup("0.0.0.1"), None);
        assert_eq!(t.lookup("2001:db8::42").unwrap().org, "V6-NET");
        assert_eq!(t.lookup("not an ip"), None);
        // Organisation names are shared between ranges.
        assert_eq!(t.orgs.len(), 4);
    }

    #[test]
    fn enrich_fills_the_right_field() {
        let t = AsnTable::from_tsv(TSV);
        let rec = |ip: &str, k: TsKind| Observation {
            ip: Some(ip.into()),
            ts_kind: k,
            ..Default::default()
        };
        let mut v = vec![
            rec("198.51.100.9", TsKind::Request),
            rec("203.0.113.9", TsKind::Submit),
            Observation {
                asn: Some(1),
                ..rec("198.51.100.9", TsKind::Request)
            },
            rec("192.0.2.1", TsKind::Request),
        ];
        assert_eq!(t.enrich(&mut v), 2);
        assert_eq!((v[0].asn, v[0].target_asn), (Some(64500), None));
        assert_eq!((v[1].asn, v[1].target_asn), (None, Some(64501)));
        assert_eq!(v[2].asn, Some(1));
        assert_eq!(v[3].asn, None);
    }
}
