//! Published network ranges: the address ranges cloud providers publish
//! for their own services (AWS, Google Cloud, Oracle Cloud, Cloudflare),
//! and the Tor Project's list of exit relay addresses.
//!
//! The table is descriptive context for a record's client address: which
//! provider, region and service the address belongs to (its hosting
//! class), and whether it is a Tor exit. It never adds to a score and never
//! links records. A Tor exit lowers trust in hosting-based signals: the
//! exit relay names neither the agent's host nor its developer, so
//! attribution leaves those records out of its hosting claims
//! ([`crate::attribution::attribute`]).
//!
//! Formats, as the providers serve them:
//! - AWS `ip-ranges.json`: `prefixes[].ip_prefix` and
//!   `ipv6_prefixes[].ipv6_prefix`, each with `region` and `service`. A
//!   range listed under a specific service (`EC2`) and under the catch-all
//!   `AMAZON` keeps the specific one.
//! - Google Cloud `cloud.json`: `prefixes[].ipv4Prefix` or `ipv6Prefix`,
//!   with `scope` (the region) and `service`.
//! - Oracle Cloud `public_ip_ranges.json`: `regions[].region` with
//!   `cidrs[].cidr` and `cidrs[].tags`.
//! - Cloudflare `ips-v4` and `ips-v6`: one prefix per line.
//! - Tor `torbulkexitlist`: one exit address per line.
//!
//! The CLI downloads the files into the data directory (`sc_collect::
//! netranges`); they are never committed. This module holds no I/O.

use crate::analyze::Analysis;
use crate::model::TsKind;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;

/// Where an address's range was published, as a lookup reports it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NetClass {
    /// The provider's display name (`AWS`, `Google Cloud`).
    pub provider: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
}

impl NetClass {
    /// `AWS us-east-1 EC2`, `Cloudflare`: provider, region, service.
    pub fn label(&self) -> String {
        [
            Some(self.provider.as_str()),
            self.region.as_deref(),
            self.service.as_deref(),
        ]
        .into_iter()
        .flatten()
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
    }
}

/// What the table says about one address.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NetInfo<'a> {
    /// The most specific published range holding the address.
    pub class: Option<&'a NetClass>,
    /// The address is on the Tor exit list.
    pub tor: bool,
}

impl NetInfo<'_> {
    pub fn is_empty(&self) -> bool {
        self.class.is_none() && !self.tor
    }
}

/// The published ranges, searched most specific prefix first.
#[derive(Debug, Default, Clone)]
pub struct NetRanges {
    /// Prefix length (in the 128-bit space) to network to (class, priority).
    by_len: BTreeMap<u8, HashMap<u128, (u32, u8)>>,
    classes: Vec<NetClass>,
    class_ids: HashMap<NetClass, u32>,
    tor: HashSet<u128>,
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

/// `a.b.c.d/n` or `x::/n` as (network, length in the 128-bit space).
fn cidr(s: &str) -> Option<(u128, u8)> {
    let (addr, len) = s.trim().split_once('/')?;
    let ip: IpAddr = addr.trim().parse().ok()?;
    let len: u8 = len.trim().parse().ok()?;
    let len = match ip {
        IpAddr::V4(_) if len <= 32 => len + 96,
        IpAddr::V6(_) if len <= 128 => len,
        _ => return None,
    };
    Some((key(ip) & mask(len), len))
}

fn text(v: &Value, k: &str) -> Option<String> {
    v.get(k)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

impl NetRanges {
    /// Prefixes held, and Tor exits.
    pub fn len(&self) -> (usize, usize) {
        (self.by_len.values().map(HashMap::len).sum(), self.tor.len())
    }

    pub fn is_empty(&self) -> bool {
        self.by_len.is_empty() && self.tor.is_empty()
    }

    fn class_id(&mut self, c: NetClass) -> u32 {
        if let Some(&id) = self.class_ids.get(&c) {
            return id;
        }
        let id = self.classes.len() as u32;
        self.classes.push(c.clone());
        self.class_ids.insert(c, id);
        id
    }

    /// Add one prefix. Of two classes for the same prefix, the higher
    /// `priority` wins, then the first added.
    fn add(&mut self, prefix: &str, class: NetClass, priority: u8) -> bool {
        let Some((net, len)) = cidr(prefix) else {
            return false;
        };
        let id = self.class_id(class);
        let slot = self.by_len.entry(len).or_default();
        match slot.get(&net) {
            Some(&(_, p)) if p >= priority => {}
            _ => {
                slot.insert(net, (id, priority));
            }
        }
        true
    }

    /// Add AWS's `ip-ranges.json`. Returns the prefixes read.
    pub fn add_aws(&mut self, json: &str) -> Result<usize, String> {
        let v: Value = serde_json::from_str(json).map_err(|e| format!("AWS ranges: {e}"))?;
        let mut n = 0;
        for (list, field) in [("prefixes", "ip_prefix"), ("ipv6_prefixes", "ipv6_prefix")] {
            for p in v.get(list).and_then(Value::as_array).into_iter().flatten() {
                let Some(prefix) = text(p, field) else {
                    continue;
                };
                let service = text(p, "service");
                // `AMAZON` lists every range; a specific service says more.
                let priority = u8::from(service.as_deref() != Some("AMAZON"));
                let class = NetClass {
                    provider: "AWS".into(),
                    region: text(p, "region").filter(|r| r != "GLOBAL"),
                    service,
                };
                n += usize::from(self.add(&prefix, class, priority));
            }
        }
        nonempty("AWS ranges", n)
    }

    /// Add Google Cloud's `cloud.json`.
    pub fn add_gcp(&mut self, json: &str) -> Result<usize, String> {
        let v: Value =
            serde_json::from_str(json).map_err(|e| format!("Google Cloud ranges: {e}"))?;
        let mut n = 0;
        for p in v
            .get("prefixes")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(prefix) = text(p, "ipv4Prefix").or_else(|| text(p, "ipv6Prefix")) else {
                continue;
            };
            let class = NetClass {
                provider: "Google Cloud".into(),
                region: text(p, "scope").filter(|r| r != "global"),
                service: text(p, "service").filter(|s| s != "Google Cloud"),
            };
            n += usize::from(self.add(&prefix, class, 1));
        }
        nonempty("Google Cloud ranges", n)
    }

    /// Add Oracle Cloud's `public_ip_ranges.json`.
    pub fn add_oracle(&mut self, json: &str) -> Result<usize, String> {
        let v: Value =
            serde_json::from_str(json).map_err(|e| format!("Oracle Cloud ranges: {e}"))?;
        let mut n = 0;
        for r in v
            .get("regions")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let region = text(r, "region");
            for c in r
                .get("cidrs")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let Some(prefix) = text(c, "cidr") else {
                    continue;
                };
                let tags: Vec<&str> = c
                    .get("tags")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default();
                let class = NetClass {
                    provider: "Oracle Cloud".into(),
                    region: region.clone(),
                    service: (!tags.is_empty()).then(|| tags.join("+")),
                };
                n += usize::from(self.add(&prefix, class, 1));
            }
        }
        nonempty("Oracle Cloud ranges", n)
    }

    /// Add a plain list of prefixes, one per line, all of `provider`
    /// (Cloudflare's `ips-v4` and `ips-v6`). Lines that are not prefixes
    /// are skipped.
    pub fn add_cidr_list(&mut self, provider: &str, list: &str) -> Result<usize, String> {
        let class = NetClass {
            provider: provider.into(),
            ..Default::default()
        };
        let n = list
            .lines()
            .filter(|l| self.add(l, class.clone(), 1))
            .count();
        nonempty(provider, n)
    }

    /// Add the Tor bulk exit list: one address per line; comments and
    /// other lines are skipped.
    pub fn add_tor_exits(&mut self, list: &str) -> Result<usize, String> {
        let before = self.tor.len();
        for l in list.lines() {
            if let Ok(ip) = l.trim().parse::<IpAddr>() {
                self.tor.insert(key(ip));
            }
        }
        nonempty("Tor exit list", self.tor.len() - before)
    }

    /// What the table says about `ip`, an address literal.
    pub fn lookup(&self, ip: &str) -> NetInfo<'_> {
        let Ok(ip) = ip.trim().parse::<IpAddr>() else {
            return NetInfo::default();
        };
        let k = key(ip);
        let class = self.by_len.iter().rev().find_map(|(&len, nets)| {
            nets.get(&(k & mask(len)))
                .map(|&(id, _)| &self.classes[id as usize])
        });
        NetInfo {
            class,
            tor: self.tor.contains(&k),
        }
    }
}

fn nonempty(what: &str, n: usize) -> Result<usize, String> {
    if n == 0 {
        Err(format!("{what}: no addresses in the file"))
    } else {
        Ok(n)
    }
}

/// A cluster's members by published range: descriptive context for its
/// hosting claims. Filled by [`annotate`], not by the pipeline: it needs
/// data the caller holds. Never scored, never linked on.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ClusterHosting {
    /// Members by hosting class ([`NetClass::label`]).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub classes: BTreeMap<String, usize>,
    /// Each classed member (an index into `Analysis::results`) and its class.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub members: BTreeMap<usize, NetClass>,
    /// Members sent from a Tor exit (indexes into `Analysis::results`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tor: Vec<usize>,
}

impl ClusterHosting {
    pub fn is_empty(&self) -> bool {
        self.classes.is_empty() && self.tor.is_empty()
    }

    /// `AWS us-east-1 EC2 ×3, Tor exit ×1`, or nothing.
    pub fn summary(&self) -> Option<String> {
        let mut parts: Vec<String> = self
            .classes
            .iter()
            .map(|(c, n)| format!("{c} ×{n}"))
            .collect();
        if !self.tor.is_empty() {
            parts.push(format!("Tor exit ×{}", self.tor.len()));
        }
        (!parts.is_empty()).then(|| parts.join(", "))
    }
}

/// Fill each cluster's [`ClusterHosting`] from the client addresses of its
/// members. A scan service's address is the scanner's or the target's, not
/// the client's, so submit-time records are left out. Returns the members
/// classed.
pub fn annotate(a: &mut Analysis, t: &NetRanges) -> usize {
    let mut n = 0;
    for ci in 0..a.clusters.len() {
        let mut h = ClusterHosting::default();
        for &m in &a.clusters[ci].members {
            let o = &a.results[m].obs;
            if o.ts_kind == TsKind::Submit {
                continue;
            }
            let Some(ip) = o.ip.as_deref() else {
                continue;
            };
            let info = t.lookup(ip);
            if info.tor {
                h.tor.push(m);
            }
            if let Some(c) = info.class {
                *h.classes.entry(c.label()).or_default() += 1;
                h.members.insert(m, c.clone());
            }
            n += usize::from(!info.is_empty());
        }
        a.clusters[ci].hosting = h;
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Observation;

    const AWS: &str = r#"{"syncToken":"1","createDate":"2026-10-14-03-37-06","prefixes":[
      {"ip_prefix":"198.51.100.0/24","region":"us-east-1","service":"AMAZON","network_border_group":"us-east-1"},
      {"ip_prefix":"198.51.100.0/24","region":"us-east-1","service":"EC2","network_border_group":"us-east-1"},
      {"ip_prefix":"198.51.0.0/16","region":"GLOBAL","service":"AMAZON","network_border_group":"GLOBAL"}
    ],"ipv6_prefixes":[{"ipv6_prefix":"2001:db8:a::/48","region":"eu-west-1","service":"EC2"}]}"#;
    const GCP: &str = r#"{"syncToken":"1","creationTime":"2026-10-14T01:07:47","prefixes":[
      {"ipv4Prefix":"203.0.113.0/25","service":"Google Cloud","scope":"us-central1"},
      {"ipv6Prefix":"2001:db8:b::/48","service":"Google Cloud","scope":"europe-west4"}]}"#;
    const ORACLE: &str = r#"{"last_updated_timestamp":"2026-08-25T08:06:24","regions":[
      {"region":"us-ashburn-1","cidrs":[{"cidr":"192.0.2.0/26","tags":["OCI"]},{"cidr":"bad","tags":[]}]}]}"#;

    fn table() -> NetRanges {
        let mut t = NetRanges::default();
        assert_eq!(t.add_aws(AWS), Ok(4));
        assert_eq!(t.add_gcp(GCP), Ok(2));
        assert_eq!(t.add_oracle(ORACLE), Ok(1));
        assert_eq!(
            t.add_cidr_list("Cloudflare", "192.0.2.128/25\n\n2001:db8:c::/48\n"),
            Ok(2)
        );
        assert_eq!(
            t.add_tor_exits("# exits\n192.0.2.200\n203.0.113.9\n"),
            Ok(2)
        );
        t
    }

    #[test]
    fn lookups_take_the_most_specific_range() {
        let t = table();
        assert_eq!(t.len(), (8, 2));
        let label = |ip: &str| t.lookup(ip).class.map(NetClass::label);
        // The specific service wins over the catch-all for the same range,
        // and a /24 over the /16 that holds it.
        assert_eq!(label("198.51.100.7").as_deref(), Some("AWS us-east-1 EC2"));
        assert_eq!(label("198.51.7.7").as_deref(), Some("AWS AMAZON"));
        assert_eq!(label("2001:db8:a::1").as_deref(), Some("AWS eu-west-1 EC2"));
        assert_eq!(
            label("203.0.113.5").as_deref(),
            Some("Google Cloud us-central1")
        );
        assert_eq!(
            label("192.0.2.1").as_deref(),
            Some("Oracle Cloud us-ashburn-1 OCI")
        );
        assert_eq!(label("192.0.2.130").as_deref(), Some("Cloudflare"));
        assert_eq!(label("10.0.0.1"), None);
        assert_eq!(label("not an ip"), None);
        // A Tor exit inside a cloud range is both.
        let i = t.lookup("203.0.113.9");
        assert!(i.tor && i.class.is_some());
        assert!(t.lookup("192.0.2.200").tor);
        assert!(t.lookup("::ffff:192.0.2.200").tor);
        assert!(!t.lookup("192.0.2.201").tor);
    }

    #[test]
    fn empty_or_broken_files_are_errors() {
        let mut t = NetRanges::default();
        assert!(t.add_aws("{}").is_err());
        assert!(t.add_aws("not json").is_err());
        assert!(t.add_gcp(r#"{"prefixes":[]}"#).is_err());
        assert!(t.add_cidr_list("Cloudflare", "<html>").is_err());
        assert!(t.add_tor_exits("").is_err());
        assert!(t.is_empty());
    }

    #[test]
    fn clusters_are_annotated_from_client_addresses_only() {
        let rec = |id: &str, ip: &str, kind: TsKind| Observation {
            id: id.into(),
            source: "access_log".into(),
            ts: 1_791_000_000,
            ts_kind: kind,
            url: format!("https://t.example/?q=1%27%20OR%201=1--&uqtag={id}"),
            ip: Some(ip.into()),
            ..Default::default()
        };
        let mut a = crate::analyze::Analysis::default();
        for (i, (ip, kind)) in [
            ("198.51.100.7", TsKind::Request),
            ("198.51.100.8", TsKind::Request),
            ("192.0.2.200", TsKind::Request),
            ("203.0.113.5", TsKind::Submit),
        ]
        .into_iter()
        .enumerate()
        {
            a.results.push(crate::analyze::ObsResult {
                obs: rec(&format!("r{i}"), ip, kind),
                score: 1,
                tier: crate::model::Tier::Suggestive,
                hits: Vec::new(),
                layers: Vec::new(),
                target_host: None,
                features: Vec::new(),
                cluster: Some(0),
                agent: None,
            });
        }
        a.clusters.push(crate::analyze::Cluster {
            members: vec![0, 1, 2, 3],
            ..Default::default()
        });
        a.results[0].obs.asn = Some(64500);
        a.results[2].obs.asn = Some(64501);
        assert_eq!(annotate(&mut a, &table()), 3);
        // Attribution: the ASN claim says which ranges its records came
        // from, a record with no ASN is claimed by its range, and the Tor
        // exit's record is in no claim at all, not even one naming Tor.
        let claims = crate::attribution::attribute(&a, &a.clusters[0]);
        let host = |p: &str| claims.iter().find(|c| c.party == p);
        let asn = host("AS64500").expect("AS64500");
        assert!(
            asn.details
                .iter()
                .any(|d| d == "1 of them from AWS us-east-1 EC2 published address ranges"),
            "{:?}",
            asn.details
        );
        assert!(host("AS64501").is_none(), "{claims:#?}");
        assert_eq!(host("AWS").map(|c| c.records), Some(1));
        assert!(
            claims.iter().all(|c| !c.party.contains("Tor")),
            "{claims:#?}"
        );
        // Reports carry a caution instead, never in a public notice.
        let mut a = a.clone();
        a.clusters[0].tier = crate::model::Tier::Significant;
        let report = |audience| {
            let opts = crate::report::ReportOptions {
                audience,
                ..Default::default()
            };
            crate::report::render_markdown(&a, &opts)
        };
        let internal = report(crate::report::Audience::Internal);
        assert!(
            internal.contains("**Caution.** 1 record(s) were sent through Tor exit relays; the network says nothing about the sender."),
            "{internal}"
        );
        assert!(!internal.contains("**Tor"), "{internal}");
        let public = report(crate::report::Audience::Public);
        assert!(!public.contains("Tor exit"), "{public}");
        let h = &a.clusters[0].hosting;
        assert_eq!(h.classes.get("AWS us-east-1 EC2"), Some(&2));
        assert_eq!(h.tor, [2]);
        assert_eq!(
            h.members.len(),
            3,
            "the Tor exit sits in a Cloudflare range too"
        );
        assert_eq!(
            h.summary().as_deref(),
            Some("AWS us-east-1 EC2 ×2, Cloudflare ×1, Tor exit ×1")
        );
    }
}
