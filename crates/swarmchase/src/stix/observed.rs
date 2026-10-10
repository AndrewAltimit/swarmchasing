//! What the records of each non-noise cluster yield: cyber-observables (URLs,
//! domains, networks, addresses), indicator drafts, and one `observed-data`
//! per cluster.

use super::Options;
use super::ids::stix_ts;
use super::indicators::{Draft, indicators};
use super::objects::{Head, add_sco, observed_data};
use sc_core::notice::{PublicView, WITHHELD};
use sc_core::rules::Target;
use sc_core::{Analysis, Audience, IndicatorKind, Rules, Tier};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

pub(super) struct Observed {
    /// Cyber-observables by id.
    pub scos: BTreeMap<String, Value>,
    /// Indicators by STIX pattern.
    pub drafts: BTreeMap<String, Draft>,
    /// `observed-data` per cluster index.
    pub observed: Vec<(usize, Value)>,
}

pub(super) fn observe(a: &Analysis, rules: &Rules, h: &Head, o: &Options) -> Observed {
    let public = o.audience == Audience::Public;
    let mut view = PublicView::new(a, o.exposed);
    let kinds: BTreeMap<&str, IndicatorKind> = rules
        .set
        .rules
        .iter()
        .map(|r| (r.id.as_str(), r.kind))
        .collect();
    let ua_rules: BTreeSet<&str> = rules
        .set
        .rules
        .iter()
        .filter(|r| r.target == Target::UserAgent)
        .map(|r| r.id.as_str())
        .collect();
    let asn_names: BTreeMap<u32, &str> = a
        .asns
        .iter()
        .filter_map(|x| Some((x.asn, x.org.as_deref()?)))
        .collect();

    let mut out = Observed {
        scos: BTreeMap::new(),
        drafts: BTreeMap::new(),
        observed: Vec::new(),
    };
    for (ci, cl) in a.clusters.iter().enumerate() {
        if cl.tier == Tier::Noise {
            continue;
        }
        let mut refs = BTreeSet::new();
        for &m in &cl.members {
            let r = &a.results[m];
            // The URL a public notice may show, or none at all.
            let shown = if public {
                view.record_url(r).filter(|u| !u.contains(WITHHELD))
            } else {
                Some(r.obs.url.clone())
            };
            let scos = &mut out.scos;
            if let Some(u) = shown.as_deref().filter(|u| !u.is_empty()) {
                refs.insert(add_sco(scos, "url", json!({ "value": u })));
            }
            if let Some(host) = r
                .target_host
                .as_deref()
                .filter(|h| h.parse::<IpAddr>().is_err())
            {
                refs.insert(add_sco(scos, "domain-name", json!({ "value": host })));
            }
            // The network observed in the record: the client's, or the
            // target's where a scan service recorded only that.
            if let Some(asn) = r.obs.asn.or(r.obs.target_asn) {
                let mut v = json!({ "number": asn });
                if let Some(n) = asn_names.get(&asn).copied().or_else(|| rules.asn_org(asn)) {
                    v["name"] = json!(n);
                }
                refs.insert(add_sco(scos, "autonomous-system", v));
            }
            if !public && let Some(ip) = r.obs.ip.as_deref() {
                match ip.parse::<IpAddr>() {
                    Ok(IpAddr::V4(_)) => {
                        refs.insert(add_sco(scos, "ipv4-addr", json!({ "value": ip })));
                    }
                    Ok(IpAddr::V6(_)) => {
                        refs.insert(add_sco(scos, "ipv6-addr", json!({ "value": ip })));
                    }
                    Err(_) => {}
                }
            }
            for (pattern, d) in indicators(r, &kinds, &ua_rules, public, shown.is_some(), &mut view)
            {
                let e = out.drafts.entry(pattern).or_insert(d);
                e.tier = e.tier.max(cl.tier);
                if r.obs.ts > 0 {
                    e.valid_from = e.valid_from.min(r.obs.ts);
                }
                e.clusters.insert(ci);
            }
        }
        if refs.is_empty() {
            continue;
        }
        let mut members: Vec<&str> = cl
            .members
            .iter()
            .map(|&m| a.results[m].obs.id.as_str())
            .collect();
        members.sort_unstable();
        let first = if cl.start > 0 {
            stix_ts(cl.start)
        } else {
            h.created.clone()
        };
        let last = if cl.end > 0 {
            stix_ts(cl.end)
        } else {
            first.clone()
        };
        out.observed.push((
            ci,
            observed_data(
                h,
                o.case_id,
                &members,
                (first, last),
                refs.into_iter().collect(),
            ),
        ));
    }
    out
}
