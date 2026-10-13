//! An IODEF v2 document (RFC 7970) as an SC-Submission.
//!
//! | Element | Becomes |
//! |---|---|
//! | `Incident/IncidentID`, `Description` | The claim's summary. |
//! | `ReportTime` | The stated submission time. |
//! | `StartTime`, `EndTime`, `DetectTime` (any level) | The claim's span. |
//! | `Contact` (role `creator` or `reporter`, else the first) | The submitter: `ContactName`, `Email/EmailTo`. |
//! | `System` (category `source`) `Node/Address` | IP indicators; `DomainData/Name` an `other` indicator. |
//! | `System` (category `target`) `Node/DomainData/Name` | Claim targets, and the host of the log lines. |
//! | `Record/RecordData/RecordItem` | Log lines. |
//! | `URL`, `Reference/URL` | Public-record references when they name a record by id; otherwise URL indicators. |
//!
//! Every other element with text is kept as an unmapped claim, by its path.

use super::xml::Node;
use super::{Builder, Converted, Format, is_ip, public_record};
use crate::spec::{Caps, IndicatorKind};
use std::collections::BTreeSet;

pub fn convert(root: &Node, caps: &Caps) -> Result<Converted, Vec<String>> {
    if root.name != "IODEF-Document" {
        return Err(vec![format!(
            "the root element is <{}>; an IODEF document's is <IODEF-Document>",
            super::short(&root.name, 60)
        )]);
    }
    let mut b = Builder::new(Format::Iodef);
    b.version = root.attr("version").map(str::to_string);
    let mut used: BTreeSet<usize> = BTreeSet::new();
    used.insert(root.id);
    let incidents: Vec<&Node> = root.all("Incident").collect();
    if incidents.is_empty() {
        return Err(vec!["an IODEF document needs an <Incident>".into()]);
    }
    b.objects = incidents.len();
    for inc in &incidents {
        incident(&mut b, inc, &mut used);
    }
    // Every element with text that nothing above read.
    for n in root.walk() {
        if !used.contains(&n.id) && !n.text.is_empty() {
            b.unmapped(&format!("iodef:{}", path_of(root, n.id)), &n.text);
        }
    }
    b.finish(caps)
}

fn incident(b: &mut Builder, inc: &Node, used: &mut BTreeSet<usize>) {
    used.insert(inc.id);
    let mut take = |n: &Node| {
        used.insert(n.id);
        n.text.clone()
    };
    let id = inc.child("IncidentID").map(&mut take);
    let mut head = String::from("IODEF incident");
    if let Some(id) = id.filter(|s| !s.is_empty()) {
        head.push(' ');
        head.push_str(&id);
    }
    head.push('.');
    b.summary(&head);
    for d in inc.all("Description") {
        let t = take(d);
        b.summary(&t);
    }
    if let Some(t) = inc.child("ReportTime") {
        b.submitted = Some(take(t));
    }
    if let Some(t) = inc.child("GenerationTime") {
        take(t);
    }
    // Times anywhere in the incident.
    for n in inc.walk() {
        if matches!(n.name.as_str(), "StartTime" | "EndTime" | "DetectTime") && b.seen(&n.text) {
            used.insert(n.id);
        }
    }
    contact(b, inc, used);
    let mut hosts: Vec<String> = Vec::new();
    for n in inc.walk() {
        if n.name == "System" {
            system(b, n, used, &mut hosts);
        }
    }
    let host = hosts.first().cloned();
    for n in inc.walk() {
        match n.name.as_str() {
            "RecordData" => record(b, n, used, host.clone()),
            "URL" if !used.contains(&n.id) => {
                used.insert(n.id);
                url(b, &n.text);
            }
            // Containers: their own text is whitespace.
            "EventData" | "Flow" | "Record" | "RelatedActivity" | "Node" | "DomainData"
            | "Email" | "Service" => {
                used.insert(n.id);
            }
            _ => {}
        }
    }
}

fn contact(b: &mut Builder, inc: &Node, used: &mut BTreeSet<usize>) {
    let contacts: Vec<&Node> = inc.all("Contact").collect();
    let Some(c) = contacts
        .iter()
        .find(|c| matches!(c.attr("role"), Some("creator" | "reporter")))
        .or(contacts.first())
    else {
        return;
    };
    used.insert(c.id);
    if let Some(n) = c.child("ContactName") {
        used.insert(n.id);
        b.submitter.name = Some(n.text.clone()).filter(|s| !s.is_empty());
    }
    let email = c
        .walk()
        .into_iter()
        .find(|n| matches!(n.name.as_str(), "EmailTo" | "Email") && !n.text.is_empty());
    if let Some(e) = email {
        used.insert(e.id);
        b.submitter.contact = Some(e.text.clone());
    }
}

fn system(b: &mut Builder, sys: &Node, used: &mut BTreeSet<usize>, hosts: &mut Vec<String>) {
    let category = sys.attr("category").unwrap_or("");
    used.insert(sys.id);
    for node in sys.all("Node") {
        used.insert(node.id);
        for n in node.walk() {
            let text = n.text.trim();
            if text.is_empty() {
                continue;
            }
            match (category, n.name.as_str()) {
                ("source", "Address") if is_ip(text) => {
                    used.insert(n.id);
                    b.indicator(
                        IndicatorKind::Ip,
                        text,
                        Some("an IODEF source address".into()),
                    );
                }
                ("source", "Name") => {
                    used.insert(n.id);
                    b.indicator(
                        IndicatorKind::Other,
                        text,
                        Some("an IODEF source host name".into()),
                    );
                }
                ("target", "Name") => {
                    used.insert(n.id);
                    b.target(text);
                    hosts.push(text.to_ascii_lowercase());
                }
                _ => {}
            }
        }
    }
}

fn record(b: &mut Builder, rd: &Node, used: &mut BTreeSet<usize>, host: Option<String>) {
    used.insert(rd.id);
    let mut note = Vec::new();
    for n in rd.all("DateTime") {
        used.insert(n.id);
        b.seen(&n.text);
        note.push(n.text.clone());
    }
    for n in rd.all("Description") {
        used.insert(n.id);
        note.push(n.text.clone());
    }
    let mut lines = Vec::new();
    for item in rd.all("RecordItem") {
        let dtype = item.attr("dtype").unwrap_or("string");
        if matches!(dtype, "string" | "ext-value") || item.attr("dtype").is_none() {
            used.insert(item.id);
            lines.extend(item.text.lines().map(str::to_string));
        }
    }
    let note = (!note.is_empty()).then(|| format!("IODEF record: {}", note.join(": ")));
    b.lines(lines, host, note);
}

fn url(b: &mut Builder, text: &str) {
    let t = text.trim();
    if t.is_empty() {
        return;
    }
    if let Some(r) = public_record(None, None, Some(t)) {
        b.push(crate::spec::Evidence::PublicRecord(r));
    } else if t.starts_with("http://") || t.starts_with("https://") {
        b.indicator(
            IndicatorKind::Url,
            t,
            Some("a URL in the IODEF document".into()),
        );
    } else {
        b.unmapped("iodef:URL", t);
    }
}

/// `Incident/EventData/Method/Description`: the path to node `id`.
fn path_of(root: &Node, id: usize) -> String {
    fn go<'a>(n: &'a Node, id: usize, out: &mut Vec<&'a str>) -> bool {
        out.push(&n.name);
        if n.id == id {
            return true;
        }
        for c in &n.children {
            if go(c, id, out) {
                return true;
            }
        }
        out.pop();
        false
    }
    let mut out = Vec::new();
    go(root, id, &mut out);
    out.into_iter().skip(1).collect::<Vec<_>>().join("/")
}
