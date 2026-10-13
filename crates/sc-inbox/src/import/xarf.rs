//! An X-ARF report as an SC-Submission.
//!
//! X-ARF v4 (`xarf_version`, `reporter`, `source_identifier`, `category`,
//! `type`, `timestamp`, `evidence`) and the older v3 layout (`ReporterInfo`,
//! `Report` with `ReportClass`, `ReportType`, `Date`, `SourceIp`, `Samples`)
//! are both read:
//!
//! | Field | Becomes |
//! |---|---|
//! | `reporter` / `ReporterInfo` | The submitter: organisation, contact, and its domain as the key. |
//! | `category`, `type`, `report_id`, `description` | The claim's summary. |
//! | `timestamp` / `Date` | The claim's span. |
//! | `source_identifier` / `SourceIp` | An IP indicator (another value an `other` indicator). |
//! | `url` / `Url` | A URL indicator. |
//! | `evidence` / `Samples` | Decoded: a DKIM-signed message or a signed HTTP request as a signed artifact (unchecked); other text as log lines; anything else an unmapped claim with its type, size and hash. |
//!
//! Every other field is kept as an unmapped claim.

use super::{Builder, Converted, Format, decode_b64, is_ip, sha256_hex, text_of};
use crate::spec::{Caps, Evidence, IndicatorKind, SignScheme, Signed};
use serde_json::Value;

pub fn convert(doc: &Value, caps: &Caps) -> Result<Converted, Vec<String>> {
    let Some(top) = doc.as_object() else {
        return Err(vec!["an X-ARF report is a JSON object".into()]);
    };
    let mut b = Builder::new(Format::Xarf);
    b.objects = 1;
    if top.contains_key("xarf_version") {
        v4(&mut b, top);
    } else {
        v3(&mut b, top);
    }
    b.finish(caps)
}

fn s(v: Option<&Value>) -> Option<String> {
    v.and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn v4(b: &mut Builder, top: &serde_json::Map<String, Value>) {
    b.version = s(top.get("xarf_version"));
    let used = [
        "xarf_version",
        "report_id",
        "timestamp",
        "reporter",
        "source_identifier",
        "source_port",
        "category",
        "type",
        "description",
        "evidence",
        "url",
        "urls",
    ];
    if let Some(r) = top.get("reporter").and_then(Value::as_object) {
        b.submitter.name = s(r.get("org"));
        b.submitter.contact = s(r.get("contact"));
        b.submitter.key = s(r.get("domain")).map(|d| d.to_ascii_lowercase());
        for (k, v) in r {
            if !matches!(k.as_str(), "org" | "contact" | "domain") {
                b.unmapped(&format!("xarf.reporter.{k}"), &text_of(v));
            }
        }
    }
    let class = [s(top.get("category")), s(top.get("type"))]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join("/");
    summary(
        b,
        &class,
        s(top.get("report_id")),
        s(top.get("description")),
    );
    if let Some(t) = s(top.get("timestamp"))
        && !b.seen(&t)
    {
        b.unmapped("xarf.timestamp", &t);
    }
    source(b, s(top.get("source_identifier")), top.get("source_port"));
    for k in ["url", "urls"] {
        urls(b, top.get(k), &format!("xarf.{k}"));
    }
    for (i, e) in top
        .get("evidence")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
    {
        sample(
            b,
            &format!("xarf.evidence[{i}]"),
            s(e.get("content_type")),
            s(e.get("payload")),
            true,
            s(e.get("description")),
            s(e.get("hash")),
        );
        if let Some(m) = e.as_object() {
            for (k, v) in m {
                if !matches!(
                    k.as_str(),
                    "content_type" | "payload" | "description" | "hash" | "size"
                ) {
                    b.unmapped(&format!("xarf.evidence[{i}].{k}"), &text_of(v));
                }
            }
        }
    }
    rest(b, top, &used, "xarf");
}

fn v3(b: &mut Builder, top: &serde_json::Map<String, Value>) {
    b.version = s(top.get("Version")).or(Some("3".into()));
    let used = ["Version", "ReporterInfo", "Report"];
    if let Some(r) = top.get("ReporterInfo").and_then(Value::as_object) {
        b.submitter.name = s(r.get("ReporterOrg")).or(s(r.get("ReporterContactName")));
        b.submitter.contact = s(r.get("ReporterContactEmail")).or(s(r.get("ReporterOrgEmail")));
        b.submitter.key = s(r.get("ReporterOrgDomain")).map(|d| d.to_ascii_lowercase());
        for (k, v) in r {
            if !matches!(
                k.as_str(),
                "ReporterOrg"
                    | "ReporterContactName"
                    | "ReporterContactEmail"
                    | "ReporterOrgEmail"
                    | "ReporterOrgDomain"
            ) {
                b.unmapped(&format!("xarf.ReporterInfo.{k}"), &text_of(v));
            }
        }
    }
    let Some(r) = top.get("Report").and_then(Value::as_object) else {
        rest(b, top, &used, "xarf");
        return;
    };
    let class = [
        s(r.get("ReportClass")),
        s(r.get("ReportType")),
        s(r.get("ReportSubType")),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>()
    .join("/");
    summary(b, &class, s(r.get("ReportID")), s(r.get("Description")));
    if let Some(t) = s(r.get("Date"))
        && !b.seen(&t)
    {
        b.unmapped("xarf.Report.Date", &t);
    }
    source(b, s(r.get("SourceIp")), r.get("SourcePort"));
    urls(b, r.get("Url"), "xarf.Report.Url");
    for (i, e) in r
        .get("Samples")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
    {
        sample(
            b,
            &format!("xarf.Report.Samples[{i}]"),
            s(e.get("ContentType")),
            s(e.get("Payload")),
            e.get("Base64Encoded")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            s(e.get("Description")),
            None,
        );
    }
    let report_used = [
        "ReportClass",
        "ReportType",
        "ReportSubType",
        "ReportID",
        "Description",
        "Date",
        "SourceIp",
        "SourcePort",
        "Url",
        "Samples",
    ];
    rest(b, r, &report_used, "xarf.Report");
    rest(b, top, &used, "xarf");
}

fn summary(b: &mut Builder, class: &str, id: Option<String>, description: Option<String>) {
    let mut head = String::from("X-ARF");
    if !class.is_empty() {
        head.push(' ');
        head.push_str(class);
    }
    head.push_str(" report");
    if let Some(id) = id {
        head.push(' ');
        head.push_str(&id);
    }
    head.push('.');
    b.summary(&head);
    if let Some(d) = description {
        b.summary(&d);
    }
}

fn source(b: &mut Builder, id: Option<String>, port: Option<&Value>) {
    let Some(id) = id else { return };
    let port = port.map(text_of);
    let note = Some(match &port {
        Some(p) => format!("the reported source, port {p}"),
        None => "the reported source".into(),
    });
    let kind = if is_ip(&id) {
        IndicatorKind::Ip
    } else {
        IndicatorKind::Other
    };
    b.indicator(kind, &id, note);
}

fn urls(b: &mut Builder, v: Option<&Value>, path: &str) {
    match v {
        Some(Value::String(u)) => b.indicator(IndicatorKind::Url, u, None),
        Some(Value::Array(a)) => {
            for u in a {
                match u.as_str() {
                    Some(u) => b.indicator(IndicatorKind::Url, u, None),
                    None => b.unmapped(path, &text_of(u)),
                }
            }
        }
        Some(other) => b.unmapped(path, &text_of(other)),
        None => {}
    }
}

/// One evidence sample, decoded.
fn sample(
    b: &mut Builder,
    path: &str,
    content_type: Option<String>,
    payload: Option<String>,
    base64: bool,
    description: Option<String>,
    hash: Option<String>,
) {
    let ct = content_type.unwrap_or_else(|| "application/octet-stream".into());
    let Some(payload) = payload else {
        b.unmapped(path, &format!("{ct} with no payload"));
        return;
    };
    let bytes = if base64 {
        match decode_b64(&payload) {
            Some(x) => x,
            None => {
                b.unmapped(path, &format!("{ct} payload that is not base64"));
                return;
            }
        }
    } else {
        payload.into_bytes()
    };
    let mut note = format!("X-ARF evidence ({ct})");
    if let Some(d) = &description {
        note.push_str(": ");
        note.push_str(&super::short(d, 500));
    }
    if let Some(h) = &hash {
        note.push_str(&format!(" [{h}]"));
    }
    let Ok(text) = String::from_utf8(bytes.clone()) else {
        b.unmapped(
            path,
            &format!(
                "{ct}, {} bytes, not text, sha256:{}",
                bytes.len(),
                sha256_hex(&bytes)
            ),
        );
        return;
    };
    let low = text.to_ascii_lowercase();
    let lct = ct.to_ascii_lowercase();
    if low.contains("dkim-signature:") {
        b.push(Evidence::Signed(Signed {
            scheme: SignScheme::Dkim,
            signer: tag(&text, "d="),
            content: text,
            note: Some(note),
        }));
    } else if low.contains("signature-input:") && low.contains("\nsignature:") {
        b.push(Evidence::Signed(Signed {
            scheme: SignScheme::HttpMessageSignature,
            signer: tag(&text, "keyid=\""),
            content: text,
            note: Some(note),
        }));
    } else if lct.starts_with("text/")
        || lct.starts_with("message/")
        || lct.contains("json")
        || lct.contains("log")
    {
        b.lines(text.lines().map(str::to_string).collect(), None, Some(note));
    } else {
        b.unmapped(
            path,
            &format!("{ct}, {} bytes, sha256:{}", bytes.len(), sha256_hex(&bytes)),
        );
    }
}

/// The value after `key` up to `;`, `"`, `,` or whitespace.
fn tag(text: &str, key: &str) -> Option<String> {
    let i = text.find(key)? + key.len();
    let v: String = text[i..]
        .chars()
        .take_while(|c| !matches!(c, ';' | '"' | ',') && !c.is_whitespace())
        .collect();
    (!v.is_empty()).then_some(v)
}

/// Every field of `m` not in `used`, as an unmapped claim.
fn rest(b: &mut Builder, m: &serde_json::Map<String, Value>, used: &[&str], path: &str) {
    for (k, v) in m {
        if !used.contains(&k.as_str()) {
            b.unmapped(&format!("{path}.{k}"), &text_of(v));
        }
    }
}
