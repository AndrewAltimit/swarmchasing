//! Web archive captures as [`Observation`]s.
//!
//! A capture gets the same id, source and record link whichever way it
//! arrived: a collector page from the Wayback Machine or Arquivo.pt CDX
//! index, or a CDX export imported by hand. The id is
//! `<archive>:<timestamp>:<digest>:<url hash>`, so the same capture
//! deduplicates across both paths. The digest is of the response body, so
//! different URLs saved in the same second with the same body (a batch of
//! saves that all got one error page) share it; the hash of the redacted URL
//! keeps them apart.

use crate::model::{Observation, TsKind, parse_ts};
use crate::redact::redact_url;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Archive {
    Wayback,
    Arquivo,
}

impl Archive {
    /// The `Observation::source` of its captures.
    pub fn source(self) -> &'static str {
        match self {
            Self::Wayback => "wayback",
            Self::Arquivo => "arquivo",
        }
    }

    /// The public page of one capture.
    pub fn link(self, ts: &str, original: &str) -> String {
        match self {
            Self::Wayback => format!("https://web.archive.org/web/{ts}/{original}"),
            Self::Arquivo => format!("https://arquivo.pt/wayback/{ts}/{original}"),
        }
    }

    /// The archive a CDX row came from, read from the fields that name it:
    /// Arquivo.pt's `filename` and `collection` name its own collections
    /// (`AWP…`, `…arquivo…`). Anything else is taken as the Wayback Machine.
    pub fn detect<'a>(fields: impl IntoIterator<Item = &'a str>) -> Self {
        let arquivo = fields.into_iter().any(|f| {
            let f = f.trim();
            f.to_ascii_lowercase().contains("arquivo")
                || f.strip_prefix("AWP")
                    .is_some_and(|r| r.starts_with(|c: char| c.is_ascii_digit()))
        });
        if arquivo {
            Self::Arquivo
        } else {
            Self::Wayback
        }
    }
}

/// One capture. `ts` is the 14-digit CDX timestamp, `original` the captured
/// URL. The caller redacts it.
pub fn capture(
    archive: Archive,
    ts: &str,
    original: &str,
    status: Option<u16>,
    digest: &str,
) -> Observation {
    Observation {
        id: format!(
            "{}:{ts}:{digest}:{}",
            archive.source(),
            crate::fingerprint::short_hash(&redact_url(original, &mut 0))
        ),
        source: archive.source().into(),
        ts: parse_ts(ts).unwrap_or(0),
        status,
        ts_kind: TsKind::Capture,
        reference: Some(archive.link(ts, original)),
        url: original.to_string(),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_and_links() {
        let o = capture(
            Archive::Arquivo,
            "20261004081000",
            "https://a.example/",
            Some(200),
            "D",
        );
        assert!(o.id.starts_with("arquivo:20261004081000:D:"), "{}", o.id);
        assert_eq!(o.source, "arquivo");
        assert_eq!(
            o.reference.as_deref(),
            Some("https://arquivo.pt/wayback/20261004081000/https://a.example/")
        );
        assert_eq!(Archive::detect(["AWP29"]), Archive::Arquivo);
        assert_eq!(
            Archive::detect(["ARQUIVO-20261004-00001.warc.gz"]),
            Archive::Arquivo
        );
        assert_eq!(
            Archive::detect(["AWPX", "", "crawl-1.warc.gz"]),
            Archive::Wayback
        );
    }

    #[test]
    fn same_second_and_body_but_different_urls_get_different_ids() {
        let at = |url: &str| capture(Archive::Wayback, "20261004081000", url, None, "E").id;
        assert_ne!(at("https://a.example/1"), at("https://a.example/2"));
        // The same whether the URL is redacted before or after.
        let raw = "https://a.example/?api_key=s3cr3t";
        assert_eq!(at(raw), at(&redact_url(raw, &mut 0)));
    }
}
