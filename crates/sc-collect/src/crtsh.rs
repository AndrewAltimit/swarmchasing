//! Certificate Transparency via crt.sh: the certificates issued for a name.

use crate::Client;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertRecord {
    pub id: u64,
    #[serde(default)]
    pub issuer_name: String,
    #[serde(default)]
    pub common_name: String,
    #[serde(default)]
    pub name_value: String,
    #[serde(default)]
    pub entry_timestamp: String,
    #[serde(default)]
    pub not_before: String,
    #[serde(default)]
    pub not_after: String,
}

impl Client {
    /// Certificate Transparency search via crt.sh (e.g. `%.hysandbox.example.com`).
    pub fn crtsh(&self, query: &str) -> Result<Vec<CertRecord>> {
        let mut u = url::Url::parse("https://crt.sh/")?;
        u.query_pairs_mut()
            .append_pair("q", query)
            .append_pair("output", "json");
        let body = self.get(u.as_str())?;
        if body.trim().is_empty() {
            return Ok(vec![]);
        }
        let mut recs: Vec<CertRecord> = serde_json::from_str(&body).context("crt.sh JSON")?;
        recs.sort_by(|a, b| b.entry_timestamp.cmp(&a.entry_timestamp));
        Ok(recs)
    }
}
