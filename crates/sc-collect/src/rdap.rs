//! RDAP domain records, for the registrar's abuse contact when a domain has
//! no security.txt.

use crate::Client;
use anyhow::Result;

impl Client {
    /// RDAP record for a registered domain, via the rdap.org bootstrap
    /// redirector. Returns (request URL, JSON body).
    pub fn rdap_domain(&self, domain: &str) -> Result<(String, String)> {
        let url = format!(
            "https://rdap.org/domain/{}",
            domain.trim().trim_end_matches('.')
        );
        let body = self.get(&url)?;
        Ok((url, body))
    }
}
