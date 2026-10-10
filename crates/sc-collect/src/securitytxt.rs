//! An affected organisation's RFC 9116 security.txt, for its security
//! contact: a published contact file on the organisation's own site.

use crate::Client;
use anyhow::Result;

impl Client {
    /// Fetch `/.well-known/security.txt` (falling back to `/security.txt`).
    /// Returns (request URL, body).
    pub fn security_txt(&self, domain: &str) -> Result<(String, String)> {
        let domain = domain
            .trim()
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .trim_end_matches('/');
        let mut last_err = None;
        for path in ["/.well-known/security.txt", "/security.txt"] {
            let url = format!("https://{domain}{path}");
            match self.get(&url) {
                Ok(body) if body.to_ascii_lowercase().contains("contact:") => {
                    return Ok((url, body));
                }
                Ok(_) => last_err = Some(anyhow::anyhow!("{url}: no Contact field")),
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap())
    }
}
