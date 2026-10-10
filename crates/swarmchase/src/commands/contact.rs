//! `swarmchase contact`: a domain's RFC 9116 security.txt contact.

use anyhow::Result;
use sc_collect::Client;
use sc_core::parse_security_txt;
use std::time::Duration;

pub fn run(domain: &str) -> Result<()> {
    let client = Client::new(Duration::from_millis(500))?;
    match client.security_txt(domain) {
        Ok((url, body)) => {
            let s = parse_security_txt(&body);
            println!(
                "source:  {url}{}",
                if s.signed { " (PGP signed)" } else { "" }
            );
            for c in &s.contact {
                println!("contact: {c}");
            }
            for p in &s.policy {
                println!("policy:  {p}");
            }
            for e in &s.encryption {
                println!("key:     {e}");
            }
            if let Some(x) = &s.expires {
                println!("expires: {x}");
            }
        }
        Err(e) => {
            println!("No security.txt for {domain}: {e:#}");
            println!(
                "Fallbacks: the organisation's CERT/CSIRT, the national CERT for the country, or abuse contacts in WHOIS/RDAP."
            );
        }
    }
    Ok(())
}
