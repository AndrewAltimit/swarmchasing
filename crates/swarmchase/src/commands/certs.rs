//! `swarmchase certs`: Certificate Transparency via crt.sh.

use anyhow::Result;
use sc_collect::Client;
use std::time::Duration;

pub fn run(query: &str, json: bool) -> Result<()> {
    let client = Client::new(Duration::from_secs(2))?;
    let recs = client.crtsh(query)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&recs)?);
        return Ok(());
    }
    for r in recs {
        println!(
            "{}  {:<10}  {}  [{}]",
            r.entry_timestamp,
            r.id,
            r.name_value.replace('\n', ", "),
            r.issuer_name
        );
    }
    Ok(())
}
