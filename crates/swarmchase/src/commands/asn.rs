//! `swarmchase asn`: the offline IP-to-ASN table (iptoasn.com, PDDL 1.0) in
//! `<data>/asn/`. Once fetched, `watch` and the analysis commands fill the
//! network of records that carry only an IP.

use anyhow::{Result, bail};
use clap::{Args, Subcommand};
use sc_collect::Client;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Args)]
pub struct AsnArgs {
    #[command(subcommand)]
    cmd: AsnCmd,
    /// Data directory the table lives in.
    #[arg(
        short,
        long,
        global = true,
        default_value = "data",
        env = "SWARMCHASE_DATA"
    )]
    data: PathBuf,
}

#[derive(Subcommand)]
enum AsnCmd {
    /// Download the current table (a few MB) into <data>/asn/.
    Fetch,
    /// Look up addresses in the fetched table.
    Lookup { ips: Vec<String> },
}

pub fn run(a: AsnArgs) -> Result<()> {
    match a.cmd {
        AsnCmd::Fetch => {
            let client = Client::new(Duration::from_secs(1))?;
            let (p, n) = sc_collect::asn::fetch(&client, &a.data)?;
            let t = sc_collect::asn::load(&p)?;
            eprintln!("wrote {} ({n} bytes, {} ranges)", p.display(), t.len());
        }
        AsnCmd::Lookup { ips } => {
            let Some(t) = sc_collect::asn::load_from_data(&a.data)? else {
                bail!(
                    "no table at {}; run `swarmchase asn fetch` first",
                    sc_collect::asn::table_path(&a.data).display()
                );
            };
            for ip in ips {
                match t.lookup(&ip) {
                    Some(e) => println!("{ip}\tAS{}\t{}", e.asn, e.org),
                    None => println!("{ip}\t-\t(not in table)"),
                }
            }
        }
    }
    Ok(())
}

/// Fill the ASN of records with only an IP, from the table in the data
/// directory if one has been fetched. Quiet when there is none.
pub fn enrich(records: &mut [sc_core::Observation]) {
    if !records.iter().any(|o| o.ip.is_some()) {
        return;
    }
    let data = std::env::var("SWARMCHASE_DATA")
        .ok()
        .filter(|d| !d.is_empty())
        .map_or_else(|| PathBuf::from("data"), PathBuf::from);
    match sc_collect::asn::load_from_data(&data) {
        Ok(Some(t)) => {
            let n = t.enrich(records);
            if n > 0 {
                eprintln!("filled the ASN of {n} record(s) from the offline table");
            }
        }
        Ok(None) => {}
        Err(e) => eprintln!("warning: ASN table not loaded: {e:#}"),
    }
}
