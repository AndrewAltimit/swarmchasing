//! `swarmchase rules`: validate a rules file, or print the bundled rules.

use anyhow::Result;
use sc_core::Rules;
use std::path::Path;

pub fn run(file: Option<&Path>, dump: bool) -> Result<()> {
    if dump {
        print!("{}", sc_core::DEFAULT_RULES);
        return Ok(());
    }
    let text = match file {
        Some(p) => std::fs::read_to_string(p)?,
        None => sc_core::DEFAULT_RULES.to_string(),
    };
    let r = Rules::from_toml(&text).map_err(anyhow::Error::msg)?;
    println!(
        "ok: {} rules, {} ASN hints (version {})",
        r.set.rules.len(),
        r.set.asns.len(),
        r.set.meta.version
    );
    Ok(())
}
