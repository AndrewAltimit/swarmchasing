//! `swarmchase unwrap` and `swarmchase defang`: one URL's layers, and URLs
//! made safe to share.

use crate::util::truncate;
use anyhow::Result;
use sc_core::{Observation, Rules, defang, unwrap_layers};

/// The relay and carrier layers inside `url` and the rules it triggers.
pub fn run(url: String) -> Result<()> {
    let rules = Rules::default_rules();
    for (i, l) in unwrap_layers(&url).iter().enumerate() {
        println!(
            "{:indent$}[{i}] {} {}",
            "",
            l.via,
            l.host.as_deref().unwrap_or("(content)"),
            indent = l.depth * 2
        );
        println!(
            "{:indent$}    {}",
            "",
            defang(&truncate(&l.text, 160)),
            indent = l.depth * 2
        );
    }
    let x = sc_core::extract(
        &Observation {
            url,
            ts: 0,
            ..Default::default()
        },
        &rules,
    );
    println!(
        "\nscore {}  target {}",
        x.score,
        x.target_host.as_deref().unwrap_or("?")
    );
    for h in &x.hits {
        println!(
            "  {:<28} w{:<2} layer {}  {}",
            h.rule_id,
            h.weight,
            h.layer,
            defang(&h.matched)
        );
    }
    Ok(())
}

pub fn defang_urls(urls: &[String]) {
    for u in urls {
        println!("{}", defang(u));
    }
}
