//! `case fleet`: the admin's fleet merges and splits and the interaction
//! evidence that makes a fleet a swarm ([`sc_case::fleet`]), as the CLI
//! uses them.

pub use sc_case::fleet::*;

#[cfg(test)]
pub(crate) mod tests {
    use crate::case::test_support::*;
    use crate::case::{new_case, update};
    use crate::pinning::RulesText;
    use sc_core::{Observation, SwarmEdgeKind, analyze};

    /// Two runs with different inboxes, a day apart, opening every host
    /// with the same recon requests: two clusters, soft-linked.
    pub(crate) fn two_runs() -> Vec<Observation> {
        let mut obs = Vec::new();
        for (f, inbox) in [
            "0b6c1f0e-1111-4c2a-9a55-3f2e1d0c9b8a",
            "7d2e4a10-2222-4b3c-8a66-4e3f2a1b0c9d",
        ]
        .iter()
        .enumerate()
        {
            let t0 = 1_791_000_000 + f as i64 * 86_400;
            for (k, h) in ["a.example", "b.example", "c.example"].iter().enumerate() {
                let t = t0 + 60 * k as i64;
                for (j, p) in ["/robots.txt", "/.well-known/security.txt", "/.env"]
                    .iter()
                    .enumerate()
                {
                    obs.push(Observation {
                        id: format!("{f}{k}{j}"),
                        ts: t + j as i64,
                        url: format!("https://{h}{p}"),
                        ..Default::default()
                    });
                }
                obs.push(Observation {
                    id: format!("{f}{k}x"),
                    ts: t + 10,
                    url: format!("https://{h}/q?hook=https://webhook.site/{inbox}"),
                    ..Default::default()
                });
            }
        }
        obs
    }

    #[test]
    fn the_notice_names_a_swarm_only_once_interaction_is_recorded() {
        let root = scratch("fleet-notice");
        let rules = RulesText::load(None).unwrap();
        new_case(&root, "n-1", "N", two_runs(), &rules, "2026-10-12").unwrap();
        let a = analyze(two_runs(), &rules.rules);
        let keys: Vec<String> = a.clusters.iter().map(|c| c.key.clone()).collect();
        update(&root, "n-1", |c| {
            super::merge(c, &a, &keys, None, "d")?;
            Ok(())
        })
        .unwrap();
        let draft = |force| {
            let (p, _) =
                crate::notice::notice_draft(&root, "n-1", force, "2026-10-15", 1_791_000_000)
                    .unwrap();
            std::fs::read_to_string(p).unwrap()
        };
        assert!(!draft(false).contains("## Swarm"));
        update(&root, "n-1", |c| {
            let runs = vec!["C1#1".to_string(), "C2#1".to_string()];
            super::interaction(
                c,
                &a,
                "fleet-1",
                SwarmEdgeKind::SharedSink,
                &runs,
                "same paste",
                "d",
            )?;
            Ok(())
        })
        .unwrap();
        let md = draft(true);
        assert!(
            md.contains("## Swarm") && md.contains("shared sink"),
            "{md}"
        );
        assert!(!md.contains("same paste"), "{md}");
        cleanup(&root);
    }
}
