//! `review sample`: a stratified, seeded sample of the records the rules
//! left below suggestive, written as a review queue, to grow a reviewed
//! benign baseline.
//!
//! Records are grouped into strata by the `--stratify` keys (`source`,
//! `relay`: the first relay or carrier rule that fired, else `direct`,
//! `month`, `ts_kind`), and the sample is split over the strata in
//! proportion to their size (largest remainder), so the sample is
//! self-weighting: a rate measured on it estimates the rate over all the
//! records sampled from. Within a stratum the order is a hash of the seed
//! and the record id, so a store and a seed give the same sample on every
//! machine.
//!
//! The queue is NDJSON of the stored (already redacted) records. It stays
//! in the data directory; `review <queue> --all` labels it.

use anyhow::{Result, bail};
use sc_core::{Analysis, Observation, Tier};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(clap::Args)]
pub struct SampleArgs {
    /// A watch store directory or record files. Default: `<data>/store`.
    input: Vec<PathBuf>,
    /// Data directory (the watch's `--out`).
    #[arg(short, long, default_value = "data", env = "SWARMCHASE_DATA")]
    data: PathBuf,
    /// Comma-separated strata keys: source, relay, month, ts_kind.
    #[arg(long, default_value = "source,relay,month")]
    stratify: String,
    /// Records to sample.
    #[arg(long, default_value_t = 1200)]
    n: usize,
    #[arg(long, default_value_t = 0)]
    seed: u64,
    /// Sample records below this tier: suggestive (the noise tier),
    /// significant, or `all` for every tier.
    #[arg(long, default_value = "suggestive")]
    below: String,
    /// Where the queue goes. Default: `<data>/labels/baseline-queue-<seed>.ndjson`.
    #[arg(short, long)]
    out: Option<PathBuf>,
    #[arg(long)]
    rules: Option<PathBuf>,
}

const KEYS: [&str; 4] = ["source", "relay", "month", "ts_kind"];

/// The stratum of record `i` under `keys`, joined with ` · `.
pub fn stratum(a: &Analysis, i: usize, keys: &[&str]) -> String {
    let r = &a.results[i];
    let part = |k: &str| -> String {
        match k {
            "source" if r.obs.source.is_empty() => "unknown".into(),
            "source" => r.obs.source.clone(),
            "relay" => {
                let mut ids: Vec<&str> = r
                    .hits
                    .iter()
                    .map(|h| h.rule_id.as_str())
                    .filter(|id| id.starts_with("relay.") || id.starts_with("carrier."))
                    .collect();
                ids.sort_unstable();
                ids.first().map_or("direct".into(), |s| s.to_string())
            }
            "month" => (r.obs.ts > 0)
                .then(|| chrono::DateTime::<chrono::Utc>::from_timestamp(r.obs.ts, 0))
                .flatten()
                .map_or("unknown".into(), |d| d.format("%Y-%m").to_string()),
            "ts_kind" => {
                let k = if r.obs.ts_kind.is_unknown() {
                    sc_core::TsKind::of_source(&r.obs.source)
                } else {
                    r.obs.ts_kind
                };
                serde_json::to_value(k)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_string))
                    .unwrap_or_default()
            }
            _ => String::new(),
        }
    };
    keys.iter().map(|k| part(k)).collect::<Vec<_>>().join(" · ")
}

/// How many of `n` each stratum gets, in proportion to its size, by largest
/// remainder (ties to the earlier stratum). Every stratum gets at most its
/// size; with `n` at or above the total, everything.
pub fn allocate(sizes: &[usize], n: usize) -> Vec<usize> {
    let total: usize = sizes.iter().sum();
    if total == 0 {
        return vec![0; sizes.len()];
    }
    if n >= total {
        return sizes.to_vec();
    }
    let mut out: Vec<usize> = sizes.iter().map(|s| s * n / total).collect();
    let mut rem: Vec<(usize, usize)> = sizes
        .iter()
        .enumerate()
        .map(|(i, s)| (s * n % total, i))
        .collect();
    rem.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    let mut left = n - out.iter().sum::<usize>();
    for (_, i) in rem {
        if left == 0 {
            break;
        }
        if out[i] < sizes[i] {
            out[i] += 1;
            left -= 1;
        }
    }
    out
}

fn fnv(s: &str) -> u64 {
    s.bytes().fold(0xcbf2_9ce4_8422_2325, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

/// One stratum: its name, how many records it holds, how many were taken.
pub struct Stratum {
    pub name: String,
    pub size: usize,
    pub taken: usize,
}

/// The sample: indexes into `a.results`, and the strata.
pub fn sample(
    a: &Analysis,
    keys: &[&str],
    below: Option<Tier>,
    n: usize,
    seed: u64,
) -> (Vec<usize>, Vec<Stratum>) {
    let mut seen = std::collections::HashSet::new();
    let mut by: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (i, r) in a.results.iter().enumerate() {
        if below.is_none_or(|b| r.tier < b) && seen.insert(r.obs.id.as_str()) {
            by.entry(stratum(a, i, keys)).or_default().push(i);
        }
    }
    let sizes: Vec<usize> = by.values().map(Vec::len).collect();
    let quota = allocate(&sizes, n);
    let mut picked = Vec::new();
    let mut strata = Vec::new();
    for ((name, mut idx), q) in by.into_iter().zip(quota) {
        idx.sort_by_key(|&i| fnv(&format!("{seed}:{}", a.results[i].obs.id)));
        strata.push(Stratum {
            name,
            size: idx.len(),
            taken: q,
        });
        picked.extend(idx.into_iter().take(q));
    }
    // Interleave the strata in the queue, so a labeller who stops early has
    // labelled a spread, not one stratum.
    picked.sort_by_key(|&i| fnv(&format!("{seed}:queue:{}", a.results[i].obs.id)));
    (picked, strata)
}

pub fn run(args: SampleArgs) -> Result<()> {
    let keys: Vec<&str> = args
        .stratify
        .split(',')
        .map(str::trim)
        .filter(|k| !k.is_empty())
        .collect();
    if let Some(k) = keys.iter().find(|k| !KEYS.contains(k)) {
        bail!("--stratify: unknown key `{k}` ({})", KEYS.join(", "));
    }
    let below = match args.below.as_str() {
        "all" => None,
        t => match crate::input::parse_tier(t)? {
            Tier::Noise => bail!("--below noise would sample nothing"),
            t => Some(t),
        },
    };
    let rules = crate::pinning::RulesText::load(args.rules.as_deref())?;
    let obs: Vec<Observation> = if args.input.is_empty() {
        let dir = args.data.join("store");
        if !dir.is_dir() {
            bail!(
                "no watch store at {} (pass a store directory or record files, or set --data / SWARMCHASE_DATA)",
                dir.display()
            );
        }
        crate::store::load_store(&dir, 0)?
    } else {
        let (dirs, files): (Vec<PathBuf>, Vec<PathBuf>) =
            args.input.iter().cloned().partition(|p| p.is_dir());
        let mut out = Vec::new();
        for d in &dirs {
            out.extend(crate::store::load_store(d, 0)?);
        }
        if !files.is_empty() {
            out.extend(crate::input::read_inputs(&crate::input::InputArgs::files(
                files,
            ))?);
        }
        out
    };
    let a = sc_core::analyze(obs, &rules.rules);
    let (picked, strata) = sample(&a, &keys, below, args.n, args.seed);
    let pool: usize = strata.iter().map(|s| s.size).sum();
    println!(
        "{} records · {pool} {} · {} strata by {} · sampled {} with seed {}",
        a.total,
        below.map_or("in all tiers".into(), |t| format!("below {}", t.label())),
        strata.len(),
        keys.join(","),
        picked.len(),
        args.seed
    );
    for s in &strata {
        println!("  {:>6} of {:>7}  {}", s.taken, s.size, s.name);
    }
    let mut text = String::new();
    for &i in &picked {
        text.push_str(&serde_json::to_string(&a.results[i].obs)?);
        text.push('\n');
    }
    let out = args.out.unwrap_or_else(|| {
        args.data
            .join("labels")
            .join(format!("baseline-queue-{}.ndjson", args.seed))
    });
    if let Some(dir) = out.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(&out, text)?;
    println!(
        "queue: {} (keep it in the data directory). Label it with\n  swarmchase review {} --all --labeller <name>\nonce per labeller, then `swarmchase review --stats` for agreement and the baseline bound.",
        out.display(),
        out.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocation_is_proportional_and_exact() {
        assert_eq!(allocate(&[50, 30, 20], 10), [5, 3, 2]);
        assert_eq!(allocate(&[1, 1, 1], 2), [1, 1, 0]);
        assert_eq!(allocate(&[5, 2], 100), [5, 2]);
        assert_eq!(allocate(&[7, 3, 1], 5).iter().sum::<usize>(), 5);
        assert_eq!(allocate(&[], 5), Vec::<usize>::new());
    }

    #[test]
    fn sample_is_seeded_stratified_and_below_the_tier() {
        let o = |id: String, ts: i64, url: &str| Observation {
            id,
            source: "wayback".into(),
            ts,
            url: url.into(),
            ..Default::default()
        };
        let mut obs = Vec::new();
        for i in 0..30 {
            obs.push(o(
                format!("a{i}"),
                1_700_000_000,
                "https://www.example.com/",
            ));
            obs.push(o(
                format!("b{i}"),
                1_710_000_000,
                "https://www.example.org/x",
            ));
        }
        obs.push(o(
            "hit".into(),
            1_700_000_000,
            "https://t.example/?id=1%20OR%201=1",
        ));
        let a = sc_core::analyze(obs, &sc_core::Rules::default_rules());
        let below = Some(Tier::Suggestive);
        let (p, strata) = sample(&a, &["source", "month"], below, 10, 7);
        assert_eq!(p.len(), 10);
        assert_eq!(strata.len(), 2);
        assert_eq!(strata.iter().map(|s| s.taken).collect::<Vec<_>>(), [5, 5]);
        assert!(p.iter().all(|&i| a.results[i].obs.id != "hit"));
        assert_eq!(p, sample(&a, &["source", "month"], below, 10, 7).0);
        assert_ne!(p, sample(&a, &["source", "month"], below, 10, 8).0);
        let (all, _) = sample(&a, &["source"], None, 100, 7);
        assert_eq!(all.len(), 61);
    }
}
