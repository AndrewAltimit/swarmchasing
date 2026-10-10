//! `swarmchase`: find, link and report misaligned agent activity in public records.

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use sc_collect::{CdxQuery, Client};
use sc_core::{
    Analysis, Audience, FieldMap, Format, Observation, ReportOptions, Rules, Tier, analyze, defang,
    fmt_ts, parse_input, parse_security_txt, render_markdown, unwrap_layers,
};
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;
use watch::{read_json, to_ndjson, write_json};

mod bundle;
mod case;
mod contacts;
mod eval;
mod evidence;
mod health;
mod notice;
mod review;
mod stix;
mod watch;

#[derive(Parser)]
#[command(name = "swarmchase", version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Args, Clone)]
struct InputArgs {
    /// Input file(s): NDJSON, JSON, CDX JSON, or one URL per line. `-` for stdin.
    #[arg(required = true)]
    input: Vec<PathBuf>,
    /// auto | ndjson | json | lines | access_log
    #[arg(long, default_value = "auto")]
    format: Format,
    /// Field mapping for JSON input, e.g. `ts=submitted_at,url=page.url`.
    #[arg(long)]
    map: Option<String>,
    /// Rules file (defaults to the bundled rules/default.toml).
    #[arg(long)]
    rules: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Cmd {
    /// List flagged records, strongest first.
    Scan {
        #[command(flatten)]
        input: InputArgs,
        /// Minimum tier to show: noise | suggestive | significant
        #[arg(long, default_value = "suggestive")]
        min_tier: String,
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Full analysis (records, clusters, timing) as JSON.
    Analyze {
        #[command(flatten)]
        input: InputArgs,
        #[arg(short, long)]
        out: Option<PathBuf>,
        /// Only include flagged records in the output.
        #[arg(long)]
        flagged_only: bool,
    },
    /// Summarise clusters.
    Clusters {
        #[command(flatten)]
        input: InputArgs,
    },
    /// Flagged activity per target host: hits, first and last seen, payloads,
    /// clusters, and whether the hits are ongoing or historical.
    Endpoints {
        #[command(flatten)]
        input: InputArgs,
        /// Minimum tier to count: noise | suggestive | significant
        #[arg(long, default_value = "suggestive")]
        min_tier: String,
        /// Hits within this many days of the newest record count as ongoing.
        #[arg(long, default_value_t = 7)]
        active_days: i64,
        /// Measure "ongoing" from now instead of from the newest record.
        #[arg(long)]
        from_now: bool,
        #[arg(long)]
        json: bool,
    },
    /// Draft a disclosure report (Markdown).
    Report {
        #[command(flatten)]
        input: InputArgs,
        /// provider | affected | internal | public
        #[arg(long, default_value = "internal")]
        audience: Audience,
        /// Limit to one cluster (e.g. C1).
        #[arg(long)]
        cluster: Option<String>,
        #[arg(long)]
        reporter: Option<String>,
        /// Weakest evidence that may name a developer outside case notes:
        /// hosting_asn | shared_identifiers | provider_infrastructure |
        /// provider_confirmed. Self-identification alone never names one.
        #[arg(long, default_value = "shared_identifiers")]
        min_named: sc_core::Evidence,
        /// JSON array of claims established by case work, e.g.
        /// [{"party":"Example AI","role":"developer","evidence":"provider_confirmed","details":["…"]}]
        #[arg(long)]
        claims: Option<PathBuf>,
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// Show the relay/carrier layers inside a URL and the rules it triggers.
    Unwrap { url: String },
    /// Defang URLs for safe sharing.
    Defang { urls: Vec<String> },
    /// Collect index records from public archives (never opens captures).
    Collect {
        #[command(subcommand)]
        source: CollectSource,
    },
    /// Certificate Transparency lookup via crt.sh.
    Certs {
        /// e.g. `%.example.com`
        query: String,
        #[arg(long)]
        json: bool,
    },
    /// Find the security contact for an affected domain (RFC 9116 security.txt).
    Contact { domain: String },
    /// Collect new records from every source in a watchlist, analyse the recent
    /// window, and write a digest of what changed since the last run.
    Watch {
        /// Watchlist TOML (see watchlist.toml).
        #[arg(default_value = "watchlist.toml")]
        watchlist: PathBuf,
        /// Data directory: state, record store, and per-run output.
        #[arg(short, long, default_value = "data", env = "SWARMCHASE_DATA")]
        out: PathBuf,
        #[arg(long)]
        rules: Option<PathBuf>,
        /// Committed notices, for the case status proposals in the digest.
        #[arg(long, default_value = "notices")]
        notices: PathBuf,
    },
    /// Precision and recall of the rules on labelled records. Labels come from
    /// `--labels` (NDJSON or CSV, including Transluce's reports.csv) or, without
    /// it, from a `label` field on each input record. With floors set, exits
    /// non-zero when a floor is not met.
    Eval {
        #[command(flatten)]
        input: InputArgs,
        #[arg(long)]
        labels: Vec<PathBuf>,
        #[command(flatten)]
        floors: eval::Floors,
        /// Also write the full result as JSON.
        #[arg(long)]
        json: Option<PathBuf>,
        /// How many false positives to list.
        #[arg(long, default_value_t = 20)]
        show_fp: usize,
    },
    /// Label watch leads as agent, benign or unsure, one record at a time.
    /// Labels go to `<data>/labels/reviewed.ndjson`, which `swarmchase eval`
    /// reads directly. Progress is saved after every answer.
    Review {
        /// Records to review. Default: the watch store's last `--days` days.
        input: Vec<PathBuf>,
        /// Data directory (the watch's `--out`).
        #[arg(short, long, default_value = "data", env = "SWARMCHASE_DATA")]
        data: PathBuf,
        #[arg(long, default_value_t = 30)]
        days: i64,
        /// Queue records at or above this tier: suggestive | significant
        #[arg(long, default_value = "suggestive")]
        min_tier: String,
        /// Also queue this many unflagged records, a stable pseudo-random
        /// sample, to grow the benign baseline and catch misses.
        #[arg(long, default_value_t = 0)]
        unflagged: usize,
        /// Print the queue and exit.
        #[arg(long)]
        list: bool,
        /// Print counts of reviewed records and disagreements, and exit.
        #[arg(long)]
        stats: bool,
        #[arg(long)]
        rules: Option<PathBuf>,
    },
    /// Case files: open, classify endpoints, record attribution, draft reports.
    Case(case::CaseArgs),
    /// Public notices: add a reviewed draft, append updates, lint, build the site files.
    Notice(notice::NoticeArgs),
    /// Validate a rules file, or print the bundled rules.
    Rules {
        file: Option<PathBuf>,
        #[arg(long)]
        dump: bool,
    },
}

#[derive(Subcommand)]
enum CollectSource {
    /// Wayback Machine CDX index.
    Wayback(CollectArgs),
    /// Arquivo.pt CDX index.
    Arquivo(CollectArgs),
    /// urlquery.net report search (needs URLQUERY_APIKEY). PATTERN is a urlquery
    /// search query; --from/--to are rounded to whole days.
    Urlquery(CollectArgs),
    /// Fetch urlquery.net reports by ID (needs URLQUERY_APIKEY), e.g. to turn a
    /// labelled report list such as Transluce's reports.csv into records for
    /// `swarmchase eval`. Appends to --out and skips IDs already in it, so an
    /// interrupted fetch continues where it stopped.
    UrlqueryReports {
        /// Labels file (CSV or NDJSON with ids) or a plain list of report IDs.
        ids: PathBuf,
        /// Output NDJSON (appended to).
        #[arg(short, long)]
        out: PathBuf,
        /// Fetch at most this many agent-labelled reports, evenly spaced over
        /// the list. Benign-labelled reports (the controls) are always fetched.
        #[arg(long)]
        sample: Option<usize>,
    },
}

#[derive(Args)]
struct CollectArgs {
    /// CDX URL pattern, e.g. `r.jina.ai/*` (for urlquery, a search query)
    pattern: String,
    /// yyyyMMdd[hhmmss]
    #[arg(long)]
    from: Option<String>,
    #[arg(long)]
    to: Option<String>,
    #[arg(long, default_value_t = 5000)]
    limit: usize,
    /// exact | prefix | host | domain
    #[arg(long)]
    match_type: Option<String>,
    /// Records per request (Wayback pages through the index).
    #[arg(long, default_value_t = 1000)]
    page_size: usize,
    /// Output NDJSON file (default stdout).
    #[arg(short, long)]
    out: Option<PathBuf>,
    /// Continue an interrupted Wayback pull into `--out` (progress is kept in `<out>.resume.json`).
    #[arg(long, requires = "out")]
    resume: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Scan {
            input,
            min_tier,
            limit,
        } => {
            let min = parse_tier(&min_tier)?;
            let a = run_analysis(&input)?;
            print_summary(&a);
            let mut rows: Vec<_> = a
                .results
                .iter()
                .filter(|r| r.score > 0 && r.tier >= min)
                .collect();
            rows.sort_by(|x, y| y.score.cmp(&x.score).then(x.obs.ts.cmp(&y.obs.ts)));
            println!();
            for r in rows.iter().take(limit) {
                let rules: Vec<&str> = r.hits.iter().map(|h| h.rule_id.as_str()).collect();
                println!(
                    "[{:<11}] {:>3}  {}  {}  {}",
                    r.tier.label(),
                    r.score,
                    fmt_ts(r.obs.ts),
                    r.cluster
                        .map(|c| a.clusters[c].id.clone())
                        .unwrap_or_else(|| "-".into()),
                    defang(&truncate(&r.obs.url, 120))
                );
                println!("{:>18}{}", "", rules.join(" "));
            }
            if rows.len() > limit {
                println!("… {} more (use --limit)", rows.len() - limit);
            }
        }
        Cmd::Analyze {
            input,
            out,
            flagged_only,
        } => {
            let mut a = run_analysis(&input)?;
            if flagged_only {
                // Keep cluster member indices valid by remapping.
                let keep: Vec<usize> = (0..a.results.len())
                    .filter(|&i| a.results[i].score > 0)
                    .collect();
                let mut remap = vec![usize::MAX; a.results.len()];
                for (n, &i) in keep.iter().enumerate() {
                    remap[i] = n;
                }
                for c in &mut a.clusters {
                    c.members = c.members.iter().map(|&m| remap[m]).collect();
                }
                a.results = keep.into_iter().map(|i| a.results[i].clone()).collect();
            }
            write_out(out.as_deref(), &serde_json::to_string_pretty(&a)?)?;
        }
        Cmd::Clusters { input } => {
            let a = run_analysis(&input)?;
            print_summary(&a);
            println!();
            for c in &a.clusters {
                let hosts: Vec<String> = top(&c.target_hosts, 3);
                let rules: Vec<String> = top(&c.rules, 6);
                println!(
                    "{:<4} [{:<11}] {:>5} records  {} runs  {} → {}",
                    c.id,
                    c.tier.label(),
                    c.members.len(),
                    c.runs.len(),
                    fmt_ts(c.start),
                    fmt_ts(c.end)
                );
                println!("     targets: {}", hosts.join(", "));
                println!("     rules:   {}", rules.join(", "));
                if let Some(g) = c.timing.median_gap_secs {
                    println!(
                        "     median gap {g:.0}s, {} bursts, {} pauses",
                        c.timing.bursts.len(),
                        c.timing.pauses.len()
                    );
                }
            }
        }
        Cmd::Endpoints {
            input,
            min_tier,
            active_days,
            from_now,
            json,
        } => {
            let a = run_analysis(&input)?;
            let opts = sc_core::EndpointOptions {
                min_tier: parse_tier(&min_tier)?,
                now: if from_now {
                    chrono::Utc::now().timestamp()
                } else {
                    0
                },
                active_days,
            };
            let views = sc_core::endpoints(&a, &opts);
            if json {
                println!("{}", serde_json::to_string_pretty(&views)?);
                return Ok(());
            }
            print_summary(&a);
            println!(
                "
{} endpoint(s) at {} or above
",
                views.len(),
                opts.min_tier.label()
            );
            for v in &views {
                println!(
                    "{:<40} [{:<11}] {:>4} hits / {:<4} {:<10} {} → {}",
                    defang(&v.host),
                    v.max_tier.label(),
                    v.hits,
                    v.records,
                    v.activity.label(),
                    fmt_ts(v.first_seen),
                    fmt_ts(v.last_seen)
                );
                if v.payloads {
                    let p: Vec<&str> = v.payload_rules.keys().map(String::as_str).collect();
                    println!("{:>6}payloads: {}", "", p.join(", "));
                }
                if !v.clusters.is_empty() {
                    println!("{:>6}clusters: {}", "", v.clusters.join(", "));
                }
            }
        }
        Cmd::Report {
            input,
            audience,
            cluster,
            reporter,
            min_named,
            claims,
            out,
        } => {
            if min_named < sc_core::Evidence::FLOOR {
                eprintln!(
                    "note: self-identification alone never names a developer; using {}",
                    sc_core::Evidence::FLOOR.id()
                );
            }
            let claims: Vec<sc_core::Claim> = match &claims {
                Some(p) => serde_json::from_str(
                    &std::fs::read_to_string(p)
                        .with_context(|| format!("reading {}", p.display()))?,
                )
                .with_context(|| format!("parsing {}", p.display()))?,
                None => Vec::new(),
            };
            let a = run_analysis(&input)?;
            if let Some(id) = &cluster
                && !a.clusters.iter().any(|c| c.id.eq_ignore_ascii_case(id))
            {
                bail!("no cluster `{id}` (run `swarmchase clusters` first)");
            }
            let opts = ReportOptions {
                audience,
                cluster,
                reporter,
                generated: Some(chrono::Utc::now().format("%Y-%m-%d").to_string()),
                min_named,
                claims,
                ..Default::default()
            };
            if audience == Audience::Public {
                let n = sc_core::render_notice(&a, &opts);
                for w in &n.withheld {
                    eprintln!("withheld: {w}");
                }
                for f in &n.flags {
                    eprintln!("decide:   {f}");
                }
                for l in sc_core::notice::lint_public(&n.markdown, &Rules::default_rules())
                    .iter()
                    .chain(&n.leaks)
                {
                    eprintln!("LEAK:     {l}");
                }
                write_out(out.as_deref(), &n.markdown)?;
            } else {
                write_out(out.as_deref(), &render_markdown(&a, &opts))?;
            }
        }
        Cmd::Unwrap { url } => {
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
        }
        Cmd::Defang { urls } => {
            for u in urls {
                println!("{}", defang(&u));
            }
        }
        Cmd::Collect {
            source: CollectSource::UrlqueryReports { ids, out, sample },
        } => fetch_urlquery_reports(&ids, &out, sample)?,
        Cmd::Collect { source } => {
            let client = Client::new(Duration::from_secs(2))?;
            let (args, kind) = match source {
                CollectSource::UrlqueryReports { .. } => unreachable!("handled above"),
                CollectSource::Wayback(a) => (a, "wayback"),
                CollectSource::Arquivo(a) => (a, "arquivo"),
                CollectSource::Urlquery(a) => (a, "urlquery"),
            };
            let is_wayback = kind == "wayback";
            let q = CdxQuery {
                pattern: args.pattern,
                from: args.from,
                to: args.to,
                limit: args.limit,
                match_type: args.match_type,
                collapse_digest: false,
                page_size: args.page_size,
            };
            match (&args.out, is_wayback) {
                (Some(out), true) => collect_wayback_to_file(&client, &q, out, args.resume)?,
                _ => {
                    if args.resume {
                        bail!("--resume only applies to wayback");
                    }
                    let obs = match kind {
                        "wayback" => client.wayback_cdx(&q)?,
                        "arquivo" => client.arquivo_cdx(&q)?,
                        _ => client.urlquery(&urlquery_key()?, &q)?,
                    };
                    eprintln!("{} records", obs.len());
                    write_out(args.out.as_deref(), &to_ndjson(&obs)?)?;
                }
            }
        }
        Cmd::Certs { query, json } => {
            let client = Client::new(Duration::from_secs(2))?;
            let recs = client.crtsh(&query)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&recs)?);
            } else {
                for r in recs {
                    println!(
                        "{}  {:<10}  {}  [{}]",
                        r.entry_timestamp,
                        r.id,
                        r.name_value.replace('\n', ", "),
                        r.issuer_name
                    );
                }
            }
        }
        Cmd::Contact { domain } => {
            let client = Client::new(Duration::from_millis(500))?;
            match client.security_txt(&domain) {
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
        }
        Cmd::Watch {
            watchlist,
            out,
            rules,
            notices,
        } => watch::run(&watchlist, &out, &notices, &load_rules(rules.as_deref())?)?,
        Cmd::Eval {
            input,
            labels,
            floors,
            json,
            show_fp,
        } => {
            let l = eval::load_labels(&labels, &input.input)?;
            let a = run_analysis(&input)?;
            eval::run(&a, &l, &floors, json.as_deref(), show_fp)?;
        }
        Cmd::Case(args) => case::run(args)?,
        Cmd::Notice(args) => notice::run(args)?,
        Cmd::Review {
            input,
            data,
            days,
            min_tier,
            unflagged,
            list,
            stats,
            rules,
        } => {
            let mut store = review::ReviewStore::open(review::ReviewStore::path_in(&data))?;
            if stats {
                return review::stats(&store, &mut std::io::stdout());
            }
            let min = review::check_min_tier(parse_tier(&min_tier)?)?;
            let rules = case::RulesText::load(rules.as_deref())?;
            let from = if input.is_empty() {
                format!("the watch store's last {days} days")
            } else {
                let files: Vec<String> = input.iter().map(|p| p.display().to_string()).collect();
                files.join(", ")
            };
            let obs = if input.is_empty() {
                let dir = data.join("store");
                if !dir.is_dir() {
                    bail!(
                        "no watch store at {} (pass record files, or set --data / SWARMCHASE_DATA)",
                        dir.display()
                    );
                }
                watch::load_store(&dir, chrono::Utc::now().timestamp() - days * 86_400)?
            } else {
                read_inputs(&InputArgs {
                    input,
                    format: Format::Auto,
                    map: None,
                    rules: None,
                })?
            };
            let a = analyze(obs, &rules.rules);
            let done = store.entries.keys().cloned().collect();
            let items = review::queue(&a, &done, min, unflagged);
            println!(
                "{} records · {} reviewed before · {} in the queue ({} flagged, {} unflagged sample)",
                a.total,
                store.entries.len(),
                items.len(),
                items
                    .iter()
                    .filter(|i| i.class == review::CLASS_FLAGGED)
                    .count(),
                items
                    .iter()
                    .filter(|i| i.class == review::CLASS_SAMPLE)
                    .count(),
            );
            if list {
                for it in &items {
                    let r = &a.results[it.idx];
                    println!(
                        "{:<11} {:>3}  {}  {}",
                        r.tier.label(),
                        r.score,
                        r.obs.id,
                        defang(&truncate(&r.obs.url, 100))
                    );
                }
                return Ok(());
            }
            if items.is_empty() {
                return Ok(());
            }
            let stdin = std::io::stdin();
            let t = review::session(
                &a,
                &items,
                &mut store,
                stdin.lock(),
                &mut std::io::stdout(),
                &chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                &review::CaseSink {
                    root: data.join("cases"),
                    rules,
                    from,
                    today: chrono::Utc::now().format("%Y-%m-%d").to_string(),
                },
            )?;
            let labelled: Vec<String> =
                t.labelled.iter().map(|(k, v)| format!("{v} {k}")).collect();
            println!(
                "\nlabelled {} · skipped {}{}",
                if labelled.is_empty() {
                    "none".into()
                } else {
                    labelled.join(", ")
                },
                t.skipped,
                if t.quit {
                    " · stopped early, run again to continue"
                } else {
                    ""
                }
            );
        }
        Cmd::Rules { file, dump } => {
            if dump {
                print!("{}", sc_core::DEFAULT_RULES);
                return Ok(());
            }
            let text = match &file {
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
        }
    }
    Ok(())
}

fn urlquery_key() -> Result<String> {
    std::env::var(watch::URLQUERY_KEY_ENV)
        .ok()
        .map(|k| k.trim().to_string())
        .filter(|k| !k.is_empty())
        .with_context(|| format!("set {} to a urlquery.net API key", watch::URLQUERY_KEY_ENV))
}

/// Report IDs to fetch: every benign-labelled one, plus agent-labelled ones
/// (all, or `sample` of them evenly spaced). Plain lists count as agent.
fn report_ids(text: &str, sample: Option<usize>) -> Vec<String> {
    let labels = sc_core::parse_labels(text);
    let (mut agents, mut benign): (Vec<String>, Vec<String>) = if labels.labels.is_empty() {
        let ids = text
            .lines()
            .map(|l| l.trim().rsplit('/').next().unwrap_or("").to_string())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(|l| {
                if l.contains(':') {
                    l
                } else {
                    format!("urlquery:{l}")
                }
            })
            .collect();
        (ids, Vec::new())
    } else {
        let mut a = Vec::new();
        let mut b = Vec::new();
        for (id, l) in labels.labels {
            if l.label == sc_core::Label::Agent {
                a.push(id);
            } else {
                b.push(id);
            }
        }
        (a, b)
    };
    agents.sort();
    benign.sort();
    if let Some(n) = sample.filter(|&n| n < agents.len()) {
        let step = agents.len() as f64 / n as f64;
        agents = (0..n)
            .map(|i| agents[(i as f64 * step) as usize].clone())
            .collect();
    }
    benign.extend(agents);
    benign
}

fn fetch_urlquery_reports(ids_path: &Path, out: &Path, sample: Option<usize>) -> Result<()> {
    let text = std::fs::read_to_string(ids_path)
        .with_context(|| format!("reading {}", ids_path.display()))?;
    let ids = report_ids(&text, sample);
    let have: std::collections::HashSet<String> = std::fs::read_to_string(out)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter_map(|v| v.get("id").and_then(|x| x.as_str()).map(str::to_string))
        .collect();
    let todo: Vec<&String> = ids.iter().filter(|i| !have.contains(*i)).collect();
    eprintln!(
        "{} report IDs selected, {} already in {}, {} to fetch",
        ids.len(),
        ids.len() - todo.len(),
        out.display(),
        todo.len()
    );
    let key = urlquery_key()?;
    if let Some(dir) = out.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)?;
    }
    let client = Client::new(Duration::from_secs(2))?;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(out)?;
    let (mut ok, mut failed) = (0usize, 0usize);
    for (n, id) in todo.iter().enumerate() {
        match client.urlquery_report(&key, id) {
            Ok(o) => {
                use std::io::Write as _;
                writeln!(f, "{}", serde_json::to_string(&o)?)?;
                ok += 1;
            }
            Err(e) => {
                eprintln!("  {e:#}");
                failed += 1;
            }
        }
        if (n + 1) % 50 == 0 {
            eprintln!("  {}/{} ({ok} ok, {failed} failed)", n + 1, todo.len());
        }
    }
    eprintln!(
        "fetched {ok}, failed {failed}; records in {}",
        out.display()
    );
    Ok(())
}

fn parse_tier(s: &str) -> Result<Tier> {
    Ok(match s {
        "noise" => Tier::Noise,
        "suggestive" => Tier::Suggestive,
        "significant" => Tier::Significant,
        t => bail!("unknown tier `{t}` (noise|suggestive|significant)"),
    })
}

fn load_rules(p: Option<&Path>) -> Result<Rules> {
    match p {
        Some(p) => Rules::from_toml(
            &std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?,
        )
        .map_err(anyhow::Error::msg),
        None => Ok(Rules::default_rules()),
    }
}

fn read_inputs(args: &InputArgs) -> Result<Vec<Observation>> {
    let map = match &args.map {
        Some(m) => FieldMap::parse(m).map_err(anyhow::Error::msg)?,
        None => FieldMap::default(),
    };
    let mut all = Vec::new();
    for p in &args.input {
        let text = if p.as_os_str() == "-" {
            let mut s = String::new();
            std::io::stdin().read_to_string(&mut s)?;
            s
        } else {
            std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?
        };
        let parsed = parse_input(&text, args.format, &map);
        if parsed.redacted > 0 {
            eprintln!(
                "{}: redacted {} secret value(s)",
                p.display(),
                parsed.redacted
            );
        }
        for w in parsed.warnings.iter().take(5) {
            eprintln!("warning: {}: {w}", p.display());
        }
        if parsed.warnings.len() > 5 {
            eprintln!(
                "warning: {}: {} more",
                p.display(),
                parsed.warnings.len() - 5
            );
        }
        all.extend(parsed.observations);
    }
    Ok(all)
}

fn run_analysis(args: &InputArgs) -> Result<Analysis> {
    let rules = load_rules(args.rules.as_deref())?;
    Ok(analyze(read_inputs(args)?, &rules))
}

fn print_summary(a: &Analysis) {
    let t = |x| a.tier_counts.get(&x).copied().unwrap_or(0);
    println!(
        "{} records · {} flagged · {} significant · {} suggestive · {} clusters (max {} concurrent runs)",
        a.total,
        a.flagged,
        t(Tier::Significant),
        t(Tier::Suggestive),
        a.clusters.len(),
        a.max_concurrent_clusters
    );
    if a.timing.count > 0 {
        println!(
            "window {} → {}",
            fmt_ts(a.timing.start),
            fmt_ts(a.timing.end)
        );
    }
    if a.date_tags.consistent && a.date_tags.ahead > 0 {
        println!(
            "date tags ahead of UTC in {}/{} records → operator clock UTC{:+}..UTC{:+}",
            a.date_tags.ahead,
            a.date_tags.tagged,
            a.date_tags.min_hours.unwrap_or(0.0),
            a.date_tags.max_hours.unwrap_or(0.0)
        );
    }
    for s in a.asns.iter().take(5) {
        println!(
            "AS{} {} — {} flagged",
            s.asn,
            s.org.as_deref().unwrap_or("(unknown)"),
            s.count
        );
    }
}

fn top<K: ToString>(m: &std::collections::BTreeMap<K, usize>, n: usize) -> Vec<String> {
    let mut v: Vec<(String, usize)> = m.iter().map(|(k, c)| (k.to_string(), *c)).collect();
    v.sort_by_key(|x| std::cmp::Reverse(x.1));
    v.into_iter()
        .take(n)
        .map(|(k, c)| format!("{k}×{c}"))
        .collect()
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.into()
    } else {
        format!("{}…", s.chars().take(n).collect::<String>())
    }
}

fn write_out(path: Option<&Path>, text: &str) -> Result<()> {
    match path {
        Some(p) => {
            if let Some(dir) = p.parent().filter(|d| !d.as_os_str().is_empty()) {
                std::fs::create_dir_all(dir)?;
            }
            std::fs::write(p, text).with_context(|| format!("writing {}", p.display()))?;
            eprintln!("wrote {}", p.display());
        }
        None => print!("{text}"),
    }
    Ok(())
}

/// Progress of a long Wayback pull, saved after every page.
#[derive(Serialize, Deserialize)]
struct ResumeState {
    query: CdxQuery,
    resume_key: String,
    written: usize,
}

fn collect_wayback_to_file(client: &Client, q: &CdxQuery, out: &Path, resume: bool) -> Result<()> {
    let state_path = PathBuf::from(format!("{}.resume.json", out.display()));
    let saved: Option<ResumeState> = read_json(&state_path)?;
    let (mut key, mut written) = match saved {
        Some(s) if resume => {
            if s.query.pattern != q.pattern
                || s.query.from != q.from
                || s.query.to != q.to
                || s.query.match_type != q.match_type
            {
                bail!(
                    "{} was saved for a different query (pattern {}, from {:?}, to {:?}); rerun with the same arguments or drop --resume",
                    state_path.display(),
                    s.query.pattern,
                    s.query.from,
                    s.query.to
                );
            }
            eprintln!("resuming after {} records", s.written);
            (Some(s.resume_key), s.written)
        }
        Some(_) => {
            eprintln!(
                "note: starting over; pass --resume to continue the saved pull in {}",
                state_path.display()
            );
            (None, 0)
        }
        None if resume => bail!("nothing to resume: {} not found", state_path.display()),
        None => (None, 0),
    };
    if let Some(dir) = out.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)?;
    }
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .append(key.is_some())
        .truncate(key.is_none())
        .open(out)
        .with_context(|| format!("opening {}", out.display()))?;
    while written < q.limit {
        let size = (q.limit - written).min(q.page_size.max(1));
        let page = client.wayback_cdx_page(q, size, key.as_deref())?;
        std::io::Write::write_all(&mut f, to_ndjson(&page.records)?.as_bytes())?;
        written += page.records.len();
        key = page.resume_key;
        eprintln!("{written} records");
        match &key {
            Some(k) => write_json(
                &state_path,
                &ResumeState {
                    query: q.clone(),
                    resume_key: k.clone(),
                    written,
                },
            )?,
            None => break,
        }
    }
    if key.is_none() {
        let _ = std::fs::remove_file(&state_path);
        eprintln!("done: {written} records in {}", out.display());
    } else {
        eprintln!(
            "stopped at --limit {}; more records remain (continue with --resume and a higher --limit)",
            q.limit
        );
    }
    Ok(())
}
