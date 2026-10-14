//! Labelled records from a scenario.
//!
//! Each actor becomes one or more runs: a client (user agent, network,
//! address), a start, a pace and a list of target hosts. Each record copies
//! a [`Template`] from the palette and changes only its target host, its
//! linking identifiers (per run, or per swarm for a shared inbox) and, for a
//! retry, a cache-busting parameter. A fleet's harness adds its own
//! parameters (a step counter and a per-request trace) to every request, as
//! one request builder does; that, not the palette records, is what sets its
//! scaffold apart from unrelated agents copying the same records. An
//! escalating agent sends a relay record's target directly first, then the
//! record as written. The ground truth goes on each record as
//! the evaluation set's label fields, so the output is also an ordinary
//! labelled file for `swarmchase eval` and `swarmchase sim score`.

use crate::palette::{Palette, Template, Use};
use crate::rng::Rng;
use crate::scenario::{Actor, Basis, Kind, Mode, Pace, Prose, Scenario, TagScope};
use sc_core::{LinkFeature, Observation, TsKind};
use serde_json::{Value, json};
use std::collections::BTreeMap;

/// User agents for agent clients: scripted and headless defaults.
const AGENT_UAS: &[&str] = &[
    "python-httpx/0.27.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/124.0.0.0 Safari/537.36",
    "node-fetch/1.0 (+https://github.com/bitinn/node-fetch)",
    "axios/1.6.8",
    "Go-http-client/2.0",
    "python-requests/2.31.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
];

/// User agents for people's browsers.
const BROWSER_UAS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
];

/// User agents of benign look-alikes: an uptime service, an internet-wide
/// scanner, link-preview bots, feed readers.
const MONITOR_UA: &str = "Mozilla/5.0 (compatible; UptimeRobot/2.0; http://www.uptimerobot.com/)";
const SCANNER_UA: &str = "Mozilla/5.0 (compatible; survey-scanner/2.1; +https://scanner.example/)";
const PREVIEW_UAS: &[&str] = &[
    "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)",
    "Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)",
    "Twitterbot/1.0",
    "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
    "LinkedInBot/1.0 (compatible; Mozilla/5.0; Apache-HttpClient +http://www.linkedin.com)",
    "TelegramBot (like TwitterBot)",
];
/// One link checker's scripted client, the same in every repository.
const LINK_CHECKER_UA: &str = "python-requests/2.31.0";
const SEO_UAS: &[&str] = &[
    "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)",
    "Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)",
    "Mozilla/5.0 (compatible; MJ12bot/v1.4.8; http://mj12bot.com/)",
    "Mozilla/5.0 (compatible; DotBot/1.2; +https://opensiteexplorer.org/dotbot)",
];
/// Addresses an SEO vendor shards its crawl over.
const SEO_SHARDS: usize = 4;
const FEED_UAS: &[&str] = &[
    "Feedly/1.0 (+http://www.feedly.com/fetcher.html; 12 subscribers)",
    "Mozilla/5.0 (compatible; Inoreader/1.0; https://www.inoreader.com)",
    "NewsBlur Feed Fetcher - 8 subscribers",
    "FreshRSS/1.24.1 (Linux; https://freshrss.org)",
    "Miniflux/2.1.3 (https://miniflux.app)",
];

/// Hosting networks agents run from, and access networks people use.
const CLOUD_ASNS: &[u32] = &[16509, 14061, 24940, 396982, 8075, 63949, 14618];
const ACCESS_ASNS: &[u32] = &[7922, 3320, 2856, 701, 3215, 6830];

/// Documentation address blocks (RFC 5737), so no generated address is real.
const NETS: &[&str] = &["192.0.2", "198.51.100", "203.0.113"];

/// Parameter names a harness's request builder adds: none is a linking
/// parameter, and no palette record carries one.
const HARNESS_PARAMS: &[&str] = &[
    "step", "trace", "attempt", "hop", "turn", "plan", "ctx", "via", "fmt", "lane", "stage",
    "phase",
];

/// The relay prefix an escalating agent drops for its first, direct try.
const RELAY_PREFIX: &str = "https://r.jina.ai/";

/// A fleet's request shape: the palette records it sends and the
/// parameters its harness adds.
#[derive(Debug, Clone, Default)]
struct Shape {
    templates: Vec<Template>,
    harness: Vec<String>,
}

#[derive(Debug, Clone)]
struct Client {
    ua: String,
    asn: u32,
    ip: String,
}

/// Who a run is, for the truth fields.
#[derive(Debug, Clone)]
struct Truth {
    label: Option<&'static str>,
    actor: &'static str,
    class: String,
    run: String,
    swarm: Option<String>,
    fleet: Option<String>,
}

/// One run to emit.
#[derive(Debug, Clone)]
struct RunSpec {
    truth: Truth,
    client: Client,
    start: i64,
    pace: Pace,
    /// Gaps to use instead of drawing (synchronised runs).
    gaps: Option<Vec<i64>>,
    /// One host per record, in order.
    hosts: Vec<String>,
    /// One use per record.
    uses: Vec<Use>,
    /// Templates to draw from instead of the whole palette (a scaffold).
    fixed: Option<Vec<Template>>,
    /// Parameters a harness adds to every request: a step counter first,
    /// then per-request trace values.
    harness: Vec<String>,
    /// Shapes taken in turn, record by record, instead of `fixed` and
    /// `harness` (a mimic of several fleets).
    shapes: Vec<Shape>,
    /// Identifier scope for this run's tags and inboxes.
    scope: String,
    /// Identifier scope for callback inboxes, when shared.
    sink_scope: Option<String>,
    tag: bool,
    retry: f64,
    /// An artifact URL each request names as where its notes go (a writer).
    writes: Option<String>,
    /// An artifact URL the run fetches first (a reader of another's notes).
    fetches: Option<String>,
    /// Change the request after an error (models and people do; a scanner
    /// working through its list does not).
    adapt: bool,
    /// The scope of the palette subset this run draws from, and its share.
    habits: Option<(String, f64)>,
    /// The scope of the prompt templates the run writes its prose from,
    /// when it writes prose.
    prose: Option<String>,
}

/// The palette subset an actor's runs draw from under `key`, when it does
/// not use the whole palette.
fn habits(a: &Actor, key: String) -> Option<(String, f64)> {
    (a.palette_share < 1.0).then(|| (key, a.palette_share.max(0.0)))
}

/// The scope of the prompt templates run `k` of actor `i` writes from, when
/// it writes prose: its own, its operator's (`operator`, when it has one) or
/// the actor's.
fn prose_scope(a: &Actor, i: usize, k: usize, operator: Option<&str>) -> Option<String> {
    let own = || format!("{i}:{k}");
    a.prose.map(|p| match p {
        Prose::Own => own(),
        Prose::Operator => operator.map_or_else(own, str::to_string),
        Prose::Shared => format!("{i}"),
    })
}

struct Gen<'a> {
    scenario: &'a Scenario,
    seed: u64,
    palette: &'a Palette,
    rng: Rng,
    t0: i64,
    out: Vec<Value>,
    /// Each fleet's shapes (before and after an upgrade), by actor index.
    shapes: BTreeMap<usize, Vec<Shape>>,
    /// Request times by true run, for planters copying timing.
    times: BTreeMap<String, Vec<i64>>,
    /// The current actor's options that [`Gen::run`] applies to each of its
    /// runs.
    opts: RunOpts,
}

/// Actor options [`Gen::run`] applies to every run of the actor.
#[derive(Debug, Clone, Default)]
struct RunOpts {
    /// Overrides each run's `tag`.
    tags: Option<TagScope>,
    /// A new client for every request.
    rotate: bool,
    /// Seconds between requests, a tenth either way, instead of the pace.
    gap_secs: Option<i64>,
    /// Stalls, in time order: requests due in `[start, start + secs)` leave
    /// `secs` later, each stall once per run.
    stalls: Vec<(i64, i64)>,
    /// A secret every request carries, as ingest writes it.
    secret: Option<String>,
}

/// The parameter a secret rides in.
const SECRET_PARAM: &str = "api_key";
/// The documented demo key that unrelated clients copy from one API's docs.
const DEMO_KEY: &str = "demo";

/// The labelled records of one scenario under one seed, in time order.
pub fn generate(s: &Scenario, seed: u64, palette: &Palette) -> Vec<Value> {
    let mut g = Gen {
        scenario: s,
        seed,
        palette,
        rng: Rng::new(seed).fork(&s.name),
        t0: sc_core::parse_ts(&s.start).unwrap_or(0),
        out: Vec::new(),
        shapes: BTreeMap::new(),
        times: BTreeMap::new(),
        opts: RunOpts::default(),
    };
    for (i, a) in s.actor.iter().enumerate() {
        g.opts = RunOpts {
            tags: a.tag_scope,
            rotate: a.rotate_clients,
            gap_secs: a.gap_hours.map(|h| (h * 3600.0) as i64),
            stalls: Vec::new(),
            secret: a
                .stock_secret
                .then(|| sc_core::redact::hash_token(DEMO_KEY)),
        };
        g.actor(i, a);
    }
    g.out.sort_by(|a, b| {
        let t = |v: &Value| {
            v.get("ts")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string()
        };
        t(a).cmp(&t(b))
    });
    for (n, v) in g.out.iter_mut().enumerate() {
        v["id"] = json!(format!("sim:{}:{seed}:{n:05}", s.name));
    }
    g.out
}

/// The generated records as NDJSON.
pub fn to_ndjson(records: &[Value]) -> String {
    let mut s = String::new();
    for r in records {
        s.push_str(&r.to_string());
        s.push('\n');
    }
    s
}

impl Gen<'_> {
    fn actor(&mut self, i: usize, a: &Actor) {
        let mut rng = self.rng.fork(&format!("actor{i}"));
        let mut start = self.t0 + (a.offset_hours * 3600.0) as i64;
        if a.off_hour {
            // Its own stream, so actors without it draw as before.
            start = start - start.rem_euclid(3600)
                + self
                    .rng
                    .fork(&format!("actor{i}:off_hour"))
                    .range(7 * 60, 53 * 60);
        }
        let span = i64::from(self.scenario.span_hours) * 3600;
        // Where runs of single agents and background actors start.
        let window = a.window_hours.map_or(span, |h| (h * 3600.0) as i64).max(1);
        let id = |k: usize| format!("{}-a{i}-{k}", self.scenario.name);
        let agent_truth =
            |run: String, swarm: Option<String>, fleet: Option<String>, class: &str| Truth {
                label: Some("agent"),
                actor: "agent",
                class: class.into(),
                run,
                swarm,
                fleet,
            };
        match a.kind {
            Kind::Agent => {
                let pool = self.hosts(&format!("a{i}"), a.hosts * 3);
                for k in 0..a.agents {
                    let hosts = if a.same_family {
                        let mut mine = Vec::new();
                        while mine.len() < a.hosts.min(pool.len()) {
                            let h = pool[rng.below(pool.len())].clone();
                            if !mine.contains(&h) {
                                mine.push(h);
                            }
                        }
                        mine
                    } else {
                        self.hosts(&format!("a{i}x{k}"), a.hosts)
                    };
                    let spec = RunSpec {
                        truth: agent_truth(id(k), Some("none".into()), None, "single_agent"),
                        client: agent_client(&mut rng),
                        start: start + rng.range(0, window),
                        pace: a.pace.unwrap_or(Pace::Model),
                        gaps: None,
                        hosts: spread(&hosts, a.records),
                        uses: read_then_attack(a.records, a.hosts),
                        fixed: None,
                        harness: Vec::new(),
                        shapes: Vec::new(),
                        scope: format!("{i}:{k}"),
                        sink_scope: None,
                        tag: a.tag,
                        retry: a.retry,
                        writes: None,
                        fetches: None,
                        adapt: true,
                        habits: habits(a, format!("{i}:{k}")),
                        prose: prose_scope(a, i, k, None),
                    };
                    self.run(spec, &mut rng);
                }
            }
            Kind::PromptFleet => self.prompt_fleet(i, a, start, window, &mut rng),
            Kind::Framework => self.framework(i, a, start, window, &mut rng),
            Kind::Swarm => self.swarm(i, a, start, &mut rng),
            Kind::Escalator => self.escalator(i, a, start, window, &mut rng),
            Kind::Fleet => {
                let fleet = format!("{}-f{i}", self.scenario.name);
                let scaffold = self.scaffold(&mut rng);
                let ua = rng.pick(AGENT_UAS).copied().unwrap_or_default().to_string();
                // The harness's parameters, from their own stream so the
                // rest of the actor draws as before.
                let mut hrng = self.rng.fork(&format!("actor{i}:harness"));
                let names = harness_names(&mut hrng, 3);
                let first = Shape {
                    templates: scaffold.clone(),
                    harness: names[..2].to_vec(),
                };
                // An upgrade changes one parameter and one template.
                let mut upgraded = first.clone();
                upgraded.harness[1].clone_from(&names[2]);
                if let Some(t) = hrng.pick(self.palette.get(Use::Attack)) {
                    upgraded.templates[0] = t.clone();
                }
                let interval = (a.interval_hours.unwrap_or(26.0) * 3600.0) as i64;
                // Where each agent starts after its slot: within three hours,
                // or within `window_hours` when set.
                let jitter = if a.window_hours.is_some() {
                    window
                } else {
                    3 * 3600
                };
                // Twice: four minutes after the start, and four minutes
                // after the first stall ends.
                if let Some(m) = a.stall_minutes {
                    let secs = (m * 60.0) as i64;
                    let first = start + 240;
                    self.opts.stalls = vec![(first, secs), (first + secs + 240, secs)];
                }
                if a.shared_secret {
                    let hex = Ids::new(self.seed).token(&fleet, "secret", 12);
                    self.opts.secret = Some(format!("{SECRET}{hex}"));
                }
                self.shapes.insert(i, vec![first.clone(), upgraded.clone()]);
                for k in 0..a.agents {
                    let shape = if a.upgrade_at.is_some_and(|u| k >= u) {
                        &upgraded
                    } else {
                        &first
                    };
                    let mut client = agent_client(&mut rng);
                    client.ua.clone_from(&ua);
                    let hosts = self.hosts(&format!("a{i}x{k}"), a.hosts);
                    let spec = RunSpec {
                        truth: agent_truth(
                            id(k),
                            Some("none".into()),
                            Some(fleet.clone()),
                            "scaffold_fleet",
                        ),
                        client,
                        start: start + k as i64 * interval + rng.range(0, jitter),
                        pace: a.pace.unwrap_or(Pace::Model),
                        gaps: None,
                        hosts: spread(&hosts, a.records),
                        uses: vec![Use::Attack; a.records],
                        fixed: Some(shape.templates.clone()),
                        harness: shape.harness.clone(),
                        shapes: Vec::new(),
                        scope: format!("{i}:{k}"),
                        sink_scope: None,
                        tag: a.tag,
                        retry: a.retry,
                        writes: None,
                        fetches: None,
                        adapt: true,
                        habits: None,
                        prose: prose_scope(a, i, k, Some(&fleet)),
                    };
                    // The rerun: the same hosts in the same order on another
                    // day, from a new client with new tags.
                    let rerun = a.rerun_after_hours.map(|h| {
                        let mut again = spec.clone();
                        again.truth.run = format!("{}r", id(k));
                        again.client = agent_client(&mut rng);
                        again.client.ua.clone_from(&ua);
                        again.start = spec.start + (h * 3600.0) as i64 + rng.range(0, 3600);
                        again.scope = format!("{i}:{k}:rerun");
                        again
                    });
                    self.run(spec, &mut rng);
                    if let Some(again) = rerun {
                        self.run(again, &mut rng);
                    }
                }
            }
            Kind::Scheduler => {
                let fleet = format!("{}-f{i}", self.scenario.name);
                let client = agent_client(&mut rng);
                let hosts = self.hosts(&format!("a{i}"), a.hosts * a.agents.max(1));
                for k in 0..a.agents {
                    let mine: Vec<String> = hosts
                        .iter()
                        .skip(k)
                        .step_by(a.agents.max(1))
                        .cloned()
                        .collect();
                    let spec = RunSpec {
                        truth: agent_truth(
                            id(k),
                            Some("none".into()),
                            Some(fleet.clone()),
                            "scheduler",
                        ),
                        client: client.clone(),
                        start: start + rng.range(0, 60),
                        pace: a.pace.unwrap_or(Pace::Model),
                        gaps: None,
                        hosts: spread(&mine, a.records),
                        uses: read_then_attack(a.records, mine.len()),
                        fixed: None,
                        harness: Vec::new(),
                        shapes: Vec::new(),
                        scope: format!("{i}:{k}"),
                        sink_scope: None,
                        tag: a.tag,
                        retry: a.retry,
                        writes: None,
                        fetches: None,
                        adapt: true,
                        habits: habits(a, format!("{i}")),
                        prose: None,
                    };
                    self.run(spec, &mut rng);
                }
            }
            Kind::Planter => {
                let Some(victim) = a.copies else { return };
                // The copied actor's first run's request times, when timing
                // is copied too.
                let copied: Option<Vec<i64>> = a
                    .copy_timing
                    .then(|| {
                        self.times
                            .get(&format!("{}-a{victim}-0", self.scenario.name))
                            .cloned()
                    })
                    .flatten()
                    .filter(|t| !t.is_empty());
                for k in 0..a.agents {
                    let hosts = self.hosts(&format!("a{i}x{k}"), a.hosts);
                    let (begin, gaps, records) = match &copied {
                        Some(t) => {
                            let n = a.records.min(t.len());
                            let gaps: Vec<i64> = (0..n)
                                .map(|r| if r == 0 { 0 } else { t[r] - t[r - 1] })
                                .collect();
                            (t[0] + rng.range(2, 20), Some(gaps), n)
                        }
                        None => (start + rng.range(0, 24 * 3600), None, a.records),
                    };
                    let spec = RunSpec {
                        truth: Truth {
                            label: None,
                            actor: "human",
                            class: "planted".into(),
                            run: id(k),
                            swarm: Some("none".into()),
                            fleet: None,
                        },
                        client: browser_client(&mut rng),
                        start: begin,
                        pace: a.pace.unwrap_or(Pace::Human),
                        gaps,
                        hosts: spread(&hosts, records),
                        uses: vec![Use::Sink; records],
                        fixed: None,
                        harness: Vec::new(),
                        shapes: Vec::new(),
                        scope: format!("{victim}:0"),
                        sink_scope: Some(format!("{victim}:sink")),
                        tag: a.tag,
                        retry: 0.0,
                        writes: None,
                        fetches: None,
                        adapt: true,
                        habits: None,
                        prose: None,
                    };
                    self.run(spec, &mut rng);
                }
            }
            Kind::Mimic => {
                let shapes: Vec<Shape> = a
                    .bridges
                    .iter()
                    .filter_map(|b| self.shapes.get(b).and_then(|s| s.first()).cloned())
                    .collect();
                if shapes.is_empty() {
                    return;
                }
                for k in 0..a.agents {
                    let hosts = self.hosts(&format!("a{i}x{k}"), a.hosts);
                    let spec = RunSpec {
                        truth: agent_truth(id(k), Some("none".into()), None, "mimic"),
                        client: agent_client(&mut rng),
                        start: start + rng.range(0, window),
                        pace: a.pace.unwrap_or(Pace::Model),
                        gaps: None,
                        hosts: spread(&hosts, a.records),
                        uses: vec![Use::Attack; a.records],
                        fixed: None,
                        harness: Vec::new(),
                        shapes: shapes.clone(),
                        scope: format!("{i}:{k}"),
                        sink_scope: None,
                        tag: a.tag,
                        retry: a.retry,
                        writes: None,
                        fetches: None,
                        adapt: true,
                        habits: None,
                        prose: None,
                    };
                    self.run(spec, &mut rng);
                }
            }
            Kind::TargetList | Kind::NewsSpike | Kind::Hub => {
                self.target_list(i, a, start, window, &mut rng)
            }
            Kind::UptimeMonitor
            | Kind::InternetScanner
            | Kind::LinkPreview
            | Kind::FeedPoller
            | Kind::CiLinkChecker
            | Kind::SeoCrawler => self.lookalike(i, a, start, window, &mut rng),
            _ => self.background(i, a, start, window, &mut rng),
        }
    }

    /// Agents trying each request directly, then through a relay: each
    /// route a separate tool with its own run tag.
    fn escalator(&mut self, i: usize, a: &Actor, start: i64, window: i64, rng: &mut Rng) {
        let pool: Vec<Template> = self
            .palette
            .get(Use::Attack)
            .iter()
            .filter(|t| {
                t.obs.url.len() > RELAY_PREFIX.len()
                    && t.obs.url[..RELAY_PREFIX.len()].eq_ignore_ascii_case(RELAY_PREFIX)
            })
            .cloned()
            .collect();
        if pool.is_empty() {
            return;
        }
        let basis = self.scenario.basis;
        for k in 0..a.agents {
            let hosts = self.hosts(&format!("a{i}x{k}"), a.hosts);
            let run = format!("{}-a{i}-{k}", self.scenario.name);
            let base = RunSpec {
                truth: Truth {
                    label: Some("agent"),
                    actor: "agent",
                    class: "escalating_agent".into(),
                    run: run.clone(),
                    swarm: Some("none".into()),
                    fleet: None,
                },
                client: agent_client(rng),
                start: start + rng.range(0, window),
                pace: a.pace.unwrap_or(Pace::Model),
                gaps: None,
                hosts: Vec::new(),
                uses: Vec::new(),
                fixed: None,
                harness: Vec::new(),
                shapes: Vec::new(),
                scope: String::new(),
                sink_scope: None,
                tag: a.tag,
                retry: 0.0,
                writes: None,
                fetches: None,
                adapt: true,
                habits: None,
                prose: None,
            };
            let mut ids = Ids::new(self.seed);
            let mut t = base.start;
            for r in 0..a.records {
                let host = &hosts[r % hosts.len()];
                let Some(relayed) = rng.pick(&pool).cloned() else {
                    continue;
                };
                let mut direct = relayed.clone();
                direct.obs.url = relayed.obs.url[RELAY_PREFIX.len()..].to_string();
                for (step, (tpl, route)) in [(&direct, "direct"), (&relayed, "relay")]
                    .into_iter()
                    .enumerate()
                {
                    if step > 0 {
                        t += rng.range(11 * 60, 25 * 60);
                    }
                    let mut spec = base.clone();
                    spec.scope = format!("{i}:{k}:{route}");
                    let mut url = rewrite(tpl, host, &spec, &mut ids, None);
                    if spec.tag {
                        let tag = ids.token(&spec.scope, "uqtag", 10);
                        url = add_param(&url, "uqtag", &format!("r{tag}"));
                    }
                    // The direct try goes unanswered.
                    let status =
                        (basis == Basis::Request).then_some(if step == 0 { 403 } else { 200 });
                    self.emit(&spec, &tpl.origin, url, t, status, basis);
                }
                t += gap(rng, base.pace);
            }
        }
    }

    /// Agents on one shared host list: one operator's target list worked
    /// loosely in time, unrelated agents on a news story's hosts, or a hub
    /// working the lists of the actors it bridges.
    fn target_list(&mut self, i: usize, a: &Actor, start: i64, span: i64, rng: &mut Rng) {
        let name = &self.scenario.name;
        let shared: Vec<String> = match a.kind {
            Kind::Hub => a
                .bridges
                .iter()
                .filter_map(|&j| self.scenario.actor.get(j).map(|b| (j, b.hosts)))
                .flat_map(|(j, n)| self.hosts(&format!("a{j}"), n))
                .collect(),
            _ => self.hosts(&format!("a{i}"), a.hosts),
        };
        let fleet = (a.kind == Kind::TargetList).then(|| format!("{name}-f{i}"));
        let class = match a.kind {
            Kind::TargetList => "target_list",
            Kind::NewsSpike => "news_spike",
            _ => "hub",
        };
        // One order for every agent: the list's sorted order, or one seeded
        // order from its own stream, so actors without it draw as before.
        let order: Option<Vec<String>> = if a.sorted {
            Some(shared.clone())
        } else if a.in_order {
            let mut o = shared.clone();
            shuffle(&mut o, &mut self.rng.fork(&format!("actor{i}:order")));
            Some(o)
        } else {
            None
        };
        let mut t = start;
        for k in 0..a.agents.max(1) {
            let begin = match a.kind {
                // Far enough apart that no two agents meet on one host
                // within the timing window, close enough to share hours.
                Kind::TargetList => {
                    if k > 0 {
                        t += rng.range(15 * 60, 20 * 60);
                    }
                    t
                }
                // Within six hours, or within `window_hours` when set: a
                // published list walked for days.
                Kind::NewsSpike if a.window_hours.is_some() => start + rng.range(0, span),
                Kind::NewsSpike => start + rng.range(0, span.min(6 * 3600)),
                _ => start,
            };
            let hosts = match &order {
                Some(o) => o.clone(),
                None => {
                    let mut h = shared.clone();
                    shuffle(&mut h, rng);
                    h
                }
            };
            let records = a.records.max(hosts.len());
            let spec = RunSpec {
                truth: Truth {
                    label: Some("agent"),
                    actor: "agent",
                    class: class.into(),
                    run: format!("{name}-a{i}-{k}"),
                    swarm: Some("none".into()),
                    fleet: fleet.clone(),
                },
                client: agent_client(rng),
                start: begin,
                pace: a.pace.unwrap_or(Pace::Model),
                gaps: None,
                hosts: spread(&hosts, records),
                uses: read_then_attack(records, hosts.len()),
                fixed: None,
                harness: Vec::new(),
                shapes: Vec::new(),
                scope: format!("{i}:{k}"),
                sink_scope: None,
                tag: a.tag,
                retry: a.retry,
                writes: None,
                fetches: None,
                adapt: true,
                habits: habits(a, format!("{i}:{k}")),
                prose: prose_scope(a, i, k, fleet.as_deref()),
            };
            self.run(spec, rng);
        }
    }

    /// Agents of one operator writing prose from its prompt templates, each
    /// otherwise its own: client, inbox, tags, hosts, habits and start.
    fn prompt_fleet(&mut self, i: usize, a: &Actor, start: i64, window: i64, rng: &mut Rng) {
        let fleet = format!("{}-f{i}", self.scenario.name);
        for k in 0..a.agents {
            let hosts = self.hosts(&format!("a{i}x{k}"), a.hosts);
            let client = agent_client(rng);
            let begin = start + rng.range(0, window);
            let mut spec = self.bg_spec(
                i,
                k,
                a,
                "prompt_fleet",
                "agent",
                Some("agent"),
                Use::Attack,
                Pace::Model,
                true,
                &client,
                &hosts,
                begin,
                a.records,
            );
            spec.truth.fleet = Some(fleet.clone());
            spec.uses = read_then_attack(a.records, a.hosts);
            spec.tag = a.tag;
            spec.prose = prose_scope(a, i, k, Some(&fleet)).or_else(|| Some(fleet.clone()));
            self.run(spec, rng);
        }
    }

    /// Agents of unrelated operators on one framework: its templates in a
    /// fixed rotation and its step counter, and one parameter per operator.
    fn framework(&mut self, i: usize, a: &Actor, start: i64, window: i64, rng: &mut Rng) {
        let templates = self.scaffold(rng);
        let mut hrng = self.rng.fork(&format!("actor{i}:harness"));
        let names = harness_names(&mut hrng, a.agents + 1);
        for k in 0..a.agents {
            let hosts = self.hosts(&format!("a{i}x{k}"), a.hosts);
            let client = agent_client(rng);
            let begin = start + rng.range(0, window);
            let mut spec = self.bg_spec(
                i,
                k,
                a,
                "framework_user",
                "agent",
                Some("agent"),
                Use::Attack,
                Pace::Model,
                true,
                &client,
                &hosts,
                begin,
                a.records,
            );
            spec.fixed = Some(templates.clone());
            // The framework's step counter, then the operator's own
            // parameter (another name for each, while names last).
            let own = 1 + k % (names.len() - 1).max(1);
            spec.harness = vec![names[0].clone(), names[own].clone()];
            spec.tag = a.tag;
            spec.prose = prose_scope(a, i, k, None);
            self.run(spec, rng);
        }
    }

    fn swarm(&mut self, i: usize, a: &Actor, start: i64, rng: &mut Rng) {
        let swarm = format!("{}-s{i}", self.scenario.name);
        let n = a.agents.max(2);
        let has = |m: Mode| a.modes.contains(&m);
        let pace = a.pace.unwrap_or(Pace::Model);
        let shared = self.hosts(
            &format!("a{i}"),
            a.hosts * if has(Mode::Shard) { n } else { 1 },
        );
        let sync_gaps: Vec<i64> = (0..a.records).map(|_| gap(rng, pace)).collect();
        // Each agent of a swarm is its own client: another tool, network and
        // address, as an orchestrator's workers are.
        let base = rng.below(AGENT_UAS.len());
        let net = rng.below(CLOUD_ASNS.len());
        // The hand-off artifact: one gist per swarm, its ids of the swarm's own.
        let mut ids = Ids::new(self.seed);
        let scope = format!("{i}:handoff");
        let (user, gist) = (
            format!("u{}", ids.token(&scope, "user", 6)),
            ids.token(&scope, "gist", 32),
        );
        let note = format!("https://gist.github.com/{user}/{gist}");
        let raw = format!("https://r.jina.ai/https://gist.githubusercontent.com/{user}/{gist}/raw");
        let handoff = has(Mode::Handoff);
        // Dispatch times, from their own stream so other modes draw as before.
        let dispatch = has(Mode::Dispatch);
        let mut drng = rng.fork("dispatch");
        let dispatch_gaps: Vec<i64> = (0..a.records)
            .map(|_| {
                if dispatch {
                    drng.range(10 * 60, 50 * 60)
                } else {
                    0
                }
            })
            .collect();
        let mut t = start;
        for k in 0..n {
            let reader = (has(Mode::Roles) || handoff) && k == 0;
            let hosts: Vec<String> = if has(Mode::Shard) {
                shared.iter().skip(k).step_by(n).cloned().collect()
            } else if has(Mode::Roles) {
                shared.clone()
            } else {
                self.hosts(&format!("a{i}x{k}"), a.hosts)
            };
            let uses = if reader {
                vec![Use::Read; a.records]
            } else if has(Mode::Roles) {
                vec![Use::Attack; a.records]
            } else if has(Mode::Sink) {
                (0..a.records)
                    .map(|r| if r % 2 == 0 { Use::Sink } else { Use::Attack })
                    .collect()
            } else {
                read_then_attack(a.records, hosts.len())
            };
            // A worker's delay after each dispatch.
            let late: Vec<i64> = (0..a.records)
                .map(|_| {
                    if dispatch && k > 0 {
                        drng.range(40, 85)
                    } else {
                        0
                    }
                })
                .collect();
            let mut begin = if dispatch {
                start + late.first().copied().unwrap_or(0)
            } else if handoff && k > 0 {
                t + rng.range(5 * 60, 45 * 60)
            } else if has(Mode::Roles) && k > 0 {
                t + rng.range(15 * 60, 90 * 60)
            } else if has(Mode::Sync) {
                start + rng.range(0, 20)
            } else {
                start + rng.range(0, 300)
            };
            // One dispatcher sends each step to every agent; each request
            // leaves up to the jitter after its dispatch, never before the
            // agent's previous request. Times are placed against the
            // dispatches, not the previous request, so lateness never
            // accumulates.
            let sync = (!dispatch && has(Mode::Sync)).then(|| {
                let jitter = a.jitter_secs.unwrap_or(2).max(0);
                let late: Vec<i64> = sync_gaps.iter().map(|_| rng.range(0, jitter)).collect();
                sync_times(&sync_gaps, &late)
            });
            if let Some((first, _)) = &sync {
                begin += first;
            }
            let spec = RunSpec {
                truth: Truth {
                    label: Some("agent"),
                    actor: "agent",
                    class: "swarm_agent".into(),
                    run: format!("{}-a{i}-{k}", self.scenario.name),
                    swarm: Some(swarm.clone()),
                    fleet: Some(swarm.clone()),
                },
                client: Client {
                    ua: AGENT_UAS[(base + k) % AGENT_UAS.len()].into(),
                    asn: CLOUD_ASNS[(net + k) % CLOUD_ASNS.len()],
                    ip: address(rng),
                },
                start: begin,
                pace,
                gaps: if dispatch {
                    Some(
                        (0..a.records)
                            .map(|r| dispatch_gaps[r] + late[r] - late[r.saturating_sub(1)])
                            .collect(),
                    )
                } else {
                    sync.map(|(_, gaps)| gaps)
                },
                // A reader and an attacker go through the hosts in one order.
                hosts: if has(Mode::Roles) {
                    in_order(&hosts, a.records)
                } else {
                    spread(&hosts, a.records)
                },
                uses,
                fixed: None,
                harness: Vec::new(),
                shapes: Vec::new(),
                scope: format!("{i}:{k}"),
                sink_scope: has(Mode::Sink).then(|| format!("{i}:sink")),
                tag: a.tag,
                retry: a.retry,
                writes: (handoff && k == 0).then(|| note.clone()),
                fetches: (handoff && k > 0).then(|| raw.clone()),
                adapt: true,
                habits: habits(a, format!("{i}")),
                prose: prose_scope(a, i, k, Some(&swarm)),
            };
            let end = self.run(spec, rng);
            if reader {
                t = end;
            }
        }
    }

    /// Benign look-alikes of swarm and fleet signals. Each client is its
    /// own run and its own operator, so every edge or soft link drawn
    /// between two of them is false.
    fn lookalike(&mut self, i: usize, a: &Actor, start: i64, window: i64, rng: &mut Rng) {
        let (class, palette_class) = match a.kind {
            Kind::UptimeMonitor => ("uptime_monitor", "api_client"),
            Kind::InternetScanner => ("internet_scanner", "crawler"),
            Kind::LinkPreview => ("link_preview", "crawler"),
            Kind::CiLinkChecker => ("ci_link_checker", "dev_tool"),
            Kind::SeoCrawler => ("seo_crawler", "crawler"),
            _ => ("feed_poller", "crawler"),
        };
        let pool: Vec<Template> = self
            .palette
            .benign_flagged(palette_class)
            .into_iter()
            .cloned()
            .collect();
        if pool.is_empty() {
            return;
        }
        let n = a.agents.max(1);
        let basis = self.scenario.basis;
        let ok = move |code: u16| (basis == Basis::Request).then_some(code);
        let net = rng.below(CLOUD_ASNS.len());
        let prefix = rng.pick(NETS).copied().unwrap_or("192.0.2");
        // An SEO vendor's shards are clients of one run.
        let clients = if a.kind == Kind::SeoCrawler {
            n * SEO_SHARDS
        } else {
            n
        };
        let specs: Vec<RunSpec> = (0..clients)
            .map(|c| {
                let k = if a.kind == Kind::SeoCrawler {
                    c / SEO_SHARDS
                } else {
                    c
                };
                let other_net = CLOUD_ASNS[(net + k) % CLOUD_ASNS.len()];
                let client = match a.kind {
                    Kind::CiLinkChecker => Client {
                        ua: LINK_CHECKER_UA.into(),
                        asn: other_net,
                        ip: address(rng),
                    },
                    // Each vendor's network, consecutive addresses.
                    Kind::SeoCrawler => Client {
                        ua: SEO_UAS[k % SEO_UAS.len()].into(),
                        asn: other_net,
                        ip: format!(
                            "{}.{}",
                            NETS[(k / 40) % NETS.len()],
                            10 + (k % 40) * SEO_SHARDS + c % SEO_SHARDS
                        ),
                    },
                    Kind::UptimeMonitor => Client {
                        ua: MONITOR_UA.into(),
                        asn: other_net,
                        ip: address(rng),
                    },
                    // One network, consecutive addresses.
                    Kind::InternetScanner => Client {
                        ua: SCANNER_UA.into(),
                        asn: CLOUD_ASNS[net],
                        ip: format!("{prefix}.{}", 10 + k % 240),
                    },
                    Kind::LinkPreview => Client {
                        ua: PREVIEW_UAS[k % PREVIEW_UAS.len()].into(),
                        asn: other_net,
                        ip: address(rng),
                    },
                    _ => Client {
                        ua: FEED_UAS[k % FEED_UAS.len()].into(),
                        asn: other_net,
                        ip: address(rng),
                    },
                };
                self.bg_spec(
                    i,
                    k,
                    a,
                    class,
                    "tool",
                    Some("benign"),
                    Use::Benign,
                    Pace::Tool,
                    false,
                    &client,
                    &[],
                    start,
                    0,
                )
            })
            .collect();
        let pick = |rng: &mut Rng| pool[rng.below(pool.len())].clone();
        let mut ids = Ids::new(self.seed);
        let begin = start + rng.range(0, window);
        match a.kind {
            Kind::UptimeMonitor => {
                // The same URLs from every region, one check a minute in
                // turn, each region within a second of the others.
                let hosts = self.hosts(&format!("a{i}"), a.hosts);
                let checks: Vec<(Template, String)> =
                    hosts.iter().map(|h| (pick(rng), h.clone())).collect();
                for c in 0..a.records {
                    let (tpl, host) = &checks[c % checks.len()];
                    let url = rewrite(tpl, host, &specs[0], &mut ids, None);
                    let at = begin + c as i64 * 60;
                    for spec in &specs {
                        let ts = at + rng.range(0, 2);
                        self.emit(spec, &tpl.origin, url.clone(), ts, ok(200), basis);
                    }
                }
            }
            Kind::InternetScanner => {
                // One host family split over the addresses, one probe set
                // per host, every address starting at once.
                let family = self.hosts(&format!("a{i}"), a.hosts * n);
                let probes: Vec<Template> = (0..3).map(|_| pick(rng)).collect();
                for (k, spec) in specs.iter().enumerate() {
                    let mut t = begin + rng.range(0, 3);
                    let mine = family.iter().skip(k).step_by(n);
                    let sends = mine.flat_map(|h| probes.iter().map(move |p| (p, h)));
                    for (tpl, host) in sends.take(a.records) {
                        let url = rewrite(tpl, host, spec, &mut ids, None);
                        self.emit(spec, &tpl.origin, url, t, ok(200), basis);
                        t += gap(rng, Pace::Tool);
                    }
                }
            }
            Kind::CiLinkChecker => {
                // One published list, its URLs in sorted order; every
                // repository's job starts on the hour (its runner a few
                // seconds late) and checks them in turn.
                let hosts = self.hosts(&format!("a{i}"), a.hosts);
                let checks: Vec<(Template, String)> =
                    hosts.iter().map(|h| (pick(rng), h.clone())).collect();
                let hour = begin - begin.rem_euclid(3600) + 3600;
                for spec in &specs {
                    let mut t = hour + rng.range(0, 20);
                    for c in 0..a.records {
                        let (tpl, host) = &checks[c % checks.len()];
                        let url = rewrite(tpl, host, &specs[0], &mut ids, None);
                        self.emit(spec, &tpl.origin, url, t, ok(200), basis);
                        t += gap(rng, Pace::Tool);
                    }
                }
            }
            Kind::SeoCrawler => {
                // One site's sitemap, in sitemap order; each vendor splits it
                // over its shards, every shard starting at once.
                let sitemap = self.hosts(&format!("a{i}"), a.hosts);
                let pages: Vec<(Template, String)> =
                    sitemap.iter().map(|h| (pick(rng), h.clone())).collect();
                for vendor in specs.chunks(SEO_SHARDS) {
                    let at = start + rng.range(0, window);
                    for (s, spec) in vendor.iter().enumerate() {
                        let mut t = at + rng.range(0, 3);
                        for (tpl, host) in pages.iter().skip(s).step_by(SEO_SHARDS) {
                            let url = rewrite(tpl, host, &specs[0], &mut ids, None);
                            self.emit(spec, &tpl.origin, url, t, ok(200), basis);
                            t += gap(rng, Pace::Tool);
                        }
                    }
                }
            }
            Kind::LinkPreview => {
                // Each posted link fetched by most platforms' bots within
                // seconds of the post.
                let hosts = self.hosts(&format!("a{i}"), a.hosts);
                for p in 0..a.records {
                    let posted = start + rng.range(0, window);
                    let tpl = pick(rng);
                    let host = &hosts[p % hosts.len()];
                    let url = rewrite(&tpl, host, &specs[0], &mut ids, None);
                    for spec in &specs {
                        if rng.chance(0.7) {
                            let ts = posted + rng.range(1, 6);
                            self.emit(spec, &tpl.origin, url.clone(), ts, ok(200), basis);
                        }
                    }
                }
            }
            _ => {
                // The same feeds in one order each poll, each reader on its
                // own interval and phase; through the feed host's outage
                // each reader fails once and backs off until it ends.
                let hosts = self.hosts(&format!("a{i}"), a.hosts);
                let feeds: Vec<(Template, String)> =
                    hosts.iter().map(|h| (pick(rng), h.clone())).collect();
                let down = start + window / 2 + rng.range(0, 3600);
                let up = down + rng.range(3600, 3 * 3600);
                for spec in &specs {
                    let every = [900, 1800, 3600][rng.below(3)];
                    let phase = rng.range(0, every);
                    let mut failed = false;
                    for c in 0..a.records as i64 {
                        let mut t = start + phase + c * every;
                        if (down..up).contains(&t) {
                            if !failed {
                                let (tpl, host) = &feeds[0];
                                let url = rewrite(tpl, host, &specs[0], &mut ids, None);
                                self.emit(spec, &tpl.origin, url, t, ok(503), basis);
                                failed = true;
                            }
                            continue;
                        }
                        for (tpl, host) in &feeds {
                            let url = rewrite(tpl, host, &specs[0], &mut ids, None);
                            self.emit(spec, &tpl.origin, url, t, ok(200), basis);
                            t += rng.range(1, 3);
                        }
                    }
                }
            }
        }
    }

    fn background(&mut self, i: usize, a: &Actor, start: i64, window: i64, rng: &mut Rng) {
        let (class, actor, label, uses, pace, adapt) = match a.kind {
            Kind::RelayReaders => (
                "relay_reading",
                "human",
                Some("benign"),
                Use::Benign,
                Pace::Human,
                true,
            ),
            Kind::MailGateway => (
                "mail_gateway",
                "tool",
                Some("benign"),
                Use::Benign,
                Pace::Tool,
                false,
            ),
            Kind::Cron => (
                "api_client",
                "tool",
                Some("benign"),
                Use::Benign,
                Pace::Tool,
                false,
            ),
            Kind::Crawler => (
                "crawler",
                "tool",
                Some("benign"),
                Use::Benign,
                Pace::Tool,
                false,
            ),
            Kind::Pentester => ("pentester", "tool", None, Use::Tool, Pace::Tool, false),
            Kind::ChatbotPaster => (
                "chatbot_paster",
                "human",
                None,
                Use::Human,
                Pace::Human,
                true,
            ),
            _ => return,
        };
        for k in 0..a.agents {
            let client = if actor == "human" || a.kind == Kind::Crawler {
                browser_client(rng)
            } else {
                agent_client(rng)
            };
            let hosts = self.hosts(&format!("a{i}x{k}"), a.hosts);
            let begin = if a.kind == Kind::Cron {
                // On the clock hour, every hour, with a pause of a few hours.
                let h = start - start.rem_euclid(3600) + 3600;
                for hour in 0..a.records as i64 {
                    if hour % 8 >= 6 {
                        continue;
                    }
                    let spec = self.bg_spec(
                        i,
                        k,
                        a,
                        class,
                        actor,
                        label,
                        uses,
                        pace,
                        adapt,
                        &client,
                        &hosts,
                        h + hour * 3600 + rng.range(0, 3),
                        2,
                    );
                    self.run(spec, rng);
                }
                continue;
            } else {
                start + rng.range(0, window)
            };
            let spec = self.bg_spec(
                i, k, a, class, actor, label, uses, pace, adapt, &client, &hosts, begin, a.records,
            );
            self.run(spec, rng);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn bg_spec(
        &self,
        i: usize,
        k: usize,
        a: &Actor,
        class: &str,
        actor: &'static str,
        label: Option<&'static str>,
        u: Use,
        pace: Pace,
        adapt: bool,
        client: &Client,
        hosts: &[String],
        begin: i64,
        records: usize,
    ) -> RunSpec {
        RunSpec {
            truth: Truth {
                label,
                actor,
                class: class.into(),
                run: format!("{}-a{i}-{k}", self.scenario.name),
                swarm: Some("none".into()),
                fleet: None,
            },
            client: client.clone(),
            start: begin,
            pace: a.pace.unwrap_or(pace),
            gaps: None,
            hosts: spread(hosts, records),
            uses: vec![u; records],
            fixed: (u == Use::Benign)
                .then(|| self.palette.benign(class).into_iter().cloned().collect()),
            harness: Vec::new(),
            shapes: Vec::new(),
            scope: format!("{i}:{k}"),
            sink_scope: None,
            tag: false,
            retry: a.retry,
            writes: None,
            fetches: None,
            adapt,
            habits: habits(a, format!("{i}:{k}")),
            prose: None,
        }
    }

    /// A handful of attack templates one scaffold sends again and again.
    fn scaffold(&self, rng: &mut Rng) -> Vec<Template> {
        let all = self.palette.get(Use::Attack);
        let mut out = Vec::new();
        for _ in 0..3 {
            if let Some(t) = rng.pick(all) {
                out.push(t.clone());
            }
        }
        out
    }

    /// `n` hosts in one family (the last two labels), on a reserved domain.
    fn hosts(&self, family: &str, n: usize) -> Vec<String> {
        let fam = format!("{}-{family}-{}", self.scenario.name, self.seed)
            .to_ascii_lowercase()
            .replace(|c: char| !c.is_ascii_alphanumeric() && c != '-', "-");
        (0..n.max(1))
            .map(|k| format!("h{k}.{fam}.example"))
            .collect()
    }

    /// Emits one run; returns its last timestamp.
    fn run(&mut self, mut spec: RunSpec, rng: &mut Rng) -> i64 {
        let mut t = spec.start;
        let mut step = 0usize;
        let mut ids = Ids::new(self.seed);
        let basis = self.scenario.basis;
        let opts = self.opts.clone();
        let per_request = opts.tags == Some(TagScope::PerRequest);
        if let Some(scope) = opts.tags {
            spec.tag = scope != TagScope::None;
        }
        let mut stalled = 0;
        // A rotating client is drawn from its own stream per request, so the
        // run's other draws stay as they were.
        let (seed, rotating) = (self.seed, opts.rotate);
        let rotate = |spec: &RunSpec, step: usize| {
            rotating.then(|| {
                let mut r = Rng::new(seed)
                    .fork("rotate")
                    .fork(&spec.scope)
                    .fork(&step.to_string());
                RunSpec {
                    client: agent_client(&mut r),
                    ..spec.clone()
                }
            })
        };
        if let Some(f) = &spec.fetches {
            let mut url = f.clone();
            if spec.tag {
                url = add_param(
                    &url,
                    "uqtag",
                    &format!("r{}", ids.token(&spec.scope, "uqtag", 10)),
                );
            }
            let status = (basis == Basis::Request).then_some(200);
            self.emit(&spec, "generated hand-off fetch", url, t, status, basis);
            t += gap(rng, spec.pace);
        }
        let mut sched = t;
        for (r, (host, u)) in spec.hosts.iter().zip(&spec.uses).enumerate() {
            let shape = (!spec.shapes.is_empty()).then(|| &spec.shapes[r % spec.shapes.len()]);
            let fixed = shape.map(|s| &s.templates).or(spec.fixed.as_ref());
            let harness = shape.map_or(&spec.harness, |s| &s.harness);
            let pool: Vec<&Template> = match fixed {
                Some(f) if !f.is_empty() => f.iter().collect(),
                _ => {
                    let p = self.palette.get(*u);
                    let p = if p.is_empty() {
                        self.palette.get(Use::Read)
                    } else {
                        p
                    };
                    match &spec.habits {
                        Some((key, share)) => subset(p, self.seed, key, *share),
                        None => p.iter().collect(),
                    }
                }
            };
            // A harness runs one task script: its records in a fixed
            // rotation, so its agents send one mix of them.
            let tpl = if harness.is_empty() {
                rng.pick(&pool).copied()
            } else {
                pool.get(r % pool.len().max(1)).copied()
            };
            let Some(tpl) = tpl else {
                continue;
            };
            // A scheduled run (synchronised, dispatched or copied timing)
            // keeps its schedule: retries take time after a request but do
            // not move the next one, which leaves at its scheduled time or
            // right after the last retry. A run without one paces itself
            // from its last request.
            if r > 0 {
                match spec.gaps.as_ref().and_then(|g| g.get(r).copied()) {
                    Some(g) => {
                        sched += g;
                        t = t.max(sched);
                    }
                    None => {
                        t += match opts.gap_secs {
                            Some(g) => g + rng.range(-g / 10, g / 10),
                            None => gap(rng, spec.pace),
                        };
                        sched = t;
                    }
                }
            }
            // The operator's stalls: a request due inside one leaves at its
            // end, and the rest of the run moves with it.
            while let Some(&(from, secs)) = opts.stalls.get(stalled) {
                if t < from {
                    break;
                }
                stalled += 1;
                if t < from + secs {
                    t += secs;
                    sched += secs;
                }
            }
            let error = rng.chance(spec.retry);
            let tries = if error { 3 } else { 1 };
            for k in 0..tries {
                if k > 0 {
                    t += if spec.adapt {
                        gap(rng, spec.pace).max(3)
                    } else {
                        gap(rng, Pace::Tool)
                    };
                }
                let buster = (error && (spec.adapt || k == 0)).then_some(k + 1);
                let mut url = rewrite(tpl, host, &spec, &mut ids, buster);
                // The harness's own parameters: a step counter, then a
                // trace value per request.
                for (j, name) in harness.iter().enumerate() {
                    let value = if j == 0 {
                        r.to_string()
                    } else {
                        ids.token(&format!("{}:{step}", spec.scope), name, 8)
                    };
                    url = add_param(&url, name, &value);
                }
                if let Some(p) = &spec.prose {
                    let text = prompt_text(self.seed, p, r, host);
                    url = add_param(&url, "query", &text.replace(' ', "%20"));
                }
                if spec.tag && u != &Use::Benign {
                    let tag = if per_request {
                        ids.token(&format!("{}:{step}", spec.scope), "uqtag", 10)
                    } else {
                        ids.token(&spec.scope, "uqtag", 10)
                    };
                    url = add_param(&url, "uqtag", &format!("r{tag}"));
                }
                if let Some(w) = &spec.writes {
                    url = add_param(&url, "notes", w);
                }
                if let Some(s) = &opts.secret {
                    url = add_param(&url, SECRET_PARAM, s);
                }
                let status = (basis == Basis::Request).then_some(if error && k + 1 < tries {
                    404
                } else {
                    200
                });
                match rotate(&spec, step) {
                    Some(moved) => self.emit(&moved, &tpl.origin, url, t, status, basis),
                    None => self.emit(&spec, &tpl.origin, url, t, status, basis),
                }
                step += 1;
            }
        }
        t
    }

    fn emit(
        &mut self,
        spec: &RunSpec,
        origin: &str,
        url: String,
        ts: i64,
        status: Option<u16>,
        basis: Basis,
    ) {
        let request = basis == Basis::Request;
        let obs = Observation {
            id: String::new(),
            source: basis.source().into(),
            ts,
            ts_kind: match basis {
                Basis::Request => TsKind::Request,
                Basis::Submit => TsKind::Submit,
                Basis::Capture => TsKind::Capture,
            },
            url,
            ip: request.then(|| spec.client.ip.clone()),
            asn: request.then_some(spec.client.asn),
            user_agent: request.then(|| spec.client.ua.clone()),
            status,
            ..Observation::default()
        };
        let mut v = serde_json::to_value(&obs).unwrap_or(Value::Null);
        v["ts"] = json!(rfc3339(ts));
        self.times
            .entry(spec.truth.run.clone())
            .or_default()
            .push(ts);
        let t = &spec.truth;
        if let Some(l) = t.label {
            v["label"] = json!(l);
        }
        v["actor"] = json!(t.actor);
        v["class"] = json!(t.class);
        v["run"] = json!(t.run);
        if let Some(s) = &t.swarm {
            v["swarm"] = json!(s);
        }
        if let Some(f) = &t.fleet {
            v["fleet"] = json!(f);
        }
        v["synthetic"] = json!(true);
        v["cite"] = json!(format!(
            "synthetic: sc-sim {} from {origin}",
            self.scenario.name
        ));
        self.out.push(v);
    }
}

/// Per-scope replacements for identifiers, deterministic from the seed.
struct Ids {
    seed: u64,
    memo: BTreeMap<(String, String), String>,
}

impl Ids {
    fn new(seed: u64) -> Self {
        Self {
            seed,
            memo: BTreeMap::new(),
        }
    }

    fn rng(&self, scope: &str, what: &str) -> Rng {
        Rng::new(self.seed).fork(scope).fork(what)
    }

    /// `n` hex digits standing for `what` in `scope`.
    fn token(&mut self, scope: &str, what: &str, n: usize) -> String {
        let key = (scope.to_string(), format!("token:{what}"));
        if let Some(v) = self.memo.get(&key) {
            return v.clone();
        }
        let v = self.rng(scope, what).hex(n);
        self.memo.insert(key, v.clone());
        v
    }

    /// A replacement for an identifier as written: digits become other
    /// digits, and the hex letters of a long run with digits other hex
    /// letters, so the rule that matched it still matches and a value in one
    /// scope never equals one in another.
    fn swap(&mut self, scope: &str, orig: &str) -> String {
        let key = (scope.to_string(), orig.to_string());
        if let Some(v) = self.memo.get(&key) {
            return v.clone();
        }
        let mut rng = self.rng(scope, orig);
        let mut out = String::with_capacity(orig.len());
        for run in split_runs(orig) {
            let alnum = run.chars().all(|c| c.is_ascii_alphanumeric());
            let digits = run.chars().filter(char::is_ascii_digit).count();
            let hexy =
                alnum && digits > 0 && run.len() >= 8 && run.chars().all(|c| c.is_ascii_hexdigit());
            for c in run.chars() {
                out.push(if c.is_ascii_digit() {
                    char::from(b'0' + (rng.below(10) as u8))
                } else if hexy && c.is_ascii_hexdigit() {
                    let x = char::from(b'a' + rng.below(6) as u8);
                    if c.is_ascii_uppercase() {
                        x.to_ascii_uppercase()
                    } else {
                        x
                    }
                } else {
                    c
                });
            }
        }
        self.memo.insert(key, out.clone());
        out
    }
}

/// Maximal runs of alphanumerics and of everything else.
fn split_runs(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut prev: Option<bool> = None;
    for (i, c) in s.char_indices() {
        let a = c.is_ascii_alphanumeric();
        if prev.is_some_and(|p| p != a) {
            out.push(&s[start..i]);
            start = i;
        }
        prev = Some(a);
    }
    if start < s.len() {
        out.push(&s[start..]);
    }
    out
}

/// The template's URL with its host, identifiers and cache buster changed.
fn rewrite(
    tpl: &Template,
    host: &str,
    spec: &RunSpec,
    ids: &mut Ids,
    buster: Option<usize>,
) -> String {
    let mut url = replace_ci(&tpl.obs.url, &tpl.host, host);
    for f in &tpl.features {
        let scope = match (f, &spec.sink_scope) {
            (LinkFeature::Rule { rule, .. }, Some(s)) if rule.starts_with("exfil.") => s.as_str(),
            _ => spec.scope.as_str(),
        };
        let v = f.value();
        if v.len() < 3 {
            continue;
        }
        let new = match f {
            LinkFeature::Param { .. } => format!("{v}{}", ids.token(scope, v, 6)),
            LinkFeature::Rule { .. } => ids.swap(scope, v),
        };
        url = replace_ci(&url, v, &new);
    }
    // A captured secret is one client's: each run gets its own.
    let mut out = String::with_capacity(url.len());
    let mut rest = url.as_str();
    while let Some(p) = rest.find(SECRET) {
        let end = p + SECRET.len();
        let hex = rest[end..]
            .chars()
            .take_while(char::is_ascii_hexdigit)
            .count();
        out.push_str(&rest[..end]);
        out.push_str(&ids.token(&spec.scope, &rest[end..end + hex], hex));
        rest = &rest[end + hex..];
    }
    out.push_str(rest);
    url = out;
    if let Some(n) = buster {
        url = add_param(&url, "_", &n.to_string());
    }
    url
}

/// How redaction writes a secret: this prefix and hex digits.
const SECRET: &str = "REDACTED-";

/// `s` with every case-insensitive occurrence of `from` replaced.
fn replace_ci(s: &str, from: &str, to: &str) -> String {
    if from.is_empty() {
        return s.to_string();
    }
    let lower = s.to_ascii_lowercase();
    let needle = from.to_ascii_lowercase();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while let Some(p) = lower[i..].find(&needle) {
        out.push_str(&s[i..i + p]);
        out.push_str(to);
        i += p + needle.len();
    }
    out.push_str(&s[i..]);
    out
}

/// `url` with `name=value` appended to its query, before any fragment.
fn add_param(url: &str, name: &str, value: &str) -> String {
    let (base, frag) = match url.find('#') {
        Some(p) => (&url[..p], &url[p..]),
        None => (url, ""),
    };
    let sep = if base.contains('?') { '&' } else { '?' };
    format!("{base}{sep}{name}={value}{frag}")
}

/// `ts` as RFC 3339 in UTC, the form ingest reads back.
fn rfc3339(ts: i64) -> String {
    chrono::DateTime::from_timestamp(ts, 0)
        .map(|d| d.format("%Y-%m-%dT%H:%M:%SZ").to_string())
        .unwrap_or_default()
}

/// A synchronised worker's schedule: dispatch `r` comes `gaps[r]` after
/// dispatch `r - 1` (`gaps[0]` unused) and the worker's request `late[r]`
/// after it, never before its previous request. Returns the first request's
/// lateness and the gaps between requests, placed against the dispatches.
fn sync_times(gaps: &[i64], late: &[i64]) -> (i64, Vec<i64>) {
    let (mut dispatch, mut prev) = (0i64, 0i64);
    let mut out = Vec::with_capacity(gaps.len());
    for (r, g) in gaps.iter().enumerate() {
        if r > 0 {
            dispatch += g;
        }
        let at = (dispatch + late.get(r).copied().unwrap_or(0)).max(prev);
        out.push(if r == 0 { 0 } else { at - prev });
        prev = at;
    }
    (late.first().copied().unwrap_or(0), out)
}

fn gap(rng: &mut Rng, pace: Pace) -> i64 {
    let (lo, hi) = pace.bounds();
    rng.log_range(lo, hi).round().max(0.0) as i64
}

fn agent_client(rng: &mut Rng) -> Client {
    Client {
        ua: rng.pick(AGENT_UAS).copied().unwrap_or_default().into(),
        asn: rng.pick(CLOUD_ASNS).copied().unwrap_or_default(),
        ip: address(rng),
    }
}

fn browser_client(rng: &mut Rng) -> Client {
    Client {
        ua: rng.pick(BROWSER_UAS).copied().unwrap_or_default().into(),
        asn: rng.pick(ACCESS_ASNS).copied().unwrap_or_default(),
        ip: address(rng),
    }
}

fn address(rng: &mut Rng) -> String {
    format!(
        "{}.{}",
        rng.pick(NETS).copied().unwrap_or("192.0.2"),
        rng.range(1, 254)
    )
}

/// A seeded share of `pool` (at least two templates) for one scope: the
/// templates ranked by a draw keyed on the scope and their origin.
fn subset<'a>(pool: &'a [Template], seed: u64, key: &str, share: f64) -> Vec<&'a Template> {
    let rng = Rng::new(seed).fork("habits").fork(key);
    let mut ranked: Vec<(u64, &Template)> = pool
        .iter()
        .map(|t| (rng.fork(&t.origin).next_u64(), t))
        .collect();
    ranked.sort_by_key(|x| x.0);
    let n = ((pool.len() as f64 * share).ceil() as usize).clamp(2.min(pool.len()), pool.len());
    ranked.into_iter().take(n).map(|x| x.1).collect()
}

/// Whether `name` is one a harness adds.
#[cfg(test)]
pub(crate) fn is_harness_param(name: &str) -> bool {
    HARNESS_PARAMS.contains(&name)
}

/// Words a synthetic prompt template is built from, slot by slot: a verb, an
/// adjective and a thing, a preposition before the target, then another
/// verb, a determiner, a preposition, an adjective and a thing. Two
/// operators' templates share few word triples, as unrelated prompts do.
const PROMPT_SLOTS: &[&[&str]] = &[
    &[
        "find",
        "list",
        "check",
        "locate",
        "collect",
        "compare",
        "describe",
        "review",
        "map",
        "note",
        "record",
        "summarize",
        "verify",
        "inspect",
        "gather",
        "outline",
        "rank",
        "trace",
        "count",
        "flag",
    ],
    &[
        "public",
        "older",
        "hidden",
        "main",
        "default",
        "latest",
        "shared",
        "internal",
        "external",
        "unused",
        "slow",
        "legacy",
        "mobile",
        "archived",
        "primary",
        "secondary",
        "nested",
        "signed",
        "cached",
        "empty",
    ],
    &[
        "login page",
        "contact form",
        "search box",
        "upload form",
        "status page",
        "sitemap",
        "help center",
        "price list",
        "api route",
        "error page",
        "staff list",
        "news feed",
        "docs index",
        "release notes",
        "comment form",
        "account page",
        "cookie banner",
        "download area",
        "partner list",
        "privacy page",
    ],
    &[
        "on", "for", "at", "across", "within", "behind", "under", "near",
    ],
    &[
        "explain",
        "report",
        "write down",
        "tell me",
        "show",
        "quote",
        "estimate",
        "decide",
        "confirm",
        "check again",
        "measure",
        "repeat",
        "extract",
        "save",
        "test",
        "read",
        "group",
        "sort",
        "score",
        "mark",
    ],
    &[
        "every",
        "each",
        "any",
        "all",
        "the first",
        "the last",
        "both",
        "some",
    ],
    &[
        "from", "about", "inside", "beside", "after", "before", "under", "through",
    ],
    &[
        "visible", "broken", "recent", "odd", "large", "small", "plain", "careful", "strange",
        "dated", "quiet", "loud", "early", "late", "short", "long", "clear", "rough", "steady",
        "rare",
    ],
    &[
        "field",
        "header",
        "button",
        "link",
        "message",
        "answer",
        "form",
        "redirect",
        "cookie",
        "token name",
        "status code",
        "title",
        "footer",
        "banner",
        "menu",
        "image",
        "script name",
        "version string",
        "date",
        "label",
    ],
];

/// The prose request `r` of a run writing from the prompt templates of
/// `scope` carries for `host`: one of three seeded templates, in turn, with
/// the host as its target. Synthetic words only.
fn prompt_text(seed: u64, scope: &str, r: usize, host: &str) -> String {
    let mut rng = Rng::new(seed)
        .fork("prompt")
        .fork(scope)
        .fork(&(r % 3).to_string());
    let w: Vec<&str> = PROMPT_SLOTS
        .iter()
        .map(|slot| slot[rng.below(slot.len())])
        .collect();
    format!(
        "{} the {} {} {} {host} and {} {} {} {} the {} {}",
        w[0], w[1], w[2], w[3], w[4], w[5], w[8], w[6], w[7], w[2]
    )
}

/// `n` distinct harness parameter names, in a seeded order.
fn harness_names(rng: &mut Rng, n: usize) -> Vec<String> {
    let mut left: Vec<&str> = HARNESS_PARAMS.to_vec();
    let mut out = Vec::new();
    while out.len() < n && !left.is_empty() {
        out.push(left.remove(rng.below(left.len())).to_string());
    }
    out
}

/// `v` in a seeded order.
fn shuffle<T>(v: &mut [T], rng: &mut Rng) {
    for k in (1..v.len()).rev() {
        let j = rng.below(k + 1);
        v.swap(k, j);
    }
}

/// `n` hosts drawn round-robin from `hosts`, so each host gets a share.
fn spread(hosts: &[String], n: usize) -> Vec<String> {
    (0..n)
        .map(|k| hosts[k % hosts.len().max(1)].clone())
        .collect()
}

/// `n` records through `hosts` in order, each host's records together.
fn in_order(hosts: &[String], n: usize) -> Vec<String> {
    let per = n.div_ceil(hosts.len().max(1)).max(1);
    (0..n)
        .map(|k| hosts[(k / per).min(hosts.len() - 1)].clone())
        .collect()
}

/// One read per host first, then attacks.
fn read_then_attack(records: usize, hosts: usize) -> Vec<Use> {
    (0..records)
        .map(|k| {
            if k < hosts.min(records / 2) {
                Use::Read
            } else {
                Use::Attack
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn swap_keeps_shape_and_differs_by_scope() {
        let mut ids = Ids::new(3);
        let orig = "webhook.site/1a2b3c4d-0000-4abc-8def-1234567890ab";
        let a = ids.swap("s1", orig);
        let b = ids.swap("s2", orig);
        assert_eq!(a.len(), orig.len());
        assert!(a.starts_with("webhook.site/"));
        assert_ne!(a, b);
        assert_eq!(a, ids.swap("s1", orig));
    }

    #[test]
    fn a_palette_share_is_a_seeded_subset_per_scope() {
        let rules = sc_core::Rules::default_rules();
        let p = Palette::default_palette(&rules);
        let pool = p.get(Use::Attack);
        assert!(pool.len() >= 10);
        let ids = |v: Vec<&Template>| v.iter().map(|t| t.origin.clone()).collect::<Vec<_>>();
        let a = ids(subset(pool, 7, "0:1", 0.3));
        assert_eq!(a.len(), (pool.len() as f64 * 0.3).ceil() as usize);
        assert_eq!(a, ids(subset(pool, 7, "0:1", 0.3)));
        assert_ne!(a, ids(subset(pool, 7, "0:2", 0.3)));
        assert_eq!(subset(pool, 7, "0:1", 0.0).len(), 2);
    }

    #[test]
    fn sync_lateness_does_not_accumulate() {
        // Dispatches 10 s apart; a worker 30 s late on the first and on time
        // after. It waits for nothing it already sent, then is back on the
        // dispatches: its fifth request leaves at the fifth dispatch.
        let (first, gaps) = sync_times(&[0, 10, 10, 10, 10], &[30, 0, 0, 0, 0]);
        assert_eq!(first, 30);
        assert_eq!(gaps, [0, 0, 0, 0, 10]);
        assert_eq!(first + gaps.iter().sum::<i64>(), 40);
        // On time throughout: the gaps are the dispatches'.
        assert_eq!(sync_times(&[5, 7, 9], &[2, 2, 2]), (2, vec![0, 7, 9]));
    }

    #[test]
    fn retries_do_not_move_a_schedule() {
        let rules = sc_core::Rules::default_rules();
        let palette = Palette::default_palette(&rules);
        let file = crate::ScenarioFile::parse(
            "[[scenario]]\nname = \"t\"\n[[scenario.actor]]\nkind = \"agent\"\n",
        )
        .unwrap();
        let mut g = Gen {
            scenario: &file.scenario[0],
            seed: 1,
            palette: &palette,
            rng: Rng::new(1),
            t0: 0,
            out: Vec::new(),
            shapes: BTreeMap::new(),
            times: BTreeMap::new(),
            opts: RunOpts::default(),
        };
        let mut rng = Rng::new(2);
        let spec = |gaps: Vec<i64>, rng: &mut Rng| RunSpec {
            truth: Truth {
                label: Some("agent"),
                actor: "agent",
                class: "test".into(),
                run: format!("r{}", gaps[1]),
                swarm: None,
                fleet: None,
            },
            client: agent_client(rng),
            start: 1000,
            pace: Pace::Model,
            hosts: vec!["h0.t.example".to_string(); gaps.len()],
            uses: vec![Use::Attack; gaps.len()],
            gaps: Some(gaps),
            fixed: None,
            harness: Vec::new(),
            shapes: Vec::new(),
            scope: "0:0".into(),
            sink_scope: None,
            tag: true,
            retry: 1.0,
            writes: None,
            fetches: None,
            adapt: true,
            habits: None,
            prose: None,
        };
        // Every request fails twice and is retried, each retry at most a
        // model's pace later: well inside ten minutes.
        g.run(spec(vec![0, 600, 600, 600], &mut rng), &mut rng);
        let ts = &g.times["r600"];
        assert_eq!(ts.len(), 12);
        let firsts: Vec<i64> = ts.iter().step_by(3).copied().collect();
        assert_eq!(firsts, [1000, 1600, 2200, 2800]);
        // Retries longer than the schedule's gaps: the next request leaves
        // after the last retry, never before it, and the schedule resumes.
        g.run(spec(vec![0, 1, 1, 2000], &mut rng), &mut rng);
        let ts = &g.times["r1"];
        assert!(ts.windows(2).all(|w| w[0] <= w[1]), "{ts:?}");
        assert_eq!(ts[9], 3002, "{ts:?}");
    }

    #[test]
    fn replace_and_add_param() {
        assert_eq!(
            replace_ci(
                "https://r.jina.ai/https://Old.Example/x",
                "old.example",
                "h0.new.example"
            ),
            "https://r.jina.ai/https://h0.new.example/x"
        );
        assert_eq!(
            add_param("https://a.example/p#f", "_", "1"),
            "https://a.example/p?_=1#f"
        );
        assert_eq!(
            add_param("https://a.example/p?q=1", "_", "2"),
            "https://a.example/p?q=1&_=2"
        );
    }
}
