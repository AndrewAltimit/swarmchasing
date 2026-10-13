//! Labelled records from a scenario.
//!
//! Each actor becomes one or more runs: a client (user agent, network,
//! address), a start, a pace and a list of target hosts. Each record copies
//! a [`Template`] from the palette and changes only its target host, its
//! linking identifiers (per run, or per swarm for a shared inbox) and, for a
//! retry, a cache-busting parameter. The ground truth goes on each record as
//! the evaluation set's label fields, so the output is also an ordinary
//! labelled file for `swarmchase eval` and `swarmchase sim score`.

use crate::palette::{Palette, Template, Use};
use crate::rng::Rng;
use crate::scenario::{Actor, Basis, Kind, Mode, Pace, Scenario};
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

/// Hosting networks agents run from, and access networks people use.
const CLOUD_ASNS: &[u32] = &[16509, 14061, 24940, 396982, 8075, 63949, 14618];
const ACCESS_ASNS: &[u32] = &[7922, 3320, 2856, 701, 3215, 6830];

/// Documentation address blocks (RFC 5737), so no generated address is real.
const NETS: &[&str] = &["192.0.2", "198.51.100", "203.0.113"];

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
}

/// The palette subset an actor's runs draw from under `key`, when it does
/// not use the whole palette.
fn habits(a: &Actor, key: String) -> Option<(String, f64)> {
    (a.palette_share < 1.0).then(|| (key, a.palette_share.max(0.0)))
}

struct Gen<'a> {
    scenario: &'a Scenario,
    seed: u64,
    palette: &'a Palette,
    rng: Rng,
    t0: i64,
    out: Vec<Value>,
}

/// The labelled records of one scenario under one seed, in time order.
pub fn generate(s: &Scenario, seed: u64, palette: &Palette) -> Vec<Value> {
    let mut g = Gen {
        scenario: s,
        seed,
        palette,
        rng: Rng::new(seed).fork(&s.name),
        t0: sc_core::parse_ts(&s.start).unwrap_or(0),
        out: Vec::new(),
    };
    for (i, a) in s.actor.iter().enumerate() {
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
                for k in 0..a.agents {
                    let hosts = self.hosts(&format!("a{i}x{k}"), a.hosts);
                    let spec = RunSpec {
                        truth: agent_truth(id(k), Some("none".into()), None, "single_agent"),
                        client: agent_client(&mut rng),
                        start: start + rng.range(0, span),
                        pace: a.pace.unwrap_or(Pace::Model),
                        gaps: None,
                        hosts: spread(&hosts, a.records),
                        uses: read_then_attack(a.records, a.hosts),
                        fixed: None,
                        scope: format!("{i}:{k}"),
                        sink_scope: None,
                        tag: a.tag,
                        retry: a.retry,
                        writes: None,
                        fetches: None,
                        adapt: true,
                        habits: habits(a, format!("{i}:{k}")),
                    };
                    self.run(spec, &mut rng);
                }
            }
            Kind::Swarm => self.swarm(i, a, start, &mut rng),
            Kind::Fleet => {
                let fleet = format!("{}-f{i}", self.scenario.name);
                let scaffold = self.scaffold(&mut rng);
                let ua = rng.pick(AGENT_UAS).copied().unwrap_or_default().to_string();
                for k in 0..a.agents {
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
                        start: start + k as i64 * 26 * 3600 + rng.range(0, 3 * 3600),
                        pace: a.pace.unwrap_or(Pace::Model),
                        gaps: None,
                        hosts: spread(&hosts, a.records),
                        uses: vec![Use::Attack; a.records],
                        fixed: Some(scaffold.clone()),
                        scope: format!("{i}:{k}"),
                        sink_scope: None,
                        tag: a.tag,
                        retry: a.retry,
                        writes: None,
                        fetches: None,
                        adapt: true,
                        habits: None,
                    };
                    self.run(spec, &mut rng);
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
                        scope: format!("{i}:{k}"),
                        sink_scope: None,
                        tag: a.tag,
                        retry: a.retry,
                        writes: None,
                        fetches: None,
                        adapt: true,
                        habits: habits(a, format!("{i}")),
                    };
                    self.run(spec, &mut rng);
                }
            }
            Kind::Planter => {
                let Some(victim) = a.copies else { return };
                for k in 0..a.agents {
                    let hosts = self.hosts(&format!("a{i}x{k}"), a.hosts);
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
                        start: start + rng.range(0, 24 * 3600),
                        pace: a.pace.unwrap_or(Pace::Human),
                        gaps: None,
                        hosts: spread(&hosts, a.records),
                        uses: vec![Use::Sink; a.records],
                        fixed: None,
                        scope: format!("{victim}:0"),
                        sink_scope: Some(format!("{victim}:sink")),
                        tag: a.tag,
                        retry: 0.0,
                        writes: None,
                        fetches: None,
                        adapt: true,
                        habits: None,
                    };
                    self.run(spec, &mut rng);
                }
            }
            _ => self.background(i, a, start, span, &mut rng),
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
            let begin = if handoff && k > 0 {
                t + rng.range(5 * 60, 45 * 60)
            } else if has(Mode::Roles) && k > 0 {
                t + rng.range(15 * 60, 90 * 60)
            } else if has(Mode::Sync) {
                start + rng.range(0, 20)
            } else {
                start + rng.range(0, 300)
            };
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
                gaps: has(Mode::Sync)
                    .then(|| sync_gaps.iter().map(|g| g + rng.range(-1, 1)).collect()),
                // A reader and an attacker go through the hosts in one order.
                hosts: if has(Mode::Roles) {
                    in_order(&hosts, a.records)
                } else {
                    spread(&hosts, a.records)
                },
                uses,
                fixed: None,
                scope: format!("{i}:{k}"),
                sink_scope: has(Mode::Sink).then(|| format!("{i}:sink")),
                tag: a.tag,
                retry: a.retry,
                writes: (handoff && k == 0).then(|| note.clone()),
                fetches: (handoff && k > 0).then(|| raw.clone()),
                adapt: true,
                habits: habits(a, format!("{i}")),
            };
            let end = self.run(spec, rng);
            if reader {
                t = end;
            }
        }
    }

    fn background(&mut self, i: usize, a: &Actor, start: i64, span: i64, rng: &mut Rng) {
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
                start + rng.range(0, span)
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
            scope: format!("{i}:{k}"),
            sink_scope: None,
            tag: false,
            retry: a.retry,
            writes: None,
            fetches: None,
            adapt,
            habits: habits(a, format!("{i}:{k}")),
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
    fn run(&mut self, spec: RunSpec, rng: &mut Rng) -> i64 {
        let mut t = spec.start;
        let mut step = 0usize;
        let mut ids = Ids::new(self.seed);
        let basis = self.scenario.basis;
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
        for (r, (host, u)) in spec.hosts.iter().zip(&spec.uses).enumerate() {
            let pool: Vec<&Template> = match &spec.fixed {
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
            let Some(tpl) = rng.pick(&pool).copied() else {
                continue;
            };
            if r > 0 {
                t += spec
                    .gaps
                    .as_ref()
                    .and_then(|g| g.get(r).copied())
                    .unwrap_or_else(|| gap(rng, spec.pace));
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
                if spec.tag && u != &Use::Benign {
                    let tag = ids.token(&spec.scope, "uqtag", 10);
                    url = add_param(&url, "uqtag", &format!("r{tag}"));
                }
                if let Some(w) = &spec.writes {
                    url = add_param(&url, "notes", w);
                }
                let status = (basis == Basis::Request).then_some(if error && k + 1 < tries {
                    404
                } else {
                    200
                });
                self.emit(&spec, &tpl.origin, url, t, status, basis);
                step += 1;
            }
        }
        let _ = step;
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
