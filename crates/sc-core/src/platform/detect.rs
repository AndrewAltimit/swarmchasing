//! Grouping platform events into candidate swarms, and the chance model.

use super::automation::{benign_template, practice_target};
use super::text::BANDS;
use super::{
    Action, Basis, Burst, HintStrength, NewAccounts, Platform, PlatformEvent, PlatformOptions,
    PlatformReport, PlatformSwarm, Suppressed,
};
use crate::chance::TestFamily;
use crate::timing::poisson_at_least;
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// The span a burst is weighed against is at least this long, so a batch
/// read over a few minutes does not make every group look dense.
const MIN_SPAN_SECS: i64 = 3600;
/// The span is counted in clock hours.
const HOUR: i64 = 3600;
/// An hour holding at least this share of the busiest hour's events was
/// read in full; sparser hours hold only events carried from earlier runs.
const DENSE_SHARE: usize = 10;
/// Accounts' worth of the window's base rate an hour's own new-account
/// share is shrunk toward, so an hour with few other accounts reads near the
/// window's rate.
const HOUR_PRIOR: f64 = 5.0;

/// Grouped by its target ([`Action::by_target`]): no text, no name.
fn textless(e: &PlatformEvent) -> bool {
    e.action.by_target() && e.text.is_none() && e.name_template.is_none()
}

/// Detect candidate swarms in `events`, each platform on its own.
pub fn detect(events: &[PlatformEvent], opts: &PlatformOptions) -> PlatformReport {
    let mut by: BTreeMap<Platform, Vec<&PlatformEvent>> = BTreeMap::new();
    let mut seen = BTreeSet::new();
    for e in events {
        if seen.insert(e.id.as_str()) {
            by.entry(e.platform).or_default().push(e);
        }
    }
    let mut out = PlatformReport::default();
    for evs in by.values() {
        let r = detect_platform(evs, opts);
        out.events += r.events;
        out.accounts += r.accounts;
        out.swarms.extend(r.swarms);
        out.suppressed.extend(r.suppressed);
        out.below_threshold += r.below_threshold;
        out.carry.extend(r.carry);
        out.families.extend(r.families);
    }
    out.swarms.sort_by(|a, b| {
        b.strength
            .cmp(&a.strength)
            .then(a.p_chance.total_cmp(&b.p_chance))
            .then(a.id.cmp(&b.id))
    });
    out
}

struct Uf(Vec<usize>);

impl Uf {
    fn find(&mut self, mut x: usize) -> usize {
        while self.0[x] != x {
            self.0[x] = self.0[self.0[x]];
            x = self.0[x];
        }
        x
    }
    fn union(&mut self, a: usize, b: usize) {
        let (a, b) = (self.find(a), self.find(b));
        if a != b {
            self.0[a.max(b)] = a.min(b);
        }
    }
}

/// [`detect`] over one platform's events (distinct ids).
pub fn detect_platform(events: &[&PlatformEvent], opts: &PlatformOptions) -> PlatformReport {
    let mut ev: Vec<&PlatformEvent> = events.to_vec();
    ev.sort_by(|a, b| a.ts.cmp(&b.ts).then(a.id.cmp(&b.id)));
    let n = ev.len();
    let mut out = PlatformReport {
        events: n,
        ..Default::default()
    };
    if n == 0 {
        return out;
    }
    let platform = ev[0].platform;
    let mut uf = Uf((0..n).collect());

    // Text: one template, or a near-duplicate through any LSH band. Each
    // bucket's members are joined to its first member when the full
    // signatures agree, so one chance band collision joins nothing.
    let mut skeletons: HashMap<u64, Vec<usize>> = HashMap::new();
    let mut bands: HashMap<(usize, u64), Vec<usize>> = HashMap::new();
    let mut names: HashMap<(Action, &str), Vec<usize>> = HashMap::new();
    let mut targets: HashMap<(Action, &str), Vec<usize>> = HashMap::new();
    for (i, e) in ev.iter().enumerate() {
        if textless(e) {
            targets.entry((e.action, &e.target)).or_default().push(i);
        }
        if let Some(t) = e.text.as_ref().filter(|t| t.words >= opts.min_words) {
            skeletons.entry(t.skeleton).or_default().push(i);
            for b in 0..BANDS {
                if let Some(h) = t.band(b) {
                    bands.entry((b, h)).or_default().push(i);
                }
            }
        }
        if let Some(nt) = e.name_template.as_deref().filter(|_| e.action.creates()) {
            names.entry((e.action, nt)).or_default().push(i);
        }
    }
    for v in skeletons
        .values()
        .chain(names.values())
        .chain(targets.values())
    {
        for w in v.windows(2) {
            uf.union(w[0], w[1]);
        }
    }
    for v in bands.values() {
        let Some(t0) = ev[v[0]].text.as_ref() else {
            continue;
        };
        for &j in &v[1..] {
            if ev[j]
                .text
                .as_ref()
                .is_some_and(|t| t0.similarity(t) >= opts.similarity)
            {
                uf.union(v[0], j);
            }
        }
    }

    // Window-wide baselines: the hours read in full, and the share of
    // accounts that are new. A burst is weighed against the hours read in
    // full, not first event to last: a batch of freshly read hours plus
    // sparse events carried from earlier runs saw only those hours, and
    // weighing a burst against the days between would make every small
    // group look dense.
    let mut per_hour: BTreeMap<i64, usize> = BTreeMap::new();
    for e in &ev {
        *per_hour.entry(e.ts.div_euclid(HOUR)).or_default() += 1;
    }
    let busiest = per_hour.values().copied().max().unwrap_or(0);
    let dense: BTreeSet<i64> = per_hour
        .iter()
        .filter(|&(_, &c)| c * DENSE_SHARE >= busiest)
        .map(|(&h, _)| h)
        .collect();
    let max_rank = ev.iter().filter_map(|e| e.actor_rank).max();
    let is_new = |e: &PlatformEvent| -> Option<bool> {
        let by_rank = e
            .actor_rank
            .zip(max_rank)
            .map(|(r, m)| r + opts.new_account_ranks >= m);
        match (e.first_timer, by_rank) {
            (Some(true), _) | (_, Some(true)) => Some(true),
            (Some(false), _) | (_, Some(false)) => Some(false),
            _ => None,
        }
    };
    let mut account_age: BTreeMap<&str, bool> = BTreeMap::new();
    for e in &ev {
        if e.actor.is_empty() {
            continue;
        }
        if let Some(new) = is_new(e) {
            let v = account_age.entry(&e.actor).or_insert(false);
            *v |= new;
        }
    }
    let all_accounts: BTreeSet<&str> = ev
        .iter()
        .filter(|e| !e.actor.is_empty())
        .map(|e| e.actor.as_str())
        .collect();
    // Each account's first hour in the window (events are in time order),
    // and per hour the accounts with age data first seen in it and how many
    // of them are new: the new-account rate is read in the same hours as a
    // group's accounts, so a wave of new accounts that lifts every group in
    // those hours does not count twice.
    let mut first_hour: BTreeMap<&str, i64> = BTreeMap::new();
    for e in &ev {
        if !e.actor.is_empty() {
            first_hour
                .entry(e.actor.as_str())
                .or_insert(e.ts.div_euclid(HOUR));
        }
    }
    let mut hour_age: BTreeMap<i64, (usize, usize)> = BTreeMap::new();
    for (a, new) in &account_age {
        if let Some(h) = first_hour.get(a) {
            let c = hour_age.entry(*h).or_default();
            c.0 += 1;
            c.1 += usize::from(*new);
        }
    }
    out.accounts = all_accounts.len();
    let with_age = account_age.len();
    let base_rate = if with_age > 0 {
        (account_age.values().filter(|&&v| v).count() as f64 / with_age as f64)
            .max(1.0 / with_age as f64)
    } else {
        0.0
    };

    let mut groups: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for i in 0..n {
        let r = uf.find(i);
        groups.entry(r).or_default().push(i);
    }
    let mut carry: BTreeSet<usize> = BTreeSet::new();
    for (i, e) in ev.iter().enumerate() {
        if e.text.as_ref().is_some_and(|t| !t.residue.is_empty()) {
            carry.insert(i);
        }
    }
    // Groups weighed against chance: (swarm, chance, residue-heavy).
    let mut weighed: Vec<(super::PlatformSwarm, f64, bool)> = Vec::new();
    let mut tested = 0usize;
    for members in groups.values().filter(|m| m.len() >= 2) {
        let accounts: BTreeSet<&str> = members
            .iter()
            .map(|&i| ev[i].actor.as_str())
            .filter(|a| !a.is_empty())
            .collect();
        // Text-less events on one target are common (a popular repository
        // draws stars all day); only a group with new accounts in it is
        // worth carrying.
        let by_target = members.iter().all(|&i| textless(ev[i]));
        let carry_it = if by_target {
            accounts
                .iter()
                .filter(|a| account_age.get(*a).copied().unwrap_or(false))
                .count()
                >= 2
        } else {
            accounts.len() >= 2 || accounts.is_empty()
        };
        if carry_it {
            carry.extend(members.iter().copied());
        }
        let enough = accounts.len() >= opts.min_accounts
            || (accounts.is_empty() && members.len() >= opts.min_flood);
        if !enough {
            continue;
        }
        let g = Group {
            ev: &ev,
            members,
            accounts: &accounts,
            opts,
        };
        let template = g.template();
        if by_target && practice_target(&ev[members[0]].target) {
            out.suppressed.push(Suppressed {
                platform,
                why: "practice repository".into(),
                events: members.len(),
                accounts: accounts.len(),
                template: ev[members[0]].target.clone(),
            });
            continue;
        }
        if let Some(why) = benign_template(&template).filter(|_| !by_target) {
            out.suppressed.push(Suppressed {
                platform,
                why: why.to_string(),
                events: members.len(),
                accounts: accounts.len(),
                template,
            });
            continue;
        }
        // The hours read in full, and the group's own hours.
        let mut hours = dense.clone();
        hours.extend(members.iter().map(|&i| ev[i].ts.div_euclid(HOUR)));
        let span = (hours.len() as i64 * HOUR).max(MIN_SPAN_SECS);
        tested += 1;
        let burst = g.burst(span);
        let new_accounts = g.new_accounts(&account_age, base_rate, &first_hour, &hour_age);
        let residue = g.residue();
        let texts = members.iter().filter(|&&i| ev[i].text.is_some()).count();
        let with_residue = members
            .iter()
            .filter(|&&i| ev[i].text.as_ref().is_some_and(|t| !t.residue.is_empty()))
            .count();
        let residue_heavy = texts > 0
            && with_residue as f64 / texts as f64 >= opts.residue_share
            && accounts.len() >= opts.min_accounts;
        let p_age = new_accounts.as_ref().map_or(1.0, |a| a.p_chance);
        // The new-account chance is read in the group's own hours, so given
        // its timing it is independent of the burst chance; the product of
        // two such chances is weighed as one (`x (1 - ln x)`).
        let p = match &new_accounts {
            Some(a) => crate::chance::product_chance(burst.p_chance, a.p_chance),
            None => burst.p_chance,
        };
        // A burst on one owner's repositories by established accounts is
        // what an outage, a release or a linked discussion looks like.
        let owners: BTreeSet<&str> = members.iter().map(|&i| ev[i].owner()).collect();
        let one_owner_burst = owners.len() == 1
            && !owners.contains("")
            && !accounts.is_empty()
            && p_age > opts.max_chance
            && !residue_heavy;
        // A text-less group, or a group of wiki edits, needs a burst of its
        // own: new editors' sandboxes and a new project's first stars come
        // from new accounts by nature, so account age alone says nothing.
        let needs_burst = by_target || platform == Platform::Wikimedia;
        let no_burst = needs_burst && burst.p_chance > opts.max_chance;
        if (p > opts.max_chance && !residue_heavy) || one_owner_burst || no_burst {
            out.below_threshold += 1;
            continue;
        }
        let swarm = g.swarm(
            platform,
            template,
            burst,
            new_accounts,
            residue,
            p,
            residue_heavy,
        );
        weighed.push((swarm, p, residue_heavy));
    }
    // Every group weighed is a test: those kept on their chance are cut at a
    // false discovery rate over them all. Residue-heavy groups stand on their
    // residue.
    let ps: Vec<f64> = weighed
        .iter()
        .filter(|w| w.1 <= opts.max_chance)
        .map(|w| w.1)
        .collect();
    let family = TestFamily::cut(
        &format!("platform:{}", platform.name()),
        &ps,
        tested,
        opts.fdr,
    );
    for (mut swarm, p, residue_heavy) in weighed {
        if residue_heavy || family.keeps(p) {
            swarm.tested = tested;
            swarm.reason.push_str(&format!(
                "; {:.2} such groups expected among {tested} weighed",
                p * tested as f64
            ));
            out.swarms.push(swarm);
        } else {
            out.below_threshold += 1;
        }
    }
    out.families.push(family);
    out.carry = carry.into_iter().map(|i| ev[i].id.clone()).collect();
    out
}

struct Group<'a> {
    ev: &'a [&'a PlatformEvent],
    members: &'a [usize],
    accounts: &'a BTreeSet<&'a str>,
    opts: &'a PlatformOptions,
}

impl Group<'_> {
    /// The representative's slotted text: the most common skeleton's first
    /// member, or the most common name template.
    fn template(&self) -> String {
        let mut sk: BTreeMap<u64, (usize, usize)> = BTreeMap::new();
        let mut nt: BTreeMap<&str, usize> = BTreeMap::new();
        for &i in self.members {
            if let Some(t) = &self.ev[i].text {
                let e = sk.entry(t.skeleton).or_insert((0, i));
                e.0 += 1;
            }
            if let Some(n) = &self.ev[i].name_template {
                *nt.entry(n).or_default() += 1;
            }
        }
        let text = sk
            .values()
            .max_by_key(|(c, i)| (*c, std::cmp::Reverse(*i)))
            .and_then(|&(_, i)| self.ev[i].text.as_ref())
            .map(|t| t.excerpt.clone());
        let name = nt
            .iter()
            .max_by_key(|(_, c)| **c)
            .map(|(n, _)| n.to_string());
        match (text, name) {
            (Some(t), Some(n)) => format!("{n}: {t}"),
            (Some(t), None) => t,
            (None, Some(n)) => n,
            (None, None) if self.textless() => {
                let e = self.ev[self.members[0]];
                format!("{} on {}", e.action.label(), e.target)
            }
            (None, None) => String::new(),
        }
    }

    fn rep(&self) -> Option<&super::TextSketch> {
        self.members.iter().find_map(|&i| self.ev[i].text.as_ref())
    }

    fn basis(&self) -> Vec<Basis> {
        let mut b = Vec::new();
        let texts: Vec<&super::TextSketch> = self
            .members
            .iter()
            .filter_map(|&i| self.ev[i].text.as_ref())
            .collect();
        if texts.len() >= 2 {
            let mut counts: BTreeMap<u64, usize> = BTreeMap::new();
            for t in &texts {
                *counts.entry(t.skeleton).or_default() += 1;
            }
            if counts.values().any(|&c| c >= 2) {
                b.push(Basis::Template);
            }
            if counts.len() > 1 {
                b.push(Basis::NearDuplicate);
            }
        }
        let named = self
            .members
            .iter()
            .filter(|&&i| self.ev[i].name_template.is_some())
            .count();
        if named >= 2 {
            b.push(Basis::NameTemplate);
        }
        if self.textless() {
            b.push(Basis::Target);
        }
        b
    }

    fn textless(&self) -> bool {
        self.members.len() >= 2 && self.members.iter().all(|&i| textless(self.ev[i]))
    }

    fn self_id(&self) -> Vec<(String, usize)> {
        let mut c: BTreeMap<&str, usize> = BTreeMap::new();
        for &i in self.members {
            for r in self.ev[i].text.iter().flat_map(|t| &t.self_id) {
                *c.entry(r).or_default() += 1;
            }
        }
        c.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
    }

    /// The densest window among the group's points (each account's first
    /// event; each event when the source names no account), and the chance
    /// of a window that dense anywhere in the span: a scan statistic,
    /// `span / window` windows each holding a Poisson count with the
    /// group's mean.
    fn burst(&self, span: i64) -> Burst {
        let mut first: BTreeMap<&str, i64> = BTreeMap::new();
        let mut anon = Vec::new();
        for &i in self.members {
            let e = self.ev[i];
            if e.actor.is_empty() {
                anon.push(e.ts);
            } else {
                let t = first.entry(&e.actor).or_insert(e.ts);
                *t = (*t).min(e.ts);
            }
        }
        let mut pts: Vec<i64> = first.into_values().chain(anon).collect();
        crate::sort::sort(&mut pts);
        let w = self.opts.burst_secs.max(1);
        let (mut best, mut start, mut j) = (0, pts.first().copied().unwrap_or(0), 0);
        for i in 0..pts.len() {
            while pts[i] - pts[j] > w {
                j += 1;
            }
            if i + 1 - j > best {
                best = i + 1 - j;
                start = pts[j];
            }
        }
        let k = pts.len();
        let expected = k as f64 * w as f64 / span.max(w) as f64;
        let tol = self.opts.clock_tolerance_secs;
        let r = start.rem_euclid(3600);
        let on_the_hour = r <= tol || r >= 3600 - tol;
        let weight = if on_the_hour {
            (best as f64 * self.opts.clock_weight).floor() as usize
        } else {
            best
        };
        let windows = (span as f64 / w as f64).max(1.0);
        let p_chance = if span <= w || best < 2 {
            1.0
        } else {
            (windows * poisson_at_least(expected, weight)).min(1.0)
        };
        Burst {
            start,
            window_secs: w,
            in_window: best,
            of: k,
            span_secs: span,
            expected,
            p_chance,
            on_the_hour,
        }
    }

    /// New accounts in the group, each account against the new-account
    /// share of the other accounts first seen in its hour, shrunk toward the
    /// window's base rate (a Poisson-binomial tail).
    fn new_accounts(
        &self,
        age: &BTreeMap<&str, bool>,
        base_rate: f64,
        first_hour: &BTreeMap<&str, i64>,
        hour_age: &BTreeMap<i64, (usize, usize)>,
    ) -> Option<NewAccounts> {
        let known: Vec<(&str, bool)> = self
            .accounts
            .iter()
            .filter_map(|a| age.get(a).map(|&v| (*a, v)))
            .collect();
        if known.is_empty() || base_rate <= 0.0 {
            return None;
        }
        // The group's own accounts per hour, left out of that hour's share.
        let mut own: BTreeMap<i64, (usize, usize)> = BTreeMap::new();
        for (a, v) in &known {
            if let Some(h) = first_hour.get(a) {
                let c = own.entry(*h).or_default();
                c.0 += 1;
                c.1 += usize::from(*v);
            }
        }
        let rates: Vec<f64> = known
            .iter()
            .map(|(a, _)| {
                let Some(h) = first_hour.get(a) else {
                    return base_rate;
                };
                let (all, new) = hour_age.get(h).copied().unwrap_or_default();
                let (mine, mine_new) = own.get(h).copied().unwrap_or_default();
                let (others, others_new) = (all.saturating_sub(mine), new.saturating_sub(mine_new));
                ((others_new as f64 + HOUR_PRIOR * base_rate) / (others as f64 + HOUR_PRIOR))
                    .clamp(base_rate.min(1.0), 1.0)
            })
            .collect();
        let new = known.iter().filter(|(_, v)| *v).count();
        let p_chance = if new < 2 {
            1.0
        } else {
            crate::chance::at_least(&rates, new)
        };
        Some(NewAccounts {
            new,
            of: known.len(),
            base_rate,
            hour_rate: rates.iter().sum::<f64>() / rates.len() as f64,
            p_chance,
        })
    }

    fn residue(&self) -> Vec<(String, usize)> {
        let mut c: BTreeMap<&str, usize> = BTreeMap::new();
        for &i in self.members {
            for r in self.ev[i].text.iter().flat_map(|t| &t.residue) {
                *c.entry(r).or_default() += 1;
            }
        }
        c.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
    }

    #[allow(clippy::too_many_arguments)]
    fn swarm(
        &self,
        platform: Platform,
        template: String,
        burst: Burst,
        new_accounts: Option<NewAccounts>,
        residue: Vec<(String, usize)>,
        p: f64,
        residue_heavy: bool,
    ) -> PlatformSwarm {
        let ev = self.ev;
        let m = self.members;
        let mut actions: BTreeMap<Action, usize> = BTreeMap::new();
        let mut targets: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
        for &i in m {
            *actions.entry(ev[i].action).or_default() += 1;
            let who = if ev[i].actor.is_empty() {
                ev[i].id.as_str()
            } else {
                ev[i].actor.as_str()
            };
            targets.entry(&ev[i].target).or_default().insert(who);
        }
        let distinct_targets = targets.len();
        let mut tl: Vec<(String, usize)> = targets
            .iter()
            .map(|(t, a)| (t.to_string(), a.len()))
            .collect();
        tl.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        tl.truncate(10);
        let similarity = self.rep().map(|r| {
            let s: Vec<f64> = m
                .iter()
                .filter_map(|&i| ev[i].text.as_ref())
                .take(50)
                .map(|t| r.similarity(t))
                .collect();
            s.iter().sum::<f64>() / s.len() as f64
        });
        let owners: BTreeSet<&str> = m.iter().map(|&i| ev[i].owner()).collect();

        let o = self.opts;
        let mut signals = Vec::new();
        if burst.p_chance <= o.max_chance {
            signals.push("burst");
        }
        if new_accounts
            .as_ref()
            .is_some_and(|a| a.p_chance <= o.max_chance)
        {
            signals.push("new accounts");
        }
        if residue_heavy {
            signals.push("residue");
        }
        let shared_target = tl.first().is_some_and(|t| t.1 >= o.min_accounts);
        if shared_target && distinct_targets >= 2 && owners.len() >= 2 {
            signals.push("target overlap");
        }
        let strength = if p <= o.moderate_chance && signals.len() >= 2 {
            HintStrength::Moderate
        } else {
            HintStrength::Weak
        };

        let mut caveats = Vec::new();
        if burst.on_the_hour {
            caveats.push(format!(
                "the burst starts on a clock hour, as scheduled jobs do; counted at {:.0}%",
                o.clock_weight * 100.0
            ));
        }
        if owners.len() == 1 && !owners.contains("") && distinct_targets > 1 {
            caveats.push(
                "every target belongs to one owner: org-wide automation or a migration by its members is possible".into(),
            );
        }
        if distinct_targets == 1 {
            caveats.push(
                "one target only: a call for contributions or a linked discussion can draw many accounts at once".into(),
            );
        }
        match &new_accounts {
            None => caveats.push("no account-age data on this platform".into()),
            Some(a) if a.new == 0 => caveats.push("no account is new".into()),
            _ => {}
        }
        let (start, end) = (ev[m[0]].ts, ev[m[m.len() - 1]].ts);
        if end - start > 86_400 {
            caveats.push("spread over more than a day".into());
        }
        if self.accounts.is_empty() {
            caveats.push(
                "the source names no accounts: one publisher may account for all of it".into(),
            );
        }
        if self.textless() {
            caveats.push(
                "no text: grouped by the one target they acted on; a launch, a giveaway or a link shared elsewhere draws stars, forks and pull requests in bursts too".into(),
            );
        } else if similarity.is_none() {
            caveats.push("no text: grouped by name only".into());
        }
        let self_id = self.self_id();
        if !self_id.is_empty() {
            caveats.push(
                "coding-harness self-identification is weak context: people use these harnesses for their own work".into(),
            );
        }

        let mut reason = format!(
            "{} {} from {} account(s) on {} target(s)",
            m.len(),
            match actions.len() {
                1 => actions.keys().next().map_or("events", |a| a.label()),
                _ => "events",
            },
            self.accounts.len(),
            distinct_targets
        );
        let _ = std::fmt::Write::write_fmt(
            &mut reason,
            format_args!(
                "; {} of {} in one {} min window, {:.2} expected (p {:.1e})",
                burst.in_window,
                burst.of,
                burst.window_secs / 60,
                burst.expected,
                burst.p_chance
            ),
        );
        if let Some(a) = &new_accounts {
            let _ = std::fmt::Write::write_fmt(
                &mut reason,
                format_args!(
                    "; {} of {} accounts new against {:.0}% in the same hours and {:.0}% over the window (p {:.1e})",
                    a.new,
                    a.of,
                    a.hour_rate * 100.0,
                    a.base_rate * 100.0,
                    a.p_chance
                ),
            );
        }
        if !residue.is_empty() {
            let n: usize = m
                .iter()
                .filter(|&&i| ev[i].text.as_ref().is_some_and(|t| !t.residue.is_empty()))
                .count();
            let _ = std::fmt::Write::write_fmt(
                &mut reason,
                format_args!("; {n} carry model-output residue"),
            );
        }
        if !self_id.is_empty() {
            let n: usize = m
                .iter()
                .filter(|&&i| ev[i].text.as_ref().is_some_and(|t| !t.self_id.is_empty()))
                .count();
            let _ = std::fmt::Write::write_fmt(
                &mut reason,
                format_args!("; {n} name a coding harness"),
            );
        }
        let earliest = &ev[m[0]].id;
        let id = format!(
            "PS-{:08x}",
            super::text::splitmix(super::text::fnv(
                format!("platform-swarm\0{earliest}").as_bytes()
            )) >> 32
        );
        PlatformSwarm {
            id,
            platform,
            basis: self.basis(),
            actions: actions.into_iter().collect(),
            events: m.len(),
            accounts: self.accounts.len(),
            start,
            end,
            template,
            similarity,
            burst,
            new_accounts,
            residue,
            self_id,
            targets: tl,
            distinct_targets,
            p_chance: p,
            tested: 0,
            strength,
            caveats,
            links: m.iter().take(10).map(|&i| ev[i].link.clone()).collect(),
            members: m.iter().map(|&i| ev[i].id.clone()).collect(),
            reason,
            provenance: None,
        }
    }
}
