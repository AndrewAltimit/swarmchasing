//! Synthetic swarms against benign floods. Every account, repository and
//! text here is invented.

use super::*;
use crate::rules::Rules;

const T0: i64 = 1_791_500_000;
const HOUR: i64 = 3600;

/// Deterministic pseudo-random words, so background texts differ.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 33
    }
    fn sentence(&mut self, words: usize) -> String {
        const V: [&str; 40] = [
            "build",
            "fails",
            "when",
            "the",
            "cache",
            "is",
            "cold",
            "and",
            "tests",
            "time",
            "out",
            "on",
            "linux",
            "docs",
            "mention",
            "flag",
            "that",
            "no",
            "longer",
            "exists",
            "please",
            "add",
            "support",
            "for",
            "arm",
            "wheels",
            "crash",
            "after",
            "upgrade",
            "memory",
            "grows",
            "until",
            "killed",
            "typo",
            "readme",
            "example",
            "returns",
            "wrong",
            "value",
            "sometimes",
        ];
        (0..words)
            .map(|_| V[(self.next() % V.len() as u64) as usize])
            .collect::<Vec<_>>()
            .join(" ")
    }
}

struct Ev {
    id: String,
    ts: i64,
    actor: String,
    rank: Option<u64>,
    target: &'static str,
    action: Action,
    platform: Platform,
}

fn ev(e: Ev, text: Option<&str>, rules: &Rules) -> PlatformEvent {
    let p = PlatformEvent {
        id: e.id.clone(),
        platform: e.platform,
        action: e.action,
        ts: e.ts,
        actor: if e.actor.is_empty() {
            String::new()
        } else {
            actor_key(e.platform, &e.actor)
        },
        actor_rank: e.rank,
        first_timer: None,
        target: e.target.into(),
        link: format!("https://github.com/{}/issues/{}", e.target, e.id),
        ..Default::default()
    };
    match text {
        Some(t) => p.with_text(t, &[e.target], rules),
        None => p,
    }
}

/// Six hours of ordinary issues and comments from established accounts.
fn background(rules: &Rules, n: usize) -> Vec<PlatformEvent> {
    let mut r = Lcg(7);
    const REPOS: [&str; 6] = [
        "alpha/one",
        "beta/two",
        "gamma/three",
        "delta/four",
        "eps/five",
        "zeta/six",
    ];
    (0..n)
        .map(|i| {
            let words = 10 + (r.next() % 20) as usize;
            let text = r.sentence(words);
            ev(
                Ev {
                    id: format!("bg{i}"),
                    ts: T0 + (r.next() % (6 * HOUR) as u64) as i64,
                    actor: format!("person{i}"),
                    rank: Some(10_000 + r.next() % 150_000),
                    target: REPOS[i % REPOS.len()],
                    action: Action::Comment,
                    platform: Platform::Github,
                },
                Some(&text),
                rules,
            )
        })
        .collect()
}

/// `n` accounts posting `text(i)` to `target(i)` from `start`, `gap` apart.
#[allow(clippy::too_many_arguments)]
fn wave(
    rules: &Rules,
    tag: &str,
    n: usize,
    start: i64,
    gap: i64,
    rank: impl Fn(usize) -> Option<u64>,
    target: impl Fn(usize) -> &'static str,
    text: impl Fn(usize) -> String,
) -> Vec<PlatformEvent> {
    (0..n)
        .map(|i| {
            ev(
                Ev {
                    id: format!("{tag}{i}"),
                    ts: start + i as i64 * gap,
                    actor: format!("{tag}-acct{i}"),
                    rank: rank(i),
                    target: target(i),
                    action: Action::IssueOpened,
                    platform: Platform::Github,
                },
                Some(&text(i)),
                rules,
            )
        })
        .collect()
}

const VICTIMS: [&str; 6] = [
    "libfoo/core",
    "barcorp/api",
    "quux/server",
    "acme/widgets",
    "nimbus/cli",
    "orbit/web",
];

fn agent_report(i: usize) -> String {
    format!(
        "Certainly! Here's the security report. I identified a critical remote code execution vulnerability in {} at src/handler{i}.py line {}. An attacker can exploit this to gain full control. Please patch immediately and credit [Insert GitHub username].",
        VICTIMS[i % VICTIMS.len()],
        40 + i
    )
}

#[test]
fn a_new_account_swarm_filing_templated_reports_is_found() {
    let rules = Rules::default_rules();
    let mut evs = background(&rules, 400);
    evs.extend(wave(
        &rules,
        "sw",
        6,
        T0 + 2 * HOUR + 17 * 60,
        70,
        |i| Some(160_400 + i as u64),
        |i| VICTIMS[i],
        agent_report,
    ));
    let rep = detect(&evs, &PlatformOptions::default());
    assert_eq!(rep.swarms.len(), 1, "{:#?}", rep.swarms);
    let s = &rep.swarms[0];
    assert_eq!((s.events, s.accounts, s.distinct_targets), (6, 6, 6));
    assert_eq!(s.strength, HintStrength::Moderate, "{}", s.reason);
    assert!(s.basis.contains(&Basis::Template), "{:?}", s.basis);
    assert_eq!(s.burst.in_window, 6);
    assert!(s.burst.p_chance < 1e-4, "{}", s.reason);
    let a = s.new_accounts.as_ref().unwrap();
    assert_eq!(a.new, 6);
    assert!(a.p_chance < 1e-3);
    assert!(
        s.residue
            .iter()
            .any(|(r, n)| r == "text.chat_opener" && *n == 6),
        "{:?}",
        s.residue
    );
    assert!(s.id.starts_with("PS-") && s.id.len() == 11);
    assert!(!s.template.contains("libfoo"), "{}", s.template);
    // Every member is worth carrying to the next run.
    assert!(s.members.iter().all(|m| rep.carry.contains(m)));
    assert_eq!(rep.events, 406);
}

/// Four new accounts filing one template forty minutes apart in hour 2.
fn slow_template(rules: &Rules) -> Vec<PlatformEvent> {
    wave(
        rules,
        "tp",
        4,
        T0 + 2 * HOUR + 60,
        600,
        |i| Some(160_700 + i as u64),
        |i| VICTIMS[i],
        |i| {
            format!(
                "Security issue found in {} affecting the handler{i} module, please review the attached details and patch soon",
                VICTIMS[i]
            )
        },
    )
}

#[test]
fn new_accounts_are_weighed_against_their_own_hours() {
    let rules = Rules::default_rules();
    // Alone among established accounts, four new accounts are unlikely
    // whatever their timing.
    let mut evs = background(&rules, 400);
    evs.extend(slow_template(&rules));
    let rep = detect(&evs, &PlatformOptions::default());
    assert_eq!(rep.swarms.len(), 1, "{:#?}", rep.swarms);
    let a = rep.swarms[0].new_accounts.clone().unwrap();
    assert!(a.hour_rate < 0.05 && a.p_chance < 1e-4, "{a:?}");
    assert_eq!(rep.swarms[0].tested, 1);
    let f = &rep.families[0];
    assert_eq!(
        (f.family.as_str(), f.kept, f.tested),
        ("platform:github", 1, 1)
    );
    // In an hour when a wave of new accounts arrives (a launch, a news
    // story), the same four say little: the rate they are read against is
    // the hour's, so the wave is not counted once in the timing and again
    // in the accounts.
    let mut r = Lcg(99);
    for i in 0..80 {
        let words = 10 + (r.next() % 20) as usize;
        let text = r.sentence(words);
        evs.push(ev(
            Ev {
                id: format!("wave{i}"),
                ts: T0 + 2 * HOUR + (r.next() % 3000) as i64,
                actor: format!("newcomer{i}"),
                rank: Some(160_600 + i as u64),
                target: "alpha/one",
                action: Action::Comment,
                platform: Platform::Github,
            },
            Some(&text),
            &rules,
        ));
    }
    let rep = detect(&evs, &PlatformOptions::default());
    assert!(rep.swarms.is_empty(), "{:#?}", rep.swarms);
    assert!(rep.below_threshold >= 1);
}

#[test]
fn near_duplicates_with_reworded_lines_still_group() {
    let rules = Rules::default_rules();
    let mut evs = background(&rules, 200);
    let variants = [
        "I found a serious security issue in this project where user input reaches the shell without escaping and could allow command injection by a remote attacker",
        "I found a serious security issue in this project where user input reaches the shell without escaping and could allow command injection by any remote attacker",
        "Hello I found a serious security issue in this project where user input reaches the shell without escaping and could allow command injection by a remote attacker",
        "I found a serious security issue in this project where user input reaches the shell without escaping and could allow command injection by a remote attacker thanks",
    ];
    evs.extend(wave(
        &rules,
        "nd",
        4,
        T0 + HOUR + 600,
        45,
        |i| Some(160_500 + i as u64),
        |i| VICTIMS[i],
        |i| variants[i].to_string(),
    ));
    let rep = detect(&evs, &PlatformOptions::default());
    assert_eq!(rep.swarms.len(), 1, "{:#?}", rep.swarms);
    assert!(rep.swarms[0].basis.contains(&Basis::NearDuplicate));
    assert!(rep.swarms[0].similarity.unwrap() > 0.6);
}

#[test]
fn dependency_bumps_and_contribution_drives_are_suppressed() {
    let rules = Rules::default_rules();
    let mut evs = background(&rules, 200);
    evs.extend(wave(
        &rules,
        "dep",
        12,
        T0 + HOUR,
        20,
        |i| Some(50_000 + i as u64),
        |i| VICTIMS[i % 6],
        |i| {
            format!(
                "Bumps lodash from 4.17.{i} to 4.17.21. Release notes and commits are listed below for review."
            )
        },
    ));
    evs.extend(wave(
        &rules,
        "hf",
        15,
        T0 + 3 * HOUR,
        30,
        |i| Some(160_600 + i as u64),
        |_| "alpha/one",
        |_| "Hi, I would like to work on this issue as part of Hacktoberfest. Please assign it to me, thank you!".into(),
    ));
    let rep = detect(&evs, &PlatformOptions::default());
    assert!(rep.swarms.is_empty(), "{:#?}", rep.swarms);
    let why: Vec<&str> = rep.suppressed.iter().map(|s| s.why.as_str()).collect();
    assert!(why.contains(&"dependency update"), "{why:?}");
    assert!(why.contains(&"contribution drive"), "{why:?}");
}

#[test]
fn templates_spread_over_the_window_by_established_accounts_are_not_reported() {
    let rules = Rules::default_rules();
    let mut evs = background(&rules, 300);
    // An issue template many people fill in over the day, across projects.
    evs.extend(wave(
        &rules,
        "tpl",
        8,
        T0 + 300,
        40 * 60,
        |i| Some(20_000 + 9_000 * i as u64),
        |i| VICTIMS[i % 6],
        |_| "Describe the bug: the app crashes on start. Steps to reproduce: open it. Expected behaviour: it starts. Environment: latest release.".into(),
    ));
    let rep = detect(&evs, &PlatformOptions::default());
    assert!(rep.swarms.is_empty(), "{:#?}", rep.swarms);
    assert!(rep.below_threshold >= 1);
}

#[test]
fn an_outage_burst_on_one_project_by_established_accounts_is_not_reported() {
    let rules = Rules::default_rules();
    let mut evs = background(&rules, 300);
    evs.extend(wave(
        &rules,
        "out",
        10,
        T0 + 4 * HOUR + 900,
        30,
        |i| Some(30_000 + 7_000 * i as u64),
        |_| "acme/widgets",
        |_| "The hosted service returns error 502 for every request since a few minutes ago, is there an outage right now?".into(),
    ));
    let rep = detect(&evs, &PlatformOptions::default());
    assert!(rep.swarms.is_empty(), "{:#?}", rep.swarms);
}

#[test]
fn a_scheduled_job_on_the_hour_counts_down() {
    let rules = Rules::default_rules();
    let mut evs = background(&rules, 300);
    // Four organisations' nightly jobs posting the same status at 02:00.
    let on_hour = (T0 / HOUR + 3) * HOUR;
    evs.extend(wave(
        &rules,
        "cron",
        4,
        on_hour + 5,
        10,
        |i| Some(40_000 + 11_000 * i as u64),
        |i| VICTIMS[i],
        |_| "Nightly link check finished with no broken links found in the documentation site today.".into(),
    ));
    let rep = detect(&evs, &PlatformOptions::default());
    assert!(rep.swarms.is_empty(), "{:#?}", rep.swarms);
}

#[test]
fn an_anonymous_package_flood_with_templated_names_is_a_weak_hint() {
    let mut evs: Vec<PlatformEvent> = (0..60)
        .map(|i| PlatformEvent {
            id: format!("pypi:ordinary-{i}@1.0"),
            platform: Platform::Pypi,
            action: Action::PackagePublished,
            ts: T0 + i * 360,
            target: format!("ordinary-{}", ["alpha", "beta", "gamma"][i as usize % 3]),
            link: String::new(),
            name_template: None,
            ..Default::default()
        })
        .collect();
    for i in 0..8 {
        let name = format!("agent-probe-{:04}", 17 + i);
        evs.push(PlatformEvent {
            id: format!("pypi:{name}@0.0.1"),
            platform: Platform::Pypi,
            action: Action::PackagePublished,
            ts: T0 + 2 * HOUR + 600 + i * 40,
            target: name.clone(),
            link: format!("https://pypi.org/project/{name}/0.0.1/"),
            name_template: name_template(&name, ""),
            ..Default::default()
        });
    }
    let rep = detect(&evs, &PlatformOptions::default());
    assert_eq!(rep.swarms.len(), 1, "{:#?}", rep.swarms);
    let s = &rep.swarms[0];
    assert_eq!(s.template, "agent-probe-<num>");
    assert_eq!(s.basis, [Basis::NameTemplate]);
    assert_eq!(s.accounts, 0);
    assert_eq!(s.strength, HintStrength::Weak);
    assert!(s.caveats.iter().any(|c| c.contains("names no accounts")));
}

#[test]
fn two_accounts_are_not_a_swarm_and_ids_are_stable() {
    let rules = Rules::default_rules();
    let mut evs = background(&rules, 100);
    evs.extend(wave(
        &rules,
        "pair",
        2,
        T0 + HOUR,
        30,
        |i| Some(160_000 + i as u64),
        |i| VICTIMS[i],
        agent_report,
    ));
    assert!(detect(&evs, &PlatformOptions::default()).swarms.is_empty());

    let mut evs = background(&rules, 100);
    let w = wave(
        &rules,
        "st",
        5,
        T0 + HOUR,
        30,
        |i| Some(160_000 + i as u64),
        |i| VICTIMS[i],
        agent_report,
    );
    evs.extend(w.clone());
    let a = detect(&evs, &PlatformOptions::default());
    // A later member joins; the id stays with the earliest member.
    evs.extend(wave(
        &rules,
        "st-late",
        1,
        T0 + HOUR + 400,
        0,
        |_| Some(160_100),
        |_| VICTIMS[5],
        agent_report,
    ));
    let b = detect(&evs, &PlatformOptions::default());
    assert_eq!(a.swarms[0].id, b.swarms[0].id);
    assert_eq!(b.swarms[0].events, 6);
}

#[test]
fn events_round_trip_as_json() {
    let rules = Rules::default_rules();
    let e = wave(&rules, "rt", 1, T0, 0, |_| Some(1), |_| "a/b", agent_report).remove(0);
    let s = serde_json::to_string(&e).unwrap();
    assert!(!s.contains("rt-acct0"), "the login is not stored: {s}");
    let back: PlatformEvent = serde_json::from_str(&s).unwrap();
    assert_eq!(back, e);
}

#[test]
fn a_small_group_in_one_fresh_hour_is_not_weighed_against_carried_days() {
    let rules = Rules::default_rules();
    // One hour read in full ...
    let fresh = T0 + 72 * HOUR;
    let mut evs: Vec<PlatformEvent> = background(&rules, 120)
        .into_iter()
        .map(|mut e| {
            e.ts = fresh + (e.ts - T0) / 6;
            e
        })
        .collect();
    // ... plus sparse events carried from the three days before.
    for (i, e) in background(&rules, 12).into_iter().enumerate() {
        evs.push(PlatformEvent {
            id: format!("carried{i}"),
            ts: T0 + i as i64 * 6 * HOUR,
            ..e
        });
    }
    // Three established accounts post one template within ten minutes.
    let text = "Could you publish wheels for the new interpreter release, the source build fails without a compiler on our machines.";
    let small = wave(
        &rules,
        "small",
        3,
        fresh + 1200,
        300,
        |i| Some(30_000 + 20_000 * i as u64),
        |i| VICTIMS[i],
        |_| text.into(),
    );
    evs.extend(small);
    let rep = detect(&evs, &PlatformOptions::default());
    assert!(rep.swarms.is_empty(), "{:#?}", rep.swarms);
    assert_eq!(rep.below_threshold, 1);
}

/// `n` text-less `action` events on `target`, `gap` apart, from accounts
/// ranked by `rank`.
fn textless(
    tag: &str,
    action: Action,
    n: usize,
    start: i64,
    gap: i64,
    rank: impl Fn(usize) -> u64,
    target: &'static str,
) -> Vec<PlatformEvent> {
    (0..n)
        .map(|i| PlatformEvent {
            id: format!("gh:{tag}{i}"),
            platform: Platform::Github,
            action,
            ts: start + i as i64 * gap,
            actor: actor_key(Platform::Github, &format!("{tag}-acct{i}")),
            actor_rank: Some(rank(i)),
            target: target.into(),
            link: format!("https://github.com/{target}"),
            ..Default::default()
        })
        .collect()
}

#[test]
fn a_star_burst_from_fresh_accounts_on_one_repository_is_found() {
    let rules = Rules::default_rules();
    let mut evs = background(&rules, 300);
    // A popular repository starred all day by established accounts ...
    evs.extend(textless(
        "pop",
        Action::Starred,
        40,
        T0 + 200,
        500,
        |i| 20_000 + 3_000 * i as u64,
        "famous/framework",
    ));
    // ... and a fresh repository starred by fifteen new accounts in ten minutes.
    evs.extend(textless(
        "farm",
        Action::Starred,
        15,
        T0 + 3 * HOUR + 1500,
        40,
        |i| 160_300 + i as u64,
        "fresh/tool",
    ));
    let rep = detect(&evs, &PlatformOptions::default());
    assert_eq!(rep.swarms.len(), 1, "{:#?}", rep.swarms);
    let s = &rep.swarms[0];
    assert_eq!(s.basis, [Basis::Target]);
    assert_eq!(s.actions, [(Action::Starred, 15)]);
    assert_eq!(s.template, "stars on fresh/tool");
    assert!(
        s.caveats
            .iter()
            .any(|c| c.contains("one target they acted on"))
    );
    // Only the farm, whose accounts are new, is carried.
    assert!(s.members.iter().all(|m| rep.carry.contains(m)));
    assert!(!rep.carry.iter().any(|m| m.starts_with("gh:pop")));
}

#[test]
fn text_less_pull_requests_group_by_repository_but_need_a_burst() {
    let rules = Rules::default_rules();
    let mut evs = background(&rules, 300);
    // New accounts opening pull requests on one repository over six hours:
    // no burst, so no candidate however new the accounts are.
    evs.extend(textless(
        "slow",
        Action::PullOpened,
        8,
        T0 + 100,
        45 * 60,
        |i| 160_200 + i as u64,
        "busy/project",
    ));
    // The same within minutes is one.
    evs.extend(textless(
        "fast",
        Action::PullOpened,
        8,
        T0 + 4 * HOUR + 1500,
        30,
        |i| 160_250 + i as u64,
        "target/lib",
    ));
    // And on a practice repository it is suppressed.
    evs.extend(textless(
        "fc",
        Action::PullOpened,
        8,
        T0 + 2 * HOUR + 300,
        30,
        |i| 160_270 + i as u64,
        "firstcontributions/first-contributions",
    ));
    let rep = detect(&evs, &PlatformOptions::default());
    assert_eq!(rep.swarms.len(), 1, "{:#?}", rep.swarms);
    assert_eq!(rep.swarms[0].targets[0].0, "target/lib");
    assert!(
        rep.suppressed
            .iter()
            .any(|s| s.why == "practice repository")
    );
}

#[test]
fn self_identification_is_reported_but_does_not_make_a_group_residue_heavy() {
    let rules = Rules::default_rules();
    let mut evs = background(&rules, 300);
    // Established accounts spread over the day, each PR text naming its
    // harness: below the chance threshold, footer or not.
    evs.extend(wave(
        &rules,
        "cc",
        6,
        T0 + 300,
        50 * 60,
        |i| Some(20_000 + 9_000 * i as u64),
        |i| VICTIMS[i],
        |i| format!("Refactor the config loader for module {i} and add tests for the new parser.\n\nGenerated with [Claude Code](https://claude.com/claude-code)"),
    ));
    let rep = detect(&evs, &PlatformOptions::default());
    assert!(rep.swarms.is_empty(), "{:#?}", rep.swarms);
    // A burst from new accounts is reported, with the self-id as context.
    evs.extend(wave(
        &rules,
        "ccb",
        5,
        T0 + 5 * HOUR,
        30,
        |i| Some(160_700 + i as u64),
        |i| VICTIMS[i],
        |i| format!("Add a security policy file for package {i} as requested by the audit team today.\n\nCo-Authored-By: Claude <noreply@anthropic.com>"),
    ));
    let rep = detect(&evs, &PlatformOptions::default());
    assert_eq!(rep.swarms.len(), 1, "{:#?}", rep.swarms);
    let s = &rep.swarms[0];
    assert_eq!(s.self_id, [("selfid.claude_code".to_string(), 5)]);
    assert!(s.residue.is_empty());
    assert!(s.reason.contains("5 name a coding harness"), "{}", s.reason);
}

#[test]
fn wiki_sandbox_edits_need_a_burst_not_only_new_accounts() {
    let wiki = |tag: &str, n: usize, start: i64, gap: i64| -> Vec<PlatformEvent> {
        (0..n)
            .map(|i| {
                let user = format!("{tag}user{i}");
                let title = format!("User:{user}/sandbox");
                PlatformEvent {
                    id: format!("wm:{tag}{i}"),
                    platform: Platform::Wikimedia,
                    action: Action::WikiEdited,
                    ts: start + i as i64 * gap,
                    actor: actor_key(Platform::Wikimedia, &user),
                    actor_rank: Some(1_000_000 + i as u64),
                    first_timer: Some(true),
                    target: format!("en.wikipedia.org/{title}"),
                    link: String::new(),
                    name_template: wiki_title_template(&title, &user),
                    ..Default::default()
                }
            })
            .collect()
    };
    // New editors trying their sandbox all day, and a few old hands.
    let mut evs = wiki("new", 60, T0, 360);
    for (i, e) in wiki("old", 30, T0 + 100, 700).iter_mut().enumerate() {
        e.actor_rank = Some(100_000 + i as u64);
        e.first_timer = None;
        e.name_template = None;
        evs.push(e.clone());
    }
    let rep = detect(&evs, &PlatformOptions::default());
    assert!(rep.swarms.is_empty(), "{:#?}", rep.swarms);
    // Twelve fresh accounts editing their sandboxes in four minutes.
    evs.extend(wiki("burst", 12, T0 + 3 * HOUR + 500, 20));
    let rep = detect(&evs, &PlatformOptions::default());
    assert_eq!(rep.swarms.len(), 1, "{:#?}", rep.swarms);
    assert_eq!(rep.swarms[0].template, "user:<user>/sandbox");
}
