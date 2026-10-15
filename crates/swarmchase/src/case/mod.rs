//! `swarmchase case`: case files for incidents the admin has decided to pursue.
//!
//! A case lives in `<data>/cases/<id>/`, outside git, like the watch data:
//!
//! ```text
//! case.toml            status, pinned rules, endpoints, attribution claims, contacts,
//!                      decisions, sends
//! raw/records.ndjson   the redacted records the case rests on, copied out of the
//!                      watch store before retention deletes them
//! reports/             drafts rendered from the records and case.toml
//! bundles/<date>/      evidence bundles (records, analysis, stamp, manifest)
//! outbox/              unsent e-mail drafts and paste-ready text for the admin
//! exports/             STIX, MISP and incident-framework drafts
//! evidence/<eid>.ndjson  logs affected operators sent us (`case evidence`)
//! notice.md            the public notice draft (`case notice`), edited by the
//!                      admin, then added to notices/ with `swarmchase notice add`
//! ```
//!
//! What a case is and every decision on it are in the `sc-case` crate; this
//! module reads and writes the files. The rules a case was opened with are
//! pinned ([`crate::pinning`]), and every analysis of a case goes through
//! [`Pinned`], so its reports, notice and bundles do not change when the
//! bundled rules do.
//!
//! Cases stay private until the admin publishes: an open case names
//! organisations on unconfirmed evidence, and private reports include details
//! that public notices withhold (docs/policies.md).
//!
//! [`cli`] holds the subcommands, one module per group; [`select`] picks
//! records, [`status`] shows a case, [`report`] drafts reports and e-mail
//! drafts, [`checklist`] gathers the self-review checklist's inputs,
//! [`incident`] the incident-framework drafts, and [`indicators`] is what
//! the watch matches new records against.

pub mod checklist;
mod cli;
pub mod fleet;
pub mod incident;
mod indicators;
mod report;
mod select;
pub(crate) mod status;

pub use cli::{CaseArgs, run};
pub(crate) use indicators::{CaseIndicators, indicators};
pub(crate) use report::find_contact;
#[cfg(test)]
pub(crate) use report::{draft, report};
pub use sc_case::evidence::Scope;
pub use sc_case::model::*;
pub use sc_case::report::{affected_hosts, report_options, reported};
#[cfg(test)]
pub(crate) use status::status;

use crate::pinning::{RulesText, case_rules, pin_rules};
use crate::store::{read_json_kept, write_json_kept};
use anyhow::{Context, Result, bail};
use sc_case::bundle::to_ndjson;
use sc_core::{Analysis, Audience, Observation, Rules, analyze};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

pub fn case_dir(root: &Path, id: &str) -> Result<PathBuf> {
    check_id(id)?;
    Ok(root.join(id))
}

pub fn load(root: &Path, id: &str) -> Result<Case> {
    let p = case_dir(root, id)?.join("case.toml");
    if !p.is_file() {
        bail!(
            "no case at {}{}",
            p.display(),
            sc_case::text::did_you_mean(id, ids(root).iter().map(String::as_str))
        );
    }
    let text =
        std::fs::read_to_string(&p).with_context(|| format!("no case at {}", p.display()))?;
    Case::parse(&text).with_context(|| format!("parsing {}", p.display()))
}

/// Write case.toml into the case's directory, which must exist: a case
/// renamed or deleted while a command held it is not brought back as a
/// case.toml with no records.
pub(crate) fn save(root: &Path, c: &Case) -> Result<()> {
    let dir = case_dir(root, &c.id)?;
    if !dir.is_dir() {
        bail!(
            "case {} is gone from {} (renamed or deleted meanwhile); the change was not saved",
            c.id,
            dir.display()
        );
    }
    crate::store::write_atomic(&dir.join("case.toml"), c.to_toml()?.as_bytes())
}

/// Load case `id`, change it with `f` and save it, holding the case's lock
/// ([`lock_case`]) from the load to the save, so two commands changing one
/// case at once never lose either change.
pub fn update(root: &Path, id: &str, f: impl FnOnce(&mut Case) -> Result<()>) -> Result<()> {
    modify(root, id, f)?;
    println!("updated {}", root.join(id).join("case.toml").display());
    Ok(())
}

/// [`update`] without the message, returning what `f` returns.
pub(crate) fn modify<T>(
    root: &Path,
    id: &str,
    f: impl FnOnce(&mut Case) -> Result<T>,
) -> Result<T> {
    let _lock = lock_case(root, id)?;
    let mut c = load(root, id)?;
    let v = f(&mut c)?;
    save(root, &c)?;
    Ok(v)
}

/// A held case lock; released when dropped.
pub(crate) struct CaseLock {
    file: Option<std::fs::File>,
    path: PathBuf,
}

thread_local! {
    /// The case locks this thread holds, so a change begun inside another
    /// (which would wait on itself, and whose write the outer change would
    /// then overwrite) is refused instead.
    static HELD: std::cell::RefCell<BTreeSet<PathBuf>> = const {
        std::cell::RefCell::new(BTreeSet::new())
    };
}

impl Drop for CaseLock {
    fn drop(&mut self) {
        if let Some(f) = self.file.take() {
            let _ = f.unlock();
            HELD.with(|h| h.borrow_mut().remove(&self.path));
        }
    }
}

/// Take case `id`'s lock, `<cases>/.locks/<id>.lock`, waiting while another
/// command holds it (`case contacts` holds it through its lookups). Every
/// read-change-write of a case.toml goes through it. Outside the case
/// directory, so moving a case (`case rename`) never meets an open file.
/// Taking it again while this thread holds it is an error: the inner change
/// would be lost when the outer one saves its own copy.
pub(crate) fn lock_case(root: &Path, id: &str) -> Result<CaseLock> {
    check_id(id)?;
    let dir = root.join(".locks");
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let path = dir.join(format!("{id}.lock"));
    if HELD.with(|h| h.borrow().contains(&path)) {
        bail!(
            "case {id} is already being changed by this command; a change inside that change would be lost when it saves"
        );
    }
    let f = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .with_context(|| format!("opening {}", path.display()))?;
    match f.try_lock() {
        Ok(()) => {}
        Err(std::fs::TryLockError::WouldBlock) => {
            eprintln!("case {id} is in use by another swarmchase command; waiting for it");
            f.lock()
                .with_context(|| format!("locking {}", path.display()))?;
        }
        Err(std::fs::TryLockError::Error(e)) => {
            return Err(e).with_context(|| format!("locking {}", path.display()));
        }
    }
    HELD.with(|h| h.borrow_mut().insert(path.clone()));
    Ok(CaseLock {
        file: Some(f),
        path,
    })
}

/// Which operator evidence a report for `audience` may use
/// ([`Scope::for_audience`]).
pub(crate) fn scope(audience: Audience, to: Option<&Contact>) -> Scope<'_> {
    Scope::for_audience(audience, to)
}

/// The case's records plus the operator evidence `scope` allows. For one
/// operator ([`Scope::hosts`]) only the records aimed at its own endpoints,
/// judged by the case's pinned rules: its report, bundle and exports never
/// carry another operator's records.
pub fn case_records(root: &Path, c: &Case, scope: &Scope) -> Result<Vec<Observation>> {
    records_in_scope(root, c, scope, None)
}

/// [`case_records`], with the rules that find each record's target (the
/// case's pinned rules when not given).
fn records_in_scope(
    root: &Path,
    c: &Case,
    scope: &Scope,
    rules: Option<&Rules>,
) -> Result<Vec<Observation>> {
    let mut all = load_records(root, &c.id)?;
    if let Some(hosts) = scope.hosts(c, &sc_collect::psl::registrable_domain) {
        if hosts.is_empty() {
            bail!(
                "a report to an operator covers its own endpoints, and this contact has none; give it one (`case contact add --endpoint`)"
            );
        }
        let pinned;
        let rules = match rules {
            Some(r) => r,
            None => {
                pinned = case_rules(root, c)?;
                &pinned
            }
        };
        all.retain(|o| {
            sc_core::extract::extract(o, rules)
                .target_host
                .is_some_and(|h| hosts.contains(&h.to_ascii_lowercase()))
        });
    }
    let dir = case_dir(root, &c.id)?;
    for e in c
        .evidence
        .iter()
        .filter(|e| e.in_scope(scope, c, &sc_collect::psl::registrable_domain))
    {
        let p = crate::evidence::file(&dir, &e.id);
        let text =
            std::fs::read_to_string(&p).with_context(|| format!("reading {}", p.display()))?;
        for l in text.lines().filter(|l| !l.trim().is_empty()) {
            all.push(serde_json::from_str(l).with_context(|| format!("parsing {}", p.display()))?);
        }
    }
    Ok(all)
}

/// A case with the rules it is pinned to. Every analysis of a case is made
/// here, so each one renders under the same rules.
pub struct Pinned<'a> {
    pub root: &'a Path,
    pub case: &'a Case,
    pub rules: Rules,
}

impl<'a> Pinned<'a> {
    /// Load the rules case `c` is pinned to.
    pub fn new(root: &'a Path, c: &'a Case) -> Result<Self> {
        Ok(Self {
            root,
            case: c,
            rules: case_rules(root, c)?,
        })
    }

    /// The analysis of the records `scope` allows, each cluster's client
    /// addresses described from the network ranges held beside the cases
    /// (so a Tor exit's network is in no hosting claim of a sent report).
    ///
    /// An analysis of fewer records than the case holds (one operator's,
    /// or the notice's without private logs) clusters them afresh, so each
    /// of its clusters takes the key of the case's cluster holding most of
    /// its records: fleets, wider counts and exports then speak of one set
    /// of keys. Only keys move; what the analysis holds stays in scope.
    pub fn analysis(&self, scope: &Scope) -> Result<Analysis> {
        let mut a = analyze(
            records_in_scope(self.root, self.case, scope, Some(&self.rules))?,
            &self.rules,
        );
        let narrower = match scope {
            Scope::All => false,
            Scope::Operator { .. } => true,
            Scope::Public => self.case.evidence.iter().any(|e| e.public.is_none()),
        };
        if narrower {
            let all = analyze(
                records_in_scope(self.root, self.case, &Scope::All, Some(&self.rules))?,
                &self.rules,
            );
            a.rekey_from(&all);
        }
        let data = self.root.parent().unwrap_or(self.root);
        crate::commands::netranges::annotate_in(data, &mut a);
        Ok(a)
    }
}

/// The case's analysis of the records `scope` allows, under its pinned rules.
pub fn analysis(root: &Path, c: &Case, scope: &Scope) -> Result<Analysis> {
    Pinned::new(root, c)?.analysis(scope)
}

/// The IDs of the case directories under `root`, loadable or not.
pub(crate) fn ids(root: &Path) -> Vec<String> {
    let mut ids: Vec<String> = std::fs::read_dir(root)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.join("case.toml").is_file())
        .filter_map(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .collect();
    ids.sort();
    ids
}

/// Cases that did not load: each one's ID and why.
pub(crate) type Broken = Vec<(String, String)>;

/// Every case under `root` that loads, by ID, and the IDs of those that do
/// not, with why: one damaged case.toml never hides the others.
pub(crate) fn all_readable(root: &Path) -> Result<(Vec<Case>, Broken)> {
    let mut cases = Vec::new();
    let mut broken = Vec::new();
    if let Ok(entries) = std::fs::read_dir(root) {
        for e in entries {
            let p = e?.path();
            if p.join("case.toml").is_file() {
                let id = p.file_name().unwrap_or_default().to_string_lossy();
                match load(root, &id) {
                    Ok(c) => cases.push(c),
                    Err(e) => broken.push((id.to_string(), format!("{e:#}"))),
                }
            }
        }
    }
    cases.sort_by(|a, b| a.id.cmp(&b.id));
    broken.sort();
    Ok((cases, broken))
}

/// Every case under `root`, by ID. A case file that does not parse is an error.
pub(crate) fn all(root: &Path) -> Result<Vec<Case>> {
    let mut cases = Vec::new();
    if let Ok(entries) = std::fs::read_dir(root) {
        for e in entries {
            let p = e?.path();
            if p.join("case.toml").is_file() {
                let id = p.file_name().unwrap_or_default().to_string_lossy();
                cases.push(load(root, &id)?);
            }
        }
    }
    cases.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(cases)
}

/// Append a decision log entry without printing anything.
pub(crate) fn log_entry(root: &Path, id: &str, today: &str, text: impl Into<String>) -> Result<()> {
    let _lock = lock_case(root, id)?;
    let mut c = load(root, id)?;
    c.log(today, text);
    save(root, &c)
}

fn records_path(root: &Path, id: &str) -> Result<PathBuf> {
    Ok(case_dir(root, id)?.join("raw").join("records.ndjson"))
}

/// The ids of the records case `id` holds.
pub(crate) fn record_ids(root: &Path, id: &str) -> Result<BTreeSet<String>> {
    Ok(load_records(root, id)?.into_iter().map(|o| o.id).collect())
}

/// The case's records. A line that cannot be read (a write cut short, bytes
/// that are not UTF-8) is skipped with a warning, so one bad line never
/// stops the case.
fn load_records(root: &Path, id: &str) -> Result<Vec<Observation>> {
    let p = records_path(root, id)?;
    let (records, bad) = crate::store::read_ndjson(&p)?;
    if bad > 0 {
        eprintln!("warning: {}: {bad} unreadable line(s) skipped", p.display());
    }
    Ok(records)
}

/// Open a case from `records`, pinned to `rules`.
pub(crate) fn new_case(
    root: &Path,
    id: &str,
    title: &str,
    records: Vec<Observation>,
    rules: &RulesText,
    today: &str,
) -> Result<Analysis> {
    let dir = case_dir(root, id)?;
    let _lock = lock_case(root, id)?;
    if dir.join("case.toml").exists() {
        bail!("case {id} already exists; use `case add` to add records");
    }
    if records.is_empty() {
        bail!("no records selected");
    }
    std::fs::create_dir_all(dir.join("raw"))?;
    let pin = pin_rules(root, rules)?;
    crate::store::write_atomic(&records_path(root, id)?, to_ndjson(&records).as_bytes())?;
    let a = analyze(records, &rules.rules);
    let mut c = Case::new(id, title, today, Some(pin.clone()));
    c.add_endpoints(&a);
    c.log(
        today,
        format!(
            "opened with {} records ({} flagged), rules {pin}",
            a.total, a.flagged
        ),
    );
    save(root, &c)?;
    Ok(a)
}

/// Open a case as [`new_case`] does and record its admin: `admin` (the
/// person running the command, [`admin_name`]), or a warning that none is
/// recorded. `case new` and review's `c` both open cases here.
pub(crate) fn open_case(
    root: &Path,
    id: &str,
    title: &str,
    records: Vec<Observation>,
    rules: &RulesText,
    today: &str,
    admin: Option<&str>,
) -> Result<Analysis> {
    let a = new_case(root, id, title, records, rules, today)?;
    match admin {
        Some(name) => {
            let _lock = lock_case(root, id)?;
            let mut c = load(root, id)?;
            sc_case::review::set_admin(&mut c, name, today)?;
            save(root, &c)?;
        }
        None => eprintln!(
            "warning: no admin recorded (set SWARMCHASE_ADMIN or `git config user.name`); `swarmchase case set {id} --admin \"<name>\"` before the second review"
        ),
    }
    Ok(a)
}

/// The admin's name for a new case: `SWARMCHASE_ADMIN`, else `git config
/// user.name`.
pub(crate) fn admin_name() -> Option<String> {
    let given = |s: String| Some(s.trim().to_string()).filter(|s| !s.is_empty());
    std::env::var("SWARMCHASE_ADMIN")
        .ok()
        .and_then(given)
        .or_else(|| {
            let o = std::process::Command::new("git")
                .args(["config", "user.name"])
                .output()
                .ok()
                .filter(|o| o.status.success())?;
            given(String::from_utf8_lossy(&o.stdout).into_owned())
        })
}

/// The open case (not closed) that already holds the most of `ids`, if any
/// holds one: where opening a case on those records again should add to
/// instead. Cases that do not load are passed over.
pub(crate) fn holding(root: &Path, ids: &BTreeSet<String>) -> Result<Option<String>> {
    let (cases, _) = all_readable(root)?;
    let mut best: Option<(usize, String)> = None;
    for c in cases.iter().filter(|c| c.status != CaseStatus::Closed) {
        let n = record_ids(root, &c.id)?.intersection(ids).count();
        if n > 0 && best.as_ref().is_none_or(|(b, _)| n > *b) {
            best = Some((n, c.id.clone()));
        }
    }
    Ok(best.map(|(_, id)| id))
}

/// Add the records the case does not hold yet, and any new endpoints they
/// bring, judged by the case's pinned rules.
pub(crate) fn add_records(
    root: &Path,
    id: &str,
    records: Vec<Observation>,
    today: &str,
) -> Result<(usize, usize)> {
    let _lock = lock_case(root, id)?;
    let mut c = load(root, id)?;
    let mut all = load_records(root, id)?;
    let have: BTreeSet<String> = all.iter().map(|o| o.id.clone()).collect();
    let fresh: Vec<Observation> = records
        .into_iter()
        .filter(|o| !have.contains(&o.id))
        .collect();
    if fresh.is_empty() {
        return Ok((0, 0));
    }
    crate::store::append(&records_path(root, id)?, &to_ndjson(&fresh))?;
    let n = fresh.len();
    all.extend(fresh);
    // The case's own records only: an operator's logs add no endpoints.
    let a = analyze(all, &Pinned::new(root, &c)?.rules);
    let hosts = c.add_endpoints(&a);
    c.log(
        today,
        format!("added {n} record(s), {hosts} new endpoint(s)"),
    );
    save(root, &c)?;
    Ok((n, hosts))
}

/// Give case `old` the ID `new`: move its directory, change the ID in
/// case.toml, log it, and carry the watch's hits for it over in
/// `<data>/state.json`. Refused once a notice is published, because the
/// notice's ID is public.
///
/// The data directory's lock is held throughout, so a watch never reads
/// the case or `state.json` half renamed. The new case.toml is written in
/// the old directory before the move, so the move itself is the one step
/// that changes which ID the case has.
pub(crate) fn rename(root: &Path, old: &str, new: &str, today: &str) -> Result<()> {
    let data = root.parent().unwrap_or(root);
    let _lock = crate::store::lock_data(data, "case rename")?;
    // Both IDs' case locks: a command changing the case (`case contacts`
    // through its lookups) finishes first, and one that starts after finds
    // the case gone rather than writing it back under the old ID.
    let _old = lock_case(root, old)?;
    let _new = lock_case(root, new)?;
    let mut c = load(root, old)?;
    let to = case_dir(root, new)?;
    if to.exists() {
        bail!("{} exists already", to.display());
    }
    if c.status == CaseStatus::Published || c.publish_pending.is_some() {
        bail!("case {old} has a published notice; its ID stays");
    }
    let from = case_dir(root, old)?;
    let before = std::fs::read(from.join("case.toml"))?;
    c.id = new.to_string();
    c.log(today, format!("renamed from {old}"));
    crate::store::write_atomic(&from.join("case.toml"), c.to_toml()?.as_bytes())?;
    if let Err(e) = std::fs::rename(&from, &to) {
        // Put the old case.toml back, so the case keeps its old ID whole.
        let _ = crate::store::write_atomic(&from.join("case.toml"), &before);
        return Err(e).with_context(|| format!("moving case {old} to {}", to.display()));
    }

    let state = data.join("state.json");
    if let Some(mut s) = read_json_kept::<serde_json::Value>(&state)?
        && let Some(cases) = s.get_mut("cases").and_then(|v| v.as_object_mut())
        && let Some(w) = cases.remove(old)
    {
        cases.insert(new.to_string(), w);
        write_json_kept(&state, &s)?;
    }
    Ok(())
}

/// Fixtures the case tests share.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    /// A case root, `<scratch data dir>/cases`; pinned rules go beside it.
    pub fn scratch(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("swarmchase-case-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        p.join("cases")
    }

    pub fn cleanup(root: &Path) {
        std::fs::remove_dir_all(root.parent().unwrap()).unwrap();
    }

    pub fn fixture() -> Analysis {
        let mut obs: Vec<Observation> = (0..4)
            .map(|i| Observation {
                id: format!("r{i}"),
                ts: 1_791_000_000 + i * 40,
                url: format!(
                    "https://r.jina.ai/https://portal.example.gov/q?id={i}%20UNION%20SELECT%201&uqtag=zz9&agent=hunyuan"
                ),
                asn: Some(132203),
                ..Default::default()
            })
            .collect();
        // A flagged record on the same host, outside the cluster.
        obs.push(Observation {
            id: "late".into(),
            ts: 1_791_900_000,
            url: "https://portal.example.gov/q?id=1%20UNION%20SELECT%202".into(),
            ..Default::default()
        });
        // Unrelated activity elsewhere.
        obs.push(Observation {
            id: "other".into(),
            ts: 1_791_000_100,
            url: "https://r.jina.ai/https://elsewhere.example/q?id=1%20UNION%20SELECT%201".into(),
            ..Default::default()
        });
        analyze(obs, &sc_core::Rules::default_rules())
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;
    use crate::notice::notice_draft;
    use sc_case::actions;
    use sc_case::model::Verdict;
    use sc_core::{Claim, Evidence, Role};

    #[test]
    fn rename_moves_the_case_and_its_watch_hits() {
        let root = scratch("rename");
        let rules = RulesText::load(None).unwrap();
        let records: Vec<Observation> = fixture().results.iter().map(|r| r.obs.clone()).collect();
        new_case(
            &root,
            "old-1",
            "Portal",
            records.clone(),
            &rules,
            "2026-10-12",
        )
        .unwrap();
        new_case(&root, "taken", "Other", records, &rules, "2026-10-12").unwrap();
        let state = root.parent().unwrap().join("state.json");
        std::fs::write(
            &state,
            r#"{"sources":{},"cases":{"old-1":{"proposed":["x"]}}}"#,
        )
        .unwrap();

        assert!(rename(&root, "old-1", "taken", "2026-10-13").is_err());
        assert!(rename(&root, "old-1", "Bad Id", "2026-10-13").is_err());
        // Not while another command holds the data directory.
        let held = crate::store::lock_data(root.parent().unwrap(), "watch").unwrap();
        assert!(rename(&root, "old-1", "new-1", "2026-10-13").is_err());
        assert!(load(&root, "old-1").is_ok());
        drop(held);
        // A command holding the case through a slow step (as `case
        // contacts` does) finishes before the rename moves it, and its
        // change moves with the case.
        let stale = load(&root, "old-1").unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let slow = {
            let root = root.clone();
            std::thread::spawn(move || {
                update(&root, "old-1", |c| {
                    tx.send(()).unwrap();
                    std::thread::sleep(std::time::Duration::from_millis(300));
                    c.log("d", "slow change");
                    Ok(())
                })
                .unwrap();
            })
        };
        rx.recv().unwrap();
        rename(&root, "old-1", "new-1", "2026-10-13").unwrap();
        slow.join().unwrap();
        assert!(!root.join("old-1").exists());
        let c = load(&root, "new-1").unwrap();
        assert_eq!(c.id, "new-1");
        assert_eq!(c.decisions.last().unwrap().text, "renamed from old-1");
        assert!(c.decisions.iter().any(|d| d.text == "slow change"));
        // A copy read before the rename is not written back under the old
        // ID as a case with no records.
        let err = save(&root, &stale).unwrap_err();
        assert!(err.to_string().contains("gone"), "{err}");
        assert!(!root.join("old-1").exists());
        let s = std::fs::read_to_string(&state).unwrap();
        assert!(s.contains("\"new-1\"") && !s.contains("\"old-1\""), "{s}");

        // A published notice's ID is public, so its case keeps it.
        update(&root, "new-1", |c| {
            c.status = CaseStatus::Published;
            Ok(())
        })
        .unwrap();
        assert!(rename(&root, "new-1", "newer-1", "2026-10-14").is_err());
        cleanup(&root);
    }

    #[test]
    fn a_case_analysis_reads_the_held_network_ranges() {
        let root = scratch("tor");
        let rules = RulesText::load(None).unwrap();
        let records: Vec<Observation> = fixture()
            .results
            .iter()
            .map(|r| Observation {
                ip: Some("192.0.2.200".into()),
                ts_kind: sc_core::TsKind::Request,
                ..r.obs.clone()
            })
            .collect();
        new_case(&root, "t-1", "Portal", records, &rules, "2026-10-12").unwrap();
        let ranges = root.parent().unwrap().join("netranges");
        std::fs::create_dir_all(&ranges).unwrap();
        std::fs::write(ranges.join("tor-bulk-exit-list.txt"), "192.0.2.200\n").unwrap();
        let c = load(&root, "t-1").unwrap();
        let a = analysis(&root, &c, &Scope::All).unwrap();
        assert!(a.clusters.iter().any(|c| !c.hosting.tor.is_empty()));
        // The report that is sent names no hosting network for Tor exits.
        let provider = report(&root, "t-1", Audience::Provider, None, None, "d").unwrap();
        assert!(!provider.contains("(hosting network)"), "{provider}");
        assert!(
            provider.contains("sent through Tor exit relays"),
            "{provider}"
        );
        cleanup(&root);
    }

    #[test]
    fn a_case_that_does_not_load_is_listed_apart() {
        let root = scratch("broken");
        let rules = RulesText::load(None).unwrap();
        let records: Vec<Observation> = fixture().results.iter().map(|r| r.obs.clone()).collect();
        new_case(&root, "good-1", "Portal", records, &rules, "2026-10-12").unwrap();
        std::fs::create_dir_all(root.join("bad-1")).unwrap();
        std::fs::write(root.join("bad-1").join("case.toml"), "id = [").unwrap();
        assert!(all(&root).is_err());
        let (cases, broken) = all_readable(&root).unwrap();
        assert_eq!(cases.len(), 1);
        assert_eq!(broken.len(), 1);
        assert_eq!(broken[0].0, "bad-1");
        let mut out = Vec::new();
        status::list(&root, &mut out).unwrap();
        assert!(String::from_utf8(out).unwrap().contains("good-1"));
        cleanup(&root);
    }

    fn contact(role: ContactRole, org: &str, endpoint: Option<&str>, address: &str) -> Contact {
        Contact {
            org: org.into(),
            role,
            endpoint: endpoint.map(str::to_string),
            channel: "email".into(),
            address: address.into(),
            source: "https://example.org/.well-known/security.txt".into(),
            confidence: "medium".into(),
            found_on: "2026-10-14".into(),
            purpose: None,
        }
    }

    /// Every file in the bundle directories of case `id`, as text.
    fn bundles_text(root: &Path, id: &str) -> String {
        let mut text = String::new();
        for d in std::fs::read_dir(root.join(id).join("bundles")).unwrap() {
            for f in std::fs::read_dir(d.unwrap().path()).unwrap() {
                text += &String::from_utf8_lossy(&std::fs::read(f.unwrap().path()).unwrap());
            }
        }
        text
    }

    #[test]
    fn an_operator_report_keeps_to_its_own_endpoints() {
        let root = scratch("scoped");
        let rules = RulesText::load(None).unwrap();
        // One probe run on two operators' hosts.
        let mut records: Vec<Observation> =
            fixture().results.iter().map(|r| r.obs.clone()).collect();
        records.extend((0..3).map(|i| Observation {
            id: format!("e{i}"),
            ts: 1_791_000_020 + i * 40,
            url: format!(
                "https://r.jina.ai/https://elsewhere.example/q?id={i}%20UNION%20SELECT%201&uqtag=zz9&agent=hunyuan"
            ),
            asn: Some(132203),
            ..Default::default()
        }));
        // A third operator's one request, linked to the run by its tag only.
        records.push(Observation {
            id: "w1".into(),
            ts: 1_791_000_200,
            url: "https://lone.example/login?user=admin'--&uqtag=zz9".into(),
            ..Default::default()
        });
        new_case(&root, "s-1", "Two operators", records, &rules, "2026-10-12").unwrap();
        update(&root, "s-1", |c| {
            for e in &mut c.endpoints {
                e.state = EndpointState::Targeted;
            }
            c.contacts = vec![
                contact(
                    ContactRole::Affected,
                    "example.gov",
                    Some("portal.example.gov"),
                    "security@portal.example.gov",
                ),
                contact(
                    ContactRole::Affected,
                    "elsewhere.example",
                    Some("elsewhere.example"),
                    "security@elsewhere.example",
                ),
                contact(
                    ContactRole::Affected,
                    "Nowhere",
                    None,
                    "ops@nowhere.example",
                ),
                contact(
                    ContactRole::Affected,
                    "lone.example",
                    Some("lone.example"),
                    "security@lone.example",
                ),
                contact(
                    ContactRole::Provider,
                    "Tencent",
                    None,
                    "security@tencent.example",
                ),
            ];
            Ok(())
        })
        .unwrap();
        let c = load(&root, "s-1").unwrap();
        let all = analysis(&root, &c, &Scope::All).unwrap();
        assert!(
            all.results
                .iter()
                .any(|r| r.target_host.as_deref() == Some("elsewhere.example")),
            "the fixture has a second operator"
        );

        // The provider and case notes see the whole case.
        let provider = report(&root, "s-1", Audience::Provider, None, None, "d").unwrap();
        assert!(provider.contains("elsewhere[.]example"), "{provider}");
        let notes = report(&root, "s-1", Audience::Internal, None, None, "d").unwrap();
        assert!(notes.contains("elsewhere[.]example"), "{notes}");

        // An operator sees its own endpoint, never the other one: not in
        // the report (the .eml's body) or the bundle beside it.
        let to = &c.contacts[0];
        let own = report(&root, "s-1", Audience::Affected, None, Some(to), "d").unwrap();
        assert!(own.contains("portal[.]example[.]gov"), "{own}");
        assert!(!own.contains("elsewhere") && !own.contains("lone"), "{own}");
        // What the rest of the case says, counted and never named.
        assert!(own.contains("## Wider activity"), "{own}");
        assert!(own.contains("which also reached 2 other host(s)"), "{own}");
        // An operator whose one request links to the run only through
        // records elsewhere still gets it, and nothing of the others.
        let lone = report(
            &root,
            "s-1",
            Audience::Affected,
            None,
            Some(&c.contacts[3]),
            "d",
        )
        .unwrap();
        assert!(lone.contains("lone[.]example/login"), "{lone}");
        assert!(lone.contains("only through records elsewhere"), "{lone}");
        assert!(
            !lone.contains("portal[.]") && !lone.contains("elsewhere[.]"),
            "{lone}"
        );
        let p = draft(
            &root,
            "s-1",
            Audience::Affected,
            "security@portal.example.gov",
            None,
            None,
            "2026-10-14",
            false,
        )
        .unwrap();
        assert!(p.is_file());
        let bundled = bundles_text(&root, "s-1");
        assert!(bundled.contains("portal.example.gov"));
        assert!(!bundled.contains("elsewhere"), "{bundled}");
        assert!(!bundled.contains("\"e1\""), "{bundled}");
        let records = case_records(
            &root,
            &c,
            &Scope::for_audience(Audience::Affected, Some(to)),
        )
        .unwrap();
        assert!(records.iter().all(|o| o.url.contains("portal.example.gov")));

        // Without a contact, or for a contact with no endpoint, there is no
        // operator to scope to: refused, never the whole case.
        assert!(report(&root, "s-1", Audience::Affected, None, None, "d").is_err());
        let e = draft(
            &root,
            "s-1",
            Audience::Affected,
            "ops@nowhere.example",
            None,
            None,
            "2026-10-14",
            false,
        )
        .unwrap_err();
        assert!(e.to_string().contains("own endpoints"), "{e}");
        cleanup(&root);
    }

    #[test]
    fn drafts_never_overwrite_each_other() {
        let root = scratch("stems");
        let rules = RulesText::load(None).unwrap();
        let records: Vec<Observation> = fixture().results.iter().map(|r| r.obs.clone()).collect();
        new_case(&root, "d-1", "Drafts", records, &rules, "2026-10-12").unwrap();
        update(&root, "d-1", |c| {
            c.contacts = vec![
                contact(ContactRole::Provider, "P", None, "a.b@x.org"),
                contact(ContactRole::Provider, "P", None, "a-b@x.org"),
            ];
            Ok(())
        })
        .unwrap();
        let d = |to: &str, force| {
            draft(
                &root,
                "d-1",
                Audience::Provider,
                to,
                None,
                None,
                "2026-10-14",
                force,
            )
        };
        let one = d("a.b@x.org", false).unwrap();
        let two = d("a-b@x.org", false).unwrap();
        assert_ne!(one, two, "addresses that slug alike");
        assert!(
            one.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("2026-10-14-provider-a-b-x-org-")
        );
        // A hand-edited draft is kept unless forced.
        std::fs::write(&one, "edited").unwrap();
        assert!(
            d("a.b@x.org", false)
                .unwrap_err()
                .to_string()
                .contains("--force")
        );
        assert_eq!(std::fs::read_to_string(&one).unwrap(), "edited");
        d("a.b@x.org", true).unwrap();
        assert_ne!(std::fs::read_to_string(&one).unwrap(), "edited");
        cleanup(&root);
    }

    #[test]
    fn concurrent_changes_to_one_case_are_both_kept() {
        let root = scratch("lock");
        let rules = RulesText::load(None).unwrap();
        let records: Vec<Observation> = fixture().results.iter().map(|r| r.obs.clone()).collect();
        new_case(&root, "l-1", "Lock", records, &rules, "2026-10-12").unwrap();
        // One command holds the case through a slow step (as `case contacts`
        // does through its lookups) while another adds a note.
        let (tx, rx) = std::sync::mpsc::channel();
        let slow = {
            let root = root.clone();
            std::thread::spawn(move || {
                update(&root, "l-1", |c| {
                    tx.send(()).unwrap();
                    std::thread::sleep(std::time::Duration::from_millis(300));
                    c.log("d", "slow change");
                    Ok(())
                })
                .unwrap();
            })
        };
        rx.recv().unwrap();
        update(&root, "l-1", |c| {
            c.log("d", "quick note");
            Ok(())
        })
        .unwrap();
        slow.join().unwrap();
        let c = load(&root, "l-1").unwrap();
        let texts: Vec<&str> = c.decisions.iter().map(|d| d.text.as_str()).collect();
        assert!(
            texts.contains(&"slow change") && texts.contains(&"quick note"),
            "{texts:?}"
        );
        // A change inside a change is refused, not lost: the outer one
        // fails and the case is as it was.
        let err = update(&root, "l-1", |c| {
            log_entry(&root, "l-1", "d", "nested")?;
            c.log("d", "outer");
            Ok(())
        })
        .unwrap_err();
        assert!(err.to_string().contains("already being changed"), "{err}");
        let c = load(&root, "l-1").unwrap();
        assert!(
            !c.decisions
                .iter()
                .any(|d| d.text == "nested" || d.text == "outer"),
            "{:?}",
            c.decisions
        );
        // The lock was let go: the next change goes through.
        log_entry(&root, "l-1", "d", "after").unwrap();
        let c = load(&root, "l-1").unwrap();
        assert!(c.decisions.iter().any(|d| d.text == "after"));
        cleanup(&root);
    }

    #[test]
    fn status_as_json_lists_cases_and_shows_one_defanged() {
        let root = scratch("status-json");
        let rules = RulesText::load(None).unwrap();
        let records: Vec<Observation> = fixture().results.iter().map(|r| r.obs.clone()).collect();
        new_case(&root, "j-1", "Json", records, &rules, "2026-10-12").unwrap();
        let all = status::json(&root, None).unwrap();
        assert_eq!(all["cases"][0]["id"], "j-1", "{all}");
        assert_eq!(all["cases"][0]["status"], CaseStatus::Open.label());
        let one = status::json(&root, Some("j-1")).unwrap();
        assert_eq!(one["records"], 6, "{one}");
        let hosts: Vec<&str> = one["endpoints"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|e| e["host"].as_str())
            .collect();
        assert!(!hosts.is_empty(), "{one}");
        assert!(hosts.iter().all(|h| h.contains("[.]")), "{hosts:?}");
        assert!(one["needs"].as_array().is_some_and(|n| !n.is_empty()));
        cleanup(&root);
    }

    #[test]
    fn opening_a_case_records_its_admin() {
        let root = scratch("admin");
        let rules = RulesText::load(None).unwrap();
        let records: Vec<Observation> = fixture().results.iter().map(|r| r.obs.clone()).collect();
        open_case(
            &root,
            "a-1",
            "A",
            records.clone(),
            &rules,
            "2026-10-12",
            Some("Ada"),
        )
        .unwrap();
        assert_eq!(load(&root, "a-1").unwrap().admin.as_deref(), Some("Ada"));
        open_case(
            &root,
            "a-2",
            "A",
            records.clone(),
            &rules,
            "2026-10-12",
            None,
        )
        .unwrap();
        assert_eq!(load(&root, "a-2").unwrap().admin, None);
        // The case holding the most of the records is found; a closed one
        // is not.
        let ids: BTreeSet<String> = records.iter().map(|o| o.id.clone()).collect();
        assert_eq!(holding(&root, &ids).unwrap().as_deref(), Some("a-1"));
        for id in ["a-1", "a-2"] {
            update(&root, id, |c| {
                c.status = CaseStatus::Closed;
                Ok(())
            })
            .unwrap();
        }
        assert_eq!(holding(&root, &ids).unwrap(), None);
        cleanup(&root);
    }

    #[test]
    fn case_lifecycle() {
        let root = scratch("life");
        let rules = RulesText::load(None).unwrap();
        let a = fixture();
        let records: Vec<Observation> = a
            .results
            .iter()
            .filter(|r| r.obs.id != "other")
            .map(|r| r.obs.clone())
            .collect();
        new_case(&root, "t-1", "Portal probe", records, &rules, "2026-10-12").unwrap();
        assert!(
            new_case(&root, "t-1", "again", vec![], &rules, "2026-10-12").is_err(),
            "no overwrite"
        );

        let c = load(&root, "t-1").unwrap();
        assert_eq!(c.status, CaseStatus::Open);
        assert_eq!(c.endpoints.len(), 1);
        assert_eq!(c.endpoints[0].host, "portal.example.gov");
        assert_eq!(c.endpoints[0].state, EndpointState::Unreviewed);

        // Adding records dedupes and picks up new hosts.
        let other: Vec<Observation> = a.results.iter().map(|r| r.obs.clone()).collect();
        assert_eq!(
            add_records(&root, "t-1", other, "2026-10-13").unwrap(),
            (1, 1)
        );
        assert_eq!(load_records(&root, "t-1").unwrap().len(), 6);

        // Self-identification plus a same-company network is not enough to
        // name a developer at the default threshold; a case claim is.
        let mut buf = Vec::new();
        status(&root, "t-1", &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("Tencent (Developer)"), "{s}");
        assert!(s.contains("no developer can be named yet"), "{s}");
        assert!(s.contains("classify 2 endpoint(s)"), "{s}");

        update(&root, "t-1", |c| {
            c.claims.push(Claim {
                details: vec!["uqtag zz9 also in a confirmed incident".into()],
                ..Claim::new("Tencent", Role::Developer, Evidence::SharedIdentifiers)
            });
            c.endpoints[0].state = EndpointState::Targeted;
            Ok(())
        })
        .unwrap();
        let md = report(&root, "t-1", Audience::Provider, None, None, "2026-10-14").unwrap();
        assert!(md.contains("**Tencent** (developer)"), "{md}");

        // Drafts go only to listed contacts, and never as case notes.
        assert!(
            draft(
                &root,
                "t-1",
                Audience::Affected,
                "x@y.example",
                None,
                None,
                "d",
                false
            )
            .is_err()
        );
        update(&root, "t-1", |c| {
            c.contacts.push(Contact {
                org: "portal.example.gov".into(),
                role: ContactRole::Affected,
                endpoint: Some("portal.example.gov".into()),
                channel: "email".into(),
                address: "security@portal.example.gov".into(),
                source: "https://portal.example.gov/.well-known/security.txt".into(),
                confidence: "medium".into(),
                found_on: "2026-10-14".into(),
                purpose: None,
            });
            Ok(())
        })
        .unwrap();
        assert!(
            draft(
                &root,
                "t-1",
                Audience::Internal,
                "security@portal.example.gov",
                None,
                None,
                "d",
                false
            )
            .is_err()
        );
        let p = draft(
            &root,
            "t-1",
            Audience::Affected,
            "SECURITY@portal.example.gov",
            None,
            None,
            "2026-10-14",
            false,
        )
        .unwrap();
        let eml = std::fs::read_to_string(&p).unwrap();
        assert!(eml.contains("To: security@portal.example.gov\r\n"));
        assert!(eml.contains("filename=\"MANIFEST.sha256\""));
        let bundle = root.join("t-1").join("bundles").join("2026-10-14");
        assert!(
            crate::bundle::verify(&bundle, &rules.rules)
                .unwrap()
                .is_empty()
        );
        let c = load(&root, "t-1").unwrap();
        assert_eq!(c.decisions.len(), 2);
        assert!(c.to_toml().unwrap().contains("[[claim]]"));
        assert!(
            draft(
                &root,
                "t-1",
                Audience::Public,
                "security@portal.example.gov",
                None,
                None,
                "d",
                false
            )
            .is_err(),
            "notices are published, not sent"
        );

        // The indicator notice: drafted in the case, blocked by the
        // self-review checklist and the second review until every item
        // passes, then added to notices/ without its draft banner.
        const H: i64 = 3600;
        let t0 = 1_791_500_000;
        let (p, review) = notice_draft(&root, "t-1", false, "2026-10-15", t0).unwrap();
        assert!(review.lint.is_empty(), "{:?}", review.lint);
        assert_eq!(review.unreviewed, vec!["elsewhere.example".to_string()]);
        assert!(
            notice_draft(&root, "t-1", false, "2026-10-15", t0).is_err(),
            "keeps edits"
        );
        let md = std::fs::read_to_string(&p).unwrap();
        assert!(md.contains("providers = [\"Tencent\"]"), "{md}");
        assert!(md.contains("affected = []"), "{md}");
        assert!(!md.contains("portal[.]example"), "{md}");
        let notices = root.join("notices");
        let rules = sc_core::Rules::default_rules();
        let add =
            |now| crate::notice::add_for_test(&root, "t-1", &notices, &rules, "2026-10-09", now);
        let e = add(t0 + 30 * H).unwrap_err().to_string();
        assert!(e.contains("every endpoint is classified"), "{e}");
        assert!(e.contains("alternative explanations"), "{e}");
        assert!(e.contains("every party was sent"), "{e}");
        assert!(e.contains("an approved second review"), "{e}");
        update(&root, "t-1", |c| {
            c.admin = Some("Ada Admin".into());
            c.endpoints[1].state = EndpointState::NotAffected;
            actions::classify(
                c,
                &["portal.example.gov".into()],
                EndpointState::Compromised,
                None,
                Some("operator statement: a web shell was found"),
                None,
                "2026-10-15",
            )?;
            actions::describe(
                c,
                &["portal.example.gov".into()],
                "a national government data portal",
                "2026-10-15",
            )?;
            actions::sent(
                c,
                "security@portal.example.gov",
                "email",
                None,
                Some(&rfc3339(t0 + 60)),
                None,
                t0 + 120,
            )?;
            actions::no_contact(
                c,
                sc_case::lead::ANY_PROVIDER,
                "no directory entry for the self-named vendor",
                t0 + 60,
            )?;
            for k in AlternativeKind::ALL {
                actions::alternative(c, k, Some("checked; see case notes"), None, "2026-10-15")?;
            }
            Ok(())
        })
        .unwrap();
        // The draft predates the sends, so it cannot say who was reported.
        let e = add(t0 + 30 * H).unwrap_err().to_string();
        assert!(e.contains("the draft was written after every send"), "{e}");
        notice_draft(&root, "t-1", true, "2026-10-15", t0 + 120).unwrap();
        let md = std::fs::read_to_string(&p).unwrap();
        assert!(md.contains("a national government data portal"), "{md}");
        assert!(!md.contains("portal[.]example"), "{md}");
        // A re-read inside the cooling-off does not count.
        checklist::reread(&root, "t-1", "2026-10-15", t0 + 120 + H / 2).unwrap();
        let e = add(t0 + 30 * H).unwrap_err().to_string();
        assert!(e.contains("re-read at least an hour"), "{e}");
        checklist::reread(&root, "t-1", "2026-10-15", t0 + 120 + H).unwrap();
        // The compromised endpoint's operator has 24 hours; no override.
        let e = add(t0 + 3 * H).unwrap_err().to_string();
        assert!(e.contains("The lead time runs until"), "{e}");
        assert!(e.contains(&show_time(t0 + 60 + 24 * H)), "{e}");
        // An edit after the re-read needs another re-read.
        let draft = std::fs::read_to_string(&p).unwrap();
        std::fs::write(
            &p,
            draft.replace("## Indicators", "Edited.\n\n## Indicators"),
        )
        .unwrap();
        assert!(add(t0 + 7 * H).unwrap_err().to_string().contains("re-read"));
        checklist::reread(&root, "t-1", "2026-10-15", t0 + 7 * H).unwrap();

        // The second review: never the admin, and of the exact draft.
        let review = |reviewer: &str, verdict, now| {
            let items = crate::notice::checklist_for(&root, "t-1", now).unwrap();
            let blockers = sc_case::review::blockers(&items);
            let sha = checklist::draft_sha(&root, "t-1").unwrap();
            let mut c = load(&root, "t-1").unwrap();
            let r = sc_case::review::record(
                &mut c,
                sc_case::review::Input {
                    stage: Stage::Indicators,
                    reviewer,
                    verdict,
                    note: None,
                    sha: &sha,
                },
                &blockers,
                now,
            );
            save(&root, &c).unwrap();
            r
        };
        assert!(review(" ada admin", Verdict::Approve, t0 + 7 * H).is_err());
        review("Rae Reviewer", Verdict::Approve, t0 + 7 * H).unwrap();
        // Still inside the lead.
        assert!(add(t0 + 8 * H).is_err());
        let added = add(t0 + 25 * H).unwrap();
        let text = std::fs::read_to_string(&added).unwrap();
        assert!(!text.contains("DRAFT"), "{text}");
        assert!(text.contains("kind = \"published\""), "{text}");
        assert!(
            text.contains("Reports went to the affected operators before publication")
                && text.contains(
                    "No contact could be found for the AI provider; contact was attempted."
                )
                && text.contains(sc_case::notice::REVIEWED)
                && !text.contains("Rae"),
            "{text}"
        );
        assert!(
            !text.contains("portal[.]example") && !text.contains("portal.example"),
            "{text}"
        );
        // Added is not published: reported, with the push pending.
        let c = load(&root, "t-1").unwrap();
        assert_eq!(c.status, CaseStatus::Reported);
        assert_eq!(c.publish_pending.as_deref(), Some("2026-10-09"));
        let mut buf = Vec::new();
        status(&root, "t-1", &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("publish pending"), "{s}");
        assert!(s.contains("Stage 2, naming"), "{s}");
        assert!(add(t0 + 26 * H).is_err());

        // Names: the compromised endpoint's operator waits 10 working days,
        // unless it consents.
        let naming = |now| crate::notice::naming_draft(&root, "t-1", true, "2026-10-10", now);
        let e = naming(t0 + 26 * H).unwrap_err().to_string();
        assert!(e.contains("may be named from"), "{e}");
        update(&root, "t-1", |c| {
            Ok(sc_case::naming::consent(
                c,
                "portal.example.gov",
                "operator e-mail agreeing to be named",
                t0 + 26 * H,
            )?)
        })
        .unwrap();
        let (np, hosts) = naming(t0 + 26 * H).unwrap();
        assert_eq!(hosts, ["portal.example.gov"]);
        let add_naming = |now| {
            crate::notice::add_naming_for_test(&root, "t-1", &notices, &rules, "2026-10-10", now)
        };
        let e = add_naming(t0 + 27 * H).unwrap_err().to_string();
        assert!(e.contains("an approved second review"), "{e}");
        // An objection blocks until a later approval of the current draft.
        let naming_review = |reviewer: &str, verdict| {
            let items =
                crate::notice::naming_checklist_for(&root, "t-1", &notices, t0 + 27 * H).unwrap();
            let blockers = sc_case::review::blockers(&items);
            let sha = crate::notice::naming_sha(&root, "t-1").unwrap();
            let mut c = load(&root, "t-1").unwrap();
            assert_eq!(c.stage(), Stage::Naming);
            sc_case::review::record(
                &mut c,
                sc_case::review::Input {
                    stage: Stage::Naming,
                    reviewer,
                    verdict,
                    note: Some("checked"),
                    sha: &sha,
                },
                &blockers,
                t0 + 27 * H,
            )
            .unwrap();
            save(&root, &c).unwrap();
        };
        naming_review("Rae Reviewer", Verdict::Approve);
        naming_review("Sam Second", Verdict::Object);
        assert!(add_naming(t0 + 27 * H).is_err());
        naming_review("Rae Reviewer", Verdict::Approve);
        // An edit voids the approval.
        let nd = std::fs::read_to_string(&np).unwrap();
        std::fs::write(&np, nd.replace("was affected", "was affected (edited)")).unwrap();
        assert!(add_naming(t0 + 27 * H).is_err());
        std::fs::write(&np, &nd).unwrap();
        let after = add_naming(t0 + 27 * H).unwrap();
        let text = std::fs::read_to_string(&after).unwrap();
        assert!(text.contains("kind = \"naming\""), "{text}");
        assert!(
            text.contains("affected = [\"portal.example.gov\"]"),
            "{text}"
        );
        assert!(text.contains("`portal[.]example[.]gov`"), "{text}");
        assert!(
            crate::notice::lint_file_for_test(&after, &rules).is_empty(),
            "{text}"
        );
        let c = load(&root, "t-1").unwrap();
        assert_eq!(c.named.len(), 1);
        assert!(naming(t0 + 28 * H).is_err(), "nobody left to name");

        // Not on any remote (no repository here): refused unless forced.
        let e = crate::notice::published_for_test(&root, &notices, "t-1", false, "2026-10-17");
        assert!(e.unwrap_err().to_string().contains("not on origin yet"));
        crate::notice::published_for_test(&root, &notices, "t-1", true, "2026-10-17").unwrap();
        let c = load(&root, "t-1").unwrap();
        assert_eq!((c.status, c.publish_pending), (CaseStatus::Published, None));
        assert!(crate::notice::published_for_test(&root, &notices, "t-1", true, "d").is_err());
        cleanup(&root);
    }
}
