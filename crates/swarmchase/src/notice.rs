//! `swarmchase notice`: public notices in `notices/<id>.md`.
//!
//! `swarmchase case notice` drafts a notice inside the case. Once the admin
//! has reviewed it, `notice add` checks it and copies it into `notices/`;
//! committing and pushing that file is what publishes it. `notice update`
//! appends dated updates (status changes, corrections, statements), `notice
//! lint` is the CI check that no committed notice carries what notices
//! withhold, and `notice build` writes the site's notice pages and feed.

use crate::case::{
    self, EndpointState, NOTICE_DRAFT, case_dir, case_records, load, report_options, update,
};
use crate::evidence::Scope;
use crate::pinning::{case_rules, leak_check};
use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand};
use sc_core::Rules;
use sc_core::notice::lint_public;
use sc_core::{Audience, Reported, Role, analyze, render_notice};
use sc_publish::{
    NoticeFile, NoticeMeta, NoticeStatus, NoticeUpdate, UpdateKind, build_site, check_notice,
    parse_notice, strip_draft_banner, write_notice,
};
use std::path::{Path, PathBuf};

#[derive(Args)]
pub struct NoticeArgs {
    /// The committed notices directory.
    #[arg(long, default_value = "notices", global = true)]
    dir: PathBuf,
    #[command(subcommand)]
    cmd: NoticeCmd,
}

#[derive(Subcommand)]
enum NoticeCmd {
    /// Check a case's reviewed notice draft and copy it into the notices
    /// directory. Commit and push the file to publish it.
    Add {
        case: String,
        #[arg(short, long, default_value = "data", env = "SWARMCHASE_DATA")]
        data: PathBuf,
    },
    /// Mark a case's added notice as published once it is on the remote
    /// (checked read-only against origin's refs), moving the case from
    /// reported to published.
    Published {
        case: String,
        /// Mark it without finding it on the remote (published another way).
        #[arg(long)]
        force: bool,
        #[arg(short, long, default_value = "data", env = "SWARMCHASE_DATA")]
        data: PathBuf,
    },
    /// Append a dated update to a notice.
    Update {
        id: String,
        /// update | status | correction | reply | retraction
        #[arg(long)]
        kind: UpdateKind,
        #[arg(long, conflicts_with = "text_file")]
        text: Option<String>,
        /// Read the text from a file (a statement, verbatim).
        #[arg(long)]
        text_file: Option<PathBuf>,
        /// Who a statement is from (required for `reply`).
        #[arg(long)]
        from: Option<String>,
        /// The notice's new status.
        #[arg(long)]
        status: Option<NoticeStatus>,
        /// Default: today.
        #[arg(long)]
        date: Option<String>,
        /// Data directory. With --status, the case of the same ID there (if
        /// any) gets the same notice status and a log entry.
        #[arg(short, long, default_value = "data", env = "SWARMCHASE_DATA")]
        data: PathBuf,
    },
    /// Check notices: front matter, update order, and nothing a notice
    /// withholds (callback channels, addresses, credentials). Default: every
    /// notice in the directory.
    Lint { files: Vec<PathBuf> },
    /// Write the site's notice files: index.json, one <id>.json per notice,
    /// and an Atom feed with one entry per update.
    Build {
        #[arg(long)]
        out: PathBuf,
        /// The site's URL, for feed links.
        #[arg(long, env = "SWARMCHASE_SITE_URL")]
        base_url: String,
    },
}

pub fn run(args: NoticeArgs) -> Result<()> {
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let rules = Rules::default_rules();
    match args.cmd {
        NoticeCmd::Add { case: id, data } => {
            crate::store::hint_if_empty(&data);
            let now = chrono::Utc::now().timestamp();
            let p = add(&data.join("cases"), &id, &args.dir, &rules, &today, now)?;
            println!(
                "wrote {}; it is not public until you commit and push it, then `swarmchase notice published {id}`",
                p.display()
            );
            Ok(())
        }
        NoticeCmd::Published {
            case: id,
            force,
            data,
        } => {
            let at = published(&data.join("cases"), &args.dir, &id, force, &today)?;
            println!("case {id}: published ({at})");
            Ok(())
        }
        NoticeCmd::Update {
            id,
            kind,
            text,
            text_file,
            from,
            status,
            date,
            data,
        } => {
            let text = match (text, text_file) {
                (Some(t), _) => t,
                (None, Some(p)) => std::fs::read_to_string(&p)
                    .with_context(|| format!("reading {}", p.display()))?,
                (None, None) => match (kind, status) {
                    (UpdateKind::Status, Some(s)) => format!("Status changed to {}.", s.label()),
                    _ => bail!("give the update's text with --text or --text-file"),
                },
            };
            let path = notice_path(&args.dir, &id)?;
            let mut n = read(&path)?;
            append(
                &mut n,
                NoticeUpdate {
                    date: date.unwrap_or(today),
                    kind,
                    from,
                    text: text.trim_end().to_string(),
                },
                status,
            )?;
            let problems = check_notice(&n, &rules);
            if !problems.is_empty() {
                for p in &problems {
                    eprintln!("{}: {p}", path.display());
                }
                bail!("not written: the update would break the notice");
            }
            std::fs::write(&path, write_notice(&n))?;
            println!(
                "updated {} (status {}); commit and push to publish",
                path.display(),
                n.meta.status.label()
            );
            let cases = data.join("cases");
            if let Some(s) = status
                && case::case_dir(&cases, &id)?.join("case.toml").is_file()
            {
                case::update(&cases, &id, |c| {
                    c.notice = s;
                    c.log(
                        &n.meta.updated,
                        format!("notice status: {} (notice update)", s.label()),
                    );
                    Ok(())
                })?;
            }
            Ok(())
        }
        NoticeCmd::Lint { files } => {
            let files = if files.is_empty() {
                list(&args.dir)?
            } else {
                files
            };
            let mut bad = 0;
            for f in &files {
                let problems = lint_file(f, &rules);
                for p in &problems {
                    eprintln!("{}: {p}", f.display());
                }
                bad += usize::from(!problems.is_empty());
            }
            if bad > 0 {
                bail!("{bad} of {} notice(s) failed", files.len());
            }
            println!("notices OK ({} checked)", files.len());
            Ok(())
        }
        NoticeCmd::Build { out, base_url } => {
            let n = build(&args.dir, &out, &base_url, &rules)?;
            println!("wrote {n} notice(s) to {}", out.display());
            Ok(())
        }
    }
}

fn notice_path(dir: &Path, id: &str) -> Result<PathBuf> {
    if !sc_publish::is_slug(id) {
        bail!("notice id `{id}` is not a slug");
    }
    Ok(dir.join(format!("{id}.md")))
}

/// The status of the committed notice `<dir>/<id>.md`, if there is one.
pub(crate) fn published_status(dir: &Path, id: &str) -> Result<Option<NoticeStatus>> {
    let p = notice_path(dir, id)?;
    if !p.is_file() {
        return Ok(None);
    }
    Ok(Some(read(&p)?.meta.status))
}

fn read(p: &Path) -> Result<NoticeFile> {
    let text = std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?;
    parse_notice(&text).map_err(|e| anyhow::anyhow!("{}: {e}", p.display()))
}

/// Every notice file in the directory (not its README).
fn list(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut v = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries {
            let p = e?.path();
            let name = p.file_name().unwrap_or_default().to_string_lossy();
            if name.ends_with(".md") && !name.eq_ignore_ascii_case("README.md") {
                v.push(p);
            }
        }
    }
    v.sort();
    Ok(v)
}

fn lint_file(p: &Path, rules: &Rules) -> Vec<String> {
    match read(p) {
        Err(e) => vec![e.to_string()],
        Ok(n) => {
            let mut problems = check_notice(&n, rules);
            let stem = p.file_stem().unwrap_or_default().to_string_lossy();
            if stem != n.meta.id {
                problems.push(format!("file name does not match id `{}`", n.meta.id));
            }
            problems.extend(wording_problems(&n));
            problems
        }
    }
}

/// What the self-review checks that a committed notice shows on its own:
/// attribution statements with a layer, label and tag, likelihood words
/// within their labels, and no provider in the title that the notice does
/// not name as a developer.
fn wording_problems(n: &NoticeFile) -> Vec<String> {
    let text = format!("{}\n{}", n.meta.title, n.body);
    let mut out = crate::wording::claim_problems(&n.body);
    out.extend(crate::wording::likelihood_problems(&text));
    out.extend(crate::wording::title_problems(
        &n.meta.title,
        &n.meta.providers,
        &crate::contacts::Directory::builtin(),
    ));
    out
}

fn append(n: &mut NoticeFile, u: NoticeUpdate, status: Option<NoticeStatus>) -> Result<()> {
    n.append(u, status).map_err(anyhow::Error::msg)
}

/// The first update's text: published, who the recorded sends reached
/// before it, and the parties no contact was found for.
fn published_text(r: &Reported, unreached: &[String]) -> String {
    let mut s = match r.parties() {
        Some(p) => format!(
            "Notice published. Reports went to {p} before publication, each with the fixed lead time of our disclosure policy."
        ),
        None => "Notice published.".into(),
    };
    if !unreached.is_empty() {
        s += &format!(
            " No contact could be found for {}; contact was attempted.",
            and_list(unreached)
        );
    }
    s
}

fn and_list(items: &[String]) -> String {
    match items {
        [] => String::new(),
        [one] => one.clone(),
        [init @ .., last] => format!("{} and {last}", init.join(", ")),
    }
}

/// The parties recorded as having no contact, as a notice names them:
/// the AI provider, or an affected operator by its defanged host.
fn unreached(c: &case::Case) -> Vec<String> {
    let mut v: Vec<String> = c
        .no_contact
        .iter()
        .filter(|n| {
            !c.sent
                .iter()
                .any(|s| s.recipient.eq_ignore_ascii_case(&n.party))
        })
        .map(|n| {
            if c.endpoints
                .iter()
                .any(|e| e.host.eq_ignore_ascii_case(&n.party))
            {
                format!("the operator of {}", sc_core::defang_host(&n.party))
            } else {
                "the AI provider".to_string()
            }
        })
        .collect();
    v.sort();
    v.dedup();
    v
}

/// The notice `notice add` would write for case `id`, the draft it comes
/// from, and what the withholding scan finds in it.
fn prepare(
    cases: &Path,
    id: &str,
    rules: &Rules,
    today: &str,
) -> Result<(case::Case, NoticeFile, PathBuf, Vec<String>)> {
    let c = case::load(cases, id)?;
    let draft = case::case_dir(cases, id)?.join(case::NOTICE_DRAFT);
    let mut n = read(&draft).context("run `swarmchase case notice` first")?;
    n.body = strip_draft_banner(&n.body);
    n.meta.id = id.to_string();
    n.meta.status = c.notice;
    n.meta.published = today.to_string();
    n.meta.updated = today.to_string();
    n.meta.updates = vec![NoticeUpdate {
        date: today.to_string(),
        kind: UpdateKind::Published,
        from: None,
        text: published_text(&case::reported(&c), &unreached(&c)),
    }];
    let mut problems = leak_check(cases, &c, |r| check_notice(&n, r))?;
    for p in check_notice(&n, rules) {
        if !problems.contains(&p) {
            problems.push(p);
        }
    }
    Ok((c, n, draft, problems))
}

/// The self-review checklist for case `id`'s notice draft at `now`.
pub(crate) fn checklist_for(
    cases: &Path,
    id: &str,
    now: i64,
) -> Result<Vec<case::checklist::Item>> {
    let today = case::rfc3339(now)[..10].to_string();
    let (c, n, _, problems) = prepare(cases, id, &Rules::default_rules(), &today)?;
    case::checklist::checklist(cases, &c, &n, problems, now)
}

/// Turn the case's reviewed draft into a notice file in `dir`, once every
/// item of the self-review checklist passes.
fn add(
    cases: &Path,
    id: &str,
    dir: &Path,
    rules: &Rules,
    today: &str,
    now: i64,
) -> Result<PathBuf> {
    let target = notice_path(dir, id)?;
    if target.exists() {
        bail!(
            "{} exists; use `swarmchase notice update {id}`",
            target.display()
        );
    }
    let (c, n, draft, problems) = prepare(cases, id, rules, today)?;
    for p in &problems {
        eprintln!("{}: {p}", draft.display());
    }
    let items = case::checklist::checklist(cases, &c, &n, problems, now)?;
    case::checklist::print(&items, &mut std::io::stdout())?;
    let failing = case::checklist::failing(&items);
    if !failing.is_empty() {
        let clock = case::lead::clock(&c);
        let lead = match clock.not_before {
            Some(t) if t > now => format!(
                " The lead time runs until {}; the notice cannot be added before then.",
                case::show_time(t)
            ),
            _ => String::new(),
        };
        bail!(
            "not added: {} checklist item(s) fail ({}).{lead}",
            failing.len(),
            failing.join("; ")
        );
    }
    std::fs::create_dir_all(dir)?;
    std::fs::write(&target, write_notice(&n))?;
    let not_before = case::lead::clock(&c).not_before.unwrap_or(now);
    case::update(cases, id, |c| {
        // Added is not published: the notice is public once it is pushed.
        if c.status == case::CaseStatus::Open {
            c.status = case::CaseStatus::Reported;
            c.log(today, "status: reported");
        }
        c.publish_pending = Some(today.to_string());
        c.log(
            today,
            format!(
                "self-review checklist passed; lead time ({}) ran out {}",
                case::lead::summary(c),
                case::show_time(not_before)
            ),
        );
        c.log(
            today,
            format!(
                "notice added as {} (publish pending: public once pushed; then `swarmchase notice published {id}`)",
                target.display()
            ),
        );
        Ok(())
    })?;
    Ok(target)
}

/// Where a committed notice is on the remote, if it is there: the first of
/// `origin/HEAD`, `origin/main` that holds `<dir>/<id>.md`. Reads local refs
/// only; it never fetches or pushes.
pub(crate) fn on_remote(dir: &Path, id: &str) -> Option<String> {
    let file = notice_path(dir, id).ok()?;
    let top = std::process::Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .current_dir(
            dir.parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new(".")),
        )
        .output()
        .ok()
        .filter(|o| o.status.success())?;
    let top = PathBuf::from(String::from_utf8_lossy(&top.stdout).trim());
    let abs = std::path::absolute(&file).ok()?;
    let top = std::fs::canonicalize(&top).ok()?;
    let parent = std::fs::canonicalize(abs.parent()?).ok()?;
    let rel = parent.strip_prefix(&top).ok()?.join(abs.file_name()?);
    let rel = rel.to_string_lossy().replace('\\', "/");
    ["origin/HEAD", "origin/main"].into_iter().find_map(|r| {
        let ok = std::process::Command::new("git")
            .args(["cat-file", "-e", &format!("{r}:{rel}")])
            .current_dir(&top)
            .output()
            .ok()?
            .status
            .success();
        ok.then(|| format!("{r}:{rel}"))
    })
}

/// Mark a case's notice published: it must be added, and (unless `force`)
/// found on the remote by [`on_remote`].
fn published(cases: &Path, dir: &Path, id: &str, force: bool, today: &str) -> Result<String> {
    let c = case::load(cases, id)?;
    if c.status == case::CaseStatus::Published && c.publish_pending.is_none() {
        bail!("case {id} is already marked published");
    }
    if !notice_path(dir, id)?.is_file() {
        bail!(
            "no notice {id} in {}; `swarmchase notice add {id}` first",
            dir.display()
        );
    }
    let seen = match (on_remote(dir, id), force) {
        (Some(at), _) => at,
        (None, true) => "marked by hand (--force)".to_string(),
        (None, false) => bail!(
            "notices/{id}.md is not on origin yet (local refs; run `git fetch` after pushing), or pass --force"
        ),
    };
    case::update(cases, id, |c| {
        c.status = case::CaseStatus::Published;
        c.publish_pending = None;
        c.log(today, format!("notice published ({seen})"));
        Ok(())
    })?;
    Ok(seen)
}

/// Write `index.json`, `<id>.json` and `feed.xml` into `out`. Refuses when
/// any notice fails its check.
fn build(dir: &Path, out: &Path, base_url: &str, rules: &Rules) -> Result<usize> {
    let mut notices = Vec::new();
    for p in list(dir)? {
        let problems = lint_file(&p, rules);
        if !problems.is_empty() {
            bail!("{}: {}", p.display(), problems.join("; "));
        }
        notices.push(read(&p)?);
    }
    let files = build_site(&mut notices, base_url, rules).map_err(anyhow::Error::msg)?;
    std::fs::create_dir_all(out)?;
    for (name, text) in files {
        std::fs::write(out.join(name), text)?;
    }
    Ok(notices.len())
}

/// What the admin reviews in a notice draft.
pub struct NoticeReview {
    pub withheld: Vec<String>,
    pub flags: Vec<String>,
    /// Anything a notice must not carry that got through anyway.
    pub lint: Vec<String>,
    pub unreviewed: Vec<String>,
}

pub(crate) fn notice_draft(
    root: &Path,
    id: &str,
    force: bool,
    today: &str,
    now: i64,
) -> Result<(PathBuf, NoticeReview)> {
    let c = load(root, id)?;
    let path = case_dir(root, id)?.join(NOTICE_DRAFT);
    if path.exists() && !force {
        bail!(
            "{} exists and may hold your edits; pass --force to replace it",
            path.display()
        );
    }
    let rules = case_rules(root, &c)?;
    let a = analyze(case_records(root, &c, &Scope::Public)?, &rules);
    let opts = report_options(&c, Audience::Public, None, today);
    let mut notice = render_notice(&a, &opts);
    // An endpoint seen only in records anyone could have submitted is named
    // only with the admin's logged reason, and in words that do not say a
    // request reached it.
    let all = analyze(case_records(root, &c, &Scope::All)?, &rules);
    let mut single = Vec::new();
    for h in case::checklist::single_source_hosts(&c, &all) {
        let reason = c
            .endpoints
            .iter()
            .find(|e| e.host.eq_ignore_ascii_case(&h))
            .and_then(|e| e.single_source.as_deref());
        match reason {
            Some(_) => single.push(case::checklist::single_source_line(&c, &h)),
            None => notice.flags.push(format!(
                "every record on {} is submit-anywhere: name its operator only with `swarmchase case endpoint {id} {h} <state> --single-source-reason \"…\"`, or mark it not-affected",
                sc_core::defang_host(&h)
            )),
        }
    }
    if !single.is_empty() {
        let para = format!(
            "**Submitted, not observed.** {} No server log or owner-published record shows a request reaching them.\n\n",
            single.join(" ")
        );
        notice.markdown = match notice.markdown.find("## Indicators") {
            Some(i) => format!("{}{para}{}", &notice.markdown[..i], &notice.markdown[i..]),
            None => format!("{}\n{para}", notice.markdown),
        };
    }
    let claims = a.clusters.iter().fold(c.claims.clone(), |acc, cl| {
        sc_core::attribution::merge(acc, &sc_core::attribute(&a, cl))
    });
    let mut providers: Vec<String> = claims
        .iter()
        .filter(|x| x.role == Role::Developer && x.nameable(c.min_named))
        .map(|x| x.party.clone())
        .collect();
    providers.dedup();
    let n = NoticeFile {
        meta: NoticeMeta {
            id: id.to_string(),
            title: c.title.clone(),
            status: c.notice,
            published: today.to_string(),
            updated: today.to_string(),
            providers,
            affected: case::affected_hosts(&c),
            sector: None,
            rules_version: a.rules_version.clone(),
            toolkit: env!("CARGO_PKG_VERSION").to_string(),
            updates: Vec::new(),
        },
        // A swarm the case recorded reviewed interaction for; fleets alone
        // stay out of the notice.
        body: crate::case::fleet::with_fleets(
            notice.markdown.clone(),
            &crate::case::fleet::report_section(&c, &a, Audience::Public),
        ),
    };
    let text = write_notice(&n);
    std::fs::write(&path, &text)?;
    let stamp = case::DraftStamp {
        sha256: crate::bundle::sha256_hex(text.as_bytes()),
        at: case::rfc3339(now),
    };
    let mut withheld = notice.withheld;
    for e in c
        .evidence
        .iter()
        .filter(|e| e.public.is_none() && e.kept > 0)
    {
        withheld.push(format!(
            "operator logs {} from {} (no agreement recorded; `swarmchase case evidence consent {id} {}`)",
            e.id, e.org, e.id
        ));
    }
    let mut lint = leak_check(root, &c, |r| {
        lint_public(&format!("{}\n{}", n.meta.title, n.body), r)
    })?;
    lint.extend(notice.leaks);
    let review = NoticeReview {
        lint,
        withheld,
        flags: notice.flags,
        unreviewed: c
            .endpoints
            .iter()
            .filter(|e| e.state == EndpointState::Unreviewed)
            .map(|e| e.host.clone())
            .collect(),
    };
    update(root, id, |c| {
        c.drafted = Some(stamp.clone());
        c.log(
            today,
            format!(
                "notice drafted ({} withheld, {} to decide; sha256 {})",
                review.withheld.len(),
                review.flags.len(),
                &stamp.sha256[..12]
            ),
        );
        Ok(())
    })?;
    Ok((path, review))
}

#[cfg(test)]
pub fn add_for_test(
    cases: &Path,
    id: &str,
    dir: &Path,
    rules: &Rules,
    today: &str,
    now: i64,
) -> Result<PathBuf> {
    add(cases, id, dir, rules, today, now)
}

#[cfg(test)]
pub fn published_for_test(
    cases: &Path,
    dir: &Path,
    id: &str,
    force: bool,
    today: &str,
) -> Result<String> {
    published(cases, dir, id, force, today)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn published_text_names_only_the_parties_sent() {
        let r = |provider, operators, others| Reported {
            provider,
            operators,
            others,
        };
        let lead = "before publication, each with the fixed lead time of our disclosure policy.";
        assert_eq!(
            published_text(&r(false, false, false), &[]),
            "Notice published."
        );
        assert_eq!(
            published_text(&r(false, true, false), &[]),
            format!("Notice published. Reports went to the affected operators {lead}")
        );
        assert_eq!(
            published_text(&r(true, false, false), &[]),
            format!("Notice published. Reports went to the AI provider {lead}")
        );
        assert_eq!(
            published_text(&r(true, true, true), &[]),
            format!(
                "Notice published. Reports went to the AI provider, the affected operators and other responders {lead}"
            )
        );
        let unreached = ["the operator of a[.]example".to_string()];
        assert_eq!(
            published_text(&r(true, false, false), &unreached),
            format!(
                "Notice published. Reports went to the AI provider {lead} No contact could be found for the operator of a[.]example; contact was attempted."
            )
        );
    }

    #[test]
    fn lint_checks_wording() {
        let n = parse_notice(
            "+++\nid = \"n-1\"\ntitle = \"Claude agents probe a portal\"\nstatus = \"active\"\npublished = \"2026-10-16\"\nupdated = \"2026-10-16\"\nrules_version = \"r\"\ntoolkit = \"0\"\n\n[[update]]\ndate = \"2026-10-16\"\nkind = \"published\"\ntext = \"Published.\"\n+++\n\n# Notice\n\n## Attribution\n\n- Anthropic ran it. Label: Possible; tag: Inference.\n- Suspected: almost certain operated by **Anthropic**. Tag: Conclusion.\n",
        )
        .unwrap();
        let p = wording_problems(&n);
        assert_eq!(p.len(), 3, "{p:?}");
        assert!(p.iter().any(|x| x.contains("without a layer")), "{p:?}");
        assert!(
            p.iter()
                .any(|x| x.contains("`almost certain` is stronger than Suspected")),
            "{p:?}"
        );
        assert!(
            p.iter().any(|x| x.contains("the title names `claude`")),
            "{p:?}"
        );
    }

    #[test]
    fn updates_append_in_order_and_build_writes_site_files() {
        let dir = std::env::temp_dir().join(format!("swarmchase-notices-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let rules = Rules::default_rules();
        let mut n = parse_notice(
            "+++\nid = \"n-1\"\ntitle = \"T\"\nstatus = \"active\"\npublished = \"2026-10-16\"\nupdated = \"2026-10-16\"\nrules_version = \"r\"\ntoolkit = \"0\"\n\n[[update]]\ndate = \"2026-10-16\"\nkind = \"published\"\ntext = \"Published.\"\n+++\n\n# Notice\n\nBody.\n",
        )
        .unwrap();
        let upd = |date: &str, kind| NoticeUpdate {
            date: date.into(),
            kind,
            from: None,
            text: "x".into(),
        };
        assert!(append(&mut n, upd("2026-10-15", UpdateKind::Update), None).is_err());
        assert!(append(&mut n, upd("2026-10-17", UpdateKind::Reply), None).is_err());
        assert!(append(&mut n, upd("2026-10-17", UpdateKind::Status), None).is_err());
        append(
            &mut n,
            upd("2026-10-30", UpdateKind::Status),
            Some(NoticeStatus::Contained),
        )
        .unwrap();
        assert_eq!(n.meta.updated, "2026-10-30");
        assert_eq!(n.meta.status, NoticeStatus::Contained);
        std::fs::write(dir.join("n-1.md"), write_notice(&n)).unwrap();
        std::fs::write(dir.join("README.md"), "# not a notice\n").unwrap();
        assert!(lint_file(&dir.join("n-1.md"), &rules).is_empty());

        let out = dir.join("site");
        assert_eq!(build(&dir, &out, "https://x.example/s", &rules).unwrap(), 1);
        let idx = std::fs::read_to_string(out.join("index.json")).unwrap();
        assert!(idx.contains("\"status\":\"contained\""), "{idx}");
        let page = std::fs::read_to_string(out.join("n-1.json")).unwrap();
        assert!(page.contains("\"t\":\"heading\""), "{page}");
        let feed = std::fs::read_to_string(out.join("feed.xml")).unwrap();
        assert!(feed.contains("https://x.example/s/notices/n-1/"), "{feed}");

        // A leak in any notice stops the build.
        std::fs::write(
            dir.join("n-2.md"),
            write_notice(&n)
                .replace("id = \"n-1\"", "id = \"n-2\"")
                .replace("Body.", "ntfy.sh/agent-run-77"),
        )
        .unwrap();
        assert!(build(&dir, &out, "https://x.example/s", &rules).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_pushed_notice_is_found_on_the_remote() {
        let root = std::env::temp_dir().join(format!("swarmchase-remote-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let (origin, work) = (root.join("origin.git"), root.join("work"));
        std::fs::create_dir_all(work.join("notices")).unwrap();
        let git = |dir: &Path, args: &[&str]| {
            let o = std::process::Command::new("git")
                .args(args)
                .current_dir(dir)
                .output()
                .unwrap();
            assert!(
                o.status.success(),
                "git {args:?}: {}",
                String::from_utf8_lossy(&o.stderr)
            );
        };
        git(&root, &["init", "-q", "--bare", "origin.git"]);
        git(&work, &["init", "-q", "-b", "main"]);
        git(
            &work,
            &["remote", "add", "origin", &origin.to_string_lossy()],
        );
        let dir = work.join("notices");
        std::fs::write(dir.join("n-1.md"), "x\n").unwrap();
        assert_eq!(on_remote(&dir, "n-1"), None, "not committed");
        git(&work, &["add", "notices/n-1.md"]);
        git(
            &work,
            &[
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@t.example",
                "commit",
                "-q",
                "-m",
                "n",
            ],
        );
        assert_eq!(on_remote(&dir, "n-1"), None, "committed, not pushed");
        // What a push leaves behind locally: origin's tracking ref at the
        // commit. Set it directly so the test needs no push.
        git(&work, &["update-ref", "refs/remotes/origin/main", "HEAD"]);
        assert_eq!(
            on_remote(&dir, "n-1").as_deref(),
            Some("origin/main:notices/n-1.md")
        );
        assert_eq!(on_remote(&dir, "n-2"), None);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn banner_is_stripped() {
        let b = "# T\n\n> **DRAFT** — generated by swarmchase. Verify.\n\n- **Window:** x\n";
        assert_eq!(strip_draft_banner(b), "# T\n\n- **Window:** x\n");
    }
}
