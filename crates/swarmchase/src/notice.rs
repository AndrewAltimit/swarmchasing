//! `swarmchase notice`: public notices in `notices/<id>.md`.
//!
//! A notice is published in two stages. `swarmchase case notice` drafts the
//! indicator notice inside the case: what the activity was and how to
//! recognise it, naming and locating no affected party. Once the admin has
//! re-read it and a second reviewer approved it, `notice add` checks it and
//! copies it into `notices/`; committing and pushing that file is what
//! publishes it. `case notice --naming` drafts a naming update for the
//! operators whose naming clock has run or who consented, and `notice
//! update --naming` appends it once it passes its own checklist and review.
//! `notice update` also appends other dated updates (status changes,
//! corrections, statements), which need no review; `notice lint` is the CI
//! check that no committed notice carries what notices withhold; `notice
//! build` writes the site's notice pages and feed.

use crate::case::{
    self, NAMING_DRAFT, NOTICE_DRAFT, Pinned, Scope, case_dir, load, report_options, update,
};
use crate::pinning::leak_check;
use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand};
use sc_case::lead;
use sc_case::naming::{self, NamingDraft};
use sc_case::notice::lint::{lint_notice, withholding};
use sc_case::notice::{
    NoticeFile, NoticeMeta, NoticeStatus, NoticeUpdate, UpdateKind, naming_text, parse_notice,
    published_text, strip_draft_banner, unreached, write_notice,
};
use sc_core::Rules;
use sc_core::notice::lint_public;
use sc_core::{Audience, render_notice};
use sc_publish::build_site;
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
    /// Append a dated update to a notice: a status change, correction,
    /// statement, retraction or other update, or with --naming the case's
    /// reviewed naming update.
    Update {
        id: String,
        /// update | status | correction | reply | retraction
        #[arg(long, required_unless_present = "naming")]
        kind: Option<UpdateKind>,
        /// Append the case's reviewed naming draft (`case notice <id>
        /// --naming`), naming the operators whose naming clock has run or
        /// who consented. Runs the naming checklist, with its second review.
        #[arg(long, conflicts_with_all = ["kind", "text", "text_file", "from", "status"])]
        naming: bool,
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
            naming,
            text,
            text_file,
            from,
            status,
            date,
            data,
        } => {
            if naming {
                crate::store::hint_if_empty(&data);
                let now = chrono::Utc::now().timestamp();
                let p = add_naming(&data.join("cases"), &id, &args.dir, &rules, &today, now)?;
                println!(
                    "updated {}; it is not public until you commit and push it",
                    p.display()
                );
                return Ok(());
            }
            let Some(kind) = kind else {
                bail!("give --kind, or --naming");
            };
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
            let cases = data.join("cases");
            // Another update names no affected party the notice has not named:
            // names go out only through a reviewed naming update.
            if kind == UpdateKind::Update
                && case::case_dir(&cases, &id)?.join("case.toml").is_file()
            {
                let c = case::load(&cases, &id)?;
                let p = naming::identifies(&c, &text, &n.meta.affected);
                if !p.is_empty() {
                    for x in &p {
                        eprintln!("{}: the update {x}", path.display());
                    }
                    bail!(
                        "not written: affected organisations are named only in a reviewed naming update (`swarmchase notice update {id} --naming`)"
                    );
                }
            }
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
            let problems = lint_notice(&n, &rules);
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
    if !sc_case::notice::is_slug(id) {
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

/// Every problem with a committed notice: the linter
/// ([`sc_case::notice::lint`]) and a file name matching its id.
fn lint_file(p: &Path, rules: &Rules) -> Vec<String> {
    match read(p) {
        Err(e) => vec![e.to_string()],
        Ok(n) => {
            let mut problems = lint_notice(&n, rules);
            let stem = p.file_stem().unwrap_or_default().to_string_lossy();
            if stem != n.meta.id {
                problems.push(format!("file name does not match id `{}`", n.meta.id));
            }
            problems
        }
    }
}

fn append(n: &mut NoticeFile, u: NoticeUpdate, status: Option<NoticeStatus>) -> Result<()> {
    n.append(u, status).map_err(anyhow::Error::msg)
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
    // What the notice may say about scope and agency comes from the case,
    // whatever the draft's front matter says.
    let public = case::analysis(cases, &c, &Scope::Public)?;
    let (scope, grade) = sc_case::checklist::framing(&c, &sc_case::checklist::covered(&public));
    n.meta.scope = scope;
    n.meta.agent_grade = grade.map(|g| g.code().to_string());
    let mut problems = leak_check(cases, &c, |r| withholding(&n, r))?;
    for p in withholding(&n, rules) {
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
        let clock = lead::clock(&c);
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
    let not_before = lead::clock(&c).not_before.unwrap_or(now);
    let review = sc_case::review::state(
        &c,
        case::Stage::Indicators,
        case::checklist::draft_sha(cases, id).ok().as_deref(),
    )
    .describe();
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
                "self-review checklist passed; lead time ({}) ran out {}; {}",
                lead::summary(),
                case::show_time(not_before),
                review
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
    let pinned = Pinned::new(root, &c)?;
    let a = pinned.analysis(&Scope::Public)?;
    let mut opts = report_options(&c, Audience::Public, None, today);
    // The indicator notice names and locates no affected party: each
    // affected endpoint appears by the admin's description, or as an
    // affected organisation.
    opts.target_descriptions = Some(
        c.endpoints
            .iter()
            .filter(|e| e.state.affected())
            .map(|e| {
                (
                    e.host.to_ascii_lowercase(),
                    e.sector
                        .clone()
                        .unwrap_or_else(|| "an affected organisation".into()),
                )
            })
            .collect(),
    );
    let mut notice = render_notice(&a, &opts);
    // An endpoint seen only in records anyone could have submitted is named
    // later only with the admin's logged reason.
    let all = pinned.analysis(&Scope::All)?;
    for h in case::checklist::single_source_hosts(&c, &all) {
        if c.endpoint(&h)
            .and_then(|e| e.single_source.as_deref())
            .is_none()
        {
            notice.flags.push(format!(
                "every record on {} is submit-anywhere: a naming update may name its operator only with `swarmchase case endpoint {id} {h} <state> --single-source-reason \"…\"`, or mark it not-affected",
                sc_core::defang_host(&h)
            ));
        }
    }
    let providers = sc_case::report::nameable_developers(&c, &sc_case::report::all_claims(&c, &a));
    let (scope, grade) = sc_case::checklist::framing(&c, &sc_case::checklist::covered(&a));
    let n = NoticeFile {
        meta: NoticeMeta {
            id: id.to_string(),
            title: c.title.clone(),
            status: c.notice,
            published: today.to_string(),
            updated: today.to_string(),
            providers,
            affected: Vec::new(),
            sector: None,
            scope,
            agent_grade: grade.map(|g| g.code().to_string()),
            rules_version: a.rules_version.clone(),
            toolkit: env!("CARGO_PKG_VERSION").to_string(),
            updates: Vec::new(),
        },
        // A swarm the case recorded reviewed interaction for; fleets alone
        // stay out of the notice.
        body: sc_case::fleet::with_fleets(
            notice.markdown.clone(),
            &sc_case::fleet::report_section(&c, &a, Audience::Public),
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
    lint.extend(naming::identifies(
        &c,
        &format!("{}\n{}", n.meta.title, n.body),
        &[],
    ));
    let review = NoticeReview {
        lint,
        withheld,
        flags: notice.flags,
        unreviewed: c.unreviewed().into_iter().map(str::to_string).collect(),
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

/// The notice a naming update is appended to: the committed notice in
/// `dir` when there is one, else the case's indicator draft as `notice add`
/// would write it (for `case checklist` and `case review` before it is
/// pushed anywhere the CLI can see).
fn base_notice(cases: &Path, id: &str, dir: &Path, today: &str) -> Result<NoticeFile> {
    let p = notice_path(dir, id)?;
    if p.is_file() {
        return read(&p);
    }
    let (_, n, _, _) = prepare(cases, id, &Rules::default_rules(), today)?;
    Ok(n)
}

/// The SHA-256 of the case's naming draft as it is on disk.
pub(crate) fn naming_sha(cases: &Path, id: &str) -> Result<String> {
    let p = case_dir(cases, id)?.join(NAMING_DRAFT);
    let bytes = std::fs::read(&p).map_err(|e| {
        anyhow::anyhow!(
            "reading {}: {e}; run `swarmchase case notice {id} --naming`",
            p.display()
        )
    })?;
    Ok(sc_case::bundle::sha256_hex(&bytes))
}

/// The notice with the case's naming draft appended, the draft, and the
/// naming checklist for it at `now`.
fn naming_prepare(
    cases: &Path,
    id: &str,
    dir: &Path,
    rules: &Rules,
    today: &str,
    now: i64,
) -> Result<(NoticeFile, NamingDraft, Vec<case::checklist::Item>)> {
    let c = case::load(cases, id)?;
    let path = case_dir(cases, id)?.join(NAMING_DRAFT);
    let text = std::fs::read_to_string(&path).with_context(|| {
        format!(
            "reading {}; run `swarmchase case notice {id} --naming`",
            path.display()
        )
    })?;
    let draft =
        NamingDraft::parse(&text).map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
    let mut n = base_notice(cases, id, dir, today)?;
    append(
        &mut n,
        NoticeUpdate {
            date: today.to_string(),
            kind: UpdateKind::Naming,
            from: None,
            text: naming_text(&draft.text),
        },
        None,
    )?;
    for h in &draft.hosts {
        if !n.meta.affected.iter().any(|x| x.eq_ignore_ascii_case(h)) {
            n.meta.affected.push(h.to_ascii_lowercase());
        }
    }
    let mut problems = leak_check(cases, &c, |r| withholding(&n, r))?;
    for p in lint_notice(&n, rules) {
        if !problems.contains(&p) {
            problems.push(p);
        }
    }
    let pinned = Pinned::new(cases, &c)?;
    let all = pinned.analysis(&Scope::All)?;
    let public = pinned.analysis(&Scope::Public)?;
    let sha = naming_sha(cases, id).ok();
    let items = sc_case::checklist::naming_checklist(sc_case::checklist::NamingInputs {
        case: &c,
        notice: &n,
        draft: &draft,
        all: &all,
        public: &public,
        draft_sha: sha.as_deref(),
        withholding: problems,
        now,
    });
    Ok((n, draft, items))
}

/// The naming checklist for case `id`'s naming draft at `now`; `dir` is the
/// committed notices directory.
pub(crate) fn naming_checklist_for(
    cases: &Path,
    id: &str,
    dir: &Path,
    now: i64,
) -> Result<Vec<case::checklist::Item>> {
    let today = case::rfc3339(now)[..10].to_string();
    Ok(naming_prepare(cases, id, dir, &Rules::default_rules(), &today, now)?.2)
}

/// Append the case's reviewed naming draft to its notice in `dir`, once
/// every item of the naming checklist passes.
fn add_naming(
    cases: &Path,
    id: &str,
    dir: &Path,
    rules: &Rules,
    today: &str,
    now: i64,
) -> Result<PathBuf> {
    let target = notice_path(dir, id)?;
    if !target.is_file() {
        bail!(
            "no notice {id} in {}; `swarmchase notice add {id}` first",
            dir.display()
        );
    }
    let (n, draft, items) = naming_prepare(cases, id, dir, rules, today, now)?;
    case::checklist::print_titled("Naming checklist", &items, &mut std::io::stdout())?;
    let failing = case::checklist::failing(&items);
    if !failing.is_empty() {
        bail!(
            "not added: {} naming checklist item(s) fail ({})",
            failing.len(),
            failing.join("; ")
        );
    }
    std::fs::write(&target, write_notice(&n))?;
    let review = sc_case::review::state(
        &case::load(cases, id)?,
        case::Stage::Naming,
        naming_sha(cases, id).ok().as_deref(),
    )
    .describe();
    case::update(cases, id, |c| {
        naming::mark_named(c, &draft.hosts, today);
        c.log(today, format!("naming checklist passed; {review}"));
        Ok(())
    })?;
    Ok(target)
}

/// Draft the next naming update into `<case>/naming.md`, for the operators
/// that may be named at `now`. Returns the path and the hosts it names.
pub(crate) fn naming_draft(
    root: &Path,
    id: &str,
    force: bool,
    today: &str,
    now: i64,
) -> Result<(PathBuf, Vec<String>)> {
    let c = load(root, id)?;
    let path = case_dir(root, id)?.join(NAMING_DRAFT);
    if path.exists() && !force {
        bail!(
            "{} exists and may hold your edits; pass --force to replace it",
            path.display()
        );
    }
    if !c.notice_added() {
        bail!("add the indicator notice first (`swarmchase notice add {id}`); names follow it");
    }
    let hosts = naming::ready(&c, now);
    if hosts.is_empty() {
        let mut msg = format!("no operator of case {id} may be named now:");
        for o in naming::operators(&c) {
            msg += &format!(
                "\n  operator of {}: {}",
                sc_core::defang_host(&o.host),
                o.status(now)
            );
        }
        bail!("{msg}");
    }
    let all = Pinned::new(root, &c)?.analysis(&Scope::All)?;
    let single = case::checklist::single_source_hosts(&c, &all);
    let d = naming::draft(&c, &hosts, &single);
    std::fs::write(&path, d.write())?;
    update(root, id, |c| {
        c.log(
            today,
            format!(
                "naming update drafted for {} (sha256 {})",
                hosts
                    .iter()
                    .map(|h| sc_core::defang_host(h))
                    .collect::<Vec<_>>()
                    .join(", "),
                &crate::bundle::sha256_hex(d.write().as_bytes())[..12]
            ),
        );
        Ok(())
    })?;
    Ok((path, hosts))
}

#[cfg(test)]
pub fn add_naming_for_test(
    cases: &Path,
    id: &str,
    dir: &Path,
    rules: &Rules,
    today: &str,
    now: i64,
) -> Result<PathBuf> {
    add_naming(cases, id, dir, rules, today, now)
}

#[cfg(test)]
pub fn lint_file_for_test(p: &Path, rules: &Rules) -> Vec<String> {
    lint_file(p, rules)
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
}
