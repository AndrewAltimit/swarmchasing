//! `swarmchase notice`: public notices in `notices/<id>.md`.
//!
//! `swarmchase case notice` drafts a notice inside the case. Once the admin
//! has reviewed it, `notice add` checks it and copies it into `notices/`;
//! committing and pushing that file is what publishes it. `notice update`
//! appends dated updates (status changes, corrections, statements), `notice
//! lint` is the CI check that no committed notice carries what notices
//! withhold, and `notice build` writes the site's notice pages and feed.

use crate::case;
use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand};
use sc_core::Rules;
use sc_core::notice::{
    NoticeFile, NoticePage, NoticeStatus, NoticeUpdate, UpdateKind, atom_feed, check_notice,
    index_entry, md_blocks, parse_notice, write_notice,
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
            let p = add(&data.join("cases"), &id, &args.dir, &rules, &today)?;
            println!(
                "wrote {}; it is not public until you commit and push it",
                p.display()
            );
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
    if !sc_core::notice::is_slug(id) {
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
            problems
        }
    }
}

fn append(n: &mut NoticeFile, u: NoticeUpdate, status: Option<NoticeStatus>) -> Result<()> {
    if let Some(last) = n.meta.updates.last()
        && u.date < last.date
    {
        bail!("{} is before the last update ({})", u.date, last.date);
    }
    if u.kind == UpdateKind::Reply && u.from.is_none() {
        bail!("a statement needs --from (who it is from)");
    }
    if u.kind == UpdateKind::Status && status.is_none() {
        bail!("a status update needs --status");
    }
    if u.kind == UpdateKind::Published {
        bail!("`published` is added by `notice add`");
    }
    if let Some(s) = status {
        n.meta.status = s;
    }
    n.meta.updated = u.date.clone();
    n.meta.updates.push(u);
    Ok(())
}

/// Turn the case's reviewed draft into a notice file in `dir`.
fn add(cases: &Path, id: &str, dir: &Path, rules: &Rules, today: &str) -> Result<PathBuf> {
    let target = notice_path(dir, id)?;
    if target.exists() {
        bail!(
            "{} exists; use `swarmchase notice update {id}`",
            target.display()
        );
    }
    let c = case::load(cases, id)?;
    let unreviewed: Vec<&str> = c
        .endpoints
        .iter()
        .filter(|e| e.state == case::EndpointState::Unreviewed)
        .map(|e| e.host.as_str())
        .collect();
    if !unreviewed.is_empty() {
        bail!(
            "classify every endpoint first (unreviewed: {})",
            unreviewed.join(", ")
        );
    }
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
        text: if c.sent.is_empty() {
            "Notice published.".into()
        } else {
            "Notice published. Reports went to the AI provider and the affected operators at the same time.".into()
        },
    }];
    let mut problems = case::leak_check(cases, &c, |r| check_notice(&n, r))?;
    for p in check_notice(&n, rules) {
        if !problems.contains(&p) {
            problems.push(p);
        }
    }
    if !problems.is_empty() {
        for p in &problems {
            eprintln!("{}: {p}", draft.display());
        }
        bail!("not added: fix the draft first");
    }
    if c.sent.is_empty() {
        eprintln!(
            "warning: no sends recorded for case {id}; reports and the notice go out together (`swarmchase case sent`)"
        );
    }
    std::fs::create_dir_all(dir)?;
    std::fs::write(&target, write_notice(&n))?;
    case::update(cases, id, |c| {
        c.status = case::CaseStatus::Published;
        c.log(
            today,
            format!("notice added as {} (public once pushed)", target.display()),
        );
        Ok(())
    })?;
    Ok(target)
}

fn strip_draft_banner(body: &str) -> String {
    let mut out = String::new();
    let mut skip_blank = false;
    for line in body.lines() {
        if line.starts_with("> **DRAFT**") {
            skip_blank = true;
            continue;
        }
        if skip_blank && line.trim().is_empty() {
            skip_blank = false;
            continue;
        }
        skip_blank = false;
        out.push_str(line);
        out.push('\n');
    }
    out
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
    notices.sort_by(|a, b| {
        b.meta
            .updated
            .cmp(&a.meta.updated)
            .then(a.meta.id.cmp(&b.meta.id))
    });
    std::fs::create_dir_all(out)?;
    let index: Vec<_> = notices.iter().map(index_entry).collect();
    std::fs::write(out.join("index.json"), serde_json::to_string(&index)?)?;
    for n in &notices {
        let page = NoticePage {
            meta: &n.meta,
            blocks: md_blocks(&n.body),
        };
        std::fs::write(
            out.join(format!("{}.json", n.meta.id)),
            serde_json::to_string(&page)?,
        )?;
    }
    let base = if base_url.ends_with('/') {
        base_url.to_string()
    } else {
        format!("{base_url}/")
    };
    std::fs::write(out.join("feed.xml"), atom_feed(&notices, &base))?;
    Ok(notices.len())
}

#[cfg(test)]
pub fn add_for_test(
    cases: &Path,
    id: &str,
    dir: &Path,
    rules: &Rules,
    today: &str,
) -> Result<PathBuf> {
    add(cases, id, dir, rules, today)
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
        assert!(feed.contains("https://x.example/s/#notice=n-1"), "{feed}");

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
    fn banner_is_stripped() {
        let b = "# T\n\n> **DRAFT** — generated by swarmchase. Verify.\n\n- **Window:** x\n";
        assert_eq!(strip_draft_banner(b), "# T\n\n- **Window:** x\n");
    }
}
