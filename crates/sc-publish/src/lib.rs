//! `sc-publish`: public notices as files and as the site that shows them.
//!
//! - [`file`]: the notice file (`notices/<id>.md`), its front matter and
//!   dated updates, and the check that gates publication.
//! - [`markdown`]: a notice body as plain blocks the page renders as text.
//! - [`feed`]: the Atom feed, one entry per update.
//! - [`site`]: the index and per-notice JSON the site loads, and the feed.
//!
//! What a notice may carry ([`sc_core::notice::PublicView`],
//! [`sc_core::notice::lint_public`]) stays in `sc-core`, because reports and
//! the browser need it. No network I/O and no file I/O: callers read and
//! write the files.

pub mod feed;
pub mod file;
pub mod markdown;
pub mod pages;
pub mod site;

pub use feed::atom_feed;
pub use file::{
    NoticeFile, NoticeMeta, NoticeStatus, NoticeUpdate, UpdateKind, check_notice, is_slug,
    parse_notice, strip_draft_banner, write_notice,
};
pub use markdown::{Block, Inline, ListItem, md_blocks, md_inline};
pub use pages::{SiteInputs, build_pages};
pub use site::{IndexEntry, NoticePage, build_site, index_entry};

#[cfg(test)]
mod tests {
    use super::*;
    use sc_core::Rules;

    fn notice() -> NoticeFile {
        NoticeFile {
            meta: NoticeMeta {
                id: "2026-10-portal".into(),
                title: "Portal <probe> & co".into(),
                status: NoticeStatus::Active,
                published: "2026-10-20".into(),
                updated: "2026-10-22".into(),
                providers: vec![],
                affected: vec!["portal.example.gov".into()],
                rules_version: "2026-10-12".into(),
                toolkit: "0.1.0".into(),
                updates: vec![
                    NoticeUpdate {
                        date: "2026-10-20".into(),
                        kind: UpdateKind::Published,
                        from: None,
                        text: "Initial notice.".into(),
                    },
                    NoticeUpdate {
                        date: "2026-10-22".into(),
                        kind: UpdateKind::Correction,
                        from: None,
                        text: "The window started a day later.".into(),
                    },
                ],
            },
            body: "# Notice\n\n- **Window:** a → b\n\n## Endpoints\n\n| Host | Hits |\n|---|---|\n| `a[.]b` | 3 \\| 4 |\n\n1. one — `x`\n   - rules: r1\n2. two\n\n> quoted **line**\n\nplain\ncontinued\n".into(),
        }
    }

    #[test]
    fn notice_file_round_trips_and_checks() {
        let n = notice();
        let text = write_notice(&n);
        assert!(
            text.starts_with("+++\n") && text.contains("[[update]]"),
            "{text}"
        );
        let back = parse_notice(&text).unwrap();
        assert_eq!(back, n);
        assert!(check_notice(&n, &Rules::default_rules()).is_empty());

        let mut bad = n.clone();
        bad.body.push_str("\n> **DRAFT** — x\n");
        bad.meta.updated = "2026-10-21".into();
        bad.meta.updates[1].text = "inbox is ntfy.sh/agent-run-77".into();
        assert_eq!(check_notice(&bad, &Rules::default_rules()).len(), 3);
        assert!(parse_notice("no front matter").is_err());
        assert!(parse_notice(&text.replace("2026-10-portal", "../x")).is_err());
    }

    #[test]
    fn blocks_cover_the_report_subset() {
        let b = md_blocks(&notice().body);
        assert!(matches!(&b[0], Block::Heading { level: 1, .. }));
        let Block::List {
            ordered: false,
            items,
        } = &b[1]
        else {
            panic!("{b:?}")
        };
        assert_eq!(
            items[0].c,
            vec![
                Inline::Strong("Window:".into()),
                Inline::Text(" a → b".into())
            ]
        );
        let Block::Table { head, rows } = &b[3] else {
            panic!("{b:?}")
        };
        assert_eq!(head.len(), 2);
        assert_eq!(rows[0][1], vec![Inline::Text("3 | 4".into())]);
        assert_eq!(rows[0][0], vec![Inline::Code("a[.]b".into())]);
        let Block::List {
            ordered: true,
            items,
        } = &b[4]
        else {
            panic!("{b:?}")
        };
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].sub.len(), 1);
        assert!(matches!(&b[5], Block::Quote { lines } if lines.len() == 1));
        assert_eq!(
            b[6],
            Block::Para {
                c: vec![Inline::Text("plain continued".into())]
            }
        );
        assert_eq!(md_inline("a ** b"), vec![Inline::Text("a ** b".into())]);
    }

    #[test]
    fn feed_escapes_and_orders_updates() {
        let f = atom_feed(&[notice()], "https://example.github.io/swarmchasing/");
        assert!(
            f.contains("<title>Correction: Portal &lt;probe&gt; &amp; co</title>"),
            "{f}"
        );
        assert!(f.find("Correction:").unwrap() < f.find("Published:").unwrap());
        assert!(f.contains("<updated>2026-10-22T00:00:00Z</updated>"));
        assert!(f.contains("notices/2026-10-portal/#1"));
    }
}
