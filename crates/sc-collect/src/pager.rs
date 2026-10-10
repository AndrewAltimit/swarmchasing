//! Paging shared by every record source: fetch pages until the limit or the
//! end of the index, and say where the pull stopped so it can continue.

use anyhow::Result;
use sc_core::Observation;

/// Where a pull continues.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cursor {
    /// An opaque resume key (Wayback's `resumeKey`). Valid across runs as
    /// long as the query, `from` included, is unchanged.
    Key(String),
    /// A result offset (urlquery search). Valid only within one pull: new
    /// results shift every offset.
    Offset(usize),
}

/// One page of records, and the cursor of the next page if there is one.
#[derive(Debug, Clone, Default)]
pub struct Page {
    pub records: Vec<Observation>,
    pub next: Option<Cursor>,
    /// The source had more records than it returned and cannot page to them
    /// (Arquivo.pt's index, a one-page feed). The pull is incomplete.
    pub truncated: bool,
}

/// The result of one pull.
#[derive(Debug, Default)]
pub struct Pull {
    pub observations: Vec<Observation>,
    /// Where the next pull continues; `None` once the source has nothing more.
    pub next_cursor: Option<Cursor>,
    /// The pull reached the end of the source.
    pub complete: bool,
    /// HTTP requests made, retries included.
    pub requests: usize,
    /// A page failed after earlier pages succeeded. The pull kept what it had,
    /// and `next_cursor` is the last good cursor.
    pub stopped: Option<anyhow::Error>,
    /// A page was cut short by a source that cannot page (see [`Page::truncated`]).
    pub truncated: bool,
}

impl Pull {
    /// The pull, or the error that stopped it early.
    pub fn strict(mut self) -> Result<Self> {
        match self.stopped.take() {
            Some(e) => Err(e),
            None => Ok(self),
        }
    }
}

/// Fetch pages from `start` until `limit` records or the end. `fetch` gets the
/// page size to ask for and the cursor to continue from; `on_page` sees each
/// page as it arrives (to write progress), and an error from it ends the pull.
/// A fetch error on the first page is returned; after that the pull stops and
/// keeps what it has (see [`Pull::stopped`]).
pub fn pull(
    limit: usize,
    page_size: usize,
    start: Option<Cursor>,
    mut fetch: impl FnMut(usize, Option<&Cursor>) -> Result<Page>,
    on_page: &mut dyn FnMut(&Page) -> Result<()>,
) -> Result<Pull> {
    let mut out = Pull::default();
    let mut cursor = start;
    while out.observations.len() < limit {
        let size = (limit - out.observations.len()).min(page_size.max(1));
        let page = match fetch(size, cursor.as_ref()) {
            Ok(p) => p,
            Err(e) if !out.observations.is_empty() => {
                out.stopped = Some(e);
                break;
            }
            Err(e) => return Err(e),
        };
        on_page(&page)?;
        out.truncated |= page.truncated;
        out.observations.extend(page.records);
        cursor = page.next;
        if cursor.is_none() {
            out.complete = true;
            break;
        }
    }
    out.next_cursor = cursor;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    fn page(ids: &[&str], next: Option<&str>) -> Result<Page> {
        Ok(Page {
            records: ids
                .iter()
                .map(|id| Observation {
                    id: id.to_string(),
                    ..Default::default()
                })
                .collect(),
            next: next.map(|k| Cursor::Key(k.into())),
            truncated: false,
        })
    }

    /// A fetcher that serves `pages` in order and logs what it was asked for.
    fn canned(
        pages: Vec<Result<Page>>,
        asked: &mut Vec<(usize, Option<Cursor>)>,
    ) -> impl FnMut(usize, Option<&Cursor>) -> Result<Page> + '_ {
        let mut pages = VecDeque::from(pages);
        move |size, c| {
            asked.push((size, c.cloned()));
            pages.pop_front().expect("no more pages")
        }
    }

    fn ids(p: &Pull) -> Vec<&str> {
        p.observations.iter().map(|o| o.id.as_str()).collect()
    }

    #[test]
    fn pages_until_the_end() {
        let mut asked = Vec::new();
        let pages = vec![page(&["a", "b"], Some("k1")), page(&["c"], None)];
        let p = pull(10, 2, None, canned(pages, &mut asked), &mut |_| Ok(())).unwrap();
        assert_eq!(ids(&p), ["a", "b", "c"]);
        assert!(p.complete && p.next_cursor.is_none() && p.stopped.is_none());
        assert_eq!(asked, [(2, None), (2, Some(Cursor::Key("k1".into())))]);
    }

    #[test]
    fn stops_at_the_limit_with_a_cursor() {
        let mut asked = Vec::new();
        let pages = vec![page(&["a", "b"], Some("k1")), page(&["c"], Some("k2"))];
        let start = Some(Cursor::Key("k0".into()));
        let p = pull(3, 2, start.clone(), canned(pages, &mut asked), &mut |_| {
            Ok(())
        })
        .unwrap();
        assert_eq!(ids(&p), ["a", "b", "c"]);
        assert!(!p.complete);
        assert_eq!(p.next_cursor, Some(Cursor::Key("k2".into())));
        // The last page asks only for what the limit leaves.
        assert_eq!(asked, [(2, start), (1, Some(Cursor::Key("k1".into())))]);

        // A zero limit fetches nothing and keeps the starting cursor.
        let p = pull(
            0,
            2,
            Some(Cursor::Offset(7)),
            |_, _| unreachable!(),
            &mut |_| Ok(()),
        )
        .unwrap();
        assert_eq!(p.next_cursor, Some(Cursor::Offset(7)));
        assert!(!p.complete);
    }

    #[test]
    fn a_failed_page_keeps_what_came_before() {
        let mut asked = Vec::new();
        let pages = vec![page(&["a"], Some("k1")), Err(anyhow::anyhow!("HTTP 503"))];
        let p = pull(10, 1, None, canned(pages, &mut asked), &mut |_| Ok(())).unwrap();
        assert_eq!(ids(&p), ["a"]);
        assert_eq!(p.next_cursor, Some(Cursor::Key("k1".into())));
        assert!(!p.complete);
        assert!(p.stopped.is_some());
        assert!(p.strict().is_err());

        // On the first page there is nothing to keep.
        let mut asked = Vec::new();
        let pages = vec![Err(anyhow::anyhow!("HTTP 503"))];
        assert!(pull(10, 1, None, canned(pages, &mut asked), &mut |_| Ok(())).is_err());
    }

    #[test]
    fn page_size_is_at_least_one_and_on_page_sees_every_page() {
        let mut asked = Vec::new();
        let pages = vec![page(&["a"], Some("k1")), page(&["b"], None)];
        let mut seen = 0;
        let p = pull(5, 0, None, canned(pages, &mut asked), &mut |pg| {
            seen += pg.records.len();
            Ok(())
        })
        .unwrap();
        assert_eq!((p.observations.len(), seen), (2, 2));
        assert!(asked.iter().all(|(n, _)| *n == 1));

        // An error from on_page ends the pull.
        let mut asked = Vec::new();
        let pages = vec![page(&["a"], Some("k1"))];
        let r = pull(5, 1, None, canned(pages, &mut asked), &mut |_| {
            Err(anyhow::anyhow!("disk full"))
        });
        assert!(r.is_err());
    }
}
