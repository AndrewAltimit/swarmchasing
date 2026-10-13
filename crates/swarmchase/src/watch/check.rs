//! `swarmchase watch --check`: read a watchlist strictly, without the
//! network and without a data directory.
//!
//! A key the watchlist's types do not know is an error here, though a watch
//! run ignores it: a misspelt `limt` would otherwise leave the default in
//! force with nothing said. Source entries flatten their query
//! (`sc_collect::CdxQuery`) into the entry, and serde cannot see unknown
//! keys through a flatten, so each entry's query keys are checked on their
//! own. Every source is then built the way a run builds it, which checks its
//! kind, its endpoint and its other settings, but sends nothing.

use super::Watchlist;
use anyhow::{Context, Result, bail};
use sc_collect::{CdxQuery, Kind};
use std::collections::BTreeSet;
use std::path::Path;

/// What the check found: one line per problem.
#[derive(Debug, Default)]
pub struct Findings {
    pub sources: usize,
    pub platform_sources: usize,
    pub problems: Vec<String>,
}

/// Check `path`, print what was found, and fail when anything was.
pub fn run(path: &Path) -> Result<()> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let f = check(&text);
    for p in &f.problems {
        eprintln!("{}: {p}", path.display());
    }
    if !f.problems.is_empty() {
        bail!(
            "{}: {} problem(s); a watch run would ignore or reject these",
            path.display(),
            f.problems.len()
        );
    }
    println!(
        "{}: ok ({} source(s), {} platform source(s))",
        path.display(),
        f.sources,
        f.platform_sources
    );
    Ok(())
}

/// Check a watchlist's text.
pub fn check(text: &str) -> Findings {
    let mut f = Findings::default();
    let value: toml::Value = match toml::from_str(text) {
        Ok(v) => v,
        Err(e) => {
            f.problems.push(format!("not valid TOML: {e}"));
            return f;
        }
    };
    // The whole file through the real type: unknown keys outside the
    // flattened source entries, and every type error.
    let mut unknown = Vec::new();
    let parsed: Option<Watchlist> = match serde_ignored::deserialize(value.clone(), |p| {
        unknown.push(p.to_string());
    }) {
        Ok(w) => Some(w),
        Err(e) => {
            f.problems.push(format!("does not parse: {e}"));
            None
        }
    };
    f.problems
        .extend(unknown.into_iter().map(|k| format!("unknown key `{k}`")));
    for (table, outer) in [
        ("source", &["name", "kind"][..]),
        ("platform.source", &["name", "kind", "max_events"][..]),
    ] {
        for (i, entry) in entries(&value, table).iter().enumerate() {
            f.problems.extend(query_keys(entry, outer, table, i));
        }
    }
    let Some(wl) = parsed else {
        return f;
    };
    f.sources = wl.sources.len();
    f.platform_sources = wl.platform.sources.len();
    if wl.sources.is_empty() {
        f.problems.push("no [[source]] entries".into());
    }
    if let Err(e) = wl.autonomy.check() {
        f.problems.push(format!("[autonomy]: {e:#}"));
    }
    let mut names = BTreeSet::new();
    for s in &wl.sources {
        if !names.insert(s.name.as_str()) {
            f.problems
                .push(format!("duplicate source name `{}`", s.name));
        }
        let kind: Kind = match s.kind.parse() {
            Ok(k) => k,
            Err(e) => {
                f.problems.push(format!("source `{}`: {e:#}", s.name));
                continue;
            }
        };
        // A placeholder key: building a source never sends a request.
        if let Err(e) = sc_collect::source(kind, s.query.clone(), Some("check".into())) {
            f.problems.push(format!("source `{}`: {e:#}", s.name));
        }
    }
    let mut names = BTreeSet::new();
    for s in &wl.platform.sources {
        if !names.insert(s.name.as_str()) {
            f.problems
                .push(format!("duplicate platform source name `{}`", s.name));
        }
    }
    f
}

/// The tables of the array of tables at dotted `path`.
fn entries<'v>(v: &'v toml::Value, path: &str) -> Vec<&'v toml::Table> {
    let mut cur = Some(v);
    for part in path.split('.') {
        cur = cur.and_then(|c| c.get(part));
    }
    cur.and_then(|c| c.as_array())
        .map(|a| a.iter().filter_map(|e| e.as_table()).collect())
        .unwrap_or_default()
}

/// Keys of one source entry that are neither the entry's own (`outer`) nor
/// a query field.
fn query_keys(entry: &toml::Table, outer: &[&str], table: &str, i: usize) -> Vec<String> {
    let name = entry
        .get("name")
        .and_then(|n| n.as_str())
        .map_or_else(|| format!("#{}", i + 1), |n| format!("`{n}`"));
    let mut rest = entry.clone();
    for k in outer {
        rest.remove(*k);
    }
    let mut unknown = Vec::new();
    let res: Result<CdxQuery, _> =
        serde_ignored::deserialize(toml::Value::Table(rest), |p| unknown.push(p.to_string()));
    let mut out: Vec<String> = unknown
        .into_iter()
        .map(|k| format!("[[{table}]] {name}: unknown key `{k}`"))
        .collect();
    if let Err(e) = res {
        out.push(format!("[[{table}]] {name}: {e}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_committed_watchlist_passes() {
        let f = check(include_str!("../../../../watchlist.toml"));
        assert!(f.problems.is_empty(), "{:#?}", f.problems);
        assert!(f.sources > 0);
    }

    #[test]
    fn a_misspelt_key_is_reported_wherever_it_is() {
        let f = check(
            r#"
overlap_dayz = 3
[autonomy]
interrupt = "shadow"
[[source]]
name = "a"
kind = "wayback"
pattern = "r.jina.ai/*"
limt = 10
[[source]]
name = "a"
kind = "wayback"
pattern = "x/*"
[platform]
[[platform.source]]
name = "p"
kind = "npm"
pattern = "x"
max_event = 3
"#,
        );
        let all = f.problems.join("\n");
        for want in [
            "unknown key `overlap_dayz`",
            "[[source]] `a`: unknown key `limt`",
            "duplicate source name `a`",
            "[[platform.source]] `p`: unknown key `max_event`",
        ] {
            assert!(all.contains(want), "missing {want:?} in\n{all}");
        }
        assert_eq!(f.problems.len(), 4, "{all}");
        // `[autonomy]` refuses unknown keys itself.
        let f = check(
            "[autonomy]
interupts_per_day = 2
[[source]]
name = \"a\"
kind = \"wayback\"
pattern = \"x\"
",
        );
        assert!(
            f.problems.iter().any(|p| p.contains("interupts_per_day")),
            "{f:?}"
        );
    }

    #[test]
    fn a_bad_kind_type_or_endpoint_is_reported() {
        let f = check(
            "[[source]]\nname = \"a\"\nkind = \"nosuch\"\npattern = \"x\"\n\
             [[source]]\nname = \"b\"\nkind = \"ctlog\"\npattern = \"x\"\n",
        );
        assert!(f.problems.iter().any(|p| p.contains("source `a`")), "{f:?}");
        assert!(f.problems.iter().any(|p| p.contains("source `b`")), "{f:?}");
        let f = check(
            "[[source]]\nname = \"a\"\nkind = \"wayback\"\npattern = \"x\"\nlimit = \"many\"\n",
        );
        assert!(!f.problems.is_empty(), "{f:?}");
        let f = check("min_interval_secs = 3\n");
        assert_eq!(f.problems, ["no [[source]] entries"]);
        let f = check("[[source]\n");
        assert!(f.problems[0].starts_with("not valid TOML"), "{f:?}");
    }
}
