//! Published network ranges: download the cloud providers' address-range
//! files and the Tor bulk exit list into `<data>/netranges/`, and load them
//! into an [`sc_core::netranges::NetRanges`].
//!
//! Each file is one the provider publishes about its own network, at the
//! address its documentation gives: reading it is reading a public record,
//! not probing anyone's infrastructure. A refresh fetches a file at most
//! once a day (by the held copy's age) and checks that it parses before it
//! replaces the held copy, so a failed or garbled download leaves the
//! previous one in use. The files stay in the data directory and are never
//! committed.
//!
//! Terms: AWS documents `ip-ranges.json` for exactly this use
//! (<https://docs.aws.amazon.com/vpc/latest/userguide/aws-ip-ranges.html>);
//! Google publishes `cloud.json` for customers to identify its ranges
//! (<https://support.google.com/a/answer/10026322>); Oracle publishes
//! `public_ip_ranges.json`
//! (<https://docs.oracle.com/en-us/iaas/Content/General/Concepts/addressranges.htm>);
//! Cloudflare publishes `ips-v4` and `ips-v6` (<https://www.cloudflare.com/ips/>);
//! the Tor Project publishes the bulk exit list for services to look up
//! exits (<https://check.torproject.org/torbulkexitlist>). One request per
//! file a day.

use crate::Client;
use anyhow::{Context, Result, bail};
use sc_core::netranges::NetRanges;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// How a held file is read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Aws,
    Gcp,
    Oracle,
    /// One prefix per line, all of the named provider.
    CidrList(&'static str),
    TorExits,
}

/// One published file.
#[derive(Debug, Clone, Copy)]
pub struct RangeFile {
    pub id: &'static str,
    pub url: &'static str,
    /// Its file name in `<data>/netranges/`.
    pub file: &'static str,
    pub format: Format,
}

/// The files a refresh fetches.
pub const FILES: &[RangeFile] = &[
    RangeFile {
        id: "aws",
        url: "https://ip-ranges.amazonaws.com/ip-ranges.json",
        file: "aws-ip-ranges.json",
        format: Format::Aws,
    },
    RangeFile {
        id: "gcp",
        url: "https://www.gstatic.com/ipranges/cloud.json",
        file: "gcp-cloud.json",
        format: Format::Gcp,
    },
    RangeFile {
        id: "oracle",
        url: "https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json",
        file: "oracle-public-ip-ranges.json",
        format: Format::Oracle,
    },
    RangeFile {
        id: "cloudflare-v4",
        url: "https://www.cloudflare.com/ips-v4",
        file: "cloudflare-ips-v4.txt",
        format: Format::CidrList("Cloudflare"),
    },
    RangeFile {
        id: "cloudflare-v6",
        url: "https://www.cloudflare.com/ips-v6",
        file: "cloudflare-ips-v6.txt",
        format: Format::CidrList("Cloudflare"),
    },
    RangeFile {
        id: "tor-exits",
        url: "https://check.torproject.org/torbulkexitlist",
        file: "tor-bulk-exit-list.txt",
        format: Format::TorExits,
    },
];

/// A held copy younger than this is not fetched again by a refresh that
/// respects age (the watch's).
pub const MAX_AGE: Duration = Duration::from_secs(24 * 3600);
/// Cap on one download (AWS's file, the largest, is a few MB).
const MAX_DOWNLOAD: u64 = 64 << 20;

/// `<data>/netranges`.
pub fn dir(data: &Path) -> PathBuf {
    data.join("netranges")
}

/// Where `f` is held.
pub fn path(data: &Path, f: &RangeFile) -> PathBuf {
    dir(data).join(f.file)
}

/// Add one file's text to `t`. Returns the entries read.
pub fn add(t: &mut NetRanges, format: Format, text: &str) -> Result<usize> {
    let r = match format {
        Format::Aws => t.add_aws(text),
        Format::Gcp => t.add_gcp(text),
        Format::Oracle => t.add_oracle(text),
        Format::CidrList(p) => t.add_cidr_list(p, text),
        Format::TorExits => t.add_tor_exits(text),
    };
    r.map_err(anyhow::Error::msg)
}

/// What a refresh did with one file.
#[derive(Debug)]
pub enum Refreshed {
    /// Downloaded and checked: bytes and entries.
    Fetched { bytes: u64, entries: usize },
    /// The held copy is younger than the age limit.
    Fresh,
}

/// Age of the held copy of `f`, if there is one.
pub fn age(data: &Path, f: &RangeFile) -> Option<Duration> {
    let m = std::fs::metadata(path(data, f)).ok()?.modified().ok()?;
    Some(m.elapsed().unwrap_or_default())
}

/// Fetch every file in [`FILES`] into `data`. With `max_age`, a file whose
/// held copy is younger is skipped. One failure does not stop the others;
/// a download that does not parse leaves the held copy in place.
pub fn refresh(
    client: &Client,
    data: &Path,
    max_age: Option<Duration>,
) -> Vec<(&'static str, Result<Refreshed>)> {
    FILES
        .iter()
        .map(|f| {
            let fresh = max_age.is_some_and(|m| age(data, f).is_some_and(|a| a < m));
            let r = if fresh {
                Ok(Refreshed::Fresh)
            } else {
                fetch_one(client, data, f)
            };
            (f.id, r)
        })
        .collect()
}

fn fetch_one(client: &Client, data: &Path, f: &RangeFile) -> Result<Refreshed> {
    let dest = path(data, f);
    let tmp = dest.with_extension("new");
    let bytes = client
        .download(f.url, &tmp, MAX_DOWNLOAD)
        .with_context(|| f.id)?;
    let checked = std::fs::read_to_string(&tmp)
        .map_err(anyhow::Error::from)
        .and_then(|text| add(&mut NetRanges::default(), f.format, &text));
    match checked {
        Ok(entries) => {
            std::fs::rename(&tmp, &dest)?;
            Ok(Refreshed::Fetched { bytes, entries })
        }
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            bail!(
                "{}: the download does not parse ({e:#}); the held copy stays",
                f.id
            )
        }
    }
}

/// Load every held file. Files not held are skipped; a held file that does
/// not parse is a warning. `None` when nothing is held.
pub fn load_from_data(data: &Path) -> (Option<NetRanges>, Vec<String>) {
    let mut t = NetRanges::default();
    let mut warnings = Vec::new();
    let mut held = 0;
    for f in FILES {
        let p = path(data, f);
        let Ok(text) = std::fs::read_to_string(&p) else {
            continue;
        };
        held += 1;
        if let Err(e) = add(&mut t, f.format, &text) {
            warnings.push(format!("{}: {e:#}", p.display()));
        }
    }
    ((held > 0 && !t.is_empty()).then_some(t), warnings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn held_files_load_and_broken_ones_warn() {
        let dir = std::env::temp_dir().join(format!("sc-collect-netranges-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(load_from_data(&dir).0.is_none());
        std::fs::create_dir_all(super::dir(&dir)).unwrap();
        let file = |id: &str| FILES.iter().find(|f| f.id == id).unwrap();
        std::fs::write(
            path(&dir, file("aws")),
            r#"{"prefixes":[{"ip_prefix":"198.51.100.0/24","region":"us-east-1","service":"EC2"}],"ipv6_prefixes":[]}"#,
        )
        .unwrap();
        std::fs::write(path(&dir, file("tor-exits")), "192.0.2.200\n").unwrap();
        std::fs::write(path(&dir, file("gcp")), "<html>not the file</html>").unwrap();
        let (t, warnings) = load_from_data(&dir);
        let t = t.unwrap();
        assert_eq!(
            t.lookup("198.51.100.1").class.map(|c| c.label()).as_deref(),
            Some("AWS us-east-1 EC2")
        );
        assert!(t.lookup("192.0.2.200").tor);
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(age(&dir, file("aws")).is_some_and(|a| a < MAX_AGE));
        assert!(age(&dir, file("oracle")).is_none());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn every_file_has_its_own_name_and_an_https_url() {
        let mut names: Vec<&str> = FILES.iter().map(|f| f.file).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), FILES.len());
        assert!(FILES.iter().all(|f| f.url.starts_with("https://")));
    }
}
