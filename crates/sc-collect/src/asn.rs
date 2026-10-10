//! The offline IP-to-ASN table: download iptoasn.com's `ip2asn-v4.tsv.gz`
//! into the data directory, and load it into an [`sc_core::asn::AsnTable`].
//!
//! iptoasn.com publishes the data under the Public Domain Dedication and
//! License (PDDL 1.0), updated hourly; one download per day or week is
//! plenty. The file stays in the data directory and is never committed.

use crate::Client;
use anyhow::{Context, Result};
use sc_core::asn::AsnTable;
use std::io::Read;
use std::path::{Path, PathBuf};

/// Where iptoasn.com serves the IPv4 table.
pub const IP2ASN_V4_URL: &str = "https://iptoasn.com/data/ip2asn-v4.tsv.gz";
/// Its file name in `<data>/asn/`.
pub const IP2ASN_V4_FILE: &str = "ip2asn-v4.tsv.gz";
/// Cap on the download (the file is a few MB).
const MAX_DOWNLOAD: u64 = 256 << 20;

/// `<data>/asn/ip2asn-v4.tsv.gz`.
pub fn table_path(data: &Path) -> PathBuf {
    data.join("asn").join(IP2ASN_V4_FILE)
}

/// Download the table to [`table_path`]. Returns the path and bytes written.
pub fn fetch(client: &Client, data: &Path) -> Result<(PathBuf, u64)> {
    let p = table_path(data);
    let n = client.download(IP2ASN_V4_URL, &p, MAX_DOWNLOAD)?;
    Ok((p, n))
}

/// Load a table from a `.tsv.gz` or plain `.tsv` file.
pub fn load(path: &Path) -> Result<AsnTable> {
    let f = std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut text = String::new();
    if path.extension().is_some_and(|e| e == "gz") {
        flate2::read::MultiGzDecoder::new(f)
            .read_to_string(&mut text)
            .with_context(|| format!("decompressing {}", path.display()))?;
    } else {
        std::io::BufReader::new(f).read_to_string(&mut text)?;
    }
    Ok(AsnTable::from_tsv(&text))
}

/// The table in `data`, if it has been fetched.
pub fn load_from_data(data: &Path) -> Result<Option<AsnTable>> {
    let p = table_path(data);
    if !p.exists() {
        return Ok(None);
    }
    load(&p).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn loads_gzipped_tables() {
        let dir = std::env::temp_dir().join(format!("sc-collect-asn-{}", std::process::id()));
        let p = table_path(&dir);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        e.write_all(b"198.51.100.0\t198.51.100.255\t64500\tZZ\tEXAMPLE-NET\n")
            .unwrap();
        std::fs::write(&p, e.finish().unwrap()).unwrap();
        let t = load_from_data(&dir).unwrap().unwrap();
        assert_eq!(t.lookup("198.51.100.1").unwrap().asn, 64500);
        assert!(load_from_data(&dir.join("none")).unwrap().is_none());
        let _ = std::fs::remove_dir_all(dir);
    }
}
