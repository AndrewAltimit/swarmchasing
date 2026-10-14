//! `swarmchase backup`: encrypted backups of what cannot be collected again.
//!
//! An archive is a tar of `<data>/cases`, `<data>/labels`, `<data>/rules`,
//! `<data>/inbox` (outside submissions), `<data>/state.json`, the cross-run
//! history (`ledger.json`, `summary.json`, `autonomy.ndjson`) and the
//! canary registry (never the bulk record store,
//! which the sources can refill), encrypted with age to an X25519 recipient
//! (`SWARMCHASE_BACKUP_RECIPIENT`, a public key, so the machine that makes
//! backups holds no secret) or to a passphrase
//! (`SWARMCHASE_BACKUP_PASSPHRASE`). It is written to
//! `<backup dir>/<hostname>/swarmchase-<UTC stamp>.tar.age` with a
//! `.sha256` sidecar, each written through a temporary file and a rename.
//! `create` holds the data directory's lock while it reads, so no watch or
//! case command writes into the archive's sources meanwhile.
//!
//! `verify` checks the hash, and decrypts and reads the archive through when
//! given the identity. `restore` checks that the key opens the backup before
//! it touches the directory, and never overwrites one that is not empty
//! (lock files aside) unless forced. Restored without a record
//! store, every source's cursor and seen list in `state.json` are reset, so
//! the next watch fetches the analysis window again instead of continuing
//! from where the lost store left off. `keygen` writes an
//! identity file, which belongs neither on the runner nor beside the backups.

use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand};
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};

/// What a backup holds, relative to the data directory.
pub const PARTS: [&str; 9] = [
    "cases",
    "labels",
    "rules",
    "inbox",
    "state.json",
    "ledger.json",
    "summary.json",
    "autonomy.ndjson",
    crate::canary::REGISTRY,
];
const RECIPIENT_ENV: &str = "SWARMCHASE_BACKUP_RECIPIENT";
const PASSPHRASE_ENV: &str = "SWARMCHASE_BACKUP_PASSPHRASE";

#[derive(Args)]
pub struct BackupArgs {
    #[command(subcommand)]
    cmd: BackupCmd,
}

#[derive(Subcommand)]
enum BackupCmd {
    /// Archive and encrypt cases, labels, pinned rules, the submission
    /// inbox, state.json, the cross-run ledger, summary and autonomy log,
    /// and the canary registry.
    Create {
        #[arg(short, long, default_value = "data", env = "SWARMCHASE_DATA")]
        data: PathBuf,
        /// Where backups go; each host writes to its own subdirectory.
        #[arg(long, env = "SWARMCHASE_BACKUP_DIR")]
        dir: PathBuf,
        /// Keep this many of this host's backups and delete older ones.
        #[arg(long)]
        keep: Option<usize>,
    },
    /// List the backups in the backup directory, newest first.
    List {
        #[arg(long, env = "SWARMCHASE_BACKUP_DIR")]
        dir: PathBuf,
    },
    /// Check a backup's SHA-256 against its sidecar; with --identity (or
    /// --passphrase), also decrypt it and read the archive through.
    Verify {
        file: PathBuf,
        #[arg(long)]
        identity: Option<PathBuf>,
        /// Decrypt with SWARMCHASE_BACKUP_PASSPHRASE.
        #[arg(long)]
        passphrase: bool,
    },
    /// Decrypt a backup into a directory. A directory that is not empty is
    /// refused unless --force.
    Restore {
        file: PathBuf,
        #[arg(long)]
        identity: Option<PathBuf>,
        /// Decrypt with SWARMCHASE_BACKUP_PASSPHRASE.
        #[arg(long)]
        passphrase: bool,
        #[arg(long)]
        to: PathBuf,
        #[arg(long)]
        force: bool,
    },
    /// Write a new age identity file and print its public key (the value
    /// for SWARMCHASE_BACKUP_RECIPIENT).
    Keygen {
        #[arg(long)]
        out: PathBuf,
    },
}

pub fn run(args: BackupArgs) -> Result<()> {
    match args.cmd {
        BackupCmd::Create { data, dir, keep } => {
            let key = Key::from_env()?;
            let host = hostname();
            let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
            let p = create(&data, &dir.join(&host), &stamp, &key)?;
            println!("wrote {} ({})", p.display(), key.describe());
            if let Some(k) = keep {
                for gone in rotate(&dir.join(&host), k)? {
                    println!("deleted {} (keeping {k})", gone.display());
                }
            }
            Ok(())
        }
        BackupCmd::List { dir } => {
            let mut all = Vec::new();
            for e in
                std::fs::read_dir(&dir).with_context(|| format!("reading {}", dir.display()))?
            {
                let p = e?.path();
                if p.is_dir() {
                    all.extend(backups(&p)?);
                }
            }
            all.sort_by(|a, b| b.file_name().cmp(&a.file_name()));
            for p in &all {
                let size = std::fs::metadata(p).map(|m| m.len()).unwrap_or(0);
                let side = if sidecar(p).is_file() {
                    ""
                } else {
                    "  (no .sha256)"
                };
                println!("{}  {size} bytes{side}", p.display());
            }
            println!("{} backup(s)", all.len());
            Ok(())
        }
        BackupCmd::Verify {
            file,
            identity,
            passphrase,
        } => {
            check_hash(&file)?;
            println!("{}: SHA-256 matches its sidecar", file.display());
            if let Some(key) = Key::for_reading(identity.as_deref(), passphrase)? {
                let n = read_through(&file, &key)?;
                println!("{}: decrypts; {n} archive entries read", file.display());
            } else {
                println!("not decrypted (pass --identity or --passphrase to check that too)");
            }
            Ok(())
        }
        BackupCmd::Restore {
            file,
            identity,
            passphrase,
            to,
            force,
        } => {
            let Some(key) = Key::for_reading(identity.as_deref(), passphrase)? else {
                bail!("restore needs --identity <file> or --passphrase");
            };
            check_hash(&file)?;
            if restore(&file, &key, &to, force)? {
                println!(
                    "no record store in {}: source cursors and seen lists reset, so the next watch fetches the window again",
                    to.display()
                );
            }
            println!(
                "restored {} into {}; point SWARMCHASE_DATA there or copy what you need",
                file.display(),
                to.display()
            );
            Ok(())
        }
        BackupCmd::Keygen { out } => {
            let public = keygen(&out)?;
            println!("wrote {}", out.display());
            println!("public key (set {RECIPIENT_ENV} to this): {public}");
            eprintln!(
                "keep {} off the runner and away from the backup drive: anyone with it can read every backup, and without it none can be restored",
                out.display()
            );
            Ok(())
        }
    }
}

/// How a backup is encrypted or decrypted.
pub enum Key {
    Recipient(age::x25519::Recipient),
    Identity(age::x25519::Identity),
    Passphrase(String),
}

impl Key {
    /// The key `create` encrypts to: the recipient when one is set (it needs
    /// no secret on this machine), else the passphrase.
    pub fn from_env() -> Result<Key> {
        if let Ok(r) = std::env::var(RECIPIENT_ENV)
            && !r.trim().is_empty()
        {
            return Ok(Key::Recipient(
                r.trim()
                    .parse()
                    .map_err(|e| anyhow::anyhow!("{RECIPIENT_ENV}: {e}"))?,
            ));
        }
        match std::env::var(PASSPHRASE_ENV) {
            Ok(p) if !p.is_empty() => Ok(Key::Passphrase(p)),
            _ => bail!(
                "set {RECIPIENT_ENV} (an age public key, from `swarmchase backup keygen`) or {PASSPHRASE_ENV}"
            ),
        }
    }

    fn for_reading(identity: Option<&Path>, passphrase: bool) -> Result<Option<Key>> {
        Ok(match (identity, passphrase) {
            (Some(p), _) => Some(Key::Identity(read_identity(p)?)),
            (None, true) => match std::env::var(PASSPHRASE_ENV) {
                Ok(p) if !p.is_empty() => Some(Key::Passphrase(p)),
                _ => bail!("--passphrase reads {PASSPHRASE_ENV}, which is not set"),
            },
            (None, false) => None,
        })
    }

    fn describe(&self) -> &'static str {
        match self {
            Key::Recipient(_) => "encrypted to the age recipient",
            Key::Identity(_) => "encrypted to the identity's recipient",
            Key::Passphrase(_) => "encrypted with the passphrase",
        }
    }
}

/// The identity in an age identity file (the `AGE-SECRET-KEY-` line).
pub fn read_identity(p: &Path) -> Result<age::x25519::Identity> {
    let text = std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?;
    let line = text
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with("AGE-SECRET-KEY-"))
        .with_context(|| format!("{}: no AGE-SECRET-KEY line", p.display()))?;
    line.parse()
        .map_err(|e| anyhow::anyhow!("{}: {e}", p.display()))
}

/// This machine's name, for the per-host backup directory.
pub fn hostname() -> String {
    let raw = ["HOSTNAME", "COMPUTERNAME"]
        .iter()
        .find_map(|v| std::env::var(v).ok().filter(|s| !s.trim().is_empty()))
        .or_else(|| std::fs::read_to_string("/etc/hostname").ok())
        .or_else(|| {
            std::process::Command::new("hostname")
                .output()
                .ok()
                .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        })
        .unwrap_or_default();
    let name: String = raw
        .trim()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '.' {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    if name.is_empty() || name.starts_with('.') {
        "unknown-host".into()
    } else {
        name
    }
}

fn sidecar(p: &Path) -> PathBuf {
    let mut s = p.as_os_str().to_owned();
    s.push(".sha256");
    PathBuf::from(s)
}

/// The [`PARTS`] that exist under `data`.
fn present(data: &Path) -> Result<Vec<(&'static str, PathBuf)>> {
    let found: Vec<(&'static str, PathBuf)> = PARTS
        .iter()
        .map(|part| (*part, data.join(part)))
        .filter(|(_, p)| p.is_dir() || p.is_file())
        .collect();
    if found.is_empty() {
        bail!(
            "nothing to back up in {} (no cases, labels, rules, state or history)",
            data.display()
        );
    }
    Ok(found)
}

/// Write the tar of `parts` into `out`, file by file.
fn archive<W: Write>(parts: &[(&str, PathBuf)], out: W) -> Result<W> {
    let mut b = tar::Builder::new(out);
    b.follow_symlinks(false);
    for (part, p) in parts {
        if p.is_dir() {
            b.append_dir_all(part, p)
                .with_context(|| format!("archiving {}", p.display()))?;
        } else {
            b.append_path_with_name(p, part)
                .with_context(|| format!("archiving {}", p.display()))?;
        }
    }
    Ok(b.into_inner()?)
}

/// age's encryptor for `key`.
fn encryptor(key: &Key) -> Result<age::Encryptor> {
    Ok(match key {
        Key::Recipient(r) => {
            age::Encryptor::with_recipients(std::iter::once(r as &dyn age::Recipient))?
        }
        Key::Identity(i) => {
            let r = i.to_public();
            age::Encryptor::with_recipients(std::iter::once(&r as &dyn age::Recipient))?
        }
        Key::Passphrase(p) => {
            age::Encryptor::with_user_passphrase(age::secrecy::SecretString::from(p.clone()))
        }
    })
}

/// A writer that hashes what passes through it.
struct Hashing<W> {
    inner: W,
    hash: sha2::Sha256,
}

impl<W: Write> Write for Hashing<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        use sha2::Digest as _;
        let n = self.inner.write(buf)?;
        self.hash.update(&buf[..n]);
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Stream the tar of `parts`, encrypted to `key`, into the file `p`,
/// returning the SHA-256 of what was written. Nothing is held in memory
/// beyond the buffers.
fn seal_into(parts: &[(&str, PathBuf)], key: &Key, p: &Path) -> Result<String> {
    use sha2::Digest as _;
    let f = std::fs::File::create(p).with_context(|| format!("creating {}", p.display()))?;
    let hashing = Hashing {
        inner: std::io::BufWriter::new(f),
        hash: sha2::Sha256::new(),
    };
    let sealed = archive(parts, encryptor(key)?.wrap_output(hashing)?)?;
    let mut hashing = sealed.finish()?;
    hashing.flush()?;
    let f = hashing
        .inner
        .into_inner()
        .map_err(|e| e.into_error())
        .with_context(|| format!("writing {}", p.display()))?;
    f.sync_all()
        .with_context(|| format!("writing {}", p.display()))?;
    Ok(hashing
        .hash
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

fn decrypt(file: &Path, key: &Key) -> Result<impl Read> {
    let f = std::fs::File::open(file).with_context(|| format!("opening {}", file.display()))?;
    let d = age::Decryptor::new(BufReader::new(f)).context("not an age file")?;
    let r = match key {
        Key::Identity(i) => d.decrypt(std::iter::once(i as &dyn age::Identity)),
        Key::Passphrase(p) => {
            let id = age::scrypt::Identity::new(age::secrecy::SecretString::from(p.clone()));
            d.decrypt(std::iter::once(&id as &dyn age::Identity))
        }
        Key::Recipient(_) => bail!("a public key cannot decrypt; pass the identity file"),
    };
    r.with_context(|| format!("decrypting {}", file.display()))
}

/// Write an encrypted backup of `data` into `dir` as
/// `swarmchase-<stamp>.tar.age`, with its `.sha256` sidecar.
pub fn create(data: &Path, dir: &Path, stamp: &str, key: &Key) -> Result<PathBuf> {
    // A watch or case command writing meanwhile would leave a backup that
    // mixes two states, so the archive is read under the data lock.
    let _lock = crate::store::lock_data(data, "backup create")?;
    let parts = present(data)?;
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let name = format!("swarmchase-{stamp}.tar.age");
    let path = dir.join(&name);
    if path.exists() {
        bail!("{} exists", path.display());
    }
    // Streamed through a temporary file and a rename, so a backup cut
    // short never leaves a file under the backup's name.
    let tmp = crate::store::temp_path(&path);
    let sealed = seal_into(&parts, key, &tmp).and_then(|sha| {
        std::fs::rename(&tmp, &path).with_context(|| format!("writing {}", path.display()))?;
        Ok(sha)
    });
    let sha = match sealed {
        Ok(sha) => sha,
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
    };
    crate::store::write_atomic(&sidecar(&path), format!("{sha}  {name}\n").as_bytes())?;
    Ok(path)
}

/// This host's backups, oldest first.
fn backups(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut v: Vec<PathBuf> = match std::fs::read_dir(dir) {
        Ok(entries) => entries
            .filter_map(|e| Some(e.ok()?.path()))
            .filter(|p| {
                let n = p.file_name().unwrap_or_default().to_string_lossy();
                n.starts_with("swarmchase-") && n.ends_with(".tar.age")
            })
            .collect(),
        Err(_) => Vec::new(),
    };
    v.sort();
    Ok(v)
}

/// Delete all but the newest `keep` backups in `dir`, with their sidecars.
pub fn rotate(dir: &Path, keep: usize) -> Result<Vec<PathBuf>> {
    let all = backups(dir)?;
    let n = all.len().saturating_sub(keep.max(1));
    let mut gone = Vec::new();
    for p in all.into_iter().take(n) {
        std::fs::remove_file(&p)?;
        let _ = std::fs::remove_file(sidecar(&p));
        gone.push(p);
    }
    Ok(gone)
}

/// Fail unless the file's SHA-256 matches its sidecar.
pub fn check_hash(file: &Path) -> Result<()> {
    let side = sidecar(file);
    let want =
        std::fs::read_to_string(&side).with_context(|| format!("no sidecar {}", side.display()))?;
    let want = want.split_whitespace().next().unwrap_or_default();
    let got = crate::bundle::sha256_hex(
        &std::fs::read(file).with_context(|| format!("reading {}", file.display()))?,
    );
    if want != got {
        bail!("{}: SHA-256 does not match its sidecar", file.display());
    }
    Ok(())
}

/// Decrypt and read every archive entry, writing nothing. Returns the count.
pub fn read_through(file: &Path, key: &Key) -> Result<usize> {
    let mut a = tar::Archive::new(decrypt(file, key)?);
    let mut n = 0;
    for e in a.entries()? {
        let mut e = e?;
        std::io::copy(&mut e, &mut std::io::sink())?;
        n += 1;
    }
    Ok(n)
}

/// Decrypt into `to`. The key is checked before `to` is touched, so a wrong
/// key leaves nothing behind. A directory that is not empty (the data lock's
/// files aside) is refused unless `force`; entries that would land outside
/// `to` are refused by `tar`. The data directory's lock is held throughout.
/// Returns whether the cursors were reset because `to` holds no record
/// store ([`reset_cursors`]).
pub fn restore(file: &Path, key: &Key, to: &Path, force: bool) -> Result<bool> {
    let reader = decrypt(file, key)?;
    let lock_files = [
        crate::store::LOCK_FILE.to_string(),
        format!("{}.owner", crate::store::LOCK_FILE),
    ];
    let busy = std::fs::read_dir(to).is_ok_and(|d| {
        d.flatten()
            .any(|e| !lock_files.iter().any(|l| e.file_name() == l.as_str()))
    });
    if busy && !force {
        bail!(
            "{} is not empty; restore into an empty directory, or pass --force to overwrite",
            to.display()
        );
    }
    std::fs::create_dir_all(to)?;
    let _lock = crate::store::lock_data(to, "backup restore")?;
    let mut a = tar::Archive::new(reader);
    a.set_overwrite(force);
    for e in a.entries()? {
        let mut e = e?;
        if !e.unpack_in(to)? {
            bail!("refused an entry outside {}", to.display());
        }
    }
    let has_store = std::fs::read_dir(to.join("store")).is_ok_and(|mut d| d.next().is_some());
    if has_store {
        return Ok(false);
    }
    reset_cursors(&to.join("state.json"))
}

/// Forget where each source's pulls had reached (cursor, seen IDs, a
/// pending resume key, a stream checkpoint), keeping its health history,
/// so the next watch fetches the analysis window again. Returns whether
/// `state` existed.
fn reset_cursors(state: &Path) -> Result<bool> {
    let Some(mut s) = crate::store::read_json::<serde_json::Value>(state)? else {
        return Ok(false);
    };
    if let Some(sources) = s.get_mut("sources").and_then(|v| v.as_object_mut()) {
        for src in sources.values_mut() {
            if let Some(o) = src.as_object_mut() {
                o.insert("cursor".into(), 0.into());
                o.insert("seen".into(), serde_json::json!({}));
                o.remove("pending");
                o.remove("mark");
            }
        }
    }
    crate::store::write_json(state, &s)?;
    Ok(true)
}

/// Write a new identity file at `out` (never over an existing file) and
/// return its public key.
pub fn keygen(out: &Path) -> Result<String> {
    use age::secrecy::ExposeSecret;
    if out.exists() {
        bail!("{} exists; not overwritten", out.display());
    }
    let id = age::x25519::Identity::generate();
    let public = id.to_public().to_string();
    let text = format!(
        "# created: {}\n# public key: {public}\n# Keep this file off the runner and away from the backup drive.\n{}\n",
        chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ"),
        id.to_string().expose_secret()
    );
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(out)
        .with_context(|| format!("creating {}", out.display()))?;
    f.write_all(text.as_bytes())?;
    Ok(public)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let p =
            std::env::temp_dir().join(format!("swarmchase-backup-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn data(root: &Path) -> PathBuf {
        let d = root.join("data");
        std::fs::create_dir_all(d.join("cases/c-1/raw")).unwrap();
        std::fs::write(d.join("cases/c-1/case.toml"), "id = \"c-1\"\n").unwrap();
        std::fs::write(d.join("cases/c-1/raw/records.ndjson"), "{}\n").unwrap();
        std::fs::create_dir_all(d.join("labels")).unwrap();
        std::fs::write(d.join("labels/reviewed.ndjson"), "{}\n").unwrap();
        std::fs::write(
            d.join("state.json"),
            r#"{"sources":{"uq":{"cursor":1791000000,"seen":{"a":1791000000},"mark":7,"health":{"ever_pulled":3}}}}"#,
        )
        .unwrap();
        std::fs::write(d.join("ledger.json"), "{}").unwrap();
        std::fs::write(d.join("summary.json"), "{}").unwrap();
        std::fs::write(d.join("autonomy.ndjson"), "{}\n").unwrap();
        std::fs::create_dir_all(d.join("canary")).unwrap();
        std::fs::write(d.join(crate::canary::REGISTRY), "{}").unwrap();
        // Outside submissions cannot be collected again.
        std::fs::create_dir_all(d.join("inbox")).unwrap();
        std::fs::write(d.join("inbox/sub-1.json"), "{}").unwrap();
        // The bulk store is not backed up.
        std::fs::create_dir_all(d.join("store")).unwrap();
        std::fs::write(d.join("store/uq.ndjson"), "{\"bulk\":1}\n").unwrap();
        d
    }

    #[test]
    fn create_verify_restore_with_a_recipient() {
        let root = scratch("x25519");
        let d = data(&root);
        let idf = root.join("key.txt");
        let public = keygen(&idf).unwrap();
        assert!(keygen(&idf).is_err(), "never overwrites an identity");
        assert!(public.starts_with("age1"));
        let key = Key::Recipient(public.parse().unwrap());
        let dir = root.join("backups/host");
        let p = create(&d, &dir, "20261010T000000Z", &key).unwrap();
        assert!(p.ends_with("swarmchase-20261010T000000Z.tar.age"));
        check_hash(&p).unwrap();

        // The recipient cannot decrypt; the identity can.
        assert!(read_through(&p, &key).is_err());
        let id = Key::Identity(read_identity(&idf).unwrap());
        assert!(read_through(&p, &id).unwrap() > 3);

        let to = root.join("restored");
        assert!(
            restore(&p, &id, &to, false).unwrap(),
            "no store: cursors reset"
        );
        assert_eq!(
            std::fs::read_to_string(to.join("cases/c-1/case.toml")).unwrap(),
            "id = \"c-1\"\n"
        );
        assert!(to.join("state.json").is_file());
        assert!(to.join("labels/reviewed.ndjson").is_file());
        for part in [
            "ledger.json",
            "summary.json",
            "autonomy.ndjson",
            crate::canary::REGISTRY,
        ] {
            assert!(to.join(part).is_file(), "{part}");
        }
        // With no store, every source starts over; its health history stays.
        let st: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(to.join("state.json")).unwrap()).unwrap();
        let uq = &st["sources"]["uq"];
        assert_eq!(uq["cursor"], 0);
        assert_eq!(uq["seen"], serde_json::json!({}));
        assert!(uq.get("mark").is_none());
        assert_eq!(uq["health"]["ever_pulled"], 3);
        assert!(!to.join("store").exists(), "the bulk store stays out");
        // A second restore into the same place needs --force.
        assert!(restore(&p, &id, &to, false).is_err());
        restore(&p, &id, &to, true).unwrap();
        assert!(to.join("inbox/sub-1.json").is_file());

        // A wrong key touches nothing, so the retry with the right one is
        // not refused as a directory in use.
        let fresh = root.join("fresh");
        assert!(restore(&p, &key, &fresh, false).is_err());
        assert!(!fresh.exists());
        // Lock files left by an earlier attempt do not make it busy.
        drop(crate::store::lock_data(&fresh, "backup restore").unwrap());
        restore(&p, &id, &fresh, false).unwrap();

        // Tampering is caught by the hash.
        let mut bytes = std::fs::read(&p).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        std::fs::write(&p, bytes).unwrap();
        assert!(check_hash(&p).is_err());
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn passphrase_backups_and_rotation() {
        let root = scratch("pass");
        let d = data(&root);
        let dir = root.join("backups/host");
        let key = Key::Passphrase("correct horse battery staple".into());
        let p = create(&d, &dir, "20261010T000000Z", &key).unwrap();
        assert!(read_through(&p, &key).unwrap() > 0);
        assert!(read_through(&p, &Key::Passphrase("wrong".into())).is_err());
        for s in ["20261011T000000Z", "20261012T000000Z"] {
            create(&d, &dir, s, &key).unwrap();
        }
        // Not while another command holds the data directory.
        let held = crate::store::lock_data(&d, "watch").unwrap();
        let e = create(&d, &dir, "20261013T000000Z", &key).unwrap_err();
        assert!(e.to_string().contains("in use"), "{e:#}");
        drop(held);
        let gone = rotate(&dir, 2).unwrap();
        assert_eq!(gone, std::slice::from_ref(&p));
        assert!(!sidecar(&p).exists());
        assert_eq!(backups(&dir).unwrap().len(), 2);
        assert!(create(&root.join("empty"), &dir, "x", &key).is_err());
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn hostnames_are_path_safe() {
        let h = hostname();
        assert!(!h.is_empty() && !h.contains(['/', '\\', ' ']), "{h}");
    }
}
