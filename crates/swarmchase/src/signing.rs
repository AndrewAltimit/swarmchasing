//! `swarmchase key`: the Ed25519 key evidence bundles are signed with
//! ([`sc_case::signing`]), and reading it and the published keys.
//!
//! Signing is off until `SWARMCHASE_SIGNING_KEY` holds the secret seed
//! (env.list, never committed). Then `case bundle` and `case draft` sign
//! every bundle's manifest. `case verify` checks a signature against the
//! published keys: `--key`, else `SWARMCHASE_SIGNING_PUBLIC`, else
//! `keys/bundle-signing.pub` in the working directory or the checkout this
//! was built from. The seed is never printed; `key generate` writes it to a
//! file the admin names, outside any checkout unless git ignores the path.

use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand};
use sc_case::signing::{
    PUBLIC_KEY_PATH, PublicKey, SECRET_ENV, SecretKey, parse_public_keys, public_key_file,
};
use std::io::Write as _;
use std::path::{Path, PathBuf};

/// The variable naming another published key file.
pub const PUBLIC_ENV: &str = "SWARMCHASE_SIGNING_PUBLIC";

#[derive(Args)]
pub struct KeyArgs {
    #[command(subcommand)]
    cmd: KeyCmd,
}

#[derive(Subcommand)]
enum KeyCmd {
    /// Make a new signing key: write its secret seed to --out (never over a
    /// file, never into a checkout unless git ignores the path) and print
    /// the public key and its key id. Nothing secret reaches the terminal.
    Generate {
        /// Where the secret goes, as a `SWARMCHASE_SIGNING_KEY=` line to
        /// copy into env.list.
        #[arg(long)]
        out: PathBuf,
        /// Also write the public key file here (for publishing, e.g.
        /// keys/bundle-signing.pub).
        #[arg(long)]
        public_out: Option<PathBuf>,
    },
    /// The public key and key id of SWARMCHASE_SIGNING_KEY, and whether the
    /// published key file lists it.
    Public {
        /// Write the public key file here.
        #[arg(long)]
        out: Option<PathBuf>,
        /// The published key file to compare with.
        #[arg(long, env = PUBLIC_ENV)]
        key: Option<PathBuf>,
    },
}

/// The signing key, when `SWARMCHASE_SIGNING_KEY` is set and not empty. A
/// value that is not a key is an error, so a typo never means "unsigned".
pub fn signer() -> Result<Option<SecretKey>> {
    let v = std::env::var(SECRET_ENV).unwrap_or_default();
    if v.trim().is_empty() {
        return Ok(None);
    }
    SecretKey::parse(&v).map(Some).map_err(anyhow::Error::msg)
}

/// The published keys and the file they came from: `explicit`, else
/// [`PUBLIC_ENV`], else [`PUBLIC_KEY_PATH`] in the working directory or the
/// checkout this was built from. No file found is no keys; a named file
/// that is missing, or any file that does not parse, is an error.
pub fn published(explicit: Option<&Path>) -> Result<(Option<PathBuf>, Vec<PublicKey>)> {
    let named = explicit
        .map(Path::to_path_buf)
        .or_else(|| std::env::var_os(PUBLIC_ENV).map(PathBuf::from))
        .filter(|p| !p.as_os_str().is_empty());
    let path = match named {
        Some(p) => Some(p),
        None => {
            let built = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .join(PUBLIC_KEY_PATH);
            [PathBuf::from(PUBLIC_KEY_PATH), built]
                .into_iter()
                .find(|p| p.is_file())
        }
    };
    let Some(path) = path else {
        return Ok((None, Vec::new()));
    };
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("reading the published key {}", path.display()))?;
    let keys = parse_public_keys(&text).map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
    Ok((Some(path), keys))
}

pub fn run(args: KeyArgs) -> Result<()> {
    match args.cmd {
        KeyCmd::Generate { out, public_out } => {
            let k = generate(&out)?;
            println!("wrote the secret key to {}", out.display());
            show_public(&k.public());
            if let Some(p) = public_out {
                write_new(&p, &public_key_file(&[k.public()]), false)?;
                println!("wrote the public key file {}", p.display());
            }
            eprintln!(
                "copy the {SECRET_ENV}= line from {} into env.list on the machine that drafts reports, then delete or lock away the file; anyone holding it can sign bundles as this project",
                out.display()
            );
            Ok(())
        }
        KeyCmd::Public { out, key } => {
            let k = signer()?
                .with_context(|| format!("{SECRET_ENV} is not set (see env.list.example)"))?;
            let public = k.public();
            show_public(&public);
            match published(key.as_deref())? {
                (Some(p), keys) if keys.contains(&public) => {
                    println!("listed in {}", p.display())
                }
                (Some(p), _) => println!(
                    "not listed in {}: bundles signed with it will not verify against that file",
                    p.display()
                ),
                (None, _) => println!(
                    "no published key file ({PUBLIC_KEY_PATH}): bundles signed with it can be checked only once it is published"
                ),
            }
            if let Some(p) = out {
                write_new(&p, &public_key_file(&[public]), false)?;
                println!("wrote the public key file {}", p.display());
            }
            Ok(())
        }
    }
}

fn show_public(k: &PublicKey) {
    println!("key id: {}", k.key_id());
    println!("public key: {}", k.line());
}

/// A new key from the operating system's random source, its seed written to
/// `out` as a `SWARMCHASE_SIGNING_KEY=` line.
pub fn generate(out: &Path) -> Result<SecretKey> {
    refuse_in_checkout(out)?;
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|e| anyhow::anyhow!("no random source: {e}"))?;
    let k = SecretKey::from_seed(&seed);
    seed.fill(0);
    let text = format!(
        "# swarmchasing bundle signing key {id}. Secret: anyone holding it can sign\n\
         # evidence bundles as this project. Copy the line below into env.list; never commit it.\n\
         # Public key: {line}\n\
         {SECRET_ENV}={seed}\n",
        id = k.public().key_id(),
        line = k.public().line(),
        seed = k.seed_hex(),
    );
    write_new(out, &text, true)?;
    Ok(k)
}

/// Write `text` to a new file at `path`, never over one. A `secret` file is
/// readable by its owner only where the system has Unix permissions.
fn write_new(path: &Path, text: &str, secret: bool) -> Result<()> {
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    if secret {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    #[cfg(not(unix))]
    let _ = secret;
    let mut f = o.open(path).with_context(|| {
        format!(
            "creating {} (an existing file is never overwritten)",
            path.display()
        )
    })?;
    f.write_all(text.as_bytes())?;
    Ok(())
}

/// Refuse a secret's path inside a git checkout unless git ignores it, so a
/// key cannot be committed by `git add .`.
fn refuse_in_checkout(path: &Path) -> Result<()> {
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let git = |args: &[&str]| {
        std::process::Command::new("git")
            .arg("-C")
            .arg(&parent)
            .args(args)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .ok()
    };
    let in_checkout = git(&["rev-parse", "--is-inside-work-tree"]).is_some_and(|s| s.success());
    if !in_checkout {
        return Ok(());
    }
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .context("the secret key's path needs a file name")?;
    if git(&["check-ignore", "-q", name]).is_some_and(|s| s.success()) {
        return Ok(());
    }
    bail!(
        "{} is inside a git checkout and not ignored; write the secret key outside the checkout",
        path.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_writes_the_seed_once_and_never_into_the_checkout() {
        let dir = std::env::temp_dir().join(format!("swarmchase-key-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let out = dir.join("signing.key");
        let k = generate(&out).unwrap();
        let text = std::fs::read_to_string(&out).unwrap();
        let line = text
            .lines()
            .find_map(|l| l.strip_prefix(&format!("{SECRET_ENV}=")))
            .unwrap();
        assert_eq!(SecretKey::parse(line).unwrap().public(), k.public());
        assert!(text.contains(&k.public().key_id()));
        assert!(generate(&out).is_err(), "never overwrites a key");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&out).unwrap().permissions().mode();
            assert_eq!(mode & 0o077, 0, "owner only");
        }
        // This crate's own directory is in a checkout and not ignored.
        let inside = Path::new(env!("CARGO_MANIFEST_DIR")).join("signing-test.key");
        assert!(generate(&inside).is_err());
        assert!(!inside.exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_named_key_file_must_exist_and_parse() {
        let dir = std::env::temp_dir().join(format!("swarmchase-pub-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert!(published(Some(&dir.join("missing.pub"))).is_err());
        let p = dir.join("k.pub");
        std::fs::write(&p, "ed25519 not-base64\n").unwrap();
        assert!(published(Some(&p)).is_err());
        let k = SecretKey::from_seed(&[5; 32]).public();
        std::fs::write(&p, public_key_file(std::slice::from_ref(&k))).unwrap();
        let (path, keys) = published(Some(&p)).unwrap();
        assert_eq!((path.as_deref(), keys), (Some(p.as_path()), vec![k]));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
