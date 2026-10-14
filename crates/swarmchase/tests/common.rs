//! Running the binary in a scratch directory.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// A fresh scratch directory for one test, removed when dropped.
pub struct Scratch(pub PathBuf);

impl Scratch {
    pub fn new(name: &str) -> Self {
        let p = std::env::temp_dir().join(format!("swarmchase-it-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// What one run printed, and whether it succeeded.
pub struct Run {
    pub ok: bool,
    /// The exit status: 0, 1 for an error, 2 a watch run with alerts, 3 a
    /// floor not met.
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl From<Output> for Run {
    fn from(o: Output) -> Self {
        Self {
            ok: o.status.success(),
            code: o.status.code(),
            stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
        }
    }
}

/// Run `swarmchase` in `dir` with no data directory or API key from the
/// environment, so only the arguments decide what it reads.
pub fn run(dir: &Path, args: &[&str]) -> Run {
    Command::new(env!("CARGO_BIN_EXE_swarmchase"))
        .args(args)
        .current_dir(dir)
        .env_remove("SWARMCHASE_DATA")
        .env_remove("URLQUERY_APIKEY")
        .env_remove("GITHUB_OUTPUT")
        .output()
        .expect("running swarmchase")
        .into()
}

/// Like [`run`], failing the test unless the command succeeds.
pub fn ok(dir: &Path, args: &[&str]) -> Run {
    let r = run(dir, args);
    assert!(
        r.ok,
        "swarmchase {args:?} failed\nstdout:\n{}\nstderr:\n{}",
        r.stdout, r.stderr
    );
    r
}

/// The labelled sample records, as absolute paths.
pub fn samples() -> Vec<String> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../samples/eval");
    let mut files: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "ndjson"))
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    files.sort();
    assert!(!files.is_empty(), "no samples in {}", dir.display());
    files
}

/// `args` followed by every sample file.
pub fn with_samples<'a>(args: &[&'a str], samples: &'a [String]) -> Vec<&'a str> {
    args.iter()
        .copied()
        .chain(samples.iter().map(String::as_str))
        .collect()
}
