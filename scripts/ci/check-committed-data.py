#!/usr/bin/env python3
"""The one hard rule: no raw data and no live secrets in git.

Collected records can carry exfiltrated cookies, session tokens and API keys,
and the watch pipeline's raw output names organisations before the admin has
reviewed anything. Both stay out of the repository: raw output lives in the
gitignored `data/` (cases included) or `cases/`, or in $SWARMCHASE_DATA on the runner,
and committed samples, reports and notices are redacted at ingest.

A .gitignore entry is one `git add -f` away from being fiction, so this gate
checks what is tracked or addable (or, with --staged, what is staged):

  1. Paths: nothing under `data/` or `cases/`, no `*.analysis.json`,
     no local secrets file (`env.list`, `.env`),
     and record dumps (`*.ndjson`, `*.jsonl`, CDX output) only under
     `samples/` or a crate's `tests/fixtures/`.
  2. Size: no file over 1 MiB except the lockfile. A raw dump is the usual
     way a large file arrives.
  3. Secrets: no credential-shaped value in any tracked text file. The shapes
     mirror crates/sc-core/src/redact.rs. A redacted value reads
     `REDACTED-<hex>` and never matches. A deliberate fake in a test carries
     `secret-scan: fixture` on the same line.

Usage:
    scripts/ci/check-committed-data.py            # every tracked file
    scripts/ci/check-committed-data.py --staged   # what `git commit` would add
    scripts/ci/check-committed-data.py --selftest

The detectors self-test before every run and refuse to report a pass when a
control fails. Outside a git checkout the tracked set is approximated by a
walk that skips the gitignored build and data directories.
"""

from __future__ import annotations

import fnmatch
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MAX_BYTES = 1 << 20
# The lockfile, and the committed all-samples analysis snapshot: a generated
# fixture (regenerated with UPDATE_SNAPSHOTS) that grows with the evaluation
# set and holds only synthetic sample data, no raw collector output.
SIZE_EXEMPT = {"Cargo.lock", "crates/sc-core/tests/snapshots/all.analysis.snap.json"}
WAIVER = "secret-scan: fixture"

FORBIDDEN = [
    ("data/*", "raw collector output belongs in the gitignored data/"),
    ("cases/*", "case files stay private in <data>/cases/ (swarmchase case); publish through notices/"),
    ("*.analysis.json", "analysis output is regenerable and may name unreviewed leads"),
    ("env.list", "local secrets file; commit env.list.example instead"),
    (".env", "local secrets file"),
    ("docs/PRD.md", "private planning notes; public docs describe the current state only"),
]
DUMP_GLOBS = ["*.ndjson", "*.jsonl", "*.cdx", "*.warc", "*.warc.gz"]
DUMP_ALLOWED = ["samples/*", "crates/*/tests/fixtures/*"]

SECRETS = [
    ("JWT", r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    ("AWS access key id", r"\bAKIA[0-9A-Z]{16}\b"),
    ("GitHub token", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    ("GitHub fine-grained token", r"\bgithub_pat_[A-Za-z0-9_]{40,}"),
    ("Slack token", r"\bxox[abposr]-[A-Za-z0-9-]{10,}"),
    ("OpenAI/Anthropic-style key", r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}"),
    ("Google API key", r"\bAIza[0-9A-Za-z_-]{35}"),
    ("GitLab token", r"\bglpat-[A-Za-z0-9_-]{20,}"),
    ("private key block", r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----"),
]
SECRET_RE = [(name, re.compile(rx)) for name, rx in SECRETS]

# Built by concatenation so this file never matches its own detectors.
CONTROLS_HIT = [
    "eyJ" + "hbGciOiJIUzI1NiJ9.eyJ" + "zdWIiOiIxIn0.abcdefghijkl",
    "AKIA" + "ABCDEFGHIJKLMNOP",
    "ghp_" + "a" * 36,
    "xoxb-" + "1234567890-abc",
    "sk-" + "ant-" + "a" * 24,
    "AIza" + "B" * 35,
    "glpat-" + "c" * 20,
    "-----BEGIN " + "RSA PRIVATE KEY-----",
]
CONTROLS_MISS = [
    "access_token=REDACTED-0123456789ab",
    "https://r.jina.ai/https://site.example/?uqtag=run7",
    "sk-short",
    "token=" + "eyJ" + "notajwt",
]


def match(path: str, pattern: str) -> bool:
    return fnmatch.fnmatchcase(path, pattern)


def secret_hits(line: str) -> list[str]:
    if WAIVER in line:
        return []
    return [name for name, rx in SECRET_RE if rx.search(line)]


def selftest() -> list[str]:
    errors = []
    for c in CONTROLS_HIT:
        if not secret_hits(c):
            errors.append(f"selftest: detector missed control {c[:12]}...")
    for c in CONTROLS_MISS:
        if secret_hits(c):
            errors.append(f"selftest: false positive on control {c!r}")
    if not path_problems("data/jina.ndjson") or path_problems("samples/x.ndjson"):
        errors.append("selftest: path rules wrong for data/ vs samples/")
    if not path_problems("env.list") or path_problems("env.list.example"):
        errors.append("selftest: path rules wrong for env.list")
    if not path_problems("cases/c1/raw/a.json") or not path_problems("cases/c1/case.toml"):
        errors.append("selftest: path rules wrong for cases/")
    return errors


def path_problems(path: str) -> list[str]:
    out = [why for pat, why in FORBIDDEN if match(path, pat)]
    if any(match(Path(path).name, g) for g in DUMP_GLOBS) and not any(
        match(path, a) for a in DUMP_ALLOWED
    ):
        out.append("record dumps are committed only under samples/ or tests/fixtures/")
    return out


def tracked(staged: bool) -> list[str]:
    cmd = (
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"]
        if staged
        # Untracked-but-not-ignored files too: they are one `git add .` away.
        else ["git", "ls-files", "--cached", "--others", "--exclude-standard"]
    )
    try:
        out = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, check=True)
        return [p for p in out.stdout.splitlines() if p]
    except (OSError, subprocess.CalledProcessError):
        if staged:
            return []
    skip = {".git", "target", "data", "pkg", "node_modules", "__pycache__"}
    files = []
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in skip and not d.startswith(".tmp")]
        rel = Path(dirpath).relative_to(ROOT)
        if rel.parts[:1] == ("cases",):
            continue
        files += [(rel / f).as_posix() for f in filenames]
    return files


def main(argv: list[str]) -> int:
    quiet = "--quiet" in argv
    errors = selftest()
    if errors or "--selftest" in argv:
        for e in errors:
            print(f"[check-committed-data] {e}", file=sys.stderr)
        if not errors:
            print("[check-committed-data] selftest OK")
        return 1 if errors else 0

    files = tracked("--staged" in argv)
    problems = []
    for rel in files:
        p = ROOT / rel
        if not p.is_file():
            continue
        for why in path_problems(rel):
            problems.append(f"{rel}: {why}")
        size = p.stat().st_size
        if size > MAX_BYTES and rel not in SIZE_EXEMPT:
            problems.append(f"{rel}: {size} bytes (> 1 MiB); raw dumps stay out of git")
        try:
            text = p.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for n, line in enumerate(text.splitlines(), 1):
            for name in secret_hits(line):
                problems.append(f"{rel}:{n}: unredacted {name}")

    for msg in problems:
        print(f"[check-committed-data] {msg}", file=sys.stderr)
    if problems:
        print(
            f"[check-committed-data] FAIL - {len(problems)} problem(s). Redact records "
            "through `swarmchase` ingest, move raw output to data/, or mark a "
            f"deliberate fake with `{WAIVER}`.",
            file=sys.stderr,
        )
        return 1
    if not quiet:
        print(f"[check-committed-data] OK - {len(files)} file(s) checked")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
