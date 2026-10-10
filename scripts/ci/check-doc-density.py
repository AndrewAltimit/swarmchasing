#!/usr/bin/env python3
"""Markdown legibility-density checker for committed docs.

Flags two write-optimised-but-not-read-optimised patterns that creep into
long-lived documentation:

  * Over-long lines: any line wider than the line cap. Usually a run-on
    paragraph that wants splitting, or an over-stuffed table row.
  * Over-budget table cells: any Markdown table cell holding more words than
    the cell cap. A table cell is a one-line "what this covers"; a paragraph
    belongs in a section (same page) or a linked page, with a one-line summary
    and the link left in the cell.

CLAUDE.md gets tighter caps than the rest. It is the map every contributor and
agent reads first, and a map whose rows grow into specs stops being one.

Scope: every tracked `docs/**/*.md`, every `crates/*/README.md`, every
top-level `*.md` (CLAUDE.md, README.md, CONTRIBUTING.md) and
`scripts/README.md`. Notices are out of scope (`notice lint` gates them), as
are generated files. Lines inside fenced code blocks are skipped: commands and
code may be wide.

This is a floor, not a definition of readable. A line under the cap can still
be an unreadable run-on, so do not write up to the cap.

Usage:
    scripts/ci/check-doc-density.py              # the whole corpus
    scripts/ci/check-doc-density.py --staged     # staged Markdown only (hook)
    scripts/ci/check-doc-density.py --quiet      # no success line
    scripts/ci/check-doc-density.py --self-test  # the detectors only

Exits 1 on a violation, 2 when the file list could not be read (a failed
`git` must not look like a clean corpus). Standard library only.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class Caps:
    line: int
    cell_words: int


DEFAULT = Caps(line=800, cell_words=60)
TIGHT = {"CLAUDE.md": Caps(line=600, cell_words=50)}


def caps_for(rel: str) -> Caps:
    return TIGHT.get(rel, DEFAULT)


def in_scope(rel: str) -> bool:
    p = rel.replace("\\", "/")
    if not p.endswith(".md"):
        return False
    if p.startswith("docs/") or "/" not in p or p == "scripts/README.md":
        return True
    parts = p.split("/")
    return len(parts) == 3 and parts[0] == "crates" and parts[2] == "README.md"


def git_files(staged: bool) -> list[str]:
    cmd = (
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"]
        if staged
        else ["git", "ls-files", "--cached", "--others", "--exclude-standard"]
    )
    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    # An empty list from a failed git would be a vacuous pass in a hard gate.
    if proc.returncode != 0:
        first = (proc.stderr.strip().splitlines() or ["(no output)"])[0]
        print(f"[check-doc-density] `{' '.join(cmd)}` failed: {first}", file=sys.stderr)
        sys.exit(2)
    return sorted(p for p in proc.stdout.splitlines() if in_scope(p) and (ROOT / p).is_file())


def split_cells(line: str) -> list[str]:
    """Cells of a table row, without the empties the bordering pipes leave.

    A pipe escaped as `\\|` stays inside its cell. A pipe inside a code span
    still splits, which can only under-count a cell: the safe direction for
    a commit gate."""
    raw = line.replace("\\|", "\x00").split("|")
    if raw and not raw[0].strip():
        raw = raw[1:]
    if raw and not raw[-1].strip():
        raw = raw[:-1]
    return [c.replace("\x00", "|") for c in raw]


def is_separator(cells: list[str]) -> bool:
    return bool(cells) and all(not (set(c.strip()) - set("-: ")) for c in cells)


def check_text(text: str, caps: Caps) -> list[tuple[int, str]]:
    out = []
    in_fence = False
    for n, line in enumerate(text.splitlines(), 1):
        stripped = line.lstrip()
        if stripped.startswith(("```", "~~~")):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        if len(line) > caps.line:
            out.append((n, f"line is {len(line)} chars (> {caps.line}); split the paragraph"))
        if stripped.startswith("|"):
            cells = split_cells(line)
            if is_separator(cells):
                continue
            for cell in cells:
                words = len(cell.split())
                if words > caps.cell_words:
                    out.append(
                        (n, f"table cell is {words} words (> {caps.cell_words}); "
                            "move the detail into a section and link it")
                    )
    return out


def self_test() -> list[str]:
    fails = []

    def expect(name: str, text: str, caps: Caps, want: int) -> None:
        got = len(check_text(text, caps))
        if got != want:
            fails.append(f"{name}: expected {want} violation(s), got {got}")

    long_line = "word " * 200
    fat_cell = "| a | " + "word " * 61 + "|"
    expect("over-long line", long_line, DEFAULT, 1)
    expect("line at the cap", "x" * DEFAULT.line, DEFAULT, 0)
    expect("fat table cell", "| h | h |\n|---|---|\n" + fat_cell, DEFAULT, 1)
    expect("cell at the cap", "| a | " + "word " * 60 + "|", DEFAULT, 0)
    expect("fenced code is exempt", "```\n" + long_line + "\n" + fat_cell + "\n```", DEFAULT, 0)
    expect("tilde fence is exempt", "~~~\n" + long_line + "\n~~~", DEFAULT, 0)
    expect("text after a fence is checked", "```\nx\n```\n" + long_line, DEFAULT, 1)
    expect("separator row", "| --- | :---: | ---: |", DEFAULT, 0)
    expect("escaped pipe stays in the cell", "| " + "w \\| " * 31 + "|", DEFAULT, 1)
    expect("unbordered prose is not a table", "word " * 100, DEFAULT, 0)
    claude = caps_for("CLAUDE.md")
    expect("CLAUDE.md tighter cell cap", "| a | " + "word " * 55 + "|", claude, 1)
    expect("CLAUDE.md tighter line cap", "y" * 700, claude, 1)
    for rel, want in [
        ("docs/guides/x.md", True),
        ("CLAUDE.md", True),
        ("crates/sc-core/README.md", True),
        ("crates/sc-core/src/README.md", False),
        ("scripts/README.md", True),
        ("notices/2026-10-x.md", False),
        ("samples/eval/README.md", False),
        ("docs/x.txt", False),
    ]:
        if in_scope(rel) != want:
            fails.append(f"in_scope({rel!r}) should be {want}")
    return fails


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--staged", action="store_true", help="only staged Markdown files")
    ap.add_argument("--quiet", action="store_true", help="no success line")
    ap.add_argument("--self-test", action="store_true", help="test the detectors and exit")
    args = ap.parse_args(argv)

    # The detectors check themselves on every run, so a broken detector
    # cannot report a clean corpus.
    fails = self_test()
    if fails:
        for f in fails:
            print(f"[check-doc-density] SELF-TEST FAIL: {f}", file=sys.stderr)
        return 2
    if args.self_test:
        print("[check-doc-density] self-test OK")
        return 0

    files = git_files(args.staged)
    total = 0
    for rel in files:
        text = (ROOT / rel).read_text(encoding="utf-8", errors="replace")
        for n, msg in check_text(text, caps_for(rel)):
            print(f"{rel}:{n}: {msg}")
            total += 1
    if total:
        print(f"[check-doc-density] FAIL - {total} violation(s)", file=sys.stderr)
        return 1
    if not args.quiet:
        print(f"[check-doc-density] OK - {len(files)} file(s) within budget")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
