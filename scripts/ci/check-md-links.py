#!/usr/bin/env python3
"""Relative links and heading anchors in the repository's Markdown.

A dead `#fragment` renders as a jump to the top of the page rather than an
error, so broken anchors survive review indefinitely - only a checker catches
them. When a link and a heading disagree, fix the LINK: the heading is an
anchor other pages may already point at.

Covers every tracked `*.md` (README, docs/, notices/, cases/*/reports/).
External links (http, https, mailto) are not fetched.

Usage:
    scripts/ci/check-md-links.py            # every tracked Markdown file
    scripts/ci/check-md-links.py --staged   # staged Markdown files only
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LINK = re.compile(r"(?<!!)\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
HEADING = re.compile(r"^#{1,6}\s+(.*?)\s*#*\s*$")
FENCE = re.compile(r"^\s*(```|~~~)")


def slug(heading: str) -> str:
    """GitHub's anchor rule: lowercase, drop punctuation, spaces to hyphens."""
    h = re.sub(r"`|\*\*|__|\[([^\]]*)\]\([^)]*\)", r"\1", heading).strip().lower()
    h = re.sub(r"[^\w\- ]", "", h)
    return h.replace(" ", "-")


def anchors(path: Path) -> set[str]:
    seen: dict[str, int] = {}
    out = set()
    in_fence = False
    for line in path.read_text(encoding="utf-8").splitlines():
        if FENCE.match(line):
            in_fence = not in_fence
            continue
        m = None if in_fence else HEADING.match(line)
        if not m:
            continue
        s = slug(m.group(1))
        n = seen.get(s, 0)
        seen[s] = n + 1
        out.add(s if n == 0 else f"{s}-{n}")
    return out


def md_files(staged: bool) -> list[str]:
    cmd = ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"] if staged else [
        "git", "ls-files", "--cached", "--others", "--exclude-standard"]
    out = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, check=True).stdout
    return [p for p in out.splitlines() if p.endswith(".md")]


def main(argv: list[str]) -> int:
    problems = []
    files = md_files("--staged" in argv)
    for rel in files:
        src = ROOT / rel
        if not src.is_file():
            continue
        in_fence = False
        for n, line in enumerate(src.read_text(encoding="utf-8").splitlines(), 1):
            if FENCE.match(line):
                in_fence = not in_fence
            if in_fence:
                continue
            for target in LINK.findall(re.sub(r"`[^`]*`", "", line)):
                if re.match(r"^[a-z][a-z0-9+.-]*:", target):
                    continue
                file_part, _, frag = target.partition("#")
                dest = (src.parent / file_part).resolve() if file_part else src
                if not dest.exists():
                    problems.append(f"{rel}:{n}: missing target {file_part}")
                elif frag and dest.suffix == ".md" and frag not in anchors(dest):
                    problems.append(f"{rel}:{n}: no heading for #{frag} in {dest.relative_to(ROOT).as_posix()}")
    for p in problems:
        print(f"[check-md-links] {p}", file=sys.stderr)
    if problems:
        print(f"[check-md-links] FAIL - {len(problems)} broken link(s)", file=sys.stderr)
        return 1
    if "--quiet" not in argv:
        print(f"[check-md-links] OK - {len(files)} file(s) checked")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
