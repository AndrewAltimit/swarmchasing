#!/usr/bin/env python3
"""Burned identifiers: every tag a committed notice shows is a published tag.

A run tag or marker printed in a public notice can be copied by anyone who
reads it, so it no longer identifies one operator. The analysis stops linking
on a value only when it is listed in `[linking] published_tags` in
rules/default.toml. This gate fails when a notice in notices/ shows a linking
tag or marker value that list does not hold (compared ignoring case, as the
analysis does).

What counts as shown, read from the notice text after undoing defanging:

  * a linking parameter that notices show (in both `TAG_PARAMS` in
    crates/sc-core/src/notice.rs and `[linking] strong_params`), as a feature
    (`param:uqtag=zz9`) or in a URL (`?uqtag=zz9`);
  * a match of an `agent_marker` rule with `link = true`, as a feature
    (`marker.test_tag:chatgpttest1`) or anywhere in the text.

Withheld values (`[withheld]`) are skipped. A value the notice cut short
(ending in an ellipsis) is covered by a published tag that starts with it.

Usage:
    scripts/ci/check-published-tags.py              # every notice in notices/
    scripts/ci/check-published-tags.py --quiet      # no success line
    scripts/ci/check-published-tags.py --dir <dir>  # another notices directory
    scripts/ci/check-published-tags.py --self-test  # the detectors only

Passes with no notices/ directory. Exits 1 on an unlisted value, 2 when the
rules file or TAG_PARAMS could not be read (a parse failure must not look
like a clean pass). Standard library only.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from urllib.parse import unquote_plus

ROOT = Path(__file__).resolve().parents[2]
NOTICES = ROOT / "notices"
RULES = ROOT / "rules" / "default.toml"
NOTICE_RS = ROOT / "crates" / "sc-core" / "src" / "notice.rs"

WITHHELD = "[withheld]"
QUOTED = re.compile(r'"((?:[^"\\]|\\.)*)"')
FEATURE_PARAM = re.compile(r"`param:([A-Za-z0-9_]+)=([^`]*)`")


class ConfigError(Exception):
    pass


def strings(text: str) -> list[str]:
    """The double-quoted strings in TOML or Rust text, comments skipped."""
    out = []
    for line in text.splitlines():
        pos = 0
        while True:
            m = QUOTED.search(line, pos)
            hash_at = line.find("#", pos)
            if m is None or (hash_at != -1 and hash_at < m.start()):
                break
            out.append(m.group(1).replace('\\"', '"').replace("\\\\", "\\"))
            pos = m.end()
    return out


def table(toml: str, name: str) -> str:
    """The body of the `[name]` table."""
    m = re.search(rf"^\[{re.escape(name)}\]\s*$(.*?)(?=^\[)", toml + "\n[", re.M | re.S)
    if not m:
        raise ConfigError(f"no [{name}] table in {RULES.name}")
    return m.group(1)


def array(body: str, key: str) -> list[str]:
    """A string array, on one line or one value per line up to a line that
    opens with `]` (so a `]` inside a comment or a value does not end it)."""
    m = re.search(rf"^{key}\s*=\s*\[(.*)$", body, re.M)
    if not m:
        raise ConfigError(f"no `{key}` array in [linking]")
    first = m.group(1)
    if "]" not in first.split("#", 1)[0]:
        lines = [first]
        for line in body[m.end():].splitlines()[1:]:
            if line.strip().startswith("]"):
                return strings("\n".join(lines))
            lines.append(line)
        raise ConfigError(f"`{key}` array is not closed")
    return strings(first)


def marker_patterns(toml: str) -> dict[str, re.Pattern]:
    """Linking agent_marker rules: id -> pattern."""
    out = {}
    for block in toml.split("[[rule]]")[1:]:
        block = re.split(r"^\[", block, maxsplit=1, flags=re.M)[0]
        field = lambda k: re.search(rf'^{k}\s*=\s*"((?:[^"\\]|\\.)*)"', block, re.M)
        kind, rid, pat = field("kind"), field("id"), field("pattern")
        if not (kind and rid and pat) or kind.group(1) != "agent_marker":
            continue
        if not re.search(r"^link\s*=\s*true", block, re.M):
            continue
        try:
            out[rid.group(1)] = re.compile(strings(f'"{pat.group(1)}"')[0], re.I)
        except re.error as e:
            raise ConfigError(f"rule {rid.group(1)}: pattern does not compile here: {e}")
    return out


def tag_params(rust: str) -> list[str]:
    m = re.search(r"pub const TAG_PARAMS: &\[&str\] = &\[(.*?)\];", rust, re.S)
    if not m:
        raise ConfigError(f"no TAG_PARAMS in {NOTICE_RS.name}")
    return strings(m.group(1))


def refang(s: str) -> str:
    return s.replace("hxxp", "http").replace("[.]", ".").replace("[:]", ":")


def shown(text: str, params: set[str], markers: dict[str, re.Pattern]) -> set[tuple[str, str]]:
    """(where, value) for every linking tag or marker value the text shows."""
    plain = refang(text)
    found = set()
    for m in FEATURE_PARAM.finditer(plain):
        if m.group(1).lower() in params:
            found.add((f"param:{m.group(1)}", m.group(2)))
    if params:
        names = "|".join(sorted(map(re.escape, params)))
        for m in re.finditer(rf"[?&]({names})=([^&#\s`)]+)", plain, re.I):
            found.add((f"param:{m.group(1)}", unquote_plus(m.group(2))))
    for rid, pat in markers.items():
        for m in re.finditer(rf"`{re.escape(rid)}:([^`]*)`", plain):
            found.add((rid, m.group(1)))
        for m in pat.finditer(plain):
            found.add((rid, m.group(0)))
    return {(w, v.strip()) for w, v in found if v.strip() and WITHHELD not in v}


def listed(value: str, published: list[str]) -> bool:
    v = value.lower()
    if v.endswith("…"):
        return any(p.lower().startswith(v[:-1]) for p in published)
    return any(p.lower() == v for p in published)


def unlisted(text: str, published: list[str], params: set[str], markers) -> list[tuple[str, str]]:
    return sorted((w, v) for w, v in shown(text, params, markers) if not listed(v, published))


def load() -> tuple[list[str], set[str], dict[str, re.Pattern]]:
    toml = RULES.read_text(encoding="utf-8")
    linking = table(toml, "linking")
    published = array(linking, "published_tags")
    strong = {p.lower() for p in array(linking, "strong_params")}
    params = {p.lower() for p in tag_params(NOTICE_RS.read_text(encoding="utf-8"))} & strong
    return published, params, marker_patterns(toml)


def self_test() -> list[str]:
    fails = []
    published = ["chatgpttest1", "tok=expt", "zz9", "longrunvalue-abcdef"]
    params = {"uqtag", "tag"}
    markers = {"marker.test_tag": re.compile(r"chatgpttest\d*|tok=expt", re.I)}

    def expect(name: str, text: str, want: int) -> None:
        got = unlisted(text, published, params, markers)
        if len(got) != want:
            fails.append(f"{name}: expected {want} unlisted value(s), got {got}")

    expect("listed param feature", "linked by: `param:uqtag=zz9`", 0)
    expect("listed ignoring case", "linked by: `param:uqtag=ZZ9`", 0)
    expect("unlisted param feature", "linked by: `param:uqtag=yy8`", 1)
    expect("unlisted tag in a defanged URL", "1. x — `hxxps://a[.]example/p?id=1&tag=run%2D7`", 1)
    expect("percent-encoded listed tag", "`hxxps://a[.]example/?uqtag=z%7A9`", 0)
    expect("withheld value", "`param:uqtag=[withheld]` and `hxxps://a[.]example/?uqtag=[withheld]`", 0)
    expect("non-linking param", "`param:tok=abc` and `hxxps://a[.]example/?q=abc&sid=s1`", 0)
    expect("listed marker feature", "linked by: `marker.test_tag:chatgpttest1`", 0)
    expect("unlisted marker feature", "linked by: `marker.test_tag:chatgpttest42`", 1)
    expect("unlisted marker in a URL", "`hxxps://a[.]example/?q=chatgpttest7`", 1)
    expect("cut-short value covered", "`param:uqtag=longrunvalue-abc…`", 0)
    expect("cut-short value not covered", "`param:uqtag=otherrun-abc…`", 1)
    expect("prose without tags", "Records were linked by shared tags.", 0)

    toml = (
        '[linking]\nstrong_params = ["uqtag", "tok"] # c\n'
        'published_tags = [\n  "a1", # source "x"\n  "b\\"2",\n]\nwindow_secs = 1\n'
        '[[rule]]\nid = "marker.t"\nkind = "agent_marker"\npattern = "t\\\\d+"\nlink = true\n'
        '[[rule]]\nid = "exfil.x"\nkind = "exfil"\npattern = "x"\nlink = true\n'
        '[[rule]]\nid = "marker.n"\nkind = "agent_marker"\npattern = "n"\n'
    )
    if array(table(toml, "linking"), "published_tags") != ["a1", 'b"2']:
        fails.append(f"published_tags parse: {array(table(toml, 'linking'), 'published_tags')}")
    m = marker_patterns(toml)
    if list(m) != ["marker.t"] or not m["marker.t"].fullmatch("T12"):
        fails.append(f"marker rules parse: {m}")
    if tag_params('pub const TAG_PARAMS: &[&str] = &[\n    "uqtag", "run",\n];') != ["uqtag", "run"]:
        fails.append("TAG_PARAMS parse")
    return fails


def shown_path(p: Path) -> str:
    try:
        return p.relative_to(ROOT).as_posix()
    except ValueError:
        return p.as_posix()


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--dir", type=Path, default=NOTICES, help="notices directory (default: notices/)")
    ap.add_argument("--quiet", action="store_true", help="no success line")
    ap.add_argument("--self-test", action="store_true", help="test the detectors and exit")
    args = ap.parse_args(argv)

    fails = self_test()
    if fails:
        for f in fails:
            print(f"[check-published-tags] SELF-TEST FAIL - {f}", file=sys.stderr)
        return 2
    if args.self_test:
        print("[check-published-tags] self-test OK")
        return 0

    notices = args.dir.resolve()
    files = sorted(
        p for p in notices.glob("*.md") if p.name.lower() != "readme.md"
    ) if notices.is_dir() else []
    if not files:
        if not args.quiet:
            print("[check-published-tags] OK - no notices")
        return 0
    try:
        published, params, markers = load()
    except (OSError, ConfigError) as e:
        print(f"[check-published-tags] ERROR - {e}", file=sys.stderr)
        return 2

    bad = 0
    for p in files:
        for where, value in unlisted(p.read_text(encoding="utf-8"), published, params, markers):
            bad += 1
            print(
                f"{shown_path(p)}: `{value}` ({where}) is public but not in "
                "[linking] published_tags in rules/default.toml; add it with the notice as its source",
                file=sys.stderr,
            )
    if bad:
        print(f"[check-published-tags] FAIL - {bad} unlisted value(s)", file=sys.stderr)
        return 1
    if not args.quiet:
        print(f"[check-published-tags] OK - {len(files)} notice(s), every shown tag is published")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
