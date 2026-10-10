#!/usr/bin/env python3
"""Safety checks for the public site.

The site renders attack payloads: HTML programs, XSS probes, injection
strings. Three layers keep them inert, and this gate checks each:

  1. A strict Content-Security-Policy on every page: no inline script, no
     eval (only `wasm-unsafe-eval` for the WASM module), no network access
     beyond the site's own files.
  2. Page code that never parses strings as HTML or code: no innerHTML,
     outerHTML, insertAdjacentHTML, document.write, eval, new Function or
     string timers, no navigation by assignment, and in the markup no inline
     script, style or event handler, and no javascript: or plain-http links.
  3. A site built from committed inputs only. The generator's allow-list
     names no data directory, and with --inputs every file a build read must
     be tracked by git and outside data/ and $SWARMCHASE_DATA.

Without arguments it checks the sources: site/**/*.js, the page templates in
crates/sc-publish/src/pages/ and the generator's allow-list (the gates job,
before anything is built). After scripts/ci/build-site.sh:

    scripts/ci/check-site.py --built _site --inputs <log>   # every generated page
    scripts/ci/check-site.py --selftest                     # the detectors only

The generated WASM bindings (pkg/) are not checked; they are built in CI.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SITE = ROOT / "site"
PAGES = ROOT / "crates" / "sc-publish" / "src" / "pages"
GENERATOR = ROOT / "crates" / "sc-publish" / "src" / "bin" / "sc-site.rs"

CSP_META = re.compile(
    r"""<meta\s+http-equiv=["']Content-Security-Policy["']\s+content="([^"]+)\"""",
    re.I,
)
REQUIRED = {
    "default-src": {"'none'"},
    "script-src": {"'self'", "'wasm-unsafe-eval'"},
    "style-src": {"'self'"},
    "base-uri": {"'none'"},
    "form-action": {"'none'"},
}
# Directives that may only list these sources.
ALLOWED = {"connect-src": {"'self'"}, "img-src": {"'self'"}, **REQUIRED}

# Markup patterns for sources (templates in Rust strings), checked by line.
HTML_BAD = [
    (re.compile(r"<script(?![^>]*\bsrc=)[^>]*>", re.I), "inline <script>"),
    (re.compile(r"<style\b", re.I), "inline <style> block"),
    (re.compile(r"""\sstyle\s*=\s*\\?["']""", re.I), "inline style attribute"),
    (re.compile(r"""\son[a-z]+\s*=\s*\\?["']""", re.I), "inline event handler"),
    (re.compile(r"""\b(?:href|src)\s*=\s*\\?["']\s*javascript:""", re.I), "javascript: URL"),
]
JS_BAD = [
    (re.compile(r"\.innerHTML\b"), "innerHTML"),
    (re.compile(r"\.outerHTML\b"), "outerHTML"),
    (re.compile(r"\binsertAdjacentHTML\b"), "insertAdjacentHTML"),
    (re.compile(r"\bdocument\.write"), "document.write"),
    (re.compile(r"\bcreateContextualFragment\b"), "createContextualFragment"),
    (re.compile(r"\bDOMParser\b"), "DOMParser"),
    (re.compile(r"(?<![\w.])eval\s*\("), "eval"),
    (re.compile(r"\bnew\s+Function\b"), "new Function"),
    (re.compile(r"\bset(?:Timeout|Interval)\s*\(\s*[\"'`]"), "string timer"),
    (re.compile(r"\blocation(?:\.href)?\s*=(?!=)"), "navigation by assignment"),
    (re.compile(r"\.(?:href|src)\s*=(?!=)"), "URL property assignment"),
    (re.compile(r"""\.setAttribute\(\s*["'](?:href|src|on\w+)["']"""), "URL or handler attribute set directly"),
    # Blocked by the CSP at runtime; set e.style.x (CSSOM) instead.
    (re.compile(r"""setAttribute\(\s*["']style|\bstyle\s*:\s*["'`]"""), "style attribute string"),
]

# What the generator may read (crates/sc-publish/src/bin/sc-site.rs INPUTS).
INPUT_PREFIXES = {
    "notices/",
    "docs/",
    "rules/default.toml",
    "samples/eval/",
    "samples/eval/coverage-allow.txt",
    "site/",
}
# Inputs that are built, not committed: the WASM package.
GENERATED_INPUTS = ("site/pkg/", "site/pkg-rules/")
BANNED_TAGS = {"iframe", "object", "embed", "base", "frame", "frameset", "applet"}
URL_ATTRS = {"href", "src", "action", "formaction", "xlink:href", "srcset", "poster", "data"}


def parse_csp(policy: str) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for part in policy.split(";"):
        words = part.split()
        if words:
            out[words[0].lower()] = set(words[1:])
    return out


def check_csp(html: str) -> list[str]:
    m = CSP_META.search(html)
    if not m:
        return ["no Content-Security-Policy <meta>"]
    csp = parse_csp(m.group(1))
    errors = []
    for d, need in REQUIRED.items():
        if not need <= csp.get(d, set()):
            errors.append(f"CSP {d} must include {' '.join(sorted(need))}")
    for d, sources in csp.items():
        if d in ALLOWED and not sources <= ALLOWED[d]:
            errors.append(f"CSP {d} allows {' '.join(sorted(sources - ALLOWED[d]))}")
        elif d not in ALLOWED:
            errors.append(f"CSP directive {d} is not reviewed by this gate")
    return errors


class PageCheck(HTMLParser):
    """The markup of one generated page, as a browser would parse it."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.errors: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        line = self.getpos()[0]
        err = lambda what: self.errors.append(f"{line}: {what}")  # noqa: E731
        if tag == "script":
            src = a.get("src", "")
            if not src:
                err("inline <script>")
            elif re.match(r"^[a-z][a-z0-9+.-]*:|^//", src, re.I):
                err(f"script from another origin: {src}")
        if tag == "style":
            err("inline <style> block")
        if tag in BANNED_TAGS:
            err(f"<{tag}> element")
        if tag == "meta" and a.get("http-equiv", "").lower() == "refresh":
            err("meta refresh")
        for k, v in a.items():
            if k.startswith("on"):
                err(f"inline event handler {k}")
            if k == "style":
                err("inline style attribute")
            if k in URL_ATTRS:
                u = v.strip().lower()
                if re.match(r"^(javascript|data|vbscript|file|blob):", u):
                    err(f"{k} with a {u.split(':')[0]}: URL")
                elif u.startswith("http:") or u.startswith("//"):
                    err(f"{k} to a non-https or protocol-relative URL: {v[:80]}")
                if tag == "link" and k == "href" and a.get("rel") == "stylesheet" and re.match(r"^[a-z]+:|^//", u):
                    err(f"stylesheet from another origin: {v[:80]}")


def check_page(text: str) -> list[str]:
    errors = check_csp(text)
    p = PageCheck()
    p.feed(text)
    p.close()
    return errors + p.errors


def scan(text: str, patterns) -> list[str]:
    errors = []
    for n, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith(("//", "<!--")):
            continue
        for rx, what in patterns:
            if rx.search(line):
                errors.append(f"{n}: {what}")
    return errors


def check_sources(files: dict[str, str]) -> list[str]:
    errors = []
    for name, text in sorted(files.items()):
        if name.endswith(".html"):
            errors += [f"{name}: {e}" for e in check_page(text)]
        elif name.endswith(".js"):
            errors += [f"{name}:{e}" for e in scan(text, JS_BAD)]
        elif name.endswith(".rs"):
            # Templates only: test modules hold hostile fixtures on purpose.
            errors += [f"{name}:{e}" for e in scan(text.split("#[cfg(test)]")[0], HTML_BAD)]
    return errors


def generator_inputs(text: str) -> set[str]:
    """The INPUTS allow-list of sc-site.rs: the first string of each pair."""
    m = re.search(r"const INPUTS[^=]*=\s*&\[(.*?)\];", text, re.S)
    return set(re.findall(r'\(\s*"([^"]*)"', m.group(1))) if m else set()


def check_generator(text: str) -> list[str]:
    found = generator_inputs(text)
    errors = []
    if not found:
        errors.append("sc-site.rs: no INPUTS allow-list found")
    for p in sorted(found - INPUT_PREFIXES):
        errors.append(f"sc-site.rs: INPUTS allows {p!r}, which is not a committed site input")
    if "SWARMCHASE_DATA" not in text:
        errors.append("sc-site.rs: no longer refuses $SWARMCHASE_DATA")
    return errors


def data_dirs() -> list[str]:
    dirs = ["data/"]
    env = os.environ.get("SWARMCHASE_DATA")
    if env:
        p = Path(env)
        p = p if p.is_absolute() else ROOT / p
        try:
            dirs.append(p.resolve().relative_to(ROOT).as_posix().rstrip("/") + "/")
        except ValueError:
            pass  # outside the checkout: nothing under ROOT can be in it
    return dirs


def check_inputs(paths: list[str], tracked: set[str] | None) -> list[str]:
    errors = []
    banned = data_dirs()
    for p in paths:
        p = p.strip().replace("\\", "/")
        if not p:
            continue
        if any(p == d.rstrip("/") or p.startswith(d) for d in banned) or "/../" in f"/{p}/":
            errors.append(f"input {p}: inside a data directory")
            continue
        if not any(p == pre or p.startswith(pre) for pre in INPUT_PREFIXES):
            errors.append(f"input {p}: not a committed site input")
            continue
        if tracked is not None and not p.startswith(GENERATED_INPUTS) and p not in tracked:
            errors.append(f"input {p}: not tracked by git (commit or `git add` it)")
    return errors


def git_tracked() -> set[str] | None:
    try:
        out = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True)
    except (OSError, subprocess.CalledProcessError):
        return None
    return set(out.stdout.decode("utf-8", "replace").split("\0")) - {""}


def selftest() -> list[str]:
    good_csp = (
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; '
        "script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; connect-src 'self'; "
        "base-uri 'none'; form-action 'none'\">"
    )
    controls_bad = {
        "a.html": good_csp.replace("'wasm-unsafe-eval'", "'wasm-unsafe-eval' 'unsafe-inline'"),
        "b.html": good_csp + "<script>alert(1)</script>",
        "c.html": good_csp + '<button onclick="x()">',
        "d.html": "<p>no policy</p>",
        "d2.html": good_csp + '<p style="color:red">',
        "d3.html": good_csp + '<a href="javascript:alert(1)">x</a>',
        "d4.html": good_csp + '<a href="http://example.org/">x</a>',
        "d5.html": good_csp + '<iframe srcdoc="x"></iframe>',
        "d6.html": good_csp + '<script src="https://cdn.example/x.js"></script>',
        "e.js": "x.innerHTML = rec.url;",
        "f.js": "setTimeout('x()', 1);",
        "g.js": "a.href = rec.url;",
        "h.js": "const f = eval(s);",
        "i.js": 'el("div", { style: `margin-left:${d}px` });',
        "j.js": 'a.setAttribute("href", u);',
        "k.rs": 'const X: &str = r#"<div style="x">"#;',
        "l.rs": 'const X: &str = "<button onclick=\\"x()\\">";',
    }
    errors = []
    for name, text in controls_bad.items():
        if not check_sources({name: text}):
            errors.append(f"selftest: missed the bad control {name}")
    good = {
        "ok.html": good_csp
        + '<script type="module" src="js/site.js"></script><p>payload text: onerror=alert(1) &lt;script&gt;</p>'
        + '<a href="../docs/">d</a><a href="https://github.com/x">g</a><a href="#main">m</a>',
        "ok.js": "e.textContent = rec.url; if (a.href === b) retrieval(); x.evaluate(); "
        "el('div', { style: { marginLeft: '4px' } });",
        "ok.rs": 'format!("<p class=\\"hint\\">one={}</p>", esc(x)); // <script src=\\"x\\">',
    }
    for e in check_sources(good):
        errors.append(f"selftest: false positive {e}")
    gen_bad = 'const INPUTS: &[(&str, &str)] = &[("docs/", ".md"), ("data/", "")]; SWARMCHASE_DATA'
    if not check_generator(gen_bad):
        errors.append("selftest: missed a generator allow-list naming data/")
    gen_ok = 'const INPUTS: &[(&str, &str)] = &[("docs/", ".md"), ("site/", "")]; SWARMCHASE_DATA'
    errors += [f"selftest: false positive {e}" for e in check_generator(gen_ok)]
    if not check_inputs(["data/watch/records.ndjson"], None):
        errors.append("selftest: missed an input under data/")
    if not check_inputs(["docs/x.md"], set()):
        errors.append("selftest: missed an untracked input")
    errors += [f"selftest: false positive {e}" for e in check_inputs(["docs/x.md", "site/pkg/a.wasm"], {"docs/x.md"})]
    return errors


def arg(argv: list[str], name: str) -> str | None:
    if name in argv:
        i = argv.index(name)
        if i + 1 < len(argv):
            return argv[i + 1]
    return None


def main(argv: list[str]) -> int:
    errors = selftest()
    if "--selftest" not in argv:
        files = {
            p.relative_to(ROOT).as_posix(): p.read_text(encoding="utf-8")
            for p in [*SITE.rglob("*"), *PAGES.glob("*.rs")]
            if p.suffix in (".html", ".js", ".rs") and "pkg" not in p.relative_to(ROOT).parts
        }
        if not any(n.endswith(".js") for n in files):
            errors.append("site/: no page scripts found")
        errors += check_sources(files)
        if GENERATOR.is_file():
            errors += check_generator(GENERATOR.read_text(encoding="utf-8"))
        else:
            errors.append(f"{GENERATOR.relative_to(ROOT)} not found")
        built = arg(argv, "--built")
        if built:
            out = Path(built)
            out = out if out.is_absolute() else ROOT / out
            pages = sorted(out.rglob("*.html"))
            if not pages:
                errors.append(f"{built}: no pages")
            for p in pages:
                rel = p.relative_to(out).as_posix()
                errors += [f"{built}/{rel}: {e}" for e in check_page(p.read_text(encoding="utf-8"))]
            for p in sorted(out.rglob("*.js")):
                if "pkg" in p.relative_to(out).parts:
                    continue
                rel = p.relative_to(out).as_posix()
                errors += [f"{built}/{rel}:{e}" for e in scan(p.read_text(encoding="utf-8"), JS_BAD)]
            if not errors:
                print(f"check-site: {len(pages)} generated pages checked")
        log = arg(argv, "--inputs")
        if log:
            tracked = git_tracked()
            if tracked is None:
                errors.append("--inputs: git is not available to check that inputs are committed")
            lines = Path(log).read_text(encoding="utf-8").splitlines()
            if not lines:
                errors.append("--inputs: the build read nothing")
            errors += check_inputs(lines, tracked)
            if not errors:
                print(f"check-site: {len(lines)} inputs, all committed site inputs")
    for e in errors:
        print(f"check-site: {e}", file=sys.stderr)
    if not errors:
        print("check-site: OK")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
