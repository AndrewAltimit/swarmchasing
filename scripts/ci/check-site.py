#!/usr/bin/env python3
"""Static safety checks for the browser toolkit in site/.

The site renders attack payloads: HTML programs, XSS probes, injection
strings. Two layers keep them inert, and this gate checks both:

  1. A strict Content-Security-Policy in index.html: no inline script, no
     eval (only `wasm-unsafe-eval` for the WASM module), no network access
     beyond the page's own files.
  2. Page code that never parses strings as HTML or code: no innerHTML,
     outerHTML, insertAdjacentHTML, document.write, eval, new Function or
     string timers, and no inline handlers or styles in the markup.

The generated WASM bindings (site/pkg/) are not checked; they are built in CI.

Usage:
    scripts/ci/check-site.py              # check site/
    scripts/ci/check-site.py --selftest   # check the detectors only
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SITE = ROOT / "site"

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

HTML_BAD = [
    (re.compile(r"<script(?![^>]*\bsrc=)[^>]*>", re.I), "inline <script>"),
    (re.compile(r"<style\b", re.I), "inline <style> block"),
    (re.compile(r"\sstyle\s*=", re.I), "inline style attribute"),
    (re.compile(r"\son[a-z]+\s*=", re.I), "inline event handler"),
    (re.compile(r"""\b(?:href|src)\s*=\s*["']\s*javascript:""", re.I), "javascript: URL"),
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
    # Blocked by the CSP at runtime; set e.style.x (CSSOM) instead.
    (re.compile(r"""setAttribute\(\s*["']style|\bstyle\s*:\s*["'`]"""), "style attribute string"),
]


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


def scan(text: str, patterns) -> list[str]:
    errors = []
    for n, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith(("//", "<!--")):
            continue
        for rx, what in patterns:
            if rx.search(line):
                errors.append(f"{n}: {what}")
    return errors


def check(files: dict[str, str]) -> list[str]:
    errors = []
    for name, text in sorted(files.items()):
        if name.endswith(".html"):
            errors += [f"{name}: {e}" for e in check_csp(text)]
            errors += [f"{name}:{e}" for e in scan(text, HTML_BAD)]
        elif name.endswith(".js"):
            errors += [f"{name}:{e}" for e in scan(text, JS_BAD)]
    return errors


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
        "e.js": "x.innerHTML = rec.url;",
        "f.js": "setTimeout('x()', 1);",
        "g.js": "a.href = rec.url;",
        "h.js": "const f = eval(s);",
        "i.js": 'el("div", { style: `margin-left:${d}px` });',
    }
    errors = []
    for name, text in controls_bad.items():
        if not check({name: text}):
            errors.append(f"selftest: missed the bad control {name}")
    good = {
        "ok.html": good_csp + '<script type="module" src="app.js"></script>',
        "ok.js": "e.textContent = rec.url; if (a.href === b) retrieval(); x.evaluate(); "
        "el('div', { style: { marginLeft: '4px' } });",
    }
    for e in check(good):
        errors.append(f"selftest: false positive {e}")
    return errors


def main(argv: list[str]) -> int:
    errors = selftest()
    if "--selftest" not in argv:
        files = {
            p.relative_to(ROOT).as_posix(): p.read_text(encoding="utf-8")
            for p in SITE.rglob("*")
            if p.suffix in (".html", ".js") and "pkg" not in p.relative_to(SITE).parts
        }
        if not any(n.endswith("index.html") for n in files):
            errors.append("site/index.html not found")
        errors += check(files)
    for e in errors:
        print(f"check-site: {e}", file=sys.stderr)
    if not errors:
        print("check-site: OK")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
