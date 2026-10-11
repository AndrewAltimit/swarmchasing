#!/usr/bin/env node
// Build the site with a hostile notice added, load every generated page in
// headless Chrome, and fail if anything a notice, a record, a claim or an
// edited rule carries executes or becomes markup, or if a page raises a CSP
// violation or an error.
//
// It covers: every page in the sitemap (and 404.html); the hostile notice's
// page and the index row; the index filters and their URL hash, on the
// synthetic notices in crates/sc-publish/tests/fixtures/notices/, and the
// two stages on them (an indicator notice shows no affected host, a naming
// update shows its hosts defanged); the
// bundle viewer with a hostile stamp, manifest and case claims; the workbench with XSS probes, HTML programs, a
// probe chain, an unusual path set and a cluster with every per-cluster hint
// in the records, every view, cluster, record and report audience, and
// hostile claims, and that declared testing reaches no view and no draft but
// an internal one; the rules editor and the
// evaluation with hostile edited rules; the unwrap tool; security.txt and
// defang on the tools page. It also checks layout: no page scrolls sideways
// at 390 px, every nav menu opens inside the viewport at 390 and 1440 px as
// one column, and the theme toggle cycles system, light and dark.
//
// Usage (after scripts/ci/build-site.sh, which builds site/pkg):
//     node scripts/site-xss-check.mjs [path/to/chrome]
// Chrome is found from the argument, $CHROME, or the usual install paths.
// Exit 0 is a pass, 1 a failure, 2 means it could not run (no Chrome, no
// site/pkg, or no cargo to build the fixture site). The probes only call
// console.log and set window.__xss; nothing is fetched from outside the
// local server.

import { spawn, spawnSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { extname, join, normalize, resolve } from "node:path";

const ROOT = resolve(import.meta.dirname, "..");
// Override with XSS_PORT and XSS_DEBUG_PORT when another check holds these.
const PORT = Number(process.env.XSS_PORT) || 8790;
const DEBUG_PORT = Number(process.env.XSS_DEBUG_PORT) || 9334;
const BASE = `http://127.0.0.1:${PORT}/`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const chrome = [
  process.argv[2],
  process.env.CHROME,
  "/usr/bin/google-chrome",
  "/usr/bin/chromium",
  "/usr/bin/chromium-browser",
  "C:/Program Files/Google/Chrome/Application/chrome.exe",
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
].find((p) => p && existsSync(p));
if (!chrome) {
  console.error("site-xss-check: no Chrome found; pass its path or set $CHROME");
  process.exit(2);
}
if (!existsSync(join(ROOT, "site", "pkg", "sc_wasm.js")) || !existsSync(join(ROOT, "site", "pkg-rules", "sc_rules_wasm.js"))) {
  console.error("site-xss-check: site/pkg or site/pkg-rules missing; run scripts/ci/build-site.sh first");
  process.exit(2);
}

// The probes. Each one would set window.__xss or log XSS-FIRED if it ran.
const fire = "console.log('XSS-FIRED');window.__xss=1";
const program = `<script>${fire}</script><img src=x onerror="${fire}">`;
const b64 = Buffer.from(program).toString("base64url");
const tag = `"><img src=x onerror=${fire}>`;

// A hostile notice: every field the generator renders carries a probe. It
// must still pass the notice check (nothing withheld), as a real one would.
const lit = (s) => `'''${s}'''`;
const tmp = mkdtempSync(join(tmpdir(), "sc-xss-"));
const noticesDir = join(tmp, "notices");
const siteDir = join(tmp, "site");
mkdirSync(noticesDir);
const nid = "n-xss";
writeFileSync(join(noticesDir, `${nid}.md`), `+++
id = "${nid}"
title = ${lit(program)}
status = "active"
published = "2026-10-16"
updated = "2026-10-18"
providers = [${lit(program)}]
affected = [${lit(`a.example"><img src=x onerror="${fire}">`)}]
rules_version = ${lit(program)}
toolkit = ${lit(program)}

[[update]]
date = "2026-10-16"
kind = "published"
text = ${lit(program)}

[[update]]
date = "2026-10-17"
kind = "reply"
from = ${lit(program)}
text = ${lit(program)}

[[update]]
date = "2026-10-17"
kind = "naming"
text = ${lit(program)}

[[update]]
date = "2026-10-18"
kind = "correction"
text = ${lit(`javascript:${fire}`)}
+++

# ${program}

- **${program}** \`${program}\`
  - ${tag}

1. [x](javascript:${fire})

> ${program}

| ${program} | b |
|---|---|
| \`${program}\` | ${tag} |

${program}
`);

// The synthetic notices the index filters are tested on (never under notices/).
const FIXTURES = join(ROOT, "crates", "sc-publish", "tests", "fixtures", "notices");
for (const f of readdirSync(FIXTURES).filter((f) => f.endsWith(".md"))) copyFileSync(join(FIXTURES, f), join(noticesDir, f));

const build = spawnSync("cargo", ["run", "-q", "--profile", "release-test", "-p", "sc-publish", "--bin", "sc-site", "--",
  "--out", siteDir, "--base-url", BASE, "--extra-notices", noticesDir], { cwd: ROOT, stdio: ["ignore", "inherit", "inherit"] });
if (build.error) {
  console.error(`site-xss-check: could not run cargo: ${build.error.message}`);
  process.exit(2);
}
if (build.status !== 0) {
  console.error("site-xss-check: the fixture site did not build (the hostile notice must pass the notice check)");
  process.exit(1);
}

// Records for the workbench.
const probes = [
  { id: "xss:b64", url: `https://r.jina.ai/https://httpbun.com/base64/${b64}?uqtag=xss` },
  { id: "xss:raw", url: `https://r.jina.ai/https://portal.example.gov/q?id=<img src=x onerror=${fire}>&uqtag=xss` },
  { id: "xss:js", url: `javascript:${fire}//https://a.example/` },
  { id: "xss:svg", url: `https://r.jina.ai/https://a.example/<svg/onload=${fire}>`, user_agent: `<script>${fire}</script>` },
  { id: "xss:attr", url: `https://r.jina.ai/https://a.example/"><iframe srcdoc="<script>${fire}</script>">` },
].map((p, i) => ({ ts: `2026-06-02T15:0${i}:00Z`, ...p }));
const chain = Array.from({ length: 4 }, (_, i) => ({
  id: `xss:chain${i}`,
  ts: `2026-06-02T16:0${i}:00Z`,
  url: `https://r.jina.ai/https://chain.example/q/<svg onload=${fire}>?<img src=x onerror=${fire}>=${i}&javascript:${fire}=${i * 7}&uqtag=${tag}`,
}));
const odd = [`/<img src=x onerror=${fire}>.php`, `/"><script>${fire}</script>`, `/javascript:${fire}`];
const pathset = ["h1.example", "h2.example", "h3.example"].flatMap((h, j) =>
  odd.map((p, k) => ({ id: `xss:path${j}${k}`, ts: `2026-06-02T17:${j}${k}:00Z`, url: `https://r.jina.ai/https://${h}${p}?uqtag=${tag}` })));
// One cluster with every per-cluster hint: a benchmark target, stale
// knowledge, prose, a relay stack, and declared testing, whose contact must
// never reach the page outside an internal draft.
const DECLARED = "zz-declared-contact";
const inbox = "https://webhook.site/0b6c1f0e-1111-4c2a-9a55-3f2e1d0c9b8a";
const declaredUa = `AcmeScan/1.0 (authorized security test; ${DECLARED}@acme.example)`;
const hinted = [
  { url: `http://testphp.vulnweb.com/artists.php?artist=1'&cb=${inbox}&q=${encodeURIComponent(`bitte finde die neuesten Berichte und die Zahlen <img src=x onerror=${fire}>`)}`, user_agent: declaredUa },
  { url: `http://testphp.vulnweb.com/listproducts.php?cat=1&cb=${inbox}`, user_agent: declaredUa },
  { url: `https://graph.facebook.com/v2.8/me?hook=${inbox}&x=<svg/onload=${fire}>` },
  { url: `https://graph.facebook.com/v2.9/page?hook=${inbox}` },
  { url: `https://r.jina.ai/https://www-shop-example.translate.goog/<svg/onload=${fire}>?hook=${inbox}` },
  { url: `https://r.jina.ai/https://www-shop-example.translate.goog/b?hook=${inbox}` },
].map((p, i) => ({ id: `xss:hint${i}`, ts: `2026-06-02T18:0${i}:00Z`, ...p }));
const fixture =
  readFileSync(join(ROOT, "samples/eval/published-patterns.ndjson"), "utf8").trimEnd() + "\n" +
  [...probes, ...chain, ...pathset, ...hinted].map((p) => JSON.stringify(p)).join("\n") + "\n";
const badClaims = JSON.stringify([{ party: program, role: `<script>${fire}</script>`, evidence: `javascript:${fire}` }]);
const claims = JSON.stringify([
  { party: program, role: "developer", evidence: "provider_confirmed", details: [program, `javascript:${fire}`, tag] },
  { party: `javascript:${fire}`, role: "host", evidence: "provider_confirmed", details: [program] },
]);
// Edited rules whose version and rule id carry markup and which flag every
// labelled record, so the views list them all with the hostile id.
const hostileRules = `[meta]
version = '''${program}'''
[[rule]]
id = '''agent_marker.${program}'''
kind = "agent_marker"
target = "url"
pattern = "."
weight = 9
significant = true
tactic = "T2"
`;
// A hostile evidence bundle for the tools page: records from the probes, a
// stamp and manifest whose every field carries markup, and case claims at
// every attribution layer.
const bundleDir = join(tmp, "bundle");
mkdirSync(bundleDir);
const bundleRecords = [...probes, ...chain].map((p) => JSON.stringify({ ...p, ts: Math.floor(Date.parse(p.ts) / 1000), source: program })).join("\n") + "\n";
const bundleStamp = {
  case: program, generated: program, toolkit_version: program, toolkit_commit: program, rules_version: program, records: 1,
  flagged: { [program]: "significant" }, clusters: [{ tier: "significant", members: [program] }], method: program,
  eval: { rules_version: program, labelled: 3, suggestive_precision: 0.5, suggestive_recall: 0.5 },
};
const bundleClaims = ["developer", "host", "harness", "model_family"].map((role) => ({ party: program, role, evidence: "provider_confirmed", details: [program, `javascript:${fire}`] }));
for (const [name, text] of [
  ["records.ndjson", bundleRecords],
  ["analysis.json", JSON.stringify({ total: program })],
  ["stamp.json", JSON.stringify(bundleStamp)],
  ["claims.json", JSON.stringify(bundleClaims)],
  ["MANIFEST.sha256", `${"0".repeat(64)}  records.ndjson\n${program}  stamp.json\n`],
]) writeFileSync(join(bundleDir, name), text);
const bundleFiles = ["records.ndjson", "analysis.json", "stamp.json", "claims.json", "MANIFEST.sha256"].map((n) => join(bundleDir, n));

const sectxt = `Contact: mailto:${program}\nContact: javascript:${fire}\nPolicy: ${tag}\nExpires: ${program}\n`;

const TYPES = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".wasm": "application/wasm", ".svg": "image/svg+xml", ".json": "application/json", ".xml": "application/xml" };
const server = createServer((req, res) => {
  let path = decodeURIComponent(new URL(req.url, "http://x").pathname);
  if (path === "/fixture.ndjson") return res.end(fixture);
  if (path.endsWith("/")) path += "index.html";
  const file = normalize(join(siteDir, path));
  if (!file.startsWith(siteDir) || !existsSync(file)) {
    res.statusCode = 404;
    res.setHeader("content-type", "text/html");
    return res.end(readFileSync(join(siteDir, "404.html")));
  }
  res.setHeader("content-type", TYPES[extname(file)] ?? "application/octet-stream");
  res.end(readFileSync(file));
}).listen(PORT, "127.0.0.1");

const profile = mkdtempSync(join(tmpdir(), "sc-xss-prof-"));
const proc = spawn(chrome, ["--headless=new", `--remote-debugging-port=${DEBUG_PORT}`, `--user-data-dir=${profile}`, "--no-first-run", "about:blank"], { stdio: "ignore" });

const failures = [];
let logs = [];
const stats = {};
try {
  let targets;
  for (let i = 0; i < 75 && !targets; i++) {
    try {
      targets = await (await fetch(`http://127.0.0.1:${DEBUG_PORT}/json`)).json();
    } catch {
      await sleep(200);
    }
  }
  if (!targets) throw new Error("Chrome did not start");
  const ws = new WebSocket(targets.find((t) => t.type === "page").webSocketDebuggerUrl);
  await new Promise((r) => ws.addEventListener("open", r));
  let seq = 0;
  const pending = new Map();
  ws.addEventListener("message", (ev) => {
    const m = JSON.parse(ev.data);
    if (m.id && pending.has(m.id)) {
      pending.get(m.id)(m);
      pending.delete(m.id);
    }
    if (m.method === "Runtime.consoleAPICalled") logs.push("console: " + m.params.args.map((a) => a.value ?? a.description).join(" "));
    if (m.method === "Runtime.exceptionThrown") logs.push("exception: " + (m.params.exceptionDetails.exception?.description ?? m.params.exceptionDetails.text));
    if (m.method === "Log.entryAdded") logs.push(`${m.params.entry.source}/${m.params.entry.level}: ${m.params.entry.text}`);
  });
  const send = (method, params = {}) =>
    new Promise((r) => {
      const id = ++seq;
      pending.set(id, r);
      ws.send(JSON.stringify({ id, method, params }));
    });
  const run = async (expression) => {
    const m = await send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true });
    if (m.result?.exceptionDetails) throw new Error(m.result.exceptionDetails.exception?.description ?? "evaluate failed");
    return m.result?.result?.value;
  };
  const open = async (path, ready = "document.readyState === 'complete'") => {
    await send("Page.navigate", { url: BASE + path });
    for (let i = 0; i < 60 && !(await run(`(() => { try { return !!(${ready}); } catch { return false; } })()`)); i++) await sleep(150);
    await sleep(250);
  };
  // What every page must never contain or do.
  const audit = async (where) => {
    const r = await run(`(() => {
      const n = (sel) => document.querySelectorAll(sel).length;
      return {
        xss: window.__xss ?? null,
        markup: n("main img, main iframe, main object, main embed, script:not([src]), [srcdoc], main svg [onload]"),
        handlers: [...document.querySelectorAll("*")].filter((e) => [...e.attributes].some((a) => a.name.startsWith("on"))).length,
        links: [...document.querySelectorAll("a[href]")].map((a) => a.getAttribute("href")).filter((h) => /^[a-z][a-z0-9+.-]*:/i.test(h) && !/^https:\\/\\//i.test(h) && !h.startsWith("blob:")),
      };
    })()`);
    if (r.xss !== null) failures.push(`${where}: a probe executed (window.__xss set)`);
    if (r.markup) failures.push(`${where}: ${r.markup} element(s) created from content`);
    if (r.handlers) failures.push(`${where}: ${r.handlers} element(s) with inline event handlers`);
    if (r.links.length) failures.push(`${where}: links with other schemes: ${r.links.slice(0, 3).join(", ")}`);
    for (const l of logs) {
      // The missing page's own 404 is the point of loading it.
      if (where === "no/such/page/" && /status of 404/.test(l)) continue;
      if (/XSS-FIRED|Content Security Policy|exception|error/i.test(l)) failures.push(`${where}: ${l}`);
    }
    logs = [];
  };

  await send("Runtime.enable");
  await send("Log.enable");
  await send("Page.enable");

  // Every page in the sitemap, and the 404 page.
  const sitemap = readFileSync(join(siteDir, "sitemap.xml"), "utf8");
  const pages = [...sitemap.matchAll(/<loc>([^<]+)<\/loc>/g)].map((m) => m[1].replace(BASE, ""));
  for (const p of [...pages, "404.html", "no/such/page/"]) {
    await open(p);
    await audit(p || "/");
  }
  stats.pages = pages.length + 2;

  // Layout: at 390 px no page scrolls sideways and every nav menu opens
  // inside the viewport; at 1440 px a menu is one column of full-width
  // items. Then the theme toggle cycles system, light, dark, system.
  const menuBoxes = `(async () => {
    const frame = () => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)));
    const out = [];
    for (const d of document.querySelectorAll("[data-nav-menu]")) {
      d.open = true;
      await frame();
      const r = d.querySelector(".nav-menu").getBoundingClientRect();
      const items = [...d.querySelectorAll(".nav-menu > li")].map((li) => li.getBoundingClientRect());
      out.push({ name: d.querySelector("summary").textContent, left: r.left, right: r.right, top: r.top, narrowest: Math.min(...items.map((i) => i.width)), columns: new Set(items.map((i) => Math.round(i.left))).size });
      d.open = false;
    }
    return { vw: document.documentElement.clientWidth, vh: innerHeight, out };
  })()`;
  const viewport = (width, height) => send("Emulation.setDeviceMetricsOverride", { width, height, deviceScaleFactor: 1, mobile: false });
  await viewport(390, 844);
  let wide = 0;
  for (const p of [...pages, "404.html", "analyze/#try=example"]) {
    await open(p, p.startsWith("analyze") ? `document.querySelectorAll("table.records tbody tr").length > 1` : undefined);
    const over = await run(`document.documentElement.scrollWidth - document.documentElement.clientWidth`);
    if (over > 0) failures.push(`${p || "/"}: scrolls sideways by ${over}px at 390 px`);
    wide++;
  }
  stats.narrowPages = wide;
  for (const [w, h] of [[390, 844], [1440, 900]]) {
    await viewport(w, h);
    for (const p of ["", "docs/"]) {
      await open(p);
      const m = await run(menuBoxes);
      if (!m.out.length) failures.push(`${p || "/"}: no nav menus found at ${w} px`);
      for (const b of m.out) {
        const at = `${p || "/"} at ${w} px: the ${b.name} menu`;
        if (b.left < 0 || b.right > m.vw + 0.5) failures.push(`${at} spills sideways (${Math.round(b.left)} to ${Math.round(b.right)} of ${m.vw})`);
        if (b.top < 0 || b.top > m.vh - 120) failures.push(`${at} opens off screen (top ${Math.round(b.top)} of ${m.vh})`);
        if (b.columns !== 1 || b.narrowest < 200) failures.push(`${at} is not one column of full-width items (${b.columns} columns, narrowest ${Math.round(b.narrowest)}px)`);
      }
    }
  }
  await send("Emulation.clearDeviceMetricsOverride");
  await open("");
  const themes = await run(`(() => {
    const b = document.querySelector("[data-theme-toggle]");
    const seen = [];
    for (let i = 0; i < 4; i++) {
      seen.push((document.documentElement.dataset.theme ?? "system") + "/" + (localStorage.getItem("swarmchase.theme") ?? "-") + "/" + b.dataset.mode);
      b.click();
    }
    return seen.join(" ");
  })()`);
  if (themes !== "system/-/system light/light/light dark/dark/dark system/-/system")
    failures.push(`the theme toggle did not cycle system, light, dark: ${themes}`);
  await audit("layout and theme");

  // The hostile notice: its page, and its row on the index.
  await open(`notices/${nid}/`);
  const notice = await run(`({ title: document.querySelector("main h1")?.textContent ?? "", statement: document.querySelector(".statement blockquote")?.textContent ?? "", flagged: document.querySelectorAll(".timeline li.flagged").length })`);
  if (!notice.title.includes("<script>")) failures.push("the hostile notice title did not render as text");
  if (!notice.statement.includes("<img")) failures.push("the hostile statement did not render as text");
  if (!notice.flagged) failures.push("the correction was not flagged on the timeline");
  await audit("hostile notice");
  await open("notices/");
  const rows = await run(`(() => { const f = document.querySelector("[data-notice-filters] [name=q]"); f.value = "xss"; f.dispatchEvent(new Event("input", { bubbles: true })); return [...document.querySelectorAll(".notice-table tbody tr")].filter((r) => !r.hidden).length; })()`);
  if (rows !== 1) failures.push(`the notice filter showed ${rows} row(s) for the hostile notice, expected 1`);
  if (!(await run(`location.hash === "#q=xss"`))) failures.push("the notice filter did not write the URL hash");
  // Filters from the hash, on the synthetic notices.
  const shown = `[...document.querySelectorAll(".notice-table tbody tr")].filter((r) => !r.hidden).map((r) => r.querySelector(".hint").textContent)`;
  for (const [hash, want] of [
    ["sector=health", ["synthetic-clinic-scan"]],
    ["provider=Example+AI+Labs", ["synthetic-portal-probe"]],
    ["status=historical", ["synthetic-course-relay"]],
    ["host=clinic%5B.%5Dexample", ["synthetic-clinic-scan"]],
    ["from=2026-08-01&to=2026-08-31", ["synthetic-clinic-scan"]],
    ["sector=%3Cscript%3E&from=nope", null],
  ]) {
    await open(`notices/#${hash}`);
    const got = await run(shown);
    const all = await run(`document.querySelectorAll(".notice-table tbody tr").length`);
    const ok = want ? JSON.stringify(got) === JSON.stringify(want) : got.length === all;
    if (!ok) failures.push(`notices/#${hash}: showed ${JSON.stringify(got)}`);
  }
  await audit("notice index");

  // Two stages: an indicator notice shows no affected host anywhere and says
  // so; a naming update shows its hosts, defanged.
  await open("notices/synthetic-indicator-only/");
  const stage1 = await run(`({ stage: document.querySelector(".notice-stage")?.textContent ?? "", hosts: (document.querySelector("main")?.textContent ?? "").match(/[a-z0-9-]+\\[\\.\\][a-z]/gi) ?? [], chips: document.querySelectorAll("main .chip").length })`);
  if (!/not named yet/.test(stage1.stage)) failures.push(`stage 1: stage line "${stage1.stage}"`);
  if (stage1.hosts.length || stage1.chips) failures.push(`stage 1: a host on the indicator notice: ${JSON.stringify(stage1.hosts)}`);
  await open("notices/synthetic-named-later/");
  const stage2 = await run(`({ stage: document.querySelector(".notice-stage")?.textContent ?? "", chips: [...document.querySelectorAll("main .chip")].map((c) => c.textContent) })`);
  if (!/named on 2026-09-25/.test(stage2.stage)) failures.push(`stage 2: stage line "${stage2.stage}"`);
  if (!stage2.chips.includes("lab[.]university[.]example")) failures.push(`stage 2: hosts ${JSON.stringify(stage2.chips)}`);
  await open("notices/");
  const row1 = await run(`(() => { const r = [...document.querySelectorAll(".notice-table tbody tr")].find((r) => r.querySelector(".hint")?.textContent === "synthetic-indicator-only"); return r ? { hosts: r.dataset.hosts, affected: r.querySelector("[data-label=Affected]")?.textContent ?? "" } : null; })()`);
  if (!row1 || row1.hosts.trim() || row1.affected !== "not named yet") failures.push(`stage 1 index row: ${JSON.stringify(row1)}`);
  await audit("notice stages");

  // The workbench: the synthetic example, then the probes through every view.
  await open("analyze/#try=example", `document.querySelectorAll("table.records tbody tr").length > 1`);
  const example = await run(`({ rows: document.querySelectorAll("table.records tbody tr").length, note: !document.getElementById("example-note").hidden })`);
  if (!example.rows || !example.note) failures.push(`example: ${example.rows} record rows, note shown: ${example.note}`);
  await run(`(async () => {
    document.getElementById("input").value = await (await fetch("../fixture.ndjson")).text();
    document.getElementById("input").dispatchEvent(new Event("input"));
    document.getElementById("format").value = "ndjson";
    document.getElementById("run").click();
  })()`);
  await sleep(800);
  const views = await run(`(async () => {
    const wait = (ms = 60) => new Promise((r) => setTimeout(r, ms));
    let detail = 0, hostile = false, marks = 0, declared = false;
    const hints = new Set();
    for (const b of document.querySelectorAll(".cluster-row")) {
      b.click();
      await wait();
      const c = document.getElementById("context");
      detail = Math.max(detail, c.querySelectorAll("dt").length);
      hostile ||= c.textContent.includes("onerror");
      declared ||= c.textContent.includes(${JSON.stringify(DECLARED)});
      for (const dt of c.querySelectorAll("dt")) hints.add(dt.textContent);
      for (const t of document.querySelectorAll(".viz-tabs [role=tab]")) {
        t.click();
        await wait(20);
        marks += document.querySelectorAll("#viz-panel svg *").length;
      }
    }
    for (const tr of [...document.querySelectorAll("table.records tbody tr.pick")].slice(0, 40)) {
      tr.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
      await wait(10);
      hostile ||= document.getElementById("context").textContent.includes("<svg");
    }
    for (const b of document.querySelectorAll("#viz-panel .chart-tools button")) b.click();
    // Drafting loads the tools module and re-runs the analysis there.
    document.getElementById("draft-report").click();
    const drafted = () => /^# /.test(document.getElementById("report").textContent);
    for (let i = 0; i < 100 && !drafted(); i++) await wait(100);
    // Attribution layers (tools module) for the selected cluster.
    const firstRow = document.querySelector(".cluster-row");
    if (firstRow && firstRow.getAttribute("aria-pressed") !== "true") firstRow.click();
    await wait();
    const attr = [...document.querySelectorAll("#context button")].find((b) => b.textContent.includes("attribution"));
    attr?.click();
    for (let i = 0; i < 50 && !document.querySelector("#context table.layers"); i++) await wait(100);
    const layersShown = !!document.querySelector("#context table.layers");
    const box = document.getElementById("claims");
    const type = async (v) => { box.value = v; box.dispatchEvent(new Event("input")); await wait(400); };
    await type(${JSON.stringify(badClaims)});
    const claimsError = document.getElementById("claims-status").textContent;
    await type(${JSON.stringify(claims)});
    const rep = document.getElementById("reporter");
    rep.value = ${JSON.stringify(program)};
    rep.dispatchEvent(new Event("input"));
    const aud = document.getElementById("audience");
    let named = false;
    for (const o of aud.options) {
      aud.value = o.value;
      aud.dispatchEvent(new Event("change"));
      await wait(400);
      named ||= document.getElementById("report").textContent.includes("<script>");
      if (o.value !== "internal") declared ||= document.getElementById("report").textContent.includes(${JSON.stringify(DECLARED)});
    }
    declared ||= document.getElementById("links").textContent.includes(${JSON.stringify(DECLARED)});
    return { detail, hostile, marks, claimsError, named, declared, layersShown, drafted: drafted(), hints: [...hints], links: document.querySelectorAll("#links li").length, records: document.querySelectorAll("table.records tbody tr").length };
  })()`);
  Object.assign(stats, { records: views.records, detailRows: views.detail, chartMarks: views.marks, linkItems: views.links });
  if (!views.detail) failures.push("the context panel rendered nothing for a cluster");
  if (!views.hostile) failures.push("no hostile text reached the context panel: the probes did not exercise it");
  if (!views.marks) failures.push("the views drew nothing");
  if (!views.links) failures.push("the links panel listed nothing (the probe chain should be there)");
  if (!views.claimsError) failures.push("the invalid claims raised no error");
  if (!views.drafted) failures.push("the report draft did not load (tools module)");
  if (!views.layersShown) failures.push("the attribution layers did not load (tools module)");
  if (!views.named) failures.push("the hostile claims did not reach the report as text");
  if (views.declared) failures.push("declared testing reached the page outside an internal draft");
  for (const h of ["Relay stacks", "Benchmark targets", "Stale knowledge", "Prose in parameters"])
    if (!views.hints.includes(h)) failures.push(`no cluster showed "${h}": the hint fixture did not exercise it`);
  await audit("workbench");

  // Unwrap: every probe URL.
  await open("unwrap/", `!document.getElementById("unwrap-run").disabled`);
  stats.layers = await run(`(async () => {
    let n = 0;
    for (const u of ${JSON.stringify(probes.map((p) => p.url))}) {
      document.getElementById("unwrap-url").value = u;
      document.getElementById("unwrap-run").click();
      await new Promise((r) => setTimeout(r, 50));
      n += document.querySelectorAll("#unwrap-out .layer").length;
    }
    return n;
  })()`);
  if (!stats.layers) failures.push("the unwrap tool rendered no layers");
  await audit("unwrap");

  // Tools: security.txt and defang with hostile text.
  await open("tools/", `!document.getElementById("sectxt-run").disabled`);
  const tools = await run(`(async () => {
    document.getElementById("sectxt").value = ${JSON.stringify(sectxt)};
    document.getElementById("sectxt-run").click();
    const d = document.getElementById("defang-in");
    d.value = ${JSON.stringify(program + " https://evil.example/" + tag)};
    d.dispatchEvent(new Event("input"));
    // Each card loads its module on first use: wait for both outputs.
    const filled = (id) => document.getElementById(id).childNodes.length > 0;
    for (let i = 0; i < 300 && !(filled("sectxt-out") && filled("defang-out")); i++)
      await new Promise((r) => setTimeout(r, 50));
    return { sectxt: document.getElementById("sectxt-out").textContent.includes("<script>"), defang: document.getElementById("defang-out").textContent.includes("hxxps://evil[.]example") };
  })()`);
  if (!tools.sectxt) failures.push("the hostile security.txt did not render as text");
  if (!tools.defang) failures.push("defang did not defang");
  await audit("tools");

  // The bundle viewer: a hostile bundle (stamp, manifest and case claims
  // carry probes), picked through the file input as a visitor would.
  await send("DOM.enable");
  const doc = await send("DOM.getDocument");
  const input = await send("DOM.querySelector", { nodeId: doc.result.root.nodeId, selector: "#case-files" });
  await send("DOM.setFileInputFiles", { nodeId: input.result.nodeId, files: bundleFiles });
  for (let i = 0; i < 40 && !(await run(`document.querySelectorAll("#case-out table.layers tbody tr").length`)); i++) await sleep(150);
  const bundle = await run(`(() => {
    const out = document.getElementById("case-out");
    return { layers: out.querySelectorAll("table.layers tbody tr").length, text: out.textContent.includes("<script>"), verdict: out.querySelector(".verdict")?.textContent ?? "", method: out.textContent.includes("onerror") };
  })()`);
  stats.bundleLayers = bundle.layers;
  if (bundle.layers < 4) failures.push(`the bundle viewer showed ${bundle.layers} attribution row(s), expected one per layer at least`);
  if (!bundle.text) failures.push("the hostile bundle did not render as text");
  if (!/Does not verify/.test(bundle.verdict)) failures.push(`the tampered bundle verified: ${bundle.verdict}`);
  await audit("bundle viewer");

  // Hostile edited rules: the rules editor's evaluation, then every page that runs them.
  await open("rules/");
  const ev = await run(`(async () => {
    const wait = (ms) => new Promise((r) => setTimeout(r, ms));
    const ed = document.querySelector("[data-rules-editor]");
    ed.open = true;
    ed.dispatchEvent(new Event("toggle"));
    for (let i = 0; i < 60 && document.querySelector('[data-act="eval"]').disabled; i++) await wait(100);
    document.getElementById("rules-text").value = ${JSON.stringify(hostileRules)};
    document.querySelector('[data-act="save"]').click();
    await wait(800);
    document.querySelector('[data-act="eval"]').click();
    for (let i = 0; i < 50 && !document.querySelectorAll("#eval-out tbody tr").length; i++) await wait(100);
    const out = document.getElementById("eval-out");
    return { rows: out.querySelectorAll("tbody tr").length, text: out.textContent.includes("<script>"), status: document.getElementById("rules-status").textContent };
  })()`);
  if (!ev.rows) failures.push(`the eval view rendered no rows (${ev.status})`);
  if (!ev.text) failures.push("the hostile rule id did not render as text in the eval view");
  await audit("rules editor");
  for (const p of ["analyze/#try=example", "unwrap/", "eval/"]) {
    await open(p);
    await sleep(800);
    if (p.startsWith("eval")) {
      await run(`document.querySelector('[data-act="recompute"]').click()`);
      await sleep(1500);
    }
    await audit(`${p} with hostile edited rules`);
  }
  await open("analyze/#try=example", `!document.getElementById("rules-note").hidden`);
  const ruleNote = await run(`document.getElementById("rules-note").textContent`);
  if (!ruleNote.includes("<script>")) failures.push("the edited rules' version did not show as text in the workbench");
  await run(`localStorage.clear()`);
  await audit("workbench with hostile edited rules");

  console.log(`site-xss-check: ${JSON.stringify(stats)}`);
  ws.close();
} catch (e) {
  failures.push(String(e?.message ?? e));
} finally {
  proc.kill();
  server.close();
  await sleep(300);
  for (const d of [profile, tmp]) {
    try {
      rmSync(d, { recursive: true, force: true });
    } catch {}
  }
}

for (const f of failures) console.error(`site-xss-check: ${f}`);
console.log(failures.length ? "site-xss-check: FAILED" : "site-xss-check: OK");
process.exit(failures.length ? 1 : 0);
