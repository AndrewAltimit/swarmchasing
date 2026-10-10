#!/usr/bin/env node
// Build the site with a hostile notice added, load every generated page in
// headless Chrome, and fail if anything a notice, a record, a claim or an
// edited rule carries executes or becomes markup, or if a page raises a CSP
// violation or an error.
//
// It covers: every page in the sitemap (and 404.html); the hostile notice's
// page and the index row; the workbench with XSS probes, HTML programs, a
// probe chain and an unusual path set in the records, every view, cluster,
// record and report audience, and hostile claims; the rules editor and the
// evaluation with hostile edited rules; the unwrap tool; security.txt and
// defang on the tools page.
//
// Usage (after scripts/ci/build-site.sh, which builds site/pkg):
//     node scripts/site-xss-check.mjs [path/to/chrome]
// Chrome is found from the argument, $CHROME, or the usual install paths.
// Exit 0 is a pass, 1 a failure, 2 means it could not run (no Chrome, no
// site/pkg, or no cargo to build the fixture site). The probes only call
// console.log and set window.__xss; nothing is fetched from outside the
// local server.

import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { extname, join, normalize, resolve } from "node:path";

const ROOT = resolve(import.meta.dirname, "..");
const PORT = 8790;
const DEBUG_PORT = 9334;
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
const fixture =
  readFileSync(join(ROOT, "samples/eval/published-patterns.ndjson"), "utf8").trimEnd() + "\n" +
  [...probes, ...chain, ...pathset].map((p) => JSON.stringify(p)).join("\n") + "\n";
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
  await audit("notice index");

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
    let detail = 0, hostile = false, marks = 0;
    for (const b of document.querySelectorAll(".cluster-row")) {
      b.click();
      await wait();
      const c = document.getElementById("context");
      detail = Math.max(detail, c.querySelectorAll("dt").length);
      hostile ||= c.textContent.includes("onerror");
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
    const box = document.getElementById("claims");
    const type = async (v) => { box.value = v; box.dispatchEvent(new Event("input")); await wait(); };
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
      await wait();
      named ||= document.getElementById("report").textContent.includes("<script>");
    }
    return { detail, hostile, marks, claimsError, named, links: document.querySelectorAll("#links li").length, records: document.querySelectorAll("table.records tbody tr").length };
  })()`);
  Object.assign(stats, { records: views.records, detailRows: views.detail, chartMarks: views.marks, linkItems: views.links });
  if (!views.detail) failures.push("the context panel rendered nothing for a cluster");
  if (!views.hostile) failures.push("no hostile text reached the context panel: the probes did not exercise it");
  if (!views.marks) failures.push("the views drew nothing");
  if (!views.links) failures.push("the links panel listed nothing (the probe chain should be there)");
  if (!views.claimsError) failures.push("the invalid claims raised no error");
  if (!views.named) failures.push("the hostile claims did not reach the report as text");
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
    await new Promise((r) => setTimeout(r, 50));
    return { sectxt: document.getElementById("sectxt-out").textContent.includes("<script>"), defang: document.getElementById("defang-out").textContent.includes("hxxps://evil[.]example") };
  })()`);
  if (!tools.sectxt) failures.push("the hostile security.txt did not render as text");
  if (!tools.defang) failures.push("defang did not defang");
  await audit("tools");

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
