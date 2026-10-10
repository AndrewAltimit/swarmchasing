#!/usr/bin/env node
// Load the built site in headless Chrome, analyse records that carry XSS
// probes and HTML programs, type hostile claims, test hostile rules against
// the labelled set, open a notice whose every field carries one, and fail if
// any of them executes or becomes markup, or if the page raises a CSP
// violation or an error.
//
// Usage (after scripts/ci/build-site.sh):
//     node scripts/site-xss-check.mjs [path/to/chrome]
// Chrome is found from the argument, $CHROME, or the usual install paths.
// The probes only call console.log and set window.__xss; nothing is fetched
// from outside the local server.

import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { extname, join, normalize, resolve } from "node:path";

const ROOT = resolve(import.meta.dirname, "..");
const SITE = join(ROOT, "site");
const PORT = 8790;
const DEBUG_PORT = 9334;
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
if (!existsSync(join(SITE, "pkg", "sc_wasm.js"))) {
  console.error("site-xss-check: site/pkg missing; run scripts/ci/build-site.sh first");
  process.exit(2);
}

// The probes. Each one would set window.__xss or log XSS-FIRED if it ran.
const fire = "console.log('XSS-FIRED');window.__xss=1";
const program = `<script>${fire}</script><img src=x onerror="${fire}">`;
const b64 = Buffer.from(program).toString("base64url");
const probes = [
  { id: "xss:b64", url: `https://r.jina.ai/https://httpbun.com/base64/${b64}?uqtag=xss` },
  { id: "xss:raw", url: `https://r.jina.ai/https://portal.example.gov/q?id=<img src=x onerror=${fire}>&uqtag=xss` },
  { id: "xss:js", url: `javascript:${fire}//https://a.example/` },
  { id: "xss:svg", url: `https://r.jina.ai/https://a.example/<svg/onload=${fire}>`, user_agent: `<script>${fire}</script>` },
  { id: "xss:attr", url: `https://r.jina.ai/https://a.example/"><iframe srcdoc="<script>${fire}</script>">` },
].map((p, i) => ({ ts: `2026-06-02T15:0${i}:00Z`, ...p }));
// Records that put hostile text into the cluster detail panel and the links
// card: a probe chain whose path and varied parameter names carry markup and
// link on a hostile tag, and one unusual path set requested across hosts.
const tag = `"><img src=x onerror=${fire}>`;
const chain = Array.from({ length: 4 }, (_, i) => ({
  id: `xss:chain${i}`,
  ts: `2026-06-02T16:0${i}:00Z`,
  url: `https://r.jina.ai/https://chain.example/q/<svg onload=${fire}>?<img src=x onerror=${fire}>=${i}&javascript:${fire}=${i * 7}&uqtag=${tag}`,
}));
const odd = [`/<img src=x onerror=${fire}>.php`, `/"><script>${fire}</script>`, `/javascript:${fire}`];
const pathset = ["h1.example", "h2.example", "h3.example"].flatMap((h, j) =>
  odd.map((p, k) => ({ id: `xss:path${j}${k}`, ts: `2026-06-02T17:${j}${k}:00Z`, url: `https://r.jina.ai/https://${h}${p}?uqtag=${tag}` })));
const fixture =
  readFileSync(join(ROOT, "samples/eval/published-patterns.ndjson"), "utf8").trimEnd() +
  "\n" +
  [...probes, ...chain, ...pathset].map((p) => JSON.stringify(p)).join("\n") +
  "\n";

// Claims typed into the claims box: one invalid (the error is shown), then one
// valid whose every string is hostile.
const badClaims = JSON.stringify([{ party: program, role: `<script>${fire}</script>`, evidence: `javascript:${fire}` }]);
const claims = JSON.stringify([
  { party: program, role: "developer", evidence: "provider_confirmed", details: [program, `javascript:${fire}`, tag] },
  { party: `javascript:${fire}`, role: "host", evidence: "provider_confirmed", details: [program] },
]);
// Edited rules whose version and rule id carry markup and which flag every
// labelled record, so the eval view lists them all with the hostile id.
const hostileRules = `[meta]
version = '''${program}'''
[[rule]]
id = '''agent_marker.${program}'''
kind = "agent_marker"
target = "url"
pattern = "."
weight = 9
significant = true
`;

// A hostile notice: the renderer must treat every field as text, whatever
// `swarmchase notice build` would have let through.
const span = (v) => [{ t: "text", v }, { t: "strong", v }, { t: "code", v }];
const nid = "n-xss";
const noticeMeta = {
  id: nid, title: program, status: "active", published: "2026-10-16", updated: "2026-10-17",
  providers: [program], affected: [`a.example"><img src=x onerror="${fire}">`], rules_version: program, toolkit: program,
  update: [
    { date: "2026-10-16", kind: "published", text: program },
    { date: "2026-10-17", kind: "reply", from: program, text: program },
    { date: "2026-10-17", kind: `"><img src=x onerror="${fire}">`, text: program },
  ],
};
const noticeFiles = {
  "/notices/index.json": [
    { id: nid, title: program, status: "active", published: "2026-10-16", updated: "2026-10-17", providers: [program], affected: [program], corrected: true, retracted: false },
    { id: `x" onmouseover="${fire}`, title: program, status: `"><script>${fire}</script>`, published: "", updated: "", providers: [], affected: [], corrected: false, retracted: true },
  ],
  [`/notices/${nid}.json`]: {
    meta: noticeMeta,
    blocks: [
      { t: "heading", level: `1><img src=x onerror=${fire}>`, c: span(program) },
      { t: "para", c: span(program) },
      { t: "quote", lines: [span(program)] },
      { t: "list", ordered: true, items: [{ c: span(program), sub: [span(program)] }] },
      { t: "table", head: [span(program)], rows: [[span(program)]] },
      { t: `"><script>${fire}</script>`, c: span(program) },
    ],
  },
};

const TYPES = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".wasm": "application/wasm", ".svg": "image/svg+xml" };
const server = createServer((req, res) => {
  const path = decodeURIComponent(new URL(req.url, "http://x").pathname);
  if (path === "/fixture.ndjson") return res.end(fixture);
  if (path in noticeFiles) {
    res.setHeader("content-type", "application/json");
    return res.end(JSON.stringify(noticeFiles[path]));
  }
  const file = normalize(join(SITE, path === "/" ? "index.html" : path));
  if (!file.startsWith(SITE) || !existsSync(file)) {
    res.statusCode = 404;
    return res.end();
  }
  res.setHeader("content-type", TYPES[extname(file)] ?? "application/octet-stream");
  res.end(readFileSync(file));
}).listen(PORT, "127.0.0.1");

const profile = mkdtempSync(join(tmpdir(), "sc-xss-"));
const proc = spawn(chrome, ["--headless=new", `--remote-debugging-port=${DEBUG_PORT}`, `--user-data-dir=${profile}`, "--no-first-run", "about:blank"], { stdio: "ignore" });

const failures = [];
const logs = [];
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

  await send("Runtime.enable");
  await send("Log.enable");
  await send("Page.enable");
  await send("Page.navigate", { url: `http://127.0.0.1:${PORT}/` });
  for (let i = 0; i < 50 && !(await run(`document.getElementById("ver").textContent`)); i++) await sleep(200);

  // The synthetic example loads and analyses.
  const example = await run(`(async () => {
    document.getElementById("example").click();
    await new Promise((r) => setTimeout(r, 500));
    return { rows: document.querySelectorAll("#records tbody tr").length, note: !document.getElementById("example-note").hidden };
  })()`);
  if (!example.rows || !example.note) failures.push(`example: ${example.rows} record rows, note shown: ${example.note}`);

  // Every view that shows record text: analysis tables, each cluster and its
  // detail panel, the links card, every report audience with hostile claims,
  // and the unwrap tool.
  await run(`(async () => {
    document.getElementById("input").value = await (await fetch("fixture.ndjson")).text();
    document.getElementById("input").dispatchEvent(new Event("input"));
    document.getElementById("run").click();
  })()`);
  await sleep(1000);
  const records = await run(`document.querySelectorAll("#records tr").length - 1`);
  const views = await run(`(async () => {
    const wait = () => new Promise((r) => setTimeout(r, 50));
    let detail = 0, hostile = false;
    for (const tr of document.querySelectorAll("#clusters tbody tr")) {
      tr.click();
      await wait();
      const d = document.getElementById("cluster-detail");
      detail = Math.max(detail, d.querySelectorAll("dt").length);
      hostile ||= d.textContent.includes("onerror");
    }
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
    for (const o of aud?.options ?? []) {
      aud.value = o.value;
      aud.dispatchEvent(new Event("change"));
      await wait();
      named ||= document.getElementById("report").textContent.includes("<script>");
    }
    return { detail, hostile, claimsError, named, chains: document.querySelectorAll("#links tbody tr").length };
  })()`);
  if (!views.detail) failures.push("the cluster detail panel rendered nothing");
  if (!views.hostile) failures.push("no hostile text reached the cluster detail panel: the probe records did not exercise it");
  if (!views.chains) failures.push("the links card listed no probe chain");
  if (!views.claimsError) failures.push("the invalid claims raised no error");
  if (!views.named) failures.push("the hostile claims did not reach the report as text");

  // The rules tab: hostile edited rules against the labelled set.
  const ev = await run(`(async () => {
    document.querySelector('[data-tab="rules"]').click();
    document.getElementById("rules").value = ${JSON.stringify(hostileRules)};
    document.getElementById("rules-eval").click();
    await new Promise((r) => setTimeout(r, 300));
    const out = document.getElementById("eval-out");
    const res = { rows: out.querySelectorAll("tbody tr").length, text: out.textContent.includes("<script>") };
    document.getElementById("rules-reset").click();
    document.querySelector('[data-tab="analyze"]').click();
    return res;
  })()`);
  if (!ev.rows) failures.push("the eval view rendered no rows");
  if (!ev.text) failures.push("the hostile rule id did not render as text in the eval view");
  for (const p of probes) {
    await run(`(() => { document.getElementById("unwrap-url").value = ${JSON.stringify(p.url)}; document.getElementById("unwrap-run").click(); })()`);
  }
  await sleep(500);

  // The notices tab: the list, then the hostile notice by click and by URL.
  const notice = await run(`(async () => {
    const wait = (ms) => new Promise((r) => setTimeout(r, ms));
    document.querySelector('[data-tab="notices"]').click();
    await wait(400);
    const rows = document.querySelectorAll("#notice-list tbody tr");
    for (const tr of rows) { tr.click(); await wait(200); }
    history.replaceState(null, "", "#notice=${nid}");
    document.querySelector('[data-tab="notices"]').click();
    await wait(400);
    return { rows: rows.length, title: document.querySelector("#notice-page h2")?.textContent ?? "" };
  })()`);
  if (notice.rows !== 2) failures.push(`notices list rendered ${notice.rows} row(s), expected 2`);
  if (!notice.title.includes("<script>")) failures.push("the hostile notice did not render as text");

  const r = await run(`(() => {
    const n = (sel) => document.querySelectorAll(sel).length;
    return {
      layers: n("#unwrap-out .layer"),
      xss: window.__xss ?? null,
      markup: n("img, iframe, object, embed, script:not([src]), svg [onload], #records svg"),
      handlers: [...document.querySelectorAll("*")].filter((e) => [...e.attributes].some((a) => a.name.startsWith("on"))).length,
      links: [...document.querySelectorAll("a[href]")].map((a) => a.getAttribute("href")).filter((h) => !/^https:\\/\\/(swarmcha\\.se|transluce\\.org|github\\.com)\\//.test(h) && h !== "notices/feed.xml"),
    };
  })()`);
  if (records < 1) failures.push("no records rendered: the analysis did not run");
  if (!r.layers) failures.push("the unwrap tool rendered no layers");
  if (r.xss !== null) failures.push("a probe executed (window.__xss set)");
  if (r.markup) failures.push(`${r.markup} element(s) created from record text`);
  if (r.handlers) failures.push(`${r.handlers} element(s) with inline event handlers`);
  if (r.links.length) failures.push(`unexpected links: ${r.links.join(", ")}`);
  for (const l of logs) {
    if (/XSS-FIRED|Content Security Policy|exception|error/i.test(l)) failures.push(l);
  }
  console.log(`site-xss-check: ${probes.length} probes, ${records} record rows, ${r.layers} unwrap layers, ${notice.rows} hostile notices, ${views.detail} detail rows, ${views.chains} chains, ${ev.rows} eval rows`);
  ws.close();
} catch (e) {
  failures.push(String(e?.message ?? e));
} finally {
  proc.kill();
  server.close();
  await sleep(300);
  try { rmSync(profile, { recursive: true, force: true }); } catch {}
}

for (const f of failures) console.error(`site-xss-check: ${f}`);
console.log(failures.length ? "site-xss-check: FAILED" : "site-xss-check: OK");
process.exit(failures.length ? 1 : 0);
