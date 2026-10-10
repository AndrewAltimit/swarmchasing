// The analysis workbench. Records are analysed by the engine in this page;
// nothing is uploaded. Record contents are untrusted: they reach the page as
// text only, URLs and hosts defanged, and never become links. The URL hash
// holds the selection as ids only (a cluster key, a record number, a rule
// id, a view), never hosts, URLs or other record data.
import { $, el, activate, download, fetchRoot, showError } from "../lib/dom.js";
import { arr, obj, num, fmtTs, fmtShort, dur, trunc, signed, topEntries, plural } from "../lib/fmt.js";
import { engine, editedRules, host as hostOf, rulesNote } from "../lib/wasm.js";
import { figure, legend, legendKey, tierLegend, rampLegend, swimlanes, fleetGraph, heatmap, rhythmGrid, strip, hourly } from "../lib/charts.js";

const VIEWS = ["runs", "fleet", "heat", "rhythm", "strip", "hourly"];
const STEPS = ["input", "explore", "context", "report"];
const MAX_LANES = 40;
const MAX_ROWS = 300;
const mobile = () => matchMedia("(max-width: 899px)").matches;

const sc = await engine();
rulesNote(sc, $("rules-note"));
{
  const ev = JSON.parse(sc.evidence_levels());
  $("min-named").replaceChildren(...ev.levels.map((l) => el("option", { value: l.id }, l.label)));
  $("min-named").value = ev.default;
}

let a = null; // the analysis
let dateTags = {};
let endpointsCache = null;
let sel = { c: null, r: null, rule: null };
let view = "runs";

const host = (h) => hostOf(sc, h);
const safe = (s, n = 120) => trunc(sc.defang(String(s ?? "")), n);
const pill = (tier) => el("span", { class: `pill ${String(tier).replace(/[^a-z]/g, "")}` }, String(tier));
const chips = (list) => list.map((x) => el("span", { class: "chip" }, x));
const keyOf = (c) => c.key || c.id;
const clusterBy = (k) => (a ? a.clusters.find((c) => keyOf(c) === k || c.id === k) ?? null : null);
const idOf = (k) => clusterBy(k)?.id ?? String(k);

// ── Hash state ─────────────────────────────────────────────────────────────
const VALID = { c: /^(k-[0-9a-f]{6,16}|C\d{1,5})$/, r: /^\d{1,7}$/, rule: /^[\w.\-:]{1,80}$/ };
function readHash() {
  const p = new URLSearchParams(location.hash.slice(1));
  const get = (k) => (p.has(k) && VALID[k].test(p.get(k)) ? p.get(k) : null);
  return { c: get("c"), r: get("r"), rule: get("rule"), v: VIEWS.includes(p.get("v")) ? p.get("v") : null, example: p.get("try") === "example", preset: p.get("preset") };
}
function writeHash() {
  const p = new URLSearchParams();
  if (sel.c) p.set("c", sel.c);
  if (sel.r != null) p.set("r", String(sel.r));
  if (sel.rule) p.set("rule", sel.rule);
  if (view !== "runs") p.set("v", view);
  const s = p.toString();
  history.replaceState(null, "", s ? `#${s}` : location.pathname + location.search);
}

// ── Steps (phones) ─────────────────────────────────────────────────────────
function goStep(step) {
  for (const b of document.querySelectorAll(".steps button")) {
    if (b.dataset.step === step) b.setAttribute("aria-current", "step");
    else b.removeAttribute("aria-current");
  }
  for (const p of document.querySelectorAll("[data-pane]")) p.classList.toggle("on", p.dataset.pane === step);
  if (mobile()) document.querySelector(".steps")?.scrollIntoView({ block: "start" });
}
for (const b of document.querySelectorAll(".steps button")) b.addEventListener("click", () => goStep(b.dataset.step));
goStep("input");

// ── Views (tabs) ───────────────────────────────────────────────────────────
const tabs = [...document.querySelectorAll(".viz-tabs [role=tab]")];
function setView(v, focus = false) {
  view = v;
  for (const t of tabs) {
    const on = t.dataset.view === v;
    t.setAttribute("aria-selected", String(on));
    t.tabIndex = on ? 0 : -1;
    if (on) {
      $("viz-panel").setAttribute("aria-labelledby", t.id);
      if (focus) t.focus();
    }
  }
  renderView();
  writeHash();
}
tabs.forEach((t, i) => {
  t.addEventListener("click", () => setView(t.dataset.view));
  t.addEventListener("keydown", (e) => {
    const d = e.key === "ArrowRight" ? 1 : e.key === "ArrowLeft" ? -1 : 0;
    if (e.key === "Home" || e.key === "End") {
      e.preventDefault();
      setView(tabs[e.key === "Home" ? 0 : tabs.length - 1].dataset.view, true);
    } else if (d) {
      e.preventDefault();
      setView(tabs[(i + d + tabs.length) % tabs.length].dataset.view, true);
    }
  });
});

// ── Analysis ───────────────────────────────────────────────────────────────
function runAnalysis() {
  const warn = $("warnings");
  warn.hidden = true;
  let out;
  try {
    out = JSON.parse(sc.analyze($("input").value, $("format").value, $("map").value, editedRules()));
  } catch (e) {
    warn.hidden = false;
    warn.textContent = String(e?.message ?? e);
    return false;
  }
  const notes = [];
  if (out.redacted) notes.push(`${out.redacted} secret value(s) such as cookies or tokens were replaced with hashes.`);
  if (arr(out.warnings).length) notes.push(`${out.warnings.length} warning(s): ${out.warnings.slice(0, 3).join("; ")}`);
  if (notes.length) {
    warn.hidden = false;
    warn.textContent = notes.join(" ");
  }
  a = out.analysis;
  dateTags = obj(out.cluster_date_tags);
  endpointsCache = null;
  const h = readHash();
  sel = { c: h.c && clusterBy(h.c) ? keyOf(clusterBy(h.c)) : null, r: h.r != null && a.results[+h.r] ? +h.r : null, rule: h.rule };
  for (const b of ["copy-report", "dl-report", "dl-json"]) $(b).disabled = false;
  renderAll();
  if (mobile()) goStep("explore");
  return true;
}

function renderAll() {
  renderSummary();
  renderClusterList();
  renderView();
  renderFilterBar();
  renderRecords();
  renderEndpoints();
  renderContext();
  renderLinks();
  renderReport();
  writeHash();
}

/** Change the selection; `step` moves phones to that step. */
function select(next, step = "context") {
  sel = { ...sel, ...next };
  renderClusterList();
  renderView();
  renderFilterBar();
  renderRecords();
  renderContext();
  renderReport();
  writeHash();
  if (mobile() && step) goStep(step);
}

function renderSummary() {
  const t = (k) => obj(a.tier_counts)[k] ?? 0;
  const tiles = [
    [a.total, "records"], [a.flagged, "flagged"], [t("significant"), "significant"],
    [t("suggestive"), "suggestive"], [a.clusters.length, "clusters"], [a.max_concurrent_clusters, "max concurrent runs"],
  ];
  const notes = [];
  const tm = obj(a.timing);
  if (tm.count) notes.push(`${fmtTs(tm.start)} → ${fmtTs(tm.end)}`);
  if (num(tm.median_gap_secs) != null) notes.push(`median gap ${dur(Math.round(tm.median_gap_secs))}`);
  if (arr(tm.pauses).length) notes.push(plural(tm.pauses.length, "pause"));
  const d = obj(a.date_tags);
  if (d.consistent && d.ahead > 0) notes.push(`date tags ahead of UTC in ${d.ahead}/${d.tagged}: operator clock UTC${signed(d.min_hours)}…UTC${signed(d.max_hours)}`);
  if (arr(a.asns).length) notes.push(a.asns.slice(0, 3).map((s) => `AS${s.asn}${s.org ? ` ${s.org}` : ""} (${s.count})`).join(", "));
  const box = $("summary");
  box.hidden = false;
  box.replaceChildren(
    el("div", { class: "tiles" }, tiles.map(([v, k]) => el("div", { class: "tile" }, el("div", { class: "v" }, Number(v ?? 0).toLocaleString()), el("div", { class: "k" }, k)))),
    el("p", { class: "hint" }, notes.join(" · ")),
  );
}

function renderClusterList() {
  const box = $("cluster-list");
  if (!a.clusters.length) return box.replaceChildren(el("p", { class: "hint" }, "No clusters. Records need shared identifiers or close timing to link."));
  box.replaceChildren(...a.clusters.slice(0, 200).map((c) => {
    const k = keyOf(c);
    const b = el("button", { type: "button", class: "cluster-row", "aria-pressed": String(sel.c === k) },
      el("span", { class: "cid" }, c.id), pill(c.tier), el("span", { class: "crecs" }, `${c.members.length} rec · ${c.runs.length} run${c.runs.length === 1 ? "" : "s"}`),
      el("span", { class: "ctargets" }, topEntries(c.target_hosts, 2).map(([h]) => host(h)).join(", ") || "–"));
    b.addEventListener("click", () => select({ c: sel.c === k ? null : k, r: null, rule: null }));
    return b;
  }), a.clusters.length > 200 ? el("p", { class: "hint" }, `${a.clusters.length - 200} more clusters not listed.`) : null);
}

function renderFilterBar() {
  const parts = [];
  const clear = (label, patch) => {
    const b = el("button", { type: "button", class: "chip-btn", "aria-label": `Clear ${label}` }, label);
    b.addEventListener("click", () => select(patch, null));
    return b;
  };
  if (sel.c) parts.push(clear(`cluster ${idOf(sel.c)}`, { c: null, r: null }));
  if (sel.rule) parts.push(clear(`rule ${sel.rule}`, { rule: null }));
  if (sel.r != null) parts.push(clear(`record #${sel.r}`, { r: null }));
  $("filter-bar").replaceChildren(...(parts.length ? [el("span", { class: "hint" }, "Showing:"), ...parts] : []));
}

// ── Views ──────────────────────────────────────────────────────────────────
function panelWidth() {
  return Math.max(320, $("viz-panel").clientWidth - 4);
}

function sharedPauseBands() {
  const out = [];
  for (const sp of arr(a.shared_pauses)) {
    const ka = keyOf(a.clusters.find((c) => c.id === sp.a) ?? { id: sp.a });
    const kb = keyOf(a.clusters.find((c) => c.id === sp.b) ?? { id: sp.b });
    for (const pair of arr(sp.pauses)) {
      const [pa, pb] = Array.isArray(pair) ? pair : [pair?.a, pair?.b];
      const label = `${sp.a} and ${sp.b} went quiet together (a hint to check, not a merge)`;
      if (pa) out.push({ key: ka, start: pa.start, end: pa.end, label });
      if (pb) out.push({ key: kb, start: pb.start, end: pb.end, label });
    }
  }
  return out;
}

function viewRuns() {
  const cl = a.clusters.filter((c) => arr(c.runs).some((r) => r.start > 0)).slice(0, MAX_LANES);
  const lanes = cl.map((c) => ({ key: keyOf(c), label: c.id, tier: c.tier, runs: c.runs.filter((r) => r.start > 0) }));
  const chart = swimlanes({ lanes, pauses: arr(a.timing?.pauses), bands: sharedPauseBands(), selected: sel.c, onSelect: (k) => select({ c: sel.c === k ? null : k, r: null, rule: null }), width: panelWidth(), label: "Runs per cluster over time, UTC" });
  return figure({
    chart,
    legend: legend(legendKey("k-sig", "significant"), legendKey("k-sug", "suggestive"), legendKey("k-noise", "noise"), legendKey("k-pause", "pause (all records)"), legendKey("k-band", "shared pause")),
    caption: `One lane per cluster${a.clusters.length > MAX_LANES ? ` (the ${MAX_LANES} strongest of ${a.clusters.length})` : ""}, one bar per run. Select a bar or a lane label to select its cluster.`,
    head: ["Cluster", "Tier", "Run start", "Run end", "Records"],
    rows: lanes.flatMap((l) => l.runs.map((r) => [l.label, pill(l.tier), fmtTs(r.start), fmtTs(r.end), String(r.count)])),
  });
}

/** Cluster pairs a hint connects, as graph edges. Unknown shapes are skipped. */
function fleetEdges(keys) {
  const k = (x) => {
    const c = clusterBy(String(x ?? ""));
    return c ? keyOf(c) : null;
  };
  const edges = [];
  const add = (x, y, kind, label) => {
    const p = k(x), q = k(y);
    if (p && q && p !== q && keys.has(p) && keys.has(q)) edges.push({ a: p, b: q, kind, label });
  };
  for (const sp of arr(a.shared_pauses)) add(sp.a, sp.b, "pause", `Shared pauses: ${sp.a} and ${sp.b} went quiet together${num(sp.p_chance) != null ? ` (chance ${sp.p_chance.toExponential(1)})` : ""}`);
  for (const p of arr(a.dialect_pairs)) add(p.a, p.b, "dialect", `Payload dialect: ${p.a} and ${p.b} share an uncommon mix of test payloads (Jaccard ${(num(p.jaccard) ?? 0).toFixed(2)})`);
  for (const ch of arr(a.chains)) {
    const ids = [...new Set(arr(ch.members).map((m) => a.results[m]?.cluster).filter((x) => x != null))].map((i) => a.clusters[i]?.id);
    for (let i = 1; i < ids.length; i++) add(ids[0], ids[i], "chain", `Probe chain: ${ids[0]} and ${ids[i]} sent variants of one request on ${host(ch.host)}`);
  }
  // Optional fields some analyses carry: soft links and candidate fleets.
  for (const s of arr(a.soft_links)) {
    const o = obj(s);
    const ends = arr(o.clusters).length >= 2 ? o.clusters : [o.a ?? o.from ?? o.a_key, o.b ?? o.to ?? o.b_key];
    const why = String(o.reason ?? o.kind ?? o.why ?? "soft link");
    const score = num(o.score ?? o.confidence);
    add(ends[0], ends[1], "soft", `Soft link: ${trunc(why, 120)}${score != null ? ` (${score.toFixed(2)})` : ""}`);
  }
  for (const f of arr(a.candidate_fleets)) {
    const o = Array.isArray(f) ? { clusters: f } : obj(f);
    const members = arr(o.clusters ?? o.members ?? o.keys);
    const name = trunc(String(o.reason ?? o.name ?? o.id ?? "candidate fleet"), 120);
    for (let i = 1; i < members.length; i++) add(members[0], members[i], "fleet", `Candidate fleet: ${name}`);
  }
  return edges;
}

function viewFleet() {
  const cl = [...a.clusters].sort((x, y) => y.members.length - x.members.length).slice(0, MAX_LANES).sort((x, y) => x.start - y.start);
  const keys = new Set(cl.map(keyOf));
  const nodes = cl.map((c) => ({ key: keyOf(c), label: c.id, tier: c.tier, size: c.members.length, sub: `${c.tier}, ${c.members.length} records, ${c.runs.length} runs` }));
  const edges = fleetEdges(keys);
  const kinds = new Set(edges.map((e) => e.kind));
  const names = { pause: "shared pauses", chain: "probe chain", dialect: "payload dialect", soft: "soft link", fleet: "candidate fleet" };
  const chart = fleetGraph({ nodes, edges, selected: sel.c, onSelect: (k) => select({ c: sel.c === k ? null : k, r: null, rule: null }), width: panelWidth() });
  return figure({
    chart,
    legend: legend(legendKey("k-sig", "significant"), legendKey("k-sug", "suggestive"), legendKey("k-noise", "noise"), ...[...kinds].map((k) => legendKey(`e-${k}`, names[k]))),
    caption: `Hints, not evidence: no edge changes a score or merges clusters. Node area is the cluster's record count; clusters sit in order of first activity.${edges.length ? "" : " No hints connect these clusters."}`,
    head: ["Hint", "From", "To", "Detail"],
    rows: edges.map((e) => [names[e.kind], idOf(e.a), idOf(e.b), e.label]),
  });
}

function viewHeat() {
  const cols = [...a.clusters].sort((x, y) => y.members.length - x.members.length).slice(0, 24).map((c) => ({ key: keyOf(c), label: c.id, c }));
  const totals = {};
  for (const col of cols) for (const [r, n] of Object.entries(obj(col.c.rules))) totals[r] = (totals[r] ?? 0) + n;
  const rows = Object.entries(totals).sort((x, y) => y[1] - x[1] || (x[0] < y[0] ? -1 : 1)).slice(0, 30).map(([id]) => ({ id, label: id }));
  const value = (r, c) => obj(c.c.rules)[r.id] ?? 0;
  const chart = el("div", { class: "scroll" }, heatmap({ rows, cols, value, selected: { row: sel.rule, col: sel.c }, onSelect: (rule, k) => select({ c: k, rule, r: null }, "explore"), width: panelWidth() }));
  return figure({
    chart,
    legend: rampLegend("fewer", "more records"),
    caption: "Records in each cluster that matched each rule (the 30 most common rules, the 24 largest clusters). Select a cell to filter the records to that rule in that cluster.",
    head: ["Rule", ...cols.map((c) => c.label)],
    rows: rows.map((r) => [r.label, ...cols.map((c) => String(value(r, c) || ""))]),
  });
}

function scopeIdx() {
  let idx = a.results.map((_, i) => i).filter((i) => a.results[i].score > 0);
  if (sel.c) idx = arr(clusterBy(sel.c)?.members);
  if (sel.rule) idx = idx.filter((i) => arr(a.results[i].hits).some((h) => h.rule_id === sel.rule));
  return idx;
}
const scopeText = () => [sel.c ? `cluster ${idOf(sel.c)}` : "all flagged records", sel.rule ? `rule ${sel.rule}` : null].filter(Boolean).join(", ");

function viewRhythm() {
  const counts = Array.from({ length: 7 }, () => Array(24).fill(0));
  for (const i of scopeIdx()) {
    const t = a.results[i].obs.ts;
    if (!(t > 0)) continue;
    const d = new Date(t * 1000);
    counts[(d.getUTCDay() + 6) % 7][d.getUTCHours()]++;
  }
  const rows = [];
  counts.forEach((r, d) => r.forEach((v, h) => v && rows.push([["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"][d], `${String(h).padStart(2, "0")}:00`, String(v)])));
  return figure({
    chart: el("div", { class: "scroll" }, rhythmGrid({ counts, width: panelWidth() })),
    legend: rampLegend("fewer", "more records"),
    caption: `Records by weekday and hour, UTC (${scopeText()}). People sleep and keep weekends; automated fleets need not. A hint, not evidence of where an operator is.`,
    head: ["Day", "Hour (UTC)", "Records"],
    rows,
  });
}

function viewStrip() {
  const idx = scopeIdx().filter((i) => a.results[i].obs.ts > 0 && a.results[i].target_host);
  const counts = {};
  for (const i of idx) counts[a.results[i].target_host] = (counts[a.results[i].target_host] ?? 0) + 1;
  const hosts = Object.entries(counts).sort((x, y) => y[1] - x[1] || (x[0] < y[0] ? -1 : 1)).slice(0, 14).map(([h]) => h);
  const row = new Map(hosts.map((h, i) => [h, i]));
  const points = idx.filter((i) => row.has(a.results[i].target_host)).slice(0, 2000).map((i) => {
    const r = a.results[i];
    return { t: r.obs.ts, row: row.get(r.target_host), tier: r.tier, idx: i, sel: sel.r === i, label: `#${i} · ${host(r.target_host)} · ${fmtTs(r.obs.ts)} · ${r.tier} · ${arr(r.hits).map((h) => h.rule_id).slice(0, 4).join(", ")}` };
  });
  return figure({
    chart: strip({ rows: hosts.map(host), points, onSelect: (i) => select({ r: sel.r === i ? null : i }), width: panelWidth() }),
    legend: tierLegend(),
    caption: `Flagged requests per target host over time (${scopeText()}; the 14 busiest hosts). Select a dot to see its record.`,
    head: ["Host", "Records"],
    rows: hosts.map((h) => [host(h), String(counts[h])]),
  });
}

function viewHourly() {
  const tm = obj(a.timing);
  return figure({
    chart: hourly({ data: arr(tm.hourly), pauses: arr(tm.pauses), width: panelWidth() }),
    legend: legend(legendKey("s-agent", "flagged records"), legendKey("k-pause", "pause")),
    caption: "Flagged records per hour, UTC, across the whole input.",
    head: ["Hour (UTC)", "Flagged"],
    rows: arr(tm.hourly).filter(([, c]) => c).map(([h, c]) => [fmtTs(h).slice(0, 16), String(c)]),
  });
}

function renderView() {
  const panel = $("viz-panel");
  if (!a) return;
  const make = { runs: viewRuns, fleet: viewFleet, heat: viewHeat, rhythm: viewRhythm, strip: viewStrip, hourly: viewHourly }[view];
  try {
    panel.replaceChildren(make());
  } catch (e) {
    showError(panel, e);
  }
}

let lastWidth = 0;
let resizeTimer = 0;
window.addEventListener("resize", () => {
  clearTimeout(resizeTimer);
  resizeTimer = setTimeout(() => {
    const w = $("viz-panel").clientWidth;
    if (a && Math.abs(w - lastWidth) > 24) {
      lastWidth = w;
      renderView();
    }
  }, 150);
});

// ── Records and endpoints ──────────────────────────────────────────────────
function renderRecords() {
  const idx = [...scopeIdx()].sort((x, y) => a.results[y].score - a.results[x].score || a.results[x].obs.ts - a.results[y].obs.ts);
  $("records-h").textContent = `Flagged records (${scopeText()}: ${idx.length})`;
  const shown = idx.slice(0, MAX_ROWS);
  const body = el("tbody", {}, shown.map((i) => {
    const r = a.results[i];
    const tr = el("tr", { class: `pick${sel.r === i ? " sel" : ""}`, tabindex: 0, "aria-selected": String(sel.r === i), "aria-label": `Record ${i}, ${r.tier}, score ${r.score}` },
      el("td", {}, pill(r.tier)), el("td", { class: "num" }, r.score), el("td", { class: "nowrap", title: fmtTs(r.obs.ts) }, fmtShort(r.obs.ts)),
      el("td", {}, r.cluster != null ? a.clusters[r.cluster]?.id ?? "–" : "–"),
      el("td", { class: "url" }, safe(r.obs.url, 300)),
      el("td", {}, arr(r.hits).map((h) => el("span", { class: "chip" }, h.rule_id))));
    activate(tr, () => select({ r: sel.r === i ? null : i }));
    return tr;
  }));
  if (idx.length > shown.length) body.append(el("tr", {}, el("td", { colspan: 6, class: "hint" }, `${idx.length - shown.length} more not shown; download the analysis JSON for all.`)));
  if (!idx.length) body.append(el("tr", {}, el("td", { colspan: 6, class: "hint" }, "No flagged records in this selection.")));
  $("records").replaceChildren(el("div", { class: "scroll" }, el("table", { class: "records" },
    el("thead", {}, el("tr", {}, ["Tier", "Score", "Time (UTC)", "Cluster", "URL (defanged)", "Rules"].map((h) => el("th", { scope: "col" }, h)))), body)));
}

function renderEndpoints() {
  try {
    endpointsCache ??= JSON.parse(sc.endpoints(""));
  } catch (e) {
    return showError($("endpoints"), e);
  }
  const views = endpointsCache;
  const body = el("tbody");
  if (!views.length) body.append(el("tr", {}, el("td", { colspan: 7, class: "hint" }, "No target host has a suggestive or significant hit.")));
  for (const v of views) {
    body.append(el("tr", {},
      el("td", { class: "url" }, host(v.host)), el("td", {}, pill(v.max_tier)), el("td", { class: "num" }, `${v.hits} / ${v.records}`),
      el("td", { class: "nowrap" }, fmtTs(v.first_seen)), el("td", { class: "nowrap" }, fmtTs(v.last_seen)), el("td", {}, String(v.activity ?? "")),
      el("td", {}, v.payloads ? Object.keys(obj(v.payload_rules)).map((r) => el("span", { class: "chip" }, r)) : el("span", { class: "hint" }, "none seen"))));
  }
  $("endpoints").replaceChildren(el("div", { class: "scroll" }, el("table", {},
    el("thead", {}, el("tr", {}, ["Host", "Tier", "Hits", "First seen", "Last seen", "Status", "Attack payloads"].map((h) => el("th", { scope: "col" }, h)))), body)));
}

// ── Context ────────────────────────────────────────────────────────────────
// Wording follows the CLI report (sc-core report). Every hint is descriptive:
// none changes a score or links records. Unknown fields are ignored.
const PACE = { tool: "tool pace", model: "model pace", slow: "slow pace" };
const span = (s) => `${fmtTs(s.start)} → ${fmtTs(s.end)} (${dur(Math.max(0, s.end - s.start))})`;

function rhythmText(r) {
  r = obj(r);
  const v = obj(r.verdict);
  if (!v.kind || v.kind === "too_short") return null;
  const over = `over ${num(r.days) ?? "?"} days (hour-of-day entropy ${(num(r.entropy) ?? 0).toFixed(2)}, longest idle ${dur(Math.round((num(r.longest_idle_hours) ?? 0) * 3600))})`;
  if (v.kind === "round_the_clock") return `active around the clock ${over}; people sleep, automated fleets need not (a hint, not evidence)`;
  if (v.kind === "daytime") {
    const s = num(v.start_hour) ?? 0, h = num(v.hours) ?? 0, off = num(v.utc_offset_guess) ?? 0;
    const hh = (x) => String(x).padStart(2, "0");
    return `active ${hh(s)}:00–${hh((s + h) % 24)}:00 UTC ${over}, like a working day near UTC${signed(off)} (a hint, not evidence of where the operator is)`;
  }
  return `no clear pattern ${over}`;
}

function staleText(d) {
  d = obj(d);
  if (!num(d.tags)) return null;
  if (!d.consistent) return `${d.tags} date tag(s), no consistent stale date`;
  const named = d.modal_date && num(d.same_date_share) >= 0.6 ? `, ${Math.round(d.same_date_share * 100)}% naming ${safe(d.modal_date, 20)}` : "";
  return `${d.behind} of ${d.tags} name a day at least 7 days before they were seen (median lag ${d.median_lag_days ?? "?"} days${named}), like a model with no clock writing the date it believes is today (a hint, not evidence)`;
}

function offsetText(d) {
  d = obj(d);
  if (!num(d.tagged)) return "no date tags";
  if (d.consistent && d.ahead > 0) return `ahead of UTC in ${d.ahead}/${d.tagged} tagged records: operator clock UTC${signed(num(d.min_hours) ?? 0)}…UTC${signed(num(d.max_hours) ?? 0)}`;
  return `${d.tagged} tagged record(s), no consistent offset`;
}

function chainLine(ch) {
  const varied = arr(ch.varied).map((p) => safe(p, 40)).join(", ") || "parameters";
  const notes = [];
  if (num(ch.retries_after_error)) notes.push(`${ch.retries_after_error} variant(s) followed an error response`);
  const unflagged = arr(ch.members).length - (num(ch.flagged) ?? 0);
  if (unflagged > 0) notes.push(`${unflagged} of its requests matched no rule`);
  return `${ch.variants ?? "?"} variants of ${varied} on ${safe(`https://${ch.host ?? ""}${ch.path ?? ""}`, 90).replace(/^hxxps:\/\//, "")} over ${dur(Math.max(0, (ch.end ?? 0) - (ch.start ?? 0)))} (median gap ${dur(num(ch.median_gap_secs) ?? 0)}, ${PACE[ch.pace] ?? "unknown pace"})${notes.length ? "; " + notes.join("; ") : ""}`;
}

function clusterContext(c) {
  const rows = [];
  const row = (k, ...v) => rows.push(el("dt", {}, k), el("dd", {}, ...v));
  const t = obj(c.timing);
  const runs = arr(c.runs);
  row("Records", `${c.members.length} (score ${c.score})`);
  row("Seen", `${fmtTs(c.start)} → ${fmtTs(c.end)}`);
  row("Targets", chips(topEntries(c.target_hosts, 6).map(([h, n]) => `${host(h)} ×${n}`)));
  row("Top rules", chips(topEntries(c.rules, 8).map(([r, n]) => `${r} ×${n}`)));
  row("Runs", runs.length ? el("ul", {}, runs.slice(0, 6).map((r) => el("li", {}, `${span(r)}, ${r.count ?? 0} record(s)`)), runs.length > 6 ? el("li", { class: "hint" }, `${runs.length - 6} more`) : null) : "none");
  row("Daily rhythm", rhythmText(t.rhythm) ?? el("span", { class: "hint" }, "too little data to say (needs 3 days, 20 records)"));
  row("Offset from date tags", offsetText(dateTags[c.id]));
  row("Stale date tags", staleText(t.stale_dates) ?? el("span", { class: "hint" }, "none"));
  const enc = topEntries(c.encodings, 6);
  const members = arr(c.members).length;
  const oneStyle = enc.length === 1 && enc[0][1] === members && members > 1;
  if (enc.length) row("Encoding styles", chips(enc.map(([s, n]) => `${trunc(String(s), 60)} ×${n}`)), oneStyle ? el("div", { class: "hint" }, "all records share one style: consistent with one client, not evidence on its own") : null);
  const p = obj(c.paths);
  for (const pre of arr(p.preambles))
    row("Recon preamble", `${pre.hosts ?? "?"} hosts opened with the same recon requests: `, el("code", {}, arr(pre.paths).map((x) => safe(x, 60)).join(" → ")), el("div", { class: "hint" }, "consistent with one client, not evidence on its own"));
  for (const set of arr(p.shared_unusual_sets))
    row("Unusual path set", `${set.hosts ?? "?"} hosts were asked for the same unusual paths${num(set.not_found) ? `; ${set.not_found} got 404/410` : ""}: `, chips(arr(set.paths).slice(0, 8).map((x) => safe(x, 60))));
  if (num(p.fabricated_ids))
    row("Fabricated identifiers", `${p.fabricated_ids} record(s) carry identifiers no generator produces, consistent with invented placeholders `, chips(Object.entries(obj(p.fabricated_reasons)).map(([r, n]) => `${trunc(String(r), 40)} ×${n}`)));
  const d = obj(c.dialect);
  const variants = topEntries(d.variants, 12);
  if (num(d.records) >= 2 && variants.length)
    row("Payload dialect", `${d.records} records, signature `, el("code", {}, safe(d.signature ?? "", 20)), ": ", chips(variants.map(([v, n]) => `${safe(v, 40)} ×${n}`)),
      arr(d.first_seen).length > 1 ? el("div", { class: "hint" }, `first seen ${arr(d.first_seen).slice(0, 8).map((v) => safe(v, 40)).join(" → ")}`) : null,
      el("div", { class: "hint" }, "which canonical test payloads a client reaches for: consistent with one model or tool, not evidence on its own"));
  const f = obj(c.fanout);
  if (num(f.modal_width))
    row("Parallel fan-out", `${obj(f.widths)[f.modal_width] ?? "?"} of ${f.batches ?? "?"} one-second batches were ${f.modal_width} alike requests wide `,
      chips(Object.entries(obj(f.widths)).map(([w, n]) => `${safe(w, 6)}×${n}`)),
      el("div", { class: "hint" }, "like an agent issuing tool calls in parallel; a scanner submitting a list in bulk looks the same (a hint, not evidence)"));
  const cl = obj(c.cut_lengths);
  const cut = (g, what) => {
    g = obj(g);
    if (!num(g.records)) return null;
    return `${g.records} of ${cl.truncated ?? "?"} ${what} ${g.min === g.max ? g.min : `${g.min}–${g.max}`} characters`;
  };
  const cuts = [cut(cl.url, "truncated URLs were cut at"), cut(cl.value, "cut parameter values were")].filter(Boolean);
  if (cuts.length) row("Cut lengths", cuts.join("; "), el("div", { class: "hint" }, "consistent with a model or tool output limit, not evidence on its own (rule out the source's own display limit first)"));
  const lf = arr(c.link_features);
  if (lf.length) row("Linked by", chips(lf.slice(0, 10).map((x) => safe(typeof x === "string" ? x : JSON.stringify(x), 90))), lf.length > 10 ? el("span", { class: "hint" }, ` ${lf.length - 10} more`) : null);
  const mine = new Set(arr(c.members));
  const chains = arr(a.chains).filter((ch) => arr(ch.members).some((m) => mine.has(m)));
  if (chains.length) row("Probe chains", el("ul", {}, chains.slice(0, 10).map((ch) => el("li", {}, chainLine(ch)))), el("div", { class: "hint" }, "the pace is a hint, not evidence"));
  const toReport = el("button", { type: "button" }, "Draft a report for this cluster");
  toReport.addEventListener("click", () => {
    goStep("report");
    $("h-report").scrollIntoView({ block: "start" });
  });
  return [
    el("div", { class: "ctx-head" }, el("h3", {}, `Cluster ${c.id}`), pill(c.tier), el("span", { class: "chip" }, keyOf(c))),
    el("dl", { class: "kv" }, rows),
    el("div", { class: "row" }, toReport),
  ];
}

function recordContext(i) {
  const r = a.results[i];
  const c = r.cluster != null ? a.clusters[r.cluster] : null;
  const rows = [];
  const row = (k, ...v) => rows.push(el("dt", {}, k), el("dd", {}, ...v));
  row("Time", fmtTs(r.obs.ts));
  row("Cluster", c ? (() => {
    const b = el("button", { type: "button" }, `${c.id} (${c.tier})`);
    b.addEventListener("click", () => select({ c: keyOf(c), r: null }));
    return b;
  })() : "none");
  row("Record id", trunc(String(r.obs.id ?? ""), 80));
  if (r.obs.source) row("Source", trunc(String(r.obs.source), 60));
  if (r.target_host) row("Target", host(r.target_host));
  row("URL (defanged)", el("code", {}, safe(r.obs.url, 1200)));
  row("Rules", el("ul", {}, arr(r.hits).map((h) => el("li", {}, el("strong", {}, h.rule_id), ` +${h.weight}`, h.matched ? [": ", el("code", {}, safe(h.matched, 160))] : null))));
  if (arr(r.layers).length > 1) row("Layers", `${r.layers.length} (see the unwrap tool for each)`);
  return [el("div", { class: "ctx-head" }, el("h3", {}, `Record #${i}`), pill(r.tier), el("span", { class: "hint" }, `score ${r.score}`)), el("dl", { class: "kv" }, rows)];
}

function renderContext() {
  const box = $("context");
  if (sel.r != null && a.results[sel.r]) box.replaceChildren(...recordContext(sel.r));
  else if (sel.c && clusterBy(sel.c)) box.replaceChildren(...clusterContext(clusterBy(sel.c)));
  else box.replaceChildren(el("p", { class: "hint" }, `${plural(a.clusters.length, "cluster")} and ${plural(a.flagged, "flagged record")}. Select a cluster, a run, a graph node or a record to see its timing, hints and records here.`));
}

function renderLinks() {
  const pauses = arr(a.shared_pauses);
  const out = [];
  out.push(el("h4", {}, "Shared pauses"));
  out.push(pauses.length
    ? el("ul", {}, pauses.map((sp) => el("li", {}, el("strong", {}, `${sp.a} and ${sp.b}`), ` went quiet together: ${sp.reason ?? ""}. Their records share no identifier; a link to check, not a merge.`,
        num(sp.p_chance) != null ? el("span", { class: "hint" }, ` (chance ${sp.p_chance.toExponential(1)})`) : null)))
    : el("p", { class: "hint" }, "No pair of clusters went quiet together more often than chance allows."));
  const dp = arr(a.dialect_pairs);
  out.push(el("h4", {}, "Shared payload dialects"));
  out.push(dp.length
    ? el("ul", {}, dp.map((p) => el("li", {}, el("strong", {}, `${p.a} and ${p.b}`), ` use the same uncommon mix of test payloads (Jaccard ${(num(p.jaccard) ?? 0).toFixed(2)}): `, chips(arr(p.shared).slice(0, 12).map((v) => safe(v, 40))), " A link to check, not a merge.")))
    : el("p", { class: "hint" }, "No pair of clusters shares an uncommon mix of test payloads."));
  const chains = arr(a.chains);
  out.push(el("h4", {}, `Probe chains (${chains.length})`));
  out.push(chains.length
    ? el("ul", {}, chains.slice(0, 30).map((ch) => el("li", {}, chainLine(ch))), chains.length > 30 ? el("li", { class: "hint" }, `${chains.length - 30} more`) : null)
    : el("p", { class: "hint" }, "No probe chains: no runs of three or more variants of one request."));
  const soft = arr(a.soft_links), fleets = arr(a.candidate_fleets);
  if (soft.length || fleets.length) {
    const edges = fleetEdges(new Set(a.clusters.map(keyOf))).filter((e) => e.kind === "soft" || e.kind === "fleet");
    out.push(el("h4", {}, "Soft links and candidate fleets"));
    out.push(edges.length ? el("ul", {}, edges.slice(0, 40).map((e) => el("li", {}, el("strong", {}, `${idOf(e.a)} and ${idOf(e.b)}`), ` ${e.label}`))) : el("p", { class: "hint" }, "None between the clusters shown."));
  }
  $("links").replaceChildren(...out);
}

// ── Report ─────────────────────────────────────────────────────────────────
function readClaims() {
  const status = $("claims-status");
  status.hidden = true;
  try {
    const claims = JSON.parse(sc.check_claims($("claims").value));
    $("claims-count").textContent = claims.length ? `(${claims.length})` : "";
    return claims;
  } catch (e) {
    $("claims-count").textContent = "(invalid)";
    status.textContent = String(e?.message ?? e);
    status.hidden = false;
    return null;
  }
}

function renderReport() {
  if (!a) return;
  const claims = readClaims();
  if (claims == null) {
    $("report").textContent = "Fix the claims JSON to draft a report.";
    return;
  }
  const opts = {
    audience: $("audience").value,
    cluster: sel.c,
    reporter: $("reporter").value || null,
    generated: new Date().toISOString().slice(0, 10),
    max_evidence: 10,
    min_named: $("min-named").value,
    claims,
  };
  try {
    $("report").textContent = sc.report(JSON.stringify(opts));
  } catch (e) {
    $("report").textContent = String(e?.message ?? e);
  }
}

// ── Wiring ─────────────────────────────────────────────────────────────────
async function loadExample() {
  try {
    $("input").value = await fetchRoot("assets/example.ndjson", "text");
  } catch (e) {
    return showError($("warnings"), e);
  }
  $("format").value = "ndjson";
  $("map").value = "";
  $("preset-note").hidden = true;
  if (runAnalysis()) $("example-note").hidden = false;
}

$("run").addEventListener("click", () => {
  $("example-note").hidden = true;
  runAnalysis();
});
$("example").addEventListener("click", loadExample);
$("input").addEventListener("input", () => ($("example-note").hidden = true));
$("file").addEventListener("change", async (e) => {
  const f = e.target.files[0];
  if (!f) return;
  $("example-note").hidden = true;
  $("input").value = await f.text();
  runAnalysis();
});
for (const id of ["audience", "min-named"]) $(id).addEventListener("change", renderReport);
$("reporter").addEventListener("input", renderReport);
$("claims").addEventListener("input", () => (a ? renderReport() : readClaims()));
$("copy-report").addEventListener("click", () => navigator.clipboard?.writeText($("report").textContent));
$("dl-report").addEventListener("click", () => download("swarmchase-report.md", $("report").textContent, "text/markdown"));
$("dl-json").addEventListener("click", () => a && download("swarmchase-analysis.json", JSON.stringify(a, null, 2), "application/json"));

{
  const h = readHash();
  if (h.v) setView(h.v);
  if (h.preset === "access-log") {
    $("format").value = "access_log";
    $("map").placeholder = "host=www.example.org (your own host)";
    $("preset-note").hidden = false;
    $("input").focus();
  } else if (h.example) {
    await loadExample();
  }
}
