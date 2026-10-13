// The analysis workbench. Records are analysed by the engine in this page;
// nothing is uploaded. Record contents are untrusted: they reach the page as
// text only, URLs and hosts defanged, and never become links. The URL hash
// holds the selection as ids only (a cluster key, a record number, a rule
// id, a view), never hosts, URLs or other record data.
import { $, el, activate, download, fetchRoot, showAlert, showError } from "../lib/dom.js";
import { arr, obj, num, fmtTs, fmtShort, dur, trunc, signed, topEntries, plural } from "../lib/fmt.js";
import { engine, tools, host as hostOf, pageRules, sizeNote } from "../lib/wasm.js";
import { figure, legend, legendKey, edgeKey, swarmKey, tierLegend, rampLegend, swimlanes, runExtent, zoomWindow, fleetGraph, swarmGraph, heatmap, rhythmGrid, strip, hourly } from "../lib/charts.js";
import {
  kindClass, kindLabel, tactic, route, fleetItems, language, levelOf, swarmKind, provenanceLabel, corroborationLabel, plantLabel,
} from "../lib/hints.js";
import { layersTable } from "../lib/layers.js";
import { agentLadder as ladderOf } from "../lib/agent.js";
import { scopePanel } from "../lib/scope.js";
import { sightingsPanel, resetSightings } from "../lib/sightings.js";

const VIEWS = ["runs", "fleet", "swarm", "heat", "rhythm", "strip", "hourly"];
const STEPS = ["input", "explore", "context", "report"];
const MAX_LANES = 40;
const MAX_ROWS = 300;
const mobile = () => matchMedia("(max-width: 899px)").matches;

const sc = await engine();
const rules = await pageRules(sc, $("rules-note"));
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
let lastWidth = 0; // the views panel width the current view was drawn at
let zoom = null; // the swim-lanes' time window, null for all of it
// The input the shown analysis came from, for the tools module, which
// re-runs it (deterministically) to draft reports and attribution layers.
let source = null;
let generation = 0; // bumped per analysis
let preparedGen = -1; // the generation the tools module holds
let wantReport = false; // the visitor reached the report: load the tools module

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
function goStep(step, scroll = true) {
  for (const b of document.querySelectorAll(".steps button")) {
    if (b.dataset.step === step) b.setAttribute("aria-current", "step");
    else b.removeAttribute("aria-current");
  }
  for (const p of document.querySelectorAll("[data-pane]")) p.classList.toggle("on", p.dataset.pane === step);
  // The pane's top, just under the sticky step bar (its scroll-margin-top).
  if (mobile() && scroll) document.querySelector(`[data-pane="${step}"]`)?.scrollIntoView({ block: "start" });
  // A view drawn while its pane was hidden had no width: redraw it at its size.
  if (a && step === "explore" && Math.abs($("viz-panel").clientWidth - lastWidth) > 24) renderView();
}
for (const b of document.querySelectorAll(".steps button")) b.addEventListener("click", () => goStep(b.dataset.step));
goStep("input", false);

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

// ── Input ──────────────────────────────────────────────────────────────────
/** Analyze is offered only when there is something to analyse. */
const syncRun = () => ($("run").disabled = !$("input").value.trim());

/** After a run: the records box shrinks to a line, so the clusters come up. */
function collapseInput(n) {
  const hadFocus = $("input-box").contains(document.activeElement);
  $("input-box").hidden = true;
  $("input-count").textContent = `${plural(n, "record")} loaded`;
  $("input-collapsed").hidden = false;
  $("input-edit").setAttribute("aria-expanded", "false");
  if (hadFocus) $("input-edit").focus({ preventScroll: true });
}
function expandInput(focus = false) {
  $("input-box").hidden = false;
  $("input-collapsed").hidden = true;
  $("input-edit").setAttribute("aria-expanded", "true");
  if (focus) $("input").focus();
}

const FORMATS_READ = "The workbench reads NDJSON (one JSON object per line, with a url field), a JSON array, Wayback CDX JSON, one URL per line (optionally after a timestamp), or a web server access log.";

/** Nothing was read: say why, with the first problem, and how to fix it. */
function nothingRead(title, first) {
  clearAnalysis();
  expandInput();
  showAlert($("alert"), title,
    first ? ["First problem: ", el("code", {}, trunc(String(first), 300))] : null,
    `${FORMATS_READ} If auto-detect guessed wrong, pick the format; if your fields have other names, map them, e.g. ts=submitted_at,url=page.url.`,
    "To see what an analysis looks like, press Try an example.");
}

/** Back to the empty workbench: no dashboard for an input that read nothing. */
function clearAnalysis() {
  a = null;
  source = null;
  generation++;
  endpointsCache = null;
  sel = { c: null, r: null, rule: null };
  const hint = (text, cls = "hint") => el("p", { class: cls }, text);
  $("summary").hidden = true;
  $("summary").replaceChildren();
  $("cluster-list").replaceChildren(hint("Analyse records to see their clusters: records linked by shared inbox IDs, unique tags, or the same target in a short window."));
  $("viz-panel").replaceChildren(hint("Views appear here after an analysis.", "hint empty-state"));
  $("filter-bar").replaceChildren();
  $("records-h").textContent = "Flagged records";
  $("records").replaceChildren(hint("No records yet."));
  $("endpoints").replaceChildren(hint("No endpoints yet."));
  $("context").replaceChildren(hint("Select a cluster, a run, a graph node or a record to see its timing, hints and records here."));
  $("links").replaceChildren(hint("None yet."));
  $("report").textContent = "Analyse records to draft a report.";
  for (const b of ["copy-report", "dl-report", "dl-json"]) $(b).disabled = true;
  resetSightings();
  writeHash();
}

// ── Analysis ───────────────────────────────────────────────────────────────
function runAnalysis() {
  const warn = $("warnings");
  warn.hidden = true;
  $("alert").hidden = true;
  let out;
  const src = { input: $("input").value, format: $("format").value, map: $("map").value };
  if (!src.input.trim()) {
    nothingRead("There is nothing to analyse yet.", null);
    return false;
  }
  try {
    out = JSON.parse(sc.analyze(src.input, src.format, src.map, rules));
  } catch (e) {
    nothingRead("The input could not be read.", e?.message ?? e);
    return false;
  }
  if (!num(out.analysis?.total)) {
    nothingRead("Nothing was read from this input: no line held a record.", arr(out.warnings)[0]);
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
  source = src;
  generation++;
  zoom = null;
  allRecords = false;
  // Declared testing (the declaring text and the contact it names) is for
  // case notes only, never a public page: the page drops it on receipt, so
  // no view and no download shows it. The report draft follows the engine's
  // audience gate, as the CLI does.
  for (const c of arr(a.clusters)) delete c.declared;
  dateTags = obj(out.cluster_date_tags);
  endpointsCache = null;
  const h = readHash();
  sel = { c: h.c && clusterBy(h.c) ? keyOf(clusterBy(h.c)) : null, r: h.r != null && a.results[+h.r] ? +h.r : null, rule: h.rule };
  $("dl-json").disabled = false;
  resetSightings();
  renderAll();
  collapseInput(a.total);
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

/** The focused element's key, to focus its replacement after a re-render. */
const focusKey = () => document.activeElement?.closest?.("[data-focus-key]")?.dataset.focusKey ?? null;
function refocus(key) {
  if (!key) return;
  const n = [...document.querySelectorAll("[data-focus-key]")].find((e) => e.dataset.focusKey === key);
  if (n && n.getClientRects().length) n.focus({ preventScroll: true });
}

/** Change the selection; `step` moves phones to that step. */
function select(next, step = "context") {
  const key = focusKey();
  sel = { ...sel, ...next };
  renderClusterList();
  renderView();
  renderFilterBar();
  renderRecords();
  renderContext();
  renderReport();
  writeHash();
  if (mobile() && step) goStep(step);
  else refocus(key);
}

// Escape clears the selection, from anywhere but a text field.
document.addEventListener("keydown", (e) => {
  if (e.key !== "Escape" || !a || e.target.closest?.("input, textarea, select")) return;
  if (sel.c || sel.r != null || sel.rule) select({ c: null, r: null, rule: null }, null);
});

function renderSummary() {
  const t = (k) => obj(a.tier_counts)[k] ?? 0;
  const tiles = [
    [a.total, "records"], [a.flagged, "flagged"], [t("significant"), "significant"],
    [t("suggestive"), "suggestive"], [a.clusters.length, "clusters"], [a.max_concurrent_clusters, "peak overlap", "the most clusters active at the same time"],
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
    el("div", { class: "tiles" }, tiles.map(([v, k, what]) => el("div", { class: "tile", title: what ?? null }, el("div", { class: "v" }, Number(v ?? 0).toLocaleString()), el("div", { class: "k" }, k)))),
    el("p", { class: "hint" }, notes.join(" · ")),
  );
}

function renderClusterList() {
  const box = $("cluster-list");
  if (!a.clusters.length) return box.replaceChildren(el("p", { class: "hint" }, "No clusters. Records need shared identifiers or close timing to link."));
  box.replaceChildren(...a.clusters.slice(0, 200).map((c) => {
    const k = keyOf(c);
    const b = el("button", { type: "button", class: "cluster-row", "aria-pressed": String(sel.c === k), "data-focus-key": `cl:${k}` },
      el("span", { class: "cid" }, c.id), pill(c.tier), el("span", { class: "crecs" }, `${c.members.length} rec · ${c.runs.length} run${c.runs.length === 1 ? "" : "s"}${levelOf(c.agent?.level) ? ` · ${levelOf(c.agent.level).code}` : ""}`),
      el("span", { class: "ctargets" }, topEntries(c.target_hosts, 2).map(([h]) => host(h)).join(", ") || "–"));
    b.addEventListener("click", () => select({ c: sel.c === k ? null : k, r: null, rule: null }));
    return b;
  }), ...(a.clusters.length > 200 ? [el("p", { class: "hint" }, `${a.clusters.length - 200} more clusters not listed.`)] : []));
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

function setZoom(next) {
  zoom = next;
  renderView();
  refocus("swim-chart");
}

function zoomTools(full) {
  const b = (label, text, fn, disabled = false) => {
    const x = el("button", { type: "button", "aria-label": label, disabled }, text);
    x.addEventListener("click", fn);
    return x;
  };
  const [t0, t1] = zoom ?? full;
  return el("div", { class: "zoom-tools" },
    b("Zoom in", "+", () => setZoom(zoomWindow(full, zoom, 0.5))),
    b("Zoom out", "−", () => setZoom(zoomWindow(full, zoom, 2)), !zoom),
    b("Earlier", "◀", () => setZoom(zoomWindow(full, zoom, 1, -0.25)), !zoom),
    b("Later", "▶", () => setZoom(zoomWindow(full, zoom, 1, 0.25)), !zoom),
    b("Show the whole span", "Reset", () => setZoom(null), !zoom),
    el("span", { class: "hint", "aria-live": "polite" }, zoom ? `${fmtTs(t0)} → ${fmtTs(t1)} (${dur(t1 - t0)})` : "Drag across the chart to zoom; with the chart focused, + − ← → and 0."));
}

function viewRuns() {
  const cl = a.clusters.filter((c) => arr(c.runs).some((r) => r.start > 0)).slice(0, MAX_LANES);
  const lanes = cl.map((c) => ({ key: keyOf(c), label: c.id, tier: c.tier, runs: c.runs.filter((r) => r.start > 0) }));
  const full = runExtent(lanes);
  const svgChart = swimlanes({ lanes, pauses: arr(a.timing?.pauses), bands: sharedPauseBands(), selected: sel.c, onSelect: (k) => select({ c: sel.c === k ? null : k, r: null, rule: null }), width: panelWidth(), label: "Runs per cluster over time, UTC", domain: zoom, onZoom: setZoom });
  if (svgChart instanceof SVGElement) svgChart.setAttribute("data-focus-key", "swim-chart");
  const chart = full ? el("div", {}, zoomTools(full), svgChart) : svgChart;
  return figure({
    chart,
    legend: legend(legendKey("k-sig", "significant"), legendKey("k-sug", "suggestive"), legendKey("k-noise", "noise"), legendKey("k-pause", "pause (all records)"), legendKey("k-band", "shared pause")),
    caption: `One lane per cluster${a.clusters.length > MAX_LANES ? ` (the ${MAX_LANES} strongest of ${a.clusters.length})` : ""}, one bar per run. Select a bar or a lane label to select its cluster.`,
    head: ["Cluster", "Tier", "Run start", "Run end", "Records"],
    rows: lanes.flatMap((l) => l.runs.map((r) => [l.label, pill(l.tier), fmtTs(r.start), fmtTs(r.end), String(r.count)])),
  });
}

const EDGE_NAMES = { pause: "shared pauses", chain: "probe chain", dialect: "payload dialect", soft: "soft link", fleet: "candidate fleet" };

/** Cluster pairs a hint connects, as graph edges. Unknown shapes are skipped. */
function fleetEdges(keys) {
  const k = (x) => {
    const c = clusterBy(String(x ?? ""));
    return c ? keyOf(c) : null;
  };
  const edges = [];
  const add = (x, y, kind, label, sub = "", name = EDGE_NAMES[kind]) => {
    const p = k(x), q = k(y);
    if (p && q && p !== q && keys.has(p) && keys.has(q)) edges.push({ a: p, b: q, kind, sub, name, label });
  };
  for (const sp of arr(a.shared_pauses)) add(sp.a, sp.b, "pause", `Shared pauses: ${sp.a} and ${sp.b} went quiet together${num(sp.p_chance) != null ? ` (chance ${sp.p_chance.toExponential(1)})` : ""}`);
  for (const p of arr(a.dialect_pairs)) add(p.a, p.b, "dialect", `Payload dialect: ${p.a} and ${p.b} share an uncommon mix of test payloads (Jaccard ${(num(p.jaccard) ?? 0).toFixed(2)})`);
  for (const ch of arr(a.chains)) {
    const ids = [...new Set(arr(ch.members).map((m) => a.results[m]?.cluster).filter((x) => x != null))].map((i) => a.clusters[i]?.id);
    for (let i = 1; i < ids.length; i++) add(ids[0], ids[i], "chain", `Probe chain: ${ids[0]} and ${ids[i]} sent variants of one request on ${host(ch.host)}`);
  }
  // Soft links, one edge style per kind. Shared pauses and dialects are
  // drawn above from their own lists; a kind this page does not know is
  // drawn in the generic soft-link style under its own name.
  for (const s of arr(a.soft_links)) {
    const o = obj(s);
    if (o.kind === "shared_pause" || o.kind === "dialect") continue;
    const ends = arr(o.clusters).length >= 2 ? o.clusters : [o.a ?? o.from ?? o.a_key, o.b ?? o.to ?? o.b_key];
    const name = kindLabel(o.kind);
    const score = num(o.strength ?? o.score);
    const detail = o.detail ?? o.reason;
    add(ends[0], ends[1], "soft", `Soft link, ${name}${detail ? ` (${trunc(String(detail), 140)})` : ""}${score != null ? `, strength ${score.toFixed(2)}` : ""}: a hint, not evidence`, `sk-${kindClass(o.kind)}`, name);
  }
  for (const f of arr(a.candidate_fleets)) {
    const o = Array.isArray(f) ? { clusters: f } : obj(f);
    const members = arr(o.clusters ?? o.members ?? o.keys);
    const name = trunc(String(o.id ?? o.name ?? "candidate fleet"), 60);
    const kinds = arr(o.kinds).map(String).join(", ");
    const score = num(o.strength);
    for (let i = 1; i < members.length; i++) add(members[0], members[i], "fleet", `Candidate fleet ${name} of ${members.length} clusters${kinds ? ` (${kinds})` : ""}${score != null ? `, strength ${score.toFixed(2)}` : ""}: a hint, not evidence`);
  }
  return edges;
}

function viewFleet() {
  const cl = [...a.clusters].sort((x, y) => y.members.length - x.members.length).slice(0, MAX_LANES).sort((x, y) => x.start - y.start);
  const keys = new Set(cl.map(keyOf));
  const nodes = cl.map((c) => ({ key: keyOf(c), label: c.id, tier: c.tier, size: c.members.length, sub: `${c.tier}, ${c.members.length} records, ${c.runs.length} runs` }));
  const edges = fleetEdges(keys);
  // One legend entry per edge style present: each soft-link kind has its own.
  const styles = new Map();
  for (const e of edges) styles.set(`${e.kind} ${e.sub}`.trim(), e.name);
  const chart = fleetGraph({ nodes, edges, selected: sel.c, onSelect: (k) => select({ c: sel.c === k ? null : k, r: null, rule: null }), width: panelWidth() });
  return figure({
    chart,
    legend: legend(legendKey("k-sig", "significant"), legendKey("k-sug", "suggestive"), legendKey("k-noise", "noise"), ...[...styles].map(([cls, name]) => edgeKey(cls, name))),
    caption: `Hints, not evidence: no edge changes a score or merges clusters. Node area is the cluster's record count; clusters sit in order of first activity.${edges.length ? "" : " No hints connect these clusters."}`,
    head: ["Hint", "From", "To", "Detail"],
    rows: edges.map((e) => [e.name, idOf(e.a), idOf(e.b), e.label]),
  });
}

/** Runs as nodes and the interaction hints (S1–S5) between them. */
function swarmData() {
  const nodes = new Map();
  const lanes = new Map();
  const node = (ref) => {
    ref = obj(ref);
    const c = clusterBy(String(ref.key || ref.cluster || ""));
    if (!c) return null;
    const run = arr(c.runs)[(num(ref.run) ?? 1) - 1];
    const strand = ref.strand ? safe(ref.strand, 40) : "";
    const id = `${keyOf(c)}#${ref.run}${strand ? `|${strand}` : ""}`;
    if (!nodes.has(id)) {
      const t = run && run.start > 0 ? (run.start + run.end) / 2 : c.start;
      const label = `${c.id}#${ref.run ?? "?"}${strand ? ` (${strand})` : ""}`;
      nodes.set(id, { id, lane: keyOf(c), t, label, short: `#${ref.run ?? "?"}`, sub: run ? `${fmtShort(run.start)} → ${fmtShort(run.end)} UTC, ${run.count ?? 0} record(s)` : `cluster ${c.id}` });
      lanes.set(keyOf(c), c);
    }
    return id;
  };
  const edges = [];
  for (const e of arr(a.swarm_edges)) {
    const x = node(e.a), y = node(e.b);
    if (!x || !y) continue;
    const k = swarmKind(e.kind);
    const chance = num(e.chance);
    edges.push({
      a: x, b: y, kind: String(e.kind ?? "other").replace(/[^a-z_]/g, ""), strength: String(e.strength ?? "weak").replace(/[^a-z]/g, ""),
      name: `${k.id} ${k.label}`, from: nodes.get(x).label, to: nodes.get(y).label, chance,
      detail: safe(e.detail ?? "", 200),
      label: `${k.id} ${k.label} (${e.strength ?? "?"}): ${nodes.get(x).label} → ${nodes.get(y).label}. ${safe(e.detail ?? "", 160)}${chance != null ? ` Chance ${chance.toExponential(1)}.` : ""} A hint to review, not evidence.`,
    });
  }
  const order = new Map(a.clusters.map((c, i) => [keyOf(c), i]));
  const laneList = [...lanes.values()].sort((p, q) => order.get(keyOf(p)) - order.get(keyOf(q))).slice(0, MAX_LANES)
    .map((c) => ({ key: keyOf(c), label: c.id, tier: c.tier }));
  const keep = new Set(laneList.map((l) => l.key));
  return { lanes: laneList, nodes: [...nodes.values()].filter((n) => keep.has(n.lane)), edges };
}

function viewSwarm() {
  const { lanes, nodes, edges } = swarmData();
  const kinds = [...new Set(edges.map((e) => e.kind))];
  const chart = swarmGraph({ lanes, nodes, edges, selected: sel.c, onSelect: (k) => select({ c: sel.c === k ? null : k, r: null, rule: null }), width: panelWidth() });
  return figure({
    chart,
    legend: legend(...kinds.map((k) => swarmKey(`sk-${k} st-moderate`, `${swarmKind(k).id} ${swarmKind(k).label}`)), swarmKey("st-weak", "weak"), swarmKey("st-strong", "strong")),
    caption: `Interaction hints (SC-T9) between runs: a fleet is many agents doing the same thing, a swarm one whose agents act on each other's output. Each arc is one weak-to-moderate hint; a claim of interaction needs several together and review. None changes a score, links records or merges clusters.${edges.length ? "" : " This input has none."}`,
    head: ["Kind", "Strength", "From", "To", "Chance", "Detail"],
    rows: edges.map((e) => [e.name, e.strength, e.from, e.to, e.chance != null ? e.chance.toExponential(1) : "–", e.detail]),
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
  lastWidth = panel.clientWidth;
  const make = { runs: viewRuns, fleet: viewFleet, swarm: viewSwarm, heat: viewHeat, rhythm: viewRhythm, strip: viewStrip, hourly: viewHourly }[view];
  try {
    panel.replaceChildren(make());
  } catch (e) {
    showError(panel, e);
  }
}

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
const RECORD_HEAD = ["Tier", "Score", "Time (UTC)", "Cluster", "URL (defanged)", "Rules"];
const ENDPOINT_HEAD = ["Host", "Tier", "Hits", "First seen", "Last seen", "Status", "Attack payloads"];
/** A cell labelled with its column, so the rows stack as cards on phones. */
const cell = (head, col, attrs, ...kids) => el("td", { ...attrs, "data-label": head[col] }, ...kids);

// The records list opens short (on phones, where each record is a card,
// and on wide screens alike) with a button for the rest of the selection.
const FEW_ROWS = 10;
let allRecords = false; // the visitor asked for every record of this analysis

function renderRecords() {
  const idx = [...scopeIdx()].sort((x, y) => a.results[y].score - a.results[x].score || a.results[x].obs.ts - a.results[y].obs.ts);
  $("records-h").textContent = `Flagged records (${scopeText()}: ${idx.length})`;
  const capped = idx.slice(0, MAX_ROWS);
  // A selected record past the short list shows the whole list.
  const few = !allRecords && capped.length > FEW_ROWS + 2 && !(sel.r != null && capped.indexOf(sel.r) >= FEW_ROWS);
  const shown = few ? capped.slice(0, FEW_ROWS) : capped;
  const body = el("tbody", {}, shown.map((i) => {
    const r = a.results[i];
    const tr = el("tr", { class: `pick${sel.r === i ? " sel" : ""}`, tabindex: 0, "aria-selected": String(sel.r === i), "aria-label": `Record ${i}, ${r.tier}, score ${r.score}`, "data-focus-key": `rec:${i}` },
      cell(RECORD_HEAD, 0, { class: "rc-head" }, pill(r.tier)), cell(RECORD_HEAD, 1, { class: "num rc-head rc-lab" }, r.score),
      cell(RECORD_HEAD, 2, { class: "nowrap rc-head", title: fmtTs(r.obs.ts) }, fmtShort(r.obs.ts)),
      cell(RECORD_HEAD, 3, { class: "rc-head rc-lab" }, r.cluster != null ? a.clusters[r.cluster]?.id ?? "–" : "–"),
      cell(RECORD_HEAD, 4, { class: "url" }, safe(r.obs.url, 300)),
      cell(RECORD_HEAD, 5, {}, arr(r.hits).map((h) => el("span", { class: "chip" }, h.rule_id))));
    activate(tr, () => select({ r: sel.r === i ? null : i }));
    return tr;
  }));
  if (idx.length > capped.length && !few) body.append(el("tr", {}, el("td", { colspan: 6, class: "hint" }, `${idx.length - capped.length} more not shown; download the analysis JSON for all.`)));
  if (!idx.length) body.append(el("tr", {}, el("td", { colspan: 6, class: "hint" }, "No flagged records in this selection.")));
  const more = few ? el("button", { type: "button", class: "more-rows" }, `Show all ${capped.length}${idx.length > capped.length ? ` of ${idx.length}` : ""} records`) : null;
  more?.addEventListener("click", () => {
    allRecords = true;
    renderRecords();
    // Focus moves to the first record the button revealed.
    const next = $("records").querySelectorAll("tbody tr.pick")[FEW_ROWS];
    next?.focus();
  });
  $("records").replaceChildren(el("div", { class: "scroll" }, el("table", { class: "records" },
    el("thead", {}, el("tr", {}, RECORD_HEAD.map((h) => el("th", { scope: "col" }, h)))), body)), ...(more ? [more] : []));
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
    const c = (col, attrs, ...kids) => cell(ENDPOINT_HEAD, col, attrs, ...kids);
    body.append(el("tr", {},
      c(0, { class: "url" }, host(v.host)), c(1, {}, pill(v.max_tier)), c(2, { class: "num" }, `${v.hits} / ${v.records}`),
      c(3, { class: "nowrap" }, fmtTs(v.first_seen)), c(4, { class: "nowrap" }, fmtTs(v.last_seen)), c(5, {}, String(v.activity ?? "")),
      c(6, {}, v.payloads ? Object.keys(obj(v.payload_rules)).map((r) => el("span", { class: "chip" }, r)) : el("span", { class: "hint" }, "none seen"))));
  }
  $("endpoints").replaceChildren(el("div", { class: "scroll" }, el("table", { class: "endpoints" },
    el("thead", {}, el("tr", {}, ENDPOINT_HEAD.map((h) => el("th", { scope: "col" }, h)))), body)));
}

// ── Context ────────────────────────────────────────────────────────────────
// Wording follows the CLI report (sc-core report). Every hint is descriptive:
// none changes a score or links records. Unknown fields are ignored.
const PACE = { tool: "tool pace", model: "model pace", slow: "slow pace" };

/** Tactic counts as a small bar chart; the counts are in the text. */
function tacticBars(entries) {
  const max = Math.max(1, ...entries.map(([, n]) => n));
  return el("ul", { class: "mini-bars" }, entries.map(([t, n]) => {
    const fill = el("span", { class: "fill" });
    fill.style.width = `${Math.max(4, Math.round((n / max) * 100))}%`;
    return el("li", {}, el("span", { class: "mb-label" }, tactic(t)), el("span", { class: "mb-track", "aria-hidden": "true" }, fill), el("span", { class: "mb-n" }, String(n)));
  }));
}
const BASIS = { request: "request times", submit: "submission times", capture: "archive capture times", mixed: "mixed time sources" };
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
  // Capture times say when an archive saw a request, not when it was sent: no pace.
  const timing = ch.time_basis === "capture"
    ? "capture-timed, so no pace"
    : `median gap ${dur(num(ch.median_gap_secs) ?? 0)}, ${PACE[ch.pace] ?? "unknown pace"}`;
  return `${ch.variants ?? "?"} variants of ${varied} on ${safe(`https://${ch.host ?? ""}${ch.path ?? ""}`, 90).replace(/^hxxps:\/\//, "")} over ${dur(Math.max(0, (ch.end ?? 0) - (ch.start ?? 0)))} (${timing})${notes.length ? "; " + notes.join("; ") : ""}`;
}

function clusterContext(c) {
  const rows = [];
  const row = (k, ...v) => rows.push(el("dt", {}, k), el("dd", {}, ...v));
  const t = obj(c.timing);
  const runs = arr(c.runs);
  row("Records", `${c.members.length} (score ${c.score})`);
  row("Seen", `${fmtTs(c.start)} → ${fmtTs(c.end)}`);
  const prov = topEntries(c.provenance, 4);
  row("Sources", prov.length ? chips(prov.map(([p, n]) => `${provenanceLabel(p)} ×${n}`)) : el("span", { class: "hint" }, "provenance not recorded"),
    c.corroboration ? el("span", { class: `corr ${String(c.corroboration).replace(/[^a-z_]/g, "")}` }, corroborationLabel(c.corroboration)) : null,
    el("div", { class: "hint" }, "who can put such a record into its source; one kind of source alone could be one person submitting URLs"));
  row("Targets", chips(topEntries(c.target_hosts, 6).map(([h, n]) => `${host(h)} ×${n}`)));
  row("Top rules", chips(topEntries(c.rules, 8).map(([r, n]) => `${r} ×${n}`)));
  const tac = topEntries(c.tactics, 9);
  if (tac.length) row("Tactics", tacticBars(tac), el("div", { class: "hint" }, "records per tactic: what the matches show the agent doing; descriptive, never scored"));
  if (num(c.artifacts)) row("Model artifacts", `${c.artifacts} match(es) show only that a model wrote the request (residue, self-identification)`);
  else if (Object.keys(obj(c.artifacts)).length) row("Model artifacts", chips(topEntries(c.artifacts, 8).map(([k, n]) => `${safe(k, 40)} ×${n}`)));
  if (c.time_basis) row("Times are", BASIS[c.time_basis] ?? String(c.time_basis), c.time_basis === "capture" ? el("div", { class: "hint" }, "when an archive saw the requests, not when they were sent: pace and rhythm are weak here") : null);
  const hs = c.header_sets;
  if (Array.isArray(hs) && hs.length) row("Header sets", chips(hs.slice(0, 6).map((h) => safe(typeof h === "string" ? h : JSON.stringify(h), 80))));
  else if (Object.keys(obj(hs)).length) row("Header sets", chips(topEntries(hs, 6).map(([h, n]) => `${safe(h, 80)} ×${n}`)));
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
  const stacks = topEntries(c.relay_stacks, 6);
  if (stacks.length)
    row("Relay stacks", chips(stacks.map(([st, n]) => `${safe(st, 120)} ×${n}`)),
      el("div", { class: "hint" }, "relays and carriers each record went through, outermost first; a stack of two or more hops is one client's habit, not evidence on its own"));
  const bench = topEntries(c.benchmarks, 8);
  if (bench.length)
    row("Benchmark targets", chips(bench.map(([id, n]) => `${safe(id, 60)} ×${n}`)),
      el("div", { class: "hint" }, "public practice or benchmark targets: evaluation or training activity is likely, not malice (a hint; the score is unchanged)"));
  const stale = arr(c.stale_knowledge);
  if (stale.length)
    row("Stale knowledge", el("ul", {}, stale.slice(0, 8).map((u) => el("li", {}, el("code", {}, safe(u.id, 60)),
      ` on ${num(u.records) ?? "?"} records, ${num(u.hosts) ?? "?"} hosts${u.note ? `: ${safe(u.note, 120)}` : ""}`))),
      el("div", { class: "hint" }, "retired endpoints or old clients, consistent with a model writing from old training data; old scripts do the same (a hint)"));
  const prose = obj(c.prose);
  if (num(prose.values)) {
    const langs = topEntries(prose.languages, 8);
    row("Prose in parameters", `${plural(prose.values, "distinct value")} `, langs.length ? chips(langs.map(([l, n]) => `${language(l)} ×${n}`)) : el("span", { class: "hint" }, "language unclear"),
      num(prose.mismatched) ? el("div", {}, `${prose.mismatched} in a language other than their target's country domain`) : null,
      el("div", { class: "hint" }, "an agent prompted in one language often searches a foreign site in it; travellers do too (a hint, not evidence)"));
  }
  const lf = arr(c.link_features);
  if (lf.length) row("Linked by", chips(lf.slice(0, 10).map((x) => safe(typeof x === "string" ? x : JSON.stringify(x), 90))), lf.length > 10 ? el("span", { class: "hint" }, ` ${lf.length - 10} more`) : null);
  const mine = new Set(arr(c.members));
  const chains = arr(a.chains).filter((ch) => arr(ch.members).some((m) => mine.has(m)));
  if (chains.length) row("Probe chains", el("ul", {}, chains.slice(0, 10).map((ch) => el("li", {}, chainLine(ch)))), el("div", { class: "hint" }, "the pace is a hint, not evidence"));
  const toReport = el("button", { type: "button" }, "Draft a report for this cluster");
  toReport.addEventListener("click", () => {
    startReport();
    goStep("report");
    $("h-report").scrollIntoView({ block: "start" });
  });
  return [
    el("div", { class: "ctx-head" }, el("h3", {}, `Cluster ${c.id}`), pill(c.tier), el("span", { class: "chip" }, keyOf(c))),
    ladderOf(c.agent, safe),
    scopePanel(c.scope, { safe, pick: (i) => select({ r: i }), fmLink: fm15() }),
    el("dl", { class: "kv" }, rows),
    attributionPanel(c),
    plantReview(c),
    el("div", { class: "row" }, toReport),
  ];
}

/** The page's link to FM chapter 15 (a template in the page: scripts make no links). */
const fm15 = () => $("tpl-fm15")?.content.cloneNode(true) ?? null;

/** Attribution layers, from the tools module (loaded on request). */
function attributionPanel(c) {
  const box = el("div", { class: "attr-box" });
  const btn = el("button", { type: "button" }, "Show attribution layers");
  const load = async () => {
    btn.disabled = true;
    try {
      const t = await prepared();
      const res = JSON.parse(t.attribution(JSON.stringify({ cluster: keyOf(c), claims: readClaims() ?? [], min_named: $("min-named").value })));
      box.replaceChildren(
        el("p", { class: "hint" }, `What the records support at each layer, gated as a report at the naming level chosen under Report, with any claims from case work there.${res.withheld ? ` ${res.withheld} developer candidate(s) below that level are not shown.` : ""}`),
        layersTable(res.layers));
    } catch (e) {
      showError(box, e);
    }
  };
  btn.addEventListener("click", load);
  box.append(el("p", { class: "hint" }, "Developer, host, harness and model family: who the records point at, and on what evidence. Loads the report tools."), btn);
  return el("section", { class: "ctx-section", "aria-label": "Attribution layers" }, el("h4", {}, "Attribution"), box);
}

/** Plant signals: for internal review only, never on a public page. */
function plantReview(c) {
  const ps = arr(c.plant_signals);
  return el("details", { class: "internal-review" },
    el("summary", {}, "Internal review: plant signals ", el("span", { class: "badge" }, ps.length ? String(ps.length) : "none")),
    el("p", { class: "hint" }, "Signs a cluster may have been planted, for whoever reviews this file. A prompt to check, never a finding: never scored, never linked on, never in a public notice or report. A signal most clusters in this input carry is shown with its base rate and does not count toward review."),
    ps.length
      ? el("ul", {}, ps.map((p) => {
        const rate = num(p.base_rate);
        return el("li", { class: rate != null ? "base-rated" : null }, el("strong", {}, plantLabel(p.kind)), p.detail ? `: ${safe(p.detail, 200)}` : "",
          el("span", { class: "hint" }, ` (${plural(arr(p.records).length, "record")})`),
          rate != null ? el("div", { class: "hint" }, `Base rate: ${Math.round(rate * 100)}% of the clusters here carry it. Context, not counted toward review.`) : null);
      }))
      :el("p", { class: "hint" }, "No plant signals on this cluster."));
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
  row("Rules", el("ul", {}, arr(r.hits).map((h) => el("li", {}, el("strong", {}, h.rule_id), ` +${h.weight}`,
    h.tactic ? el("span", { class: "chip" }, tactic(h.tactic)) : null, h.artifact ? el("span", { class: "chip" }, "model artifact") : null,
    h.matched ? [": ", el("code", {}, safe(h.matched, 160))] : null))));
  const sum = arr(r.hits).reduce((t, h) => t + Math.max(0, num(h.weight) ?? 0), 0);
  if (sum !== r.score) row("Score", `${r.score}, not the ${sum} the weights add to: rules that read one artifact count once per independence group, and context hits (relays, cache-busters, self-identification, headers, outcomes) together count at most one less than suggestive (FM-4.11).`);
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
  const common = arr(a.common_features);
  if (common.length) {
    out.push(el("h4", {}, `Common features (${common.length})`));
    out.push(el("p", { class: "hint" }, "Values many unrelated records share (a popular tool's tag, a shared service): kept from linking, shown so they are not read as one operator."));
    out.push(el("ul", {}, common.slice(0, 20).map((f) => el("li", {}, el("code", {}, safe(typeof f.feature === "string" ? f.feature : JSON.stringify(f.feature), 80)),
      ` in ${f.records ?? "?"} records on ${f.hosts ?? "?"} hosts${f.reason ? `: ${safe(f.reason, 120)}` : ""}`))));
  }
  const esc = arr(a.escalations);
  if (esc.length) {
    out.push(el("h4", {}, `Escalations (${esc.length})`));
    out.push(el("p", { class: "hint" }, "One target asked for again by another route (direct, then through a relay or carrier): tool escalation, a hint to check."));
    out.push(el("ul", {}, esc.slice(0, 20).map((e) => el("li", {}, el("code", {}, safe(`https://${e.host ?? ""}${e.path ?? ""}`, 90).replace(/^hxxps:\/\//, "")),
      `: ${arr(e.steps).map((s) => route(s.route)).join(" → ")} over ${dur(Math.max(0, (e.end ?? 0) - (e.start ?? 0)))}`,
      arr(e.clusters).length ? ` (clusters ${arr(e.clusters).map((x) => safe(x, 20)).join(", ")})` : "",
      e.time_basis === "capture" ? el("span", { class: "hint" }, " capture-timed") : null))));
  }
  const soft = arr(a.soft_links), fleets = arr(a.candidate_fleets);
  if (soft.length || fleets.length) {
    const edges = fleetEdges(new Set(a.clusters.map(keyOf))).filter((e) => e.kind === "soft");
    if (fleets.length) {
      out.push(el("h4", {}, `Candidate fleets (${fleets.length})`));
      out.push(el("ul", {}, fleetItems(fleets.slice(0, 20), idOf)));
    }
    out.push(el("h4", {}, `Soft links (${edges.length})`));
    out.push(edges.length ? el("ul", {}, edges.slice(0, 40).map((e) => el("li", {}, el("strong", {}, `${idOf(e.a)} and ${idOf(e.b)}`), ` ${e.label}`))) : el("p", { class: "hint" }, "None between these clusters beyond the shared pauses and dialects above."));
  }
  const sw = swarmData().edges;
  if (sw.length) {
    out.push(el("h4", {}, `Interaction hints (${sw.length})`));
    out.push(el("p", { class: "hint" }, "Runs that may act on each other's output (S1–S5): weak-to-moderate hints, never a merge. See the Swarm view."));
    out.push(el("ul", {}, sw.slice(0, 40).map((e) => el("li", {}, el("strong", {}, `${e.name} (${e.strength})`), ` ${e.from} → ${e.to}: ${e.detail}`))));
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

/** The tools module, holding this analysis (re-run on the same input). */
async function prepared() {
  const t = await tools();
  if (preparedGen !== generation) {
    t.prepare(source.input, source.format, source.map, rules);
    preparedGen = generation;
  }
  return t;
}

/**
 * The audience choice as report options. The public notice has two stages
 * (docs/policies.md): the indicator notice names no host, so it passes an
 * empty set of target descriptions, which makes the engine name none and
 * count the rest; the naming update is the public report with hosts.
 */
function audienceOpts(v) {
  if (v === "indicator") return { audience: "public", target_descriptions: {} };
  if (v === "naming" || v === "public") return { audience: "public" };
  return { audience: v };
}

let reportSeq = 0;
async function renderReport() {
  if (!a) return;
  const claims = readClaims();
  if (claims == null) {
    $("report").textContent = "Fix the claims JSON to draft a report.";
    return;
  }
  if (!wantReport) {
    $("report").textContent = `Drafting loads the report tools${sizeNote("toolsSize")}. Press "Draft the report", or scroll here.`;
    return;
  }
  const opts = {
    ...audienceOpts($("audience").value),
    cluster: sel.c,
    reporter: $("reporter").value || null,
    generated: new Date().toISOString().slice(0, 10),
    max_evidence: 10,
    min_named: $("min-named").value,
    claims,
  };
  const my = ++reportSeq;
  try {
    const t = await prepared();
    if (my !== reportSeq) return;
    $("report").textContent = t.report(JSON.stringify(opts));
    for (const b of ["copy-report", "dl-report"]) $(b).disabled = false;
  } catch (e) {
    if (my === reportSeq) $("report").textContent = String(e?.message ?? e);
  }
}

function startReport() {
  if (wantReport) return;
  wantReport = true;
  renderReport();
}
$("draft-report").addEventListener("click", startReport);
// Sightings to share: built by the tools module from this analysis, shown in
// full, saved only on Download.
sightingsPanel(async () => (a ? prepared() : null));
// Reaching the report section starts the draft (and the module download).
if ("IntersectionObserver" in window) {
  new IntersectionObserver((entries) => {
    if (a && entries.some((e) => e.isIntersecting)) startReport();
  }).observe($("report"));
}

// ── Wiring ─────────────────────────────────────────────────────────────────
async function loadExample() {
  try {
    $("input").value = await fetchRoot("assets/example.ndjson", "text");
  } catch (e) {
    return showAlert($("alert"), "The example did not load.", String(e?.message ?? e));
  }
  syncRun();
  $("format").value = "ndjson";
  syncPlaceholder();
  $("map").value = "";
  $("preset-note").hidden = true;
  if (runAnalysis()) $("example-note").hidden = false;
}

$("run").addEventListener("click", () => {
  $("example-note").hidden = true;
  runAnalysis();
});
$("example").addEventListener("click", loadExample);
$("input").addEventListener("input", () => {
  $("example-note").hidden = true;
  syncRun();
});
$("input-edit").addEventListener("click", () => expandInput(true));
$("file").addEventListener("change", async (e) => {
  const f = e.target.files[0];
  if (!f) return;
  $("example-note").hidden = true;
  $("input").value = await f.text();
  syncRun();
  runAnalysis();
});
syncRun();
// The records box shows a sample of the format picked: a Common Log Format
// line for an access log (a documentation address and a placeholder path).
const NDJSON_PLACEHOLDER = $("input").placeholder;
const ACCESS_LOG_PLACEHOLDER = '203.0.113.7 - - [04/Oct/2026:08:10:00 +0000] "GET /search?q=... HTTP/1.1" 200 512 "-" "Mozilla/5.0"';
function syncPlaceholder() {
  $("input").placeholder = $("format").value === "access_log" ? ACCESS_LOG_PLACEHOLDER : NDJSON_PLACEHOLDER;
}
$("format").addEventListener("change", syncPlaceholder);
for (const id of ["audience", "min-named"]) $(id).addEventListener("change", renderReport);
$("reporter").addEventListener("input", renderReport);
$("claims").addEventListener("input", () => (a ? renderReport() : readClaims()));
$("copy-report").addEventListener("click", () => navigator.clipboard?.writeText($("report").textContent));
$("dl-report").addEventListener("click", () => download("swarmchase-report.md", $("report").textContent, "text/markdown"));
$("dl-json").addEventListener("click", () => a && download("swarmchase-analysis.json", JSON.stringify(a, null, 2), "application/json"));

{
  const h = readHash();
  // The view is set after the example loads: setting it rewrites the hash,
  // which still holds the selection the example's analysis reads.
  if (h.preset === "access-log") {
    $("format").value = "access_log";
    syncPlaceholder();
    $("map").placeholder = "host=www.example.org (your own host)";
    // The preset's instructions come before the box they are about.
    $("input-box").prepend($("preset-note"));
    $("preset-note").hidden = false;
    $("input").focus();
  } else if (h.example) {
    await loadExample();
  }
  if (h.v) setView(h.v);
}
