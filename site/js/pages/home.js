// The landing page's walk through the method. Every step is drawn by the
// server and reads without this script. "Run it live" loads the engine,
// re-runs the synthetic showcase in this page, and adds to the steps: an
// unwrap box for any URL, zoomable runs, the interaction graph, each
// cluster's agent-likelihood ladder, and each cluster's scope tests. Record text is shown defanged, never
// as a link.
import { $, el, activate, fetchRoot, showError } from "../lib/dom.js";
import { arr, obj, fmtTs, fmtShort, dur, trunc, plural } from "../lib/fmt.js";
import { engine, host as hostOf } from "../lib/wasm.js";
import { figure, legend, legendKey, swarmKey, swimlanes, runExtent, zoomWindow, swarmGraph } from "../lib/charts.js";
import { swarmKind, levelOf } from "../lib/hints.js";
import { agentLadder } from "../lib/agent.js";
import { scopePanel } from "../lib/scope.js";

const box = document.querySelector("[data-live-box]");
const out = document.querySelector("[data-live-out]");
const slot = (id) => document.querySelector(`[data-live-slot="${id}"]`);
if (box) box.hidden = false;

let sc = null;
let a = null;
const safe = (s, n = 120) => trunc(sc.defang(String(s ?? "")), n);
const width = (node) => Math.max(320, (node?.clientWidth || 640) - 4);

function show(id, ...nodes) {
  const s = slot(id);
  if (!s) return;
  s.hidden = false;
  s.replaceChildren(el("p", { class: "live-tag" }, "Live, in this page"), ...nodes);
}

// ── Step 1: unwrap any URL ─────────────────────────────────────────────
function unwrapBox(example) {
  const input = el("input", { class: "grow", id: "live-url", spellcheck: "false", autocomplete: "off", placeholder: "https://r.jina.ai/https://..." });
  const res = el("div", { "aria-live": "polite" });
  const run = () => {
    let x;
    try {
      x = JSON.parse(sc.unwrap(input.value.trim(), ""));
    } catch (e) {
      return showError(res, e);
    }
    const byLayer = {};
    for (const h of arr(x.hits)) (byLayer[h.layer] ??= []).push(h);
    res.replaceChildren(
      el("p", {}, `Score ${x.score ?? 0} · target `, el("code", {}, x.target_host ? hostOf(sc, x.target_host) : "unknown")),
      ...arr(x.layers).map((l, i) => el("div", { class: `layer d${Math.min(4, Number(l.depth) || 0)}` },
        el("div", { class: "via" }, `[${i}] ${l.via}${l.host ? " · " + hostOf(sc, l.host) : ""}`),
        el("code", {}, safe(l.text, 400)),
        el("div", {}, (byLayer[i] ?? []).map((h) => el("span", { class: "chip" }, `${h.rule_id} +${h.weight}`))))));
  };
  const go = el("button", { type: "button", class: "primary" }, "Unwrap");
  go.addEventListener("click", run);
  input.addEventListener("keydown", (e) => e.key === "Enter" && run());
  const use = el("button", { type: "button" }, "Use the example's URL");
  use.addEventListener("click", () => {
    input.value = example ?? "";
    run();
  });
  return [
    el("label", { for: "live-url" }, "Unwrap a URL of your own (it is decoded here, never opened)"),
    el("div", { class: "row" }, input, go, example ? use : null),
    res,
  ];
}

// ── Step 4: zoomable runs and the interaction graph ────────────────────
let zoom = null;
function timeFigures() {
  const node = slot("time");
  const lanes = a.clusters.filter((c) => arr(c.runs).some((r) => r.start > 0))
    .map((c) => ({ key: c.key || c.id, label: c.id, tier: c.tier, runs: c.runs.filter((r) => r.start > 0) }));
  const full = runExtent(lanes);
  const redraw = (next) => {
    zoom = next;
    timeFigures();
    node.querySelector("svg.swim")?.focus({ preventScroll: true });
  };
  const chart = swimlanes({ lanes, pauses: arr(a.timing?.pauses), width: width(node), label: "Runs per cluster over time, UTC", domain: zoom, onZoom: redraw });
  const [t0, t1] = zoom ?? full ?? [0, 0];
  const reset = el("button", { type: "button", disabled: !zoom }, "Show the whole span");
  reset.addEventListener("click", () => redraw(null));
  const zin = el("button", { type: "button", "aria-label": "Zoom in" }, "+");
  zin.addEventListener("click", () => redraw(zoomWindow(full, zoom, 0.5)));
  const runsFig = figure({
    chart: el("div", {}, el("div", { class: "zoom-tools" }, zin, reset,
      el("span", { class: "hint" }, zoom ? `${fmtTs(t0)} → ${fmtTs(t1)} (${dur(t1 - t0)})` : "Drag across the runs to zoom; with the chart focused, + − ← → and 0.")), chart),
    legend: legend(legendKey("k-sig", "significant"), legendKey("k-sug", "suggestive"), legendKey("k-pause", "pause")),
    caption: "The same runs, drawn live: zoom into the two days.",
    head: ["Cluster", "Tier", "Run start", "Run end", "Records"],
    rows: lanes.flatMap((l) => l.runs.map((r) => [l.label, l.tier, fmtTs(r.start), fmtTs(r.end), String(r.count)])),
  });
  // Runs as nodes, hints as arcs.
  const nodes = new Map();
  const laneKeys = new Map();
  const nodeOf = (ref) => {
    const c = a.clusters.find((x) => x.key === ref?.key || x.id === ref?.cluster);
    if (!c) return null;
    const run = arr(c.runs)[(ref.run ?? 1) - 1];
    const strand = ref.strand ? safe(ref.strand, 40) : "";
    const id = `${c.id}#${ref.run}|${strand}`;
    laneKeys.set(c.key || c.id, c);
    if (!nodes.has(id)) nodes.set(id, { id, lane: c.key || c.id, t: run ? (run.start + run.end) / 2 : c.start, label: `${c.id}#${ref.run}${strand ? ` (${strand})` : ""}`, short: `#${ref.run}`, sub: run ? `${fmtShort(run.start)} → ${fmtShort(run.end)} UTC` : c.id });
    return id;
  };
  const edges = arr(a.swarm_edges).map((e) => {
    const x = nodeOf(e.a), y = nodeOf(e.b);
    const k = swarmKind(e.kind);
    return x && y ? { a: x, b: y, kind: String(e.kind).replace(/[^a-z_]/g, ""), strength: String(e.strength).replace(/[^a-z]/g, ""), name: `${k.id} ${k.label}`, label: `${k.id} ${k.label} (${e.strength}): ${nodes.get(x).label} → ${nodes.get(y).label}. ${safe(e.detail, 160)}` } : null;
  }).filter(Boolean);
  const order = new Map(a.clusters.map((c, i) => [c.key || c.id, i]));
  const slanes = [...laneKeys.values()].sort((p, q) => order.get(p.key || p.id) - order.get(q.key || q.id)).map((c) => ({ key: c.key || c.id, label: c.id, tier: c.tier }));
  const kinds = [...new Set(edges.map((e) => e.kind))];
  const swarmFig = figure({
    chart: swarmGraph({ lanes: slanes, nodes: [...nodes.values()], edges, width: width(node) }),
    legend: legend(...kinds.map((k) => swarmKey(`sk-${k} st-moderate`, `${swarmKind(k).id} ${swarmKind(k).label}`))),
    caption: "Hover or focus an arc for the hint it rests on. Each is a hint for review, never a merge.",
    head: ["Hint", "Strength", "Between"],
    rows: edges.map((e) => [e.name, e.strength, e.label]),
  });
  show("time", runsFig, swarmFig);
}

// ── Step 5: each cluster's ladder ──────────────────────────────────────
function gradePicker() {
  const panel = el("div", { class: "ladder-live" });
  let current = null;
  const buttons = a.clusters.map((c) => {
    const lv = levelOf(c.agent?.level);
    const b = el("button", { type: "button", "aria-pressed": "false" }, `${c.id}`, el("span", { class: "hint" }, ` ${lv?.code ?? "L?"}`));
    activate(b, () => pick(c, b));
    return b;
  });
  function pick(c, b) {
    current?.setAttribute("aria-pressed", "false");
    b.setAttribute("aria-pressed", "true");
    current = b;
    panel.replaceChildren(agentLadder(c.agent, safe));
  }
  show("grade", el("p", { class: "hint" }, "Pick a cluster to see the rungs, the signals on each and any cap:"), el("div", { class: "row cluster-pick" }, buttons), panel);
  const first = a.clusters.find((c) => arr(c.agent?.caps).length) ?? a.clusters[0];
  if (first) pick(first, buttons[a.clusters.indexOf(first)]);
}

// ── Step 6: each cluster's scope tests ─────────────────────────────────
function scopePicker() {
  const assessed = a.clusters.filter((c) => arr(c.scope?.tests).length);
  if (!assessed.length) return;
  const panel = el("div", { class: "ladder-live" });
  let current = null;
  const FIND = { in_scope: "in scope", scope_exceeded: "exceeded", not_assessable: "n/a" };
  const buttons = assessed.map((c) => {
    const b = el("button", { type: "button", "aria-pressed": "false" }, c.id, el("span", { class: "hint" }, ` ${FIND[c.scope.finding] ?? "?"}`));
    activate(b, () => pick(c, b));
    return b;
  });
  function pick(c, b) {
    current?.setAttribute("aria-pressed", "false");
    b.setAttribute("aria-pressed", "true");
    current = b;
    panel.replaceChildren(scopePanel(c.scope, { safe }));
  }
  show("scope", el("p", { class: "hint" }, "Pick a cluster to see its four answers and each test with the records it rests on:"), el("div", { class: "row cluster-pick" }, buttons), panel);
  // Open on a cluster with a payload but in scope, where the two differ.
  const first = assessed.find((c) => c.scope.payload_present && !c.scope.out_of_scope) ?? assessed[0];
  pick(first, buttons[assessed.indexOf(first)]);
}

async function runLive() {
  const btn = document.querySelector("[data-live]");
  btn.disabled = true;
  try {
    sc = await engine();
    const text = await fetchRoot("assets/example.ndjson", "text");
    const t = performance.now();
    a = JSON.parse(sc.analyze(text, "ndjson", "", "")).analysis;
    const ms = Math.round(performance.now() - t);
    out.textContent = `Ran in this page in ${ms} ms: ${plural(a.total, "record")}, ${plural(a.flagged, "flagged record")}, ${plural(a.clusters.length, "cluster")}, ${plural(arr(a.swarm_edges).length, "interaction hint")}. The same engine runs in the workbench.`;
    const deepest = [...a.results].filter((r) => r.tier !== "noise").sort((x, y) => arr(y.layers).length - arr(x.layers).length || y.score - x.score)[0];
    show("unwrap", ...unwrapBox(deepest?.obs?.url));
    timeFigures();
    gradePicker();
    scopePicker();
    btn.textContent = "Ran live";
  } catch (e) {
    btn.disabled = false;
    showError(out, e);
  }
}

document.querySelector("[data-live]")?.addEventListener("click", runLive);

let resizeTimer = 0;
window.addEventListener("resize", () => {
  clearTimeout(resizeTimer);
  resizeTimer = setTimeout(() => a && timeFigures(), 200);
});
