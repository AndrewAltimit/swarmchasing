// Charts as inline SVG built with DOM calls: no library, no markup strings,
// no style attributes (classes only, so the CSP holds). Every chart comes
// with a table view, and every mark that carries a tooltip shows it on hover,
// keyboard focus and tap. Labels are record-derived text: they go in as text.

import { el, svg, activate, download, roving } from "./dom.js";
import { tip } from "./tip.js";

export { tip };
import { fmtShort, fmtTs, dur } from "./fmt.js";

// Presentation properties copied onto a chart's exported copy, so the file
// draws as the page does without the site's stylesheet.
const EXPORT_PROPS = ["fill", "fill-opacity", "stroke", "stroke-width", "stroke-dasharray", "stroke-linecap", "stroke-linejoin", "stroke-opacity", "paint-order", "opacity", "font-family", "font-size", "font-weight", "visibility", "dominant-baseline"];

/**
 * A chart as a standalone SVG file: a copy with each element's computed
 * style set through CSSOM (the copy is never put in the page) and the page
 * background behind it. Text stays text: record-derived labels are never
 * markup.
 */
export function svgFile(chart) {
  const copy = chart.cloneNode(true);
  const from = [chart, ...chart.querySelectorAll("*")];
  const to = [copy, ...copy.querySelectorAll("*")];
  from.forEach((node, i) => {
    const cs = getComputedStyle(node);
    for (const p of EXPORT_PROPS) to[i].style.setProperty(p, cs.getPropertyValue(p));
    to[i].removeAttribute("tabindex");
  });
  const box = chart.viewBox?.baseVal;
  const bg = svg("rect", { x: box?.x ?? 0, y: box?.y ?? 0, width: box?.width ?? chart.getAttribute("width") ?? "100%", height: box?.height ?? chart.getAttribute("height") ?? "100%" });
  bg.style.setProperty("fill", getComputedStyle(document.body).getPropertyValue("background-color"));
  copy.prepend(bg);
  copy.setAttribute("xmlns", "http://www.w3.org/2000/svg");
  return '<?xml version="1.0" encoding="UTF-8"?>\n' + new XMLSerializer().serializeToString(copy);
}

/** A file name from a chart's label: `swarmchase-runs-per-cluster.svg`. */
const fileName = (label) => `swarmchase-${String(label || "chart").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 60) || "chart"}.svg`;

/**
 * A chart with its legend, caption, a "View as table" toggle and, for an SVG
 * chart, a download. `what` names the chart in its toggle ("View the runs as
 * a table") where a step shows more than one.
 */
export function figure({ chart, legend = null, caption = null, head = [], rows = [], what = "" }) {
  const table = el("div", { class: "scroll", hidden: true },
    el("table", {}, el("thead", {}, el("tr", {}, head.map((h) => el("th", { scope: "col" }, h)))),
      el("tbody", {}, rows.map((r) => el("tr", {}, r.map((c) => el("td", {}, c)))))));
  const asTable = what ? `View ${what} as a table` : "View as table";
  const asChart = what ? `View ${what} as a chart` : "View as chart";
  const btn = el("button", { type: "button", "aria-expanded": "false" }, asTable);
  btn.addEventListener("click", () => {
    const open = table.hidden;
    table.hidden = !open;
    chart.hidden = open;
    btn.setAttribute("aria-expanded", String(open));
    btn.textContent = open ? asChart : asTable;
  });
  const svgChart = chart instanceof SVGSVGElement ? chart : chart.querySelector?.("svg.chart");
  let save = null;
  if (svgChart) {
    save = el("button", { type: "button", title: "Download this chart as an SVG file" }, "Download SVG");
    save.addEventListener("click", () => {
      // The chart may have been redrawn since: take the one shown now.
      const now = chart instanceof SVGSVGElement ? chart : chart.querySelector?.("svg.chart") ?? svgChart;
      download(fileName(now.getAttribute("aria-label")), svgFile(now), "image/svg+xml");
    });
  }
  return el("figure", { class: "chart-box" },
    el("div", { class: "chart-tools" }, legend ?? el("span"), el("span", { class: "chart-buttons" }, btn, save)), chart, table,
    caption ? el("figcaption", {}, caption) : null);
}

export const legendKey = (cls, label) => el("span", {}, el("span", { class: `key ${cls}` }), label);
/** A legend entry drawn with the edge's own classes, so it matches the graph. */
export const edgeKey = (cls, label) => el("span", {}, svg("svg", { class: "chart key-line", viewBox: "0 0 26 10", width: 26, height: 10, "aria-hidden": "true" }, svg("path", { class: `edge ${cls}`, d: "M1,5 L25,5" })), label);
/** A legend entry for an interaction-edge kind (S1–S6) or strength. */
export const swarmKey = (cls, label) => el("span", {}, svg("svg", { class: "chart key-line", viewBox: "0 0 26 10", width: 26, height: 10, "aria-hidden": "true" }, svg("path", { class: `sedge ${cls}`, d: "M1,5 L25,5" })), label);
export const legend = (...keys) => el("p", { class: "legend" }, keys);
export const tierLegend = () => legend(legendKey("k-sig", "significant"), legendKey("k-sug", "suggestive"), legendKey("k-noise", "noise"));

/** Spans cut to [t0, t1]; spans outside it dropped. */
const clip = (spans, t0, t1) => spans.map((p) => ({ ...p, start: Math.max(p.start, t0), end: Math.min(p.end, t1) })).filter((p) => p.end > p.start);

function axisTicks(t0, t1, n) {
  const out = [];
  for (let i = 0; i <= n; i++) out.push(t0 + ((t1 - t0) * i) / n);
  return out;
}

/** The full time extent of swim-lane runs, or null. */
export function runExtent(lanes) {
  const all = lanes.flatMap((l) => l.runs);
  if (!all.length) return null;
  return [Math.min(...all.map((r) => r.start)), Math.max(...all.map((r) => r.end))];
}

/**
 * A zoomed time window: `domain` scaled by `factor` around its centre
 * (below 1 zooms in) and moved by `shift` of its width, kept inside `full`.
 * Returns null when the result covers the whole extent.
 */
export function zoomWindow(full, domain, factor = 1, shift = 0) {
  const [f0, f1] = full;
  const [d0, d1] = domain ?? full;
  const w = Math.min(f1 - f0, Math.max(60, (d1 - d0) * factor));
  let c = (d0 + d1) / 2 + shift * (d1 - d0);
  c = Math.max(f0 + w / 2, Math.min(f1 - w / 2, c));
  const out = [c - w / 2, c + w / 2];
  return out[0] <= f0 && out[1] >= f1 ? null : out;
}

/**
 * The buttons over a zoomable swim-lane chart: zoom in and out, earlier,
 * later, reset, and (with `onFit`) the fit-to-activity toggle. `full` is
 * the whole span, `zoom` the window shown (null for all of it), `setZoom`
 * takes the next window.
 */
export function zoomTools({ full, zoom, setZoom, fit = false, onFit = null }) {
  const b = (label, text, fn, disabled = false) => {
    const x = el("button", { type: "button", "aria-label": label, disabled }, text);
    x.addEventListener("click", fn);
    return x;
  };
  const [t0, t1] = zoom ?? full;
  let fitBtn = null;
  if (onFit) {
    fitBtn = el("button", { type: "button", "aria-pressed": String(fit), disabled: !!zoom, title: "Shrink idle stretches so runs days apart stay readable" }, "Fit to activity");
    fitBtn.addEventListener("click", onFit);
  }
  return el("div", { class: "zoom-tools" },
    fitBtn,
    b("Zoom in", "+", () => setZoom(zoomWindow(full, zoom, 0.5))),
    b("Zoom out", "−", () => setZoom(zoomWindow(full, zoom, 2)), !zoom),
    b("Earlier", "◀", () => setZoom(zoomWindow(full, zoom, 1, -0.25)), !zoom),
    b("Later", "▶", () => setZoom(zoomWindow(full, zoom, 1, 0.25)), !zoom),
    b("Show the whole span", "Reset", () => setZoom(null), !zoom),
    el("span", { class: "hint", "aria-live": "polite" }, zoom ? `${fmtTs(t0)} → ${fmtTs(t1)} (${dur(t1 - t0)}), to scale` : `${fit && onFit ? "Idle stretches shrink to hatched gaps. " : ""}Drag across the chart to zoom; with the chart focused, + − ← → and 0.`));
}

// The width an idle stretch keeps when the runs are fitted to activity.
const GAP_PX = 22;

/**
 * A time scale fitted to activity: the runs' active stretches share the
 * width by duration (each at least a sliver), and every idle stretch longer
 * than a few percent of the span shrinks to GAP_PX. Returns null when there
 * is no idle stretch to shrink. `x` maps a time to a position, `t` back.
 */
export function fitScale(runs, t0, t1, x0, x1) {
  const total = Math.max(60, t1 - t0);
  const minGap = Math.max(600, total * 0.05);
  const sorted = runs.map((r) => [Math.max(t0, r.start), Math.min(t1, r.end)]).filter(([a, b]) => b >= a).sort((p, q) => p[0] - q[0]);
  const segs = [];
  for (const [a, b] of sorted) {
    const last = segs[segs.length - 1];
    if (last && a - last[1] < minGap) last[1] = Math.max(last[1], b);
    else segs.push([a, b]);
  }
  if (segs.length < 2) return null;
  const avail = x1 - x0 - GAP_PX * (segs.length - 1);
  if (avail < 80) return null;
  const weight = segs.map(([a, b]) => Math.max(b - a, total * 0.03, 60));
  const sum = weight.reduce((n, w) => n + w, 0);
  const pieces = [];
  let px = x0;
  segs.forEach(([a, b], i) => {
    const w = (avail * weight[i]) / sum;
    pieces.push({ t0: a, t1: b, p0: px, p1: px + w, gap: false });
    px += w;
    if (i < segs.length - 1) {
      pieces.push({ t0: b, t1: segs[i + 1][0], p0: px, p1: px + GAP_PX, gap: true });
      px += GAP_PX;
    }
  });
  const lerp = (v, a0, a1, b0, b1) => (a1 === a0 ? (b0 + b1) / 2 : b0 + ((v - a0) / (a1 - a0)) * (b1 - b0));
  const x = (t) => {
    const p = pieces.find((q) => t <= q.t1) ?? pieces[pieces.length - 1];
    return lerp(Math.max(p.t0, Math.min(p.t1, t)), p.t0, p.t1, p.p0, p.p1);
  };
  const t = (v) => {
    const p = pieces.find((q) => v <= q.p1) ?? pieces[pieces.length - 1];
    return lerp(Math.max(p.p0, Math.min(p.p1, v)), p.p0, p.p1, p.t0, p.t1);
  };
  return { x, t, pieces };
}

/**
 * Run swim-lanes: a lane per cluster, a bar per run, `pauses` (input-wide)
 * shaded, `bands` (shared pauses, per lane key) outlined. With `onZoom`,
 * dragging across the plot zooms to that span, and the chart takes + and -
 * (zoom), the arrow keys (pan) and 0 (reset) when focused; `domain` is the
 * window shown, null for everything. With `fit` and no `domain`, idle
 * stretches shrink to a marked gap ([`fitScale`]), so runs days apart stay
 * readable; a zoomed window is always drawn to scale.
 */
export function swimlanes({ lanes, pauses = [], bands = [], selected = null, onSelect = null, width = 900, label, domain = null, onZoom = null, fit = false, empty = null }) {
  const full = runExtent(lanes);
  if (!full) {
    // A run belongs to a cluster: with none formed there is nothing to draw,
    // however well the records are timed.
    return el("p", { class: "hint" }, empty ?? (lanes.length
      ? "These clusters have no timestamped runs to draw."
      : "No clusters formed, so there are no runs to draw: records link into a cluster through shared identifiers or close timing. Every flagged record is still listed in the flagged-records table."));
  }
  const [t0, t1] = domain ?? full;
  const span = Math.max(60, t1 - t0);
  const W = Math.max(320, width), LH = 26, L = 56, R = 10, T = 6, B = 26;
  const H = T + B + LH * lanes.length;
  const fitted = fit && !domain ? fitScale(lanes.flatMap((l) => l.runs), t0, t1, L, W - R) : null;
  const x = fitted ? fitted.x : (t) => L + ((t - t0) / span) * (W - L - R);
  const tAt = fitted ? fitted.t : (px) => t0 + ((px - L) / (W - L - R)) * span;
  const root = svg("svg", {
    class: `chart swim${onZoom ? " zoomable" : ""}`, viewBox: `0 0 ${W} ${H}`, width: W, height: H, role: "group", "aria-label": label,
    tabindex: onZoom ? 0 : null, "aria-keyshortcuts": onZoom ? "+ - ArrowLeft ArrowRight 0" : null,
  });
  if (onZoom) {
    // The brush: a drag across the empty plot area selects a span.
    const area = svg("rect", { class: "brush-area", x: L, y: T, width: W - L - R, height: H - T - B });
    const brush = svg("rect", { class: "brush", x: L, y: T, width: 0, height: H - T - B, visibility: "hidden" });
    const toSvg = (ev) => {
      const r = root.getBoundingClientRect();
      return Math.max(L, Math.min(W - R, ((ev.clientX - r.left) * W) / (r.width || W)));
    };
    let from = null;
    area.addEventListener("pointerdown", (ev) => {
      from = toSvg(ev);
      area.setPointerCapture?.(ev.pointerId);
      brush.setAttribute("x", from);
      brush.setAttribute("width", 0);
      brush.setAttribute("visibility", "visible");
    });
    area.addEventListener("pointermove", (ev) => {
      if (from == null) return;
      const to = toSvg(ev);
      brush.setAttribute("x", Math.min(from, to));
      brush.setAttribute("width", Math.abs(to - from));
    });
    const end = (ev) => {
      if (from == null) return;
      const to = toSvg(ev);
      const a = Math.min(from, to), b = Math.max(from, to);
      from = null;
      brush.setAttribute("visibility", "hidden");
      if (b - a >= 8) onZoom([tAt(a), tAt(b)]);
    };
    area.addEventListener("pointerup", end);
    area.addEventListener("pointercancel", () => {
      from = null;
      brush.setAttribute("visibility", "hidden");
    });
    root.addEventListener("keydown", (ev) => {
      if (ev.target !== root) return;
      const k = ev.key;
      let next;
      if (k === "+" || k === "=") next = zoomWindow(full, domain, 0.5);
      else if (k === "-" || k === "_") next = zoomWindow(full, domain, 2);
      else if (k === "ArrowLeft") next = zoomWindow(full, domain, 1, -0.25);
      else if (k === "ArrowRight") next = zoomWindow(full, domain, 1, 0.25);
      else if (k === "0" || k === "Home") next = null;
      else return;
      ev.preventDefault();
      onZoom(next);
    });
    root.append(area);
    // On top of the bars, but never in the way of a click.
    queueMicrotask(() => root.append(brush));
  }
  for (const p of clip(pauses, t0, t1)) root.append(svg("rect", { class: "pause", x: x(p.start), y: T, width: Math.max(1, x(p.end) - x(p.start)), height: H - T - B }));
  const grid = svg("g", { class: "grid" });
  const axis = svg("g", { class: "axis" });
  if (fitted) {
    // A tick where each active stretch starts, labelled when there is room;
    // each idle stretch a hatched gap with its length.
    let lastLabel = -Infinity;
    for (const p of fitted.pieces) {
      if (p.gap) {
        root.append(tip(svg("rect", { class: "idle-gap", x: p.p0 + 3, y: T, width: Math.max(2, p.p1 - p.p0 - 6), height: H - T - B }), `Idle ${dur(p.t1 - p.t0)}, compressed`));
        axis.append(svg("path", { class: "gap-mark", d: `M${p.p0 + 6},${H - B + 6} l4,-8 M${p.p1 - 10},${H - B + 6} l4,-8` }));
        continue;
      }
      grid.append(svg("line", { x1: p.p0, x2: p.p0, y1: T, y2: H - B }));
      if (p.p0 - lastLabel >= 84 && p.p0 <= W - R - 40) {
        axis.append(svg("text", { x: p.p0, y: H - 8, "text-anchor": "start" }, fmtShort(p.t0)));
        lastLabel = p.p0;
      }
    }
  } else {
    const ticks = axisTicks(t0, t1, W < 520 ? 2 : 4);
    ticks.forEach((t, i) => {
      grid.append(svg("line", { x1: x(t), x2: x(t), y1: T, y2: H - B }));
      axis.append(svg("text", { x: x(t), y: H - 8, "text-anchor": i === 0 ? "start" : i === ticks.length - 1 ? "end" : "middle" }, fmtShort(t)));
    });
  }
  root.append(grid, axis);
  // The lane labels are one tab stop (up and down move along them), the
  // run bars another (the arrows move along them in lane, then time order).
  const labs = [];
  const bars = [];
  let selBar = -1;
  lanes.forEach((lane, i) => {
    const y = T + i * LH;
    const on = selected == null || selected === lane.key;
    root.append(svg("line", { class: "lane", x1: L, x2: W - R, y1: y + LH / 2, y2: y + LH / 2 }));
    const lab = svg("text", {
      class: `lane-label${selected === lane.key ? " sel" : ""}`, x: L - 8, y: y + LH / 2 + 4, "text-anchor": "end",
      tabindex: onSelect ? 0 : null, role: onSelect ? "button" : null, "aria-pressed": onSelect ? String(selected === lane.key) : null,
      "aria-label": onSelect ? `Cluster ${lane.label}` : null, "data-focus-key": `lane:${lane.key}`,
    }, lane.label);
    if (onSelect) activate(lab, () => onSelect(lane.key));
    labs.push(lab);
    root.append(lab);
    for (const b of clip(bands.filter((b) => b.key === lane.key), t0, t1)) {
      root.append(tip(svg("rect", { class: "band", x: x(b.start), y: y + 2, width: Math.max(2, x(b.end) - x(b.start)), height: LH - 4 }), b.label));
    }
    lane.runs.forEach((run, ri) => {
      if (run.end < t0 || run.start > t1) return;
      const r = { ...run, start: Math.max(run.start, t0), end: Math.min(run.end, t1) };
      const bw = Math.max(5, x(r.end) - x(r.start));
      const bar = svg("rect", {
        class: `run tier-${lane.tier}${on ? "" : " dim"}${selected === lane.key ? " sel" : ""}`,
        x: Math.min(x(r.start), W - R - bw), y: y + 6, width: bw, height: LH - 12, rx: 4,
        tabindex: onSelect ? 0 : null, role: onSelect ? "button" : null,
        "aria-label": `${lane.label}: run ${fmtTs(run.start)} to ${fmtTs(run.end)}, ${run.count} records`, "data-focus-key": `run:${lane.key}:${ri}`,
      });
      tip(bar, `${lane.label} · ${fmtShort(run.start)} → ${fmtShort(run.end)} UTC (${dur(Math.max(0, run.end - run.start))}) · ${run.count} record(s)`);
      if (onSelect) activate(bar, () => onSelect(lane.key));
      if (selBar < 0 && selected === lane.key) selBar = bars.length;
      bars.push(bar);
      root.append(bar);
    });
  });
  if (onSelect) {
    roving(labs, { current: Math.max(0, lanes.findIndex((l) => l.key === selected)), horizontal: false });
    roving(bars, { current: Math.max(0, selBar) });
  }
  return root;
}

/**
 * The order nodes take around the fleet graph: each group's members side by
 * side (groups in the order given, members in node order, a node in the
 * first group that names it), then the rest in node order. Deterministic.
 */
export function groupOrder(nodes, groups) {
  const at = new Map(nodes.map((n, i) => [n.key, i]));
  const placed = new Set();
  const order = [];
  for (const g of groups) {
    for (const i of [...new Set(g.members.filter((k) => at.has(k)).map((k) => at.get(k)))].sort((p, q) => p - q)) {
      if (!placed.has(i)) {
        placed.add(i);
        order.push(i);
      }
    }
  }
  nodes.forEach((_, i) => placed.has(i) || order.push(i));
  return order;
}

/**
 * Fleet graph: clusters as nodes (area by records, colour by tier), hints as
 * edges. Laid out on an ellipse in the order given (first-seen time), except
 * that each of `groups` ({label, members: node keys}, the candidate fleets)
 * sits together behind a light band that names it, so its edges stay short.
 * The layout depends only on its input, so it is stable.
 */
export function fleetGraph({ nodes, edges, groups = [], selected = null, onSelect = null, width = 900 }) {
  if (!nodes.length) return el("p", { class: "hint" }, "No clusters.");
  const W = Math.max(320, width), H = Math.min(560, Math.max(300, W * 0.62));
  const cx = W / 2, cy = H / 2, rad = Math.min(W, H) / 2 - 44;
  const rx = Math.min(W / 2 - 50, rad * 1.45), ry = rad;
  const maxSize = Math.max(1, ...nodes.map((n) => n.size));
  const angle = (slot) => (slot / nodes.length) * Math.PI * 2 - Math.PI / 2;
  const slotOf = new Map(groupOrder(nodes, groups).map((i, slot) => [nodes[i].key, slot]));
  const pos = new Map();
  for (const n of nodes) {
    const a = angle(slotOf.get(n.key));
    const k = nodes.length === 1 ? 0 : 1;
    pos.set(n.key, { x: cx + k * rx * Math.cos(a), y: cy + k * ry * Math.sin(a), r: 7 + 15 * Math.sqrt(n.size / maxSize) });
  }
  const root = svg("svg", { class: "chart fleet", viewBox: `0 0 ${W} ${H}`, width: W, height: H, role: "group", "aria-label": "Clusters and the hints that connect them" });
  // Bands first, under the edges and nodes: an arc of the ellipse from a
  // fleet's first member to its last, wide enough to hold the nodes.
  const taken = new Set();
  for (const g of groups) {
    const slots = [...new Set(g.members.filter((k) => slotOf.has(k) && !taken.has(k)).map((k) => slotOf.get(k)))].sort((p, q) => p - q);
    for (const k of g.members) taken.add(k);
    if (slots.length < 2 || nodes.length < 2) continue;
    const a0 = angle(slots[0]), a1 = angle(slots[slots.length - 1]), mid = (a0 + a1) / 2;
    const d = `M${cx + rx * Math.cos(a0)},${cy + ry * Math.sin(a0)} A${rx},${ry} 0 ${a1 - a0 > Math.PI ? 1 : 0} 1 ${cx + rx * Math.cos(a1)},${cy + ry * Math.sin(a1)}`;
    root.append(tip(svg("g", { class: "fleet-band" }, svg("path", { d }),
      svg("text", { class: "band-label", x: cx + (rx - 58) * Math.cos(mid), y: cy + (ry - 50) * Math.sin(mid) + 4, "text-anchor": "middle" }, g.label)), `${g.label}: a hint for review, not evidence`));
  }
  const near = new Set();
  if (selected) for (const e of edges) if (e.a === selected || e.b === selected) near.add(e.a).add(e.b);
  // Parallel edges between one pair bow apart.
  const seen = new Map();
  for (const e of edges) {
    const p = pos.get(e.a), q = pos.get(e.b);
    if (!p || !q || e.a === e.b) continue;
    const pair = [e.a, e.b].sort().join("|");
    const k = seen.get(pair) ?? 0;
    seen.set(pair, k + 1);
    const mx = (p.x + q.x) / 2, my = (p.y + q.y) / 2;
    const dx = q.x - p.x, dy = q.y - p.y, len = Math.hypot(dx, dy) || 1;
    const bow = (k % 2 ? -1 : 1) * Math.ceil(k / 2) * 16 + (k ? 0 : 0);
    const c = { x: mx + (-dy / len) * bow, y: my + (dx / len) * bow };
    const d = `M${p.x},${p.y} Q${c.x},${c.y} ${q.x},${q.y}`;
    const dim = selected && !(e.a === selected || e.b === selected);
    root.append(svg("path", { class: `edge ${e.kind}${e.sub ? ` ${e.sub}` : ""}${dim ? " dim" : ""}`, d }));
    const hit = svg("path", { class: "edge-hit", d, tabindex: 0, role: "img", "aria-label": e.label });
    tip(hit, e.label);
    root.append(hit);
  }
  for (const n of nodes) {
    const p = pos.get(n.key);
    const dim = selected && selected !== n.key && !near.has(n.key);
    const c = svg("circle", {
      class: `node tier-${n.tier}${selected === n.key ? " sel" : ""}${dim ? " dim" : ""}`, cx: p.x, cy: p.y, r: p.r,
      tabindex: onSelect ? 0 : null, role: onSelect ? "button" : null, "aria-label": `${n.label}: ${n.sub}`,
      "aria-pressed": onSelect ? String(selected === n.key) : null, "data-focus-key": `node:${n.key}`,
    });
    tip(c, `${n.label} · ${n.sub}`);
    if (onSelect) activate(c, () => onSelect(n.key));
    root.append(c);
    const below = p.y > cy ? 1 : -1;
    root.append(svg("text", { class: "node-label", x: p.x, y: p.y + below * (p.r + 12) + (below > 0 ? 0 : 4), "text-anchor": "middle" }, n.label));
  }
  return root;
}

/** Five-step sequential class for v of max (q0 = none). */
const q = (v, max) => (v <= 0 ? 0 : Math.min(5, 1 + Math.floor((v / Math.max(1, max)) * 4.999)));
export const rampLegend = (lo, hi) => el("span", { class: "legend" }, `${lo} `, el("span", { class: "legend-ramp", "aria-hidden": "true" }, [1, 2, 3, 4, 5].map((i) => el("i", { class: `q${i}` }))), ` ${hi}`);

/** Rule × cluster heatmap; a cell selects that rule within that cluster. */
export function heatmap({ rows, cols, value, selected = {}, onSelect = null, width = 900 }) {
  if (!rows.length || !cols.length) return el("p", { class: "hint" }, "No rule hits in clusters.");
  const L = Math.min(220, Math.max(120, Math.max(...rows.map((r) => r.label.length)) * 6.6)), T = 30, R = 6;
  const cw = Math.max(22, Math.min(46, (Math.max(320, width) - L - R) / cols.length));
  const ch = 20;
  const W = L + R + cw * cols.length, H = T + ch * rows.length + 4;
  let max = 0;
  for (const r of rows) for (const c of cols) max = Math.max(max, value(r, c));
  const root = svg("svg", { class: "chart heat", viewBox: `0 0 ${W} ${H}`, width: W, height: H, role: "group", "aria-label": "Rule hits per cluster" });
  cols.forEach((c, j) => root.append(svg("text", { x: L + j * cw + cw / 2, y: T - 10, "text-anchor": "middle", class: selected.col === c.key ? "lane-label sel" : "" }, c.label)));
  rows.forEach((r, i) => {
    const y = T + i * ch;
    root.append(svg("text", { class: `lane-label${selected.row === r.id ? " sel" : ""}`, x: L - 6, y: y + ch / 2 + 4, "text-anchor": "end" }, r.label));
    cols.forEach((c, j) => {
      const v = value(r, c);
      const k = q(v, max);
      const sel = selected.row === r.id && selected.col === c.key;
      const cell = svg("rect", {
        class: `cell q${k}${sel ? " sel" : ""}`, x: L + j * cw, y, width: cw, height: ch, rx: 2,
        tabindex: v && onSelect ? 0 : null, role: v && onSelect ? "button" : null,
        "aria-label": v ? `${r.label} in ${c.label}: ${v} record(s)` : null, "data-focus-key": `cell:${r.id}:${c.key}`,
      });
      if (v) {
        tip(cell, `${r.label} · ${c.label}: ${v} record(s)`);
        if (onSelect) activate(cell, () => onSelect(r.id, c.key));
      }
      root.append(cell);
      if (v && cw >= 26) root.append(svg("text", { class: `cell-v ${k >= 4 ? "on-dark" : "on-light"}`, x: L + j * cw + cw / 2, y: y + ch / 2 + 4, "text-anchor": "middle" }, String(v)));
    });
  });
  return root;
}

const DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
/** A 7 × 24 grid of counts by UTC weekday and hour. */
export function rhythmGrid({ counts, width = 900 }) {
  const L = 40, T = 22, R = 4;
  const cw = Math.max(11, Math.min(34, (Math.max(320, width) - L - R) / 24));
  const ch = Math.max(16, Math.min(26, cw));
  const W = L + R + cw * 24, H = T + ch * 7 + 4;
  const max = Math.max(0, ...counts.flat());
  const root = svg("svg", { class: "chart rhythm", viewBox: `0 0 ${W} ${H}`, width: W, height: H, role: "group", "aria-label": "Flagged records by weekday and hour, UTC" });
  for (let h = 0; h < 24; h += cw < 18 ? 3 : 2) root.append(svg("text", { x: L + h * cw + cw / 2, y: T - 8, "text-anchor": "middle" }, String(h).padStart(2, "0")));
  counts.forEach((row, d) => {
    root.append(svg("text", { class: "lane-label", x: L - 6, y: T + d * ch + ch / 2 + 4, "text-anchor": "end" }, DAYS[d]));
    row.forEach((v, h) => {
      const cell = svg("rect", { class: `cell q${q(v, max)}`, x: L + h * cw, y: T + d * ch, width: cw, height: ch, rx: 2, tabindex: v ? 0 : null, role: v ? "img" : null, "aria-label": v ? `${DAYS[d]} ${String(h).padStart(2, "0")}:00 UTC: ${v}` : null });
      if (v) tip(cell, `${DAYS[d]} ${String(h).padStart(2, "0")}:00–${String(h).padStart(2, "0")}:59 UTC · ${v} record(s)`);
      root.append(cell);
    });
  });
  return root;
}

/** Endpoint × time: a row per host, a dot per flagged record. */
export function strip({ rows, points, onSelect = null, width = 900 }) {
  if (!points.length) return el("p", { class: "hint" }, "No flagged records with timestamps.");
  const t0 = Math.min(...points.map((p) => p.t)), t1 = Math.max(...points.map((p) => p.t));
  const span = Math.max(60, t1 - t0);
  const L = Math.min(240, Math.max(110, Math.max(...rows.map((r) => r.length)) * 6.6)), R = 12, T = 6, B = 26, RH = 24;
  const W = Math.max(320, width), H = T + B + RH * rows.length;
  const x = (t) => L + ((t - t0) / span) * (W - L - R);
  const root = svg("svg", { class: "chart strip", viewBox: `0 0 ${W} ${H}`, width: W, height: H, role: "group", "aria-label": "Flagged requests per target host over time" });
  const grid = svg("g", { class: "grid" });
  const ticks = axisTicks(t0, t1, W < 520 ? 2 : 4);
  ticks.forEach((t, i) => {
    grid.append(svg("line", { x1: x(t), x2: x(t), y1: T, y2: H - B }));
    root.append(svg("text", { x: x(t), y: H - 8, "text-anchor": i === 0 ? "start" : i === ticks.length - 1 ? "end" : "middle" }, fmtShort(t)));
  });
  root.prepend(grid);
  rows.forEach((r, i) => {
    root.append(svg("line", { class: "lane", x1: L, x2: W - R, y1: T + i * RH + RH / 2, y2: T + i * RH + RH / 2 }));
    root.append(svg("text", { class: "lane-label", x: L - 8, y: T + i * RH + RH / 2 + 4, "text-anchor": "end" }, r));
  });
  const focusable = points.length <= 300;
  for (const p of points) {
    const d = svg("circle", { class: `dot tier-${p.tier}${p.sel ? " sel" : ""}`, cx: x(p.t), cy: T + p.row * RH + RH / 2, r: p.sel ? 6 : 4.5, tabindex: focusable && onSelect ? 0 : null, role: focusable && onSelect ? "button" : null, "aria-label": focusable ? p.label : null, "data-focus-key": `dot:${p.idx}` });
    tip(d, p.label);
    if (onSelect) activate(d, () => onSelect(p.idx));
    root.append(d);
  }
  return root;
}

/** Flagged records per hour, pauses shaded. */
export function hourly({ data, pauses = [], width = 900 }) {
  if (!data.length) return el("p", { class: "hint" }, "No timestamps on flagged records.");
  const W = Math.max(320, width), H = 220, L = 36, R = 8, T = 8, B = 26;
  data = [...data].sort((p, q) => p[0] - q[0]);
  const max = Math.max(1, ...data.map((d) => d[1]));
  // Hours may be listed sparsely (empty hours left out): place each by its time.
  const x0 = data[0][0], hours = Math.round((data[data.length - 1][0] - x0) / 3600) + 1, span = hours * 3600;
  const step = (W - L - R) / hours;
  const bw = Math.max(1, step - 2);
  const y = (v) => T + (H - T - B) * (1 - v / max);
  const xs = (t) => L + ((t - x0) / span) * (W - L - R);
  const root = svg("svg", { class: "chart hourly", viewBox: `0 0 ${W} ${H}`, width: W, height: H, role: "group", "aria-label": "Flagged records per hour, UTC" });
  const grid = svg("g", { class: "grid" });
  for (const v of [...new Set([0, Math.round(max / 2), max])]) {
    grid.append(svg("line", { x1: L, x2: W - R, y1: y(v), y2: y(v) }));
    root.append(svg("text", { x: L - 6, y: y(v) + 4, "text-anchor": "end" }, String(v)));
  }
  root.prepend(grid);
  for (const p of clip(pauses, x0, x0 + span)) root.append(svg("rect", { class: "pause", x: xs(p.start), y: T, width: Math.max(1, xs(p.end) - xs(p.start)), height: H - T - B }));
  const every = Math.max(1, Math.ceil(hours / Math.max(2, Math.floor(W / 110))));
  for (let i = 0; i < hours; i += every) {
    const h = x0 + i * 3600;
    root.append(svg("text", { x: L + i * step + step / 2, y: H - 8, "text-anchor": "middle" }, hours > 24 ? fmtShort(h).replace(/:\d\d$/, "h") : fmtShort(h).slice(6)));
  }
  data.forEach(([h, c]) => {
    const i = Math.round((h - x0) / 3600);
    if (!c) return;
    const bar = svg("rect", { class: "bar", x: L + i * step + 1, y: y(c), width: bw, height: H - B - y(c), rx: Math.min(4, bw / 2), tabindex: data.length <= 200 ? 0 : null, role: "img", "aria-label": `${fmtTs(h).slice(0, 16)} UTC: ${c} flagged` });
    tip(bar, `${fmtTs(h).slice(0, 16)} UTC · ${c} flagged`);
    root.append(bar);
  });
  return root;
}

/**
 * Swarm view: runs as nodes on a time axis, one lane per cluster, and the
 * interaction hints between them as arcs styled by kind (S1–S6) and
 * weighted by strength. `nodes`: {id, lane, t, label, short, sub};
 * `lanes`: {key, label, tier}; `edges`: {a, b, kind, strength, label}.
 */
export function swarmGraph({ lanes, nodes, edges, selected = null, onSelect = null, width = 900 }) {
  if (!nodes.length) return el("p", { class: "hint" }, "No interaction hints between runs.");
  const t0 = Math.min(...nodes.map((n) => n.t)), t1 = Math.max(...nodes.map((n) => n.t));
  const span = Math.max(60, t1 - t0);
  const W = Math.max(320, width), LH = 50, L = 56, R = 26, T = 34, B = 26;
  const H = T + B + LH * Math.max(1, lanes.length);
  const laneY = new Map(lanes.map((l, i) => [l.key, T + i * LH + LH / 2]));
  const laneOf = new Map(nodes.map((n) => [n.id, n.lane]));
  const tierOf = new Map(lanes.map((l) => [l.key, l.tier]));
  const x = (t) => L + 10 + ((t - t0) / span) * (W - L - R - 20);
  // Strands of one run share a time: fan them out a little.
  const pos = new Map();
  const stack = new Map();
  for (const n of nodes) {
    const k = `${n.lane}|${Math.round(x(n.t) / 8)}`;
    const i = stack.get(k) ?? 0;
    stack.set(k, i + 1);
    pos.set(n.id, { x: x(n.t) + (i % 2 ? 1 : -1) * Math.ceil(i / 2) * 16, y: (laneY.get(n.lane) ?? T) + (i ? (i % 2 ? 8 : -8) : 0) });
  }
  const root = svg("svg", { class: "chart swarm", viewBox: `0 0 ${W} ${H}`, width: W, height: H, role: "group", "aria-label": "Runs and the interaction hints between them" });
  const grid = svg("g", { class: "grid" });
  const ticks = axisTicks(t0, t1, W < 520 ? 2 : 4);
  ticks.forEach((t, i) => {
    grid.append(svg("line", { x1: x(t), x2: x(t), y1: T - 12, y2: H - B }));
    root.append(svg("text", { x: x(t), y: H - 8, "text-anchor": i === 0 ? "start" : i === ticks.length - 1 ? "end" : "middle" }, fmtShort(t)));
  });
  root.prepend(grid);
  for (const l of lanes) {
    const y = laneY.get(l.key);
    root.append(svg("line", { class: "lane", x1: L, x2: W - R, y1: y, y2: y }));
    const lab = svg("text", {
      class: `lane-label${selected === l.key ? " sel" : ""}`, x: L - 8, y: y + 4, "text-anchor": "end",
      tabindex: onSelect ? 0 : null, role: onSelect ? "button" : null, "aria-pressed": onSelect ? String(selected === l.key) : null,
      "aria-label": onSelect ? `Cluster ${l.label}` : null, "data-focus-key": `slane:${l.key}`,
    }, l.label);
    if (onSelect) activate(lab, () => onSelect(l.key));
    root.append(lab);
  }
  const seen = new Map();
  for (const e of edges) {
    const p = pos.get(e.a), q = pos.get(e.b);
    if (!p || !q) continue;
    const pair = [e.a, e.b].sort().join("|");
    const k = seen.get(pair) ?? 0;
    seen.set(pair, k + 1);
    // Arcs bow upward; same-lane arcs and repeats bow further.
    const lift = 16 + Math.min(54, Math.abs(q.x - p.x) * 0.16) + k * 10 + (Math.abs(q.y - p.y) < 1 ? 8 : 0);
    const c = { x: (p.x + q.x) / 2, y: Math.max(4, Math.min(p.y, q.y) - lift) };
    const d = `M${p.x},${p.y} Q${c.x},${c.y} ${q.x},${q.y}`;
    const dim = selected && laneOf.get(e.a) !== selected && laneOf.get(e.b) !== selected;
    root.append(svg("path", { class: `sedge sk-${e.kind} st-${e.strength}${dim ? " dim" : ""}`, d }));
    const hit = svg("path", { class: "edge-hit", d, tabindex: 0, role: "img", "aria-label": e.label });
    tip(hit, e.label);
    root.append(hit);
  }
  for (const n of nodes) {
    const p = pos.get(n.id);
    const dim = selected && selected !== n.lane;
    const c = svg("circle", {
      class: `node tier-${tierOf.get(n.lane) ?? "noise"}${selected === n.lane ? " sel" : ""}${dim ? " dim" : ""}`, cx: p.x, cy: p.y, r: 6.5,
      tabindex: onSelect ? 0 : null, role: onSelect ? "button" : null, "aria-label": `${n.label}: ${n.sub}`, "data-focus-key": `snode:${n.id}`,
    });
    tip(c, `${n.label} · ${n.sub}`);
    if (onSelect) activate(c, () => onSelect(n.lane));
    root.append(c);
    root.append(svg("text", { class: "node-label", x: p.x, y: p.y + 19, "text-anchor": "middle" }, n.short ?? n.label));
  }
  return root;
}
