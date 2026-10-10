// Charts as inline SVG built with DOM calls: no library, no markup strings,
// no style attributes (classes only, so the CSP holds). Every chart comes
// with a table view, and every mark that carries a tooltip shows it on hover,
// keyboard focus and tap. Labels are record-derived text: they go in as text.

import { el, svg, activate } from "./dom.js";
import { fmtShort, fmtTs, dur } from "./fmt.js";

const tipBox = () => document.getElementById("tip");

/** Show `text()` near `node` on hover, focus and tap. */
export function tip(node, text) {
  const show = (ev) => {
    const t = tipBox();
    if (!t) return;
    t.textContent = typeof text === "function" ? text() : text;
    t.hidden = false;
    let x, y;
    if (ev && "clientX" in ev && ev.clientX) {
      x = ev.clientX + 12;
      y = ev.clientY + 14;
    } else {
      const r = node.getBoundingClientRect();
      x = r.left + r.width / 2;
      y = r.bottom + 8;
    }
    const w = t.offsetWidth || 200;
    t.style.left = `${Math.max(4, Math.min(x, window.innerWidth - w - 8))}px`;
    t.style.top = `${Math.min(y, window.innerHeight - (t.offsetHeight || 40) - 8)}px`;
  };
  const hide = () => {
    const t = tipBox();
    if (t) t.hidden = true;
  };
  node.addEventListener("mousemove", show);
  node.addEventListener("mouseleave", hide);
  node.addEventListener("focus", show);
  node.addEventListener("blur", hide);
  node.addEventListener("touchstart", (ev) => show(ev.touches?.[0] ?? null), { passive: true });
  return node;
}

/** A chart with its legend, caption and a "View as table" toggle. */
export function figure({ chart, legend = null, caption = null, head = [], rows = [] }) {
  const table = el("div", { class: "scroll", hidden: true },
    el("table", {}, el("thead", {}, el("tr", {}, head.map((h) => el("th", { scope: "col" }, h)))),
      el("tbody", {}, rows.map((r) => el("tr", {}, r.map((c) => el("td", {}, c)))))));
  const btn = el("button", { type: "button", "aria-expanded": "false" }, "View as table");
  btn.addEventListener("click", () => {
    const open = table.hidden;
    table.hidden = !open;
    chart.hidden = open;
    btn.setAttribute("aria-expanded", String(open));
    btn.textContent = open ? "View as chart" : "View as table";
  });
  return el("figure", { class: "chart-box" },
    el("div", { class: "chart-tools" }, legend ?? el("span"), btn), chart, table,
    caption ? el("figcaption", {}, caption) : null);
}

export const legendKey = (cls, label) => el("span", {}, el("span", { class: `key ${cls}` }), label);
export const legend = (...keys) => el("p", { class: "legend" }, keys);
export const tierLegend = () => legend(legendKey("k-sig", "significant"), legendKey("k-sug", "suggestive"), legendKey("k-noise", "noise"));

/** Spans cut to [t0, t1]; spans outside it dropped. */
const clip = (spans, t0, t1) => spans.map((p) => ({ ...p, start: Math.max(p.start, t0), end: Math.min(p.end, t1) })).filter((p) => p.end > p.start);

function axisTicks(t0, t1, n) {
  const out = [];
  for (let i = 0; i <= n; i++) out.push(t0 + ((t1 - t0) * i) / n);
  return out;
}

/**
 * Run swim-lanes: a lane per cluster, a bar per run, `pauses` (input-wide)
 * shaded, `bands` (shared pauses, per lane key) outlined.
 */
export function swimlanes({ lanes, pauses = [], bands = [], selected = null, onSelect = null, width = 900, label }) {
  const all = lanes.flatMap((l) => l.runs);
  if (!all.length) return el("p", { class: "hint" }, "No runs with timestamps.");
  const t0 = Math.min(...all.map((r) => r.start));
  const t1 = Math.max(...all.map((r) => r.end));
  const span = Math.max(60, t1 - t0);
  const W = Math.max(320, width), LH = 26, L = 56, R = 10, T = 6, B = 26;
  const H = T + B + LH * lanes.length;
  const x = (t) => L + ((t - t0) / span) * (W - L - R);
  const root = svg("svg", { class: "chart swim", viewBox: `0 0 ${W} ${H}`, width: W, height: H, role: "group", "aria-label": label });
  for (const p of clip(pauses, t0, t1)) root.append(svg("rect", { class: "pause", x: x(p.start), y: T, width: Math.max(1, x(p.end) - x(p.start)), height: H - T - B }));
  const grid = svg("g", { class: "grid" });
  const axis = svg("g", { class: "axis" });
  const ticks = axisTicks(t0, t1, W < 520 ? 2 : 4);
  ticks.forEach((t, i) => {
    grid.append(svg("line", { x1: x(t), x2: x(t), y1: T, y2: H - B }));
    axis.append(svg("text", { x: x(t), y: H - 8, "text-anchor": i === 0 ? "start" : i === ticks.length - 1 ? "end" : "middle" }, fmtShort(t)));
  });
  root.append(grid, axis);
  lanes.forEach((lane, i) => {
    const y = T + i * LH;
    const on = selected == null || selected === lane.key;
    root.append(svg("line", { class: "lane", x1: L, x2: W - R, y1: y + LH / 2, y2: y + LH / 2 }));
    const lab = svg("text", { class: `lane-label${selected === lane.key ? " sel" : ""}`, x: L - 8, y: y + LH / 2 + 4, "text-anchor": "end" }, lane.label);
    if (onSelect) lab.addEventListener("click", () => onSelect(lane.key));
    root.append(lab);
    for (const b of clip(bands.filter((b) => b.key === lane.key), t0, t1)) {
      root.append(tip(svg("rect", { class: "band", x: x(b.start), y: y + 2, width: Math.max(2, x(b.end) - x(b.start)), height: LH - 4 }), b.label));
    }
    for (const r of lane.runs) {
      const bw = Math.max(5, x(r.end) - x(r.start));
      const bar = svg("rect", {
        class: `run tier-${lane.tier}${on ? "" : " dim"}${selected === lane.key ? " sel" : ""}`,
        x: Math.min(x(r.start), W - R - bw), y: y + 6, width: bw, height: LH - 12, rx: 4,
        tabindex: onSelect ? 0 : null, role: onSelect ? "button" : null,
        "aria-label": `${lane.label}: run ${fmtTs(r.start)} to ${fmtTs(r.end)}, ${r.count} records`,
      });
      tip(bar, `${lane.label} · ${fmtShort(r.start)} → ${fmtShort(r.end)} UTC (${dur(Math.max(0, r.end - r.start))}) · ${r.count} record(s)`);
      if (onSelect) activate(bar, () => onSelect(lane.key));
      root.append(bar);
    }
  });
  return root;
}

/**
 * Fleet graph: clusters as nodes (area by records, colour by tier), hints as
 * edges. Laid out on a circle by first-seen time, so the layout is stable.
 */
export function fleetGraph({ nodes, edges, selected = null, onSelect = null, width = 900 }) {
  if (!nodes.length) return el("p", { class: "hint" }, "No clusters.");
  const W = Math.max(320, width), H = Math.min(560, Math.max(300, W * 0.62));
  const cx = W / 2, cy = H / 2, rad = Math.min(W, H) / 2 - 44;
  const maxSize = Math.max(1, ...nodes.map((n) => n.size));
  const pos = new Map();
  nodes.forEach((n, i) => {
    const a = (i / nodes.length) * Math.PI * 2 - Math.PI / 2;
    const r = nodes.length === 1 ? 0 : rad;
    pos.set(n.key, { x: cx + r * Math.cos(a), y: cy + r * Math.sin(a), r: 7 + 15 * Math.sqrt(n.size / maxSize) });
  });
  const root = svg("svg", { class: "chart fleet", viewBox: `0 0 ${W} ${H}`, width: W, height: H, role: "group", "aria-label": "Clusters and the hints that connect them" });
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
    root.append(svg("path", { class: `edge ${e.kind}${dim ? " dim" : ""}`, d }));
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
      "aria-pressed": onSelect ? String(selected === n.key) : null,
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
        "aria-label": v ? `${r.label} in ${c.label}: ${v} record(s)` : null,
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
    const d = svg("circle", { class: `dot tier-${p.tier}${p.sel ? " sel" : ""}`, cx: x(p.t), cy: T + p.row * RH + RH / 2, r: p.sel ? 6 : 4.5, tabindex: focusable && onSelect ? 0 : null, role: focusable && onSelect ? "button" : null, "aria-label": focusable ? p.label : null });
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
