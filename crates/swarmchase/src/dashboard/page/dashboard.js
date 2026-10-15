// Monitoring dashboard: what is new since the admin last looked, whether
// monitoring is healthy, what waits on the admin, and the command for each
// next step. Read-only: everything comes from GET /api/overview, the same
// document `swarmchase dashboard --json` prints. Which run the admin last
// looked at is remembered in this browser only (UI.prefs).
"use strict";

const { el, api, toast, keys, plural, copy, icon, emptyState, settings, progress } = UI;
const SEEN = "dashboard.seen";
const BAND = "dashboard.band";
const REFRESH_MS = 120000;

const state = { data: null, since: UI.prefs.get(SEEN), band: UI.prefs.get(BAND) || "all", loading: false, at: 0 };

// ---- formatting -------------------------------------------------------------

/** `20261011T060000Z` as `2026-10-11 06:00 UTC`. */
function stampText(s) {
  if (!s || s.length !== 16) return s || "";
  return `${s.slice(0, 4)}-${s.slice(4, 6)}-${s.slice(6, 8)} ${s.slice(9, 11)}:${s.slice(11, 13)} UTC`;
}

function ago(hours) {
  if (hours == null) return "";
  if (hours < 1) return "under an hour ago";
  if (hours < 48) return `${plural(hours, "hour")} ago`;
  return `${plural(Math.round(hours / 24), "day")} ago`;
}

/** Text with `code spans` as <code>, as nodes. */
function ticks(text) {
  return String(text || "").split("`").map((part, i) => (i % 2 ? el("code", part) : part));
}

function tierDot(t) { return el("span.dot." + t, { title: t, "aria-hidden": "true" }); }

function gradeChip(g) {
  if (!g) return null;
  return el("span.chip.grade.g-" + g.code.toLowerCase(), { title: `Agent grade: ${g.label}` }, el("b", g.code), " ", g.label);
}

const STATUS = {
  failing: { cls: "agent", icon: "alert", text: "failing" },
  skipped: { cls: "unsure", icon: "alert", text: "skipped" },
  quiet: { cls: "unsure", icon: "search", text: "quiet" },
  "catching-up": { cls: "outline", icon: "inbox", text: "catching up" },
  ok: { cls: "benign", icon: "check", text: "ok" },
  "never-run": { cls: "outline", icon: "inbox", text: "not run yet" },
};

function statusChip(s) {
  const m = STATUS[s] || { cls: "outline", icon: "inbox", text: s };
  return el("span.chip." + m.cls, icon(m.icon), m.text);
}

/** A copyable command line. */
function command(cmd, label) {
  if (!cmd) return null;
  return el("div.cmd",
    el("code.mono", cmd),
    el("button.btn.ghost.small.icon-only", {
      type: "button", title: "Copy command", "aria-label": `Copy command${label ? ": " + label : ""}`,
      onclick: () => copy(cmd),
    }, icon("copy")));
}

function section(id, title, sub, ...body) {
  return el("section.dsec#" + id, { "aria-labelledby": id + "-h" },
    el("div.dsec-head", el("h2#" + id + "-h", title), sub ? el("p.muted.small", sub) : null),
    ...body);
}

function none(text) { return el("p.none.muted", text); }

// ---- tiles --------------------------------------------------------------------

function tile(target, label, value, sub, cls = "") {
  return el("a.tile.card" + (cls ? "." + cls : ""), {
    href: "#" + target,
    onclick: (e) => { e.preventDefault(); jump(target); },
  }, el("span.tile-label", label), el("span.tile-value", value), el("span.tile-sub", sub));
}

function tiles(d) {
  const n = d.new;
  const h = d.health;
  const r = d.waiting.review;
  const cases = (d.waiting.cases || []).filter((c) => c.id);
  const fresh = n ? n.clusters.length + n.lone_total : 0;
  const counts = h.counts || {};
  const trouble = (counts.failing || 0) + (h.drift || []).length;
  const healthText = h.level === "ok" ? "Healthy" : h.level === "alert" ? "Needs attention" : "Watch";
  const healthSub = [
    counts.failing ? `${counts.failing} failing` : null,
    (h.drift || []).length ? plural(h.drift.length, "drifting rule") : null,
    counts.skipped ? `${counts.skipped} skipped` : null,
    counts.quiet ? `${counts.quiet} quiet` : null,
  ].filter(Boolean).join(" · ") || "every source ran";
  const needs = cases.reduce((a, c) => a + (c.needs || []).length, 0);
  const bands = (d.attention && d.attention.by_band) || {};
  return el("div.tiles",
    tile("attention", "Attention queue", d.attention ? String(bands.urgent || 0) : "–",
      d.attention ? `urgent · ${bands.look || 0} look · ${bands.watch || 0} watch` : "no queue yet",
      bands.urgent ? "hot.urgent" : ""),
    tile("new", "New since " + (d.since && d.since.stamp ? stampText(d.since.stamp) : "the first run"),
      n ? String(fresh) : "–",
      n ? `${plural(n.clusters.length, "cluster")} · ${n.lone_total} lone · ${plural(n.records, "record")} collected` : "no analysis yet",
      fresh ? "hot" : ""),
    tile("health", "Monitoring", healthText, healthSub, "lvl-" + h.level + (trouble ? ".hot" : "")),
    tile("waiting", "Review queue", r ? String(r.unreviewed) : "–",
      r ? `unreviewed in ${plural(r.groups, "group")}` : "no analysis yet"),
    tile("cases", "Open cases", String(cases.length), cases.length ? plural(needs, "open item") : "none open"));
}

// ---- next steps ---------------------------------------------------------------

const KIND = { health: "Health", drift: "Drift", watch: "Watch", mail: "Mail", attention: "Urgent", new: "New", review: "Review", case: "Case", "case-proposal": "Proposal" };

function actions(d) {
  const list = d.actions || [];
  return section("next", "Next steps", "Most urgent first. Nothing here runs by itself; copy a command into a terminal.",
    list.length ? el("ol.actions", list.map((a) => el("li.action.k-" + a.kind,
      el("span.chip.kind", KIND[a.kind] || a.kind),
      el("div.action-main",
        el("div.action-title", a.title),
        a.detail ? el("div.action-detail.muted", ticks(a.detail)) : null,
        command(a.command, a.title)))))
      : el("div.calm", icon("check"), el("span", "Nothing waits on you. The next watch run will show up here.")));
}

// ---- new ------------------------------------------------------------------------

function sinceLine(d) {
  const s = d.since || {};
  const basis = {
    "previous-run": "the run before the latest (as the digest does)",
    requested: "the run you marked seen",
    "nearest-kept-run": "the nearest kept run before the one you marked seen",
    "before-kept-runs": "before every kept run, so everything kept counts as new",
    "first-run": "nothing: this is the first run",
  }[s.basis] || s.basis;
  return [s.stamp ? `Compared with ${stampText(s.stamp)}, ` : "Compared with ", basis, "."];
}

function newSection(d) {
  const n = d.new;
  if (!n) {
    return section("new", "New since you last looked", null,
      none("The latest run has no analysis.json; run the watch again."));
  }
  const seenNow = state.since && state.since === d.run.latest;
  const controls = el("div.row-actions",
    el("button.btn.small" + (seenNow ? "" : ".primary"), {
      type: "button", onclick: markSeen, disabled: seenNow ? true : null,
      title: "Count only what later runs collect as new (key s)",
    }, icon("check"), seenNow ? "Latest run marked seen" : "Mark latest run seen"),
    state.since ? el("button.btn.ghost.small", { type: "button", onclick: forget, title: "Compare with the run before the latest again" },
      "Show the latest run's changes") : null);
  const clusters = n.clusters.length
    ? el("div.table-wrap", el("table.dtable",
      el("thead", el("tr", ["Cluster", "Grade", "Change", "Records", "Span", "Targets", "Rules"].map((h) => el("th", { scope: "col" }, h)))),
      el("tbody", n.clusters.map(clusterRow))))
    : none(seenNow ? "No new or escalated cluster since you marked the latest run seen." : "No new or escalated cluster above noise.");
  const lone = n.lone.length
    ? el("div.table-wrap", el("table.dtable",
      el("thead", el("tr", ["Host", "Grade", "Score", "Rules", "Source", "Captured"].map((h) => el("th", { scope: "col" }, h)))),
      el("tbody", n.lone.map((r) => el("tr",
        el("td", el("span.host", tierDot(r.tier), el("code", r.host || "unknown"))),
        el("td", gradeChip(r.grade)),
        el("td.num", String(r.score)),
        el("td", el("span.rules", r.rules.map((x) => el("span.chip.outline.rule", x)))),
        el("td", r.source),
        el("td.nowrap.muted", r.time))))))
    : none("No new significant record outside a cluster.");
  const tierBits = Object.entries(n.clusters_by_tier || {}).map(([t, c]) => el("span.tier." + t, tierDot(t), `${c} ${t}`));
  const gradeBits = Object.entries(n.clusters_by_grade || {}).sort().reverse().map(([g, c]) => el("span.chip.outline", el("b", g), ` ${c}`));
  return section("new", "New since you last looked", sinceLine(d),
    controls,
    el("div.summary-line", el("span", plural(n.records, "record"), " collected"), tierBits, gradeBits),
    el("h3", `Clusters (${n.clusters.length})`),
    clusters,
    el("h3", `Significant records outside any cluster (${n.lone_total})`),
    lone,
    n.lone_total > n.lone.length ? el("p.muted.small", `${n.lone_total - n.lone.length} more; the digest and the review page list them all.`) : null,
    el("h3", `Endpoints newly hit (${n.endpoints_total})`),
    n.endpoints.length ? el("div.chips", n.endpoints.map((h) => el("code.chip.outline", h))) : none("None."));
}

function clusterRow(c) {
  const change = c.change === "escalated" ? `escalated from ${c.from_tier}` : "new";
  return el("tr",
    el("td",
      el("div.cl-id", tierDot(c.tier), el("b", c.id), " ", el("code.muted", c.cluster_key || c.key)),
      el("details.open-case", el("summary", "Open a case"), command(c.open_case, "open a case"))),
    el("td", gradeChip(c.grade)),
    el("td", el("span.chip" + (c.change === "escalated" ? ".unsure" : ".outline"), change)),
    el("td.num", String(c.records), c.new_records && c.new_records !== c.records ? el("span.muted.small", ` (${c.new_records} new)`) : null),
    el("td.nowrap.muted.small", c.start, el("br"), c.end),
    el("td", c.targets.map((t) => el("code.target", t))),
    el("td", el("span.rules", c.rules.map((x) => el("span.chip.outline.rule", x)))));
}

// ---- attention queue -------------------------------------------------------------

const BAND_TEXT = { urgent: "Urgent", look: "Look", watch: "Watch" };
const FACTOR_TEXT = { growth: "Growth", spread: "Spread", interaction: "Interaction", recency: "Recency", novelty: "Novelty", volume: "Volume" };

function bandChip(b) { return b ? el("span.chip.band.b-" + b, BAND_TEXT[b] || b) : null; }

function trajectoryChip(it) {
  const g = it.growth != null && it.growth >= 1.5 ? `, ${it.growth.toFixed(1)}x in a day` : "";
  const hot = ["growing", "resurgent", "new"].includes(it.trajectory);
  return el("span.chip" + (hot ? ".unsure" : ".outline"), it.trajectory_label + g);
}

/** Records on each of a thread's recent runs, oldest first. */
function recordSpark(counts, name) {
  if (!counts || !counts.length) return null;
  const max = Math.max(1, ...counts);
  const box = el("span.spark", { role: "img", "aria-label": `${name}: records on its last ${counts.length} runs: ${counts.join(", ")}` });
  counts.forEach((n, i) => {
    const b = el("span.bar" + (i === counts.length - 1 ? ".last" : ""), { title: `${counts.length - 1 - i} run(s) before the latest: ${n} records` });
    b.style.height = `${Math.max(8, (100 * n) / max)}%`;
    box.append(b);
  });
  return box;
}

/** The momentum score as one bar of its parts. */
function meter(it) {
  const bar = el("span.meter", { role: "img", "aria-label": `Momentum ${it.momentum} of 100: ` + it.factors.map((f) => `${f.name} ${f.points}`).join(", ") });
  it.factors.forEach((f, i) => {
    if (!f.points) return;
    const s = el("span.f-" + i, { title: `${FACTOR_TEXT[f.name] || f.name}: ${f.points} of ${f.max} (${f.detail})` });
    s.style.width = `${f.points}%`;
    bar.append(s);
  });
  return el("span.meter-wrap", bar, el("b.small", String(it.momentum)));
}

function queueItem(it) {
  const name = `${it.id} ${it.key}`;
  return el("li.qitem.b-" + it.band,
    el("div.q-head",
      el("span.q-rank.muted", "#" + it.rank),
      bandChip(it.band),
      el("span.cl-id", tierDot(it.tier), el("b", it.id), " ", el("code.muted", it.key)),
      gradeChip({ code: it.grade, label: it.grade_label }),
      trajectoryChip(it),
      it.fleet ? el("span.chip.outline", { title: "In a candidate fleet this run" }, "fleet " + it.fleet) : null,
      it.swarm_edges ? el("span.chip.outline", plural(it.swarm_edges, "interaction edge")) : null,
      (it.cases || []).map((c) => el("span.chip.benign", { title: "A case covers its records" }, "case " + c))),
    el("ul.q-why", it.why.map((w) => el("li", w)),
      (it.caps || []).map((c) => el("li.cap", icon("alert"), " ", c))),
    el("div.q-meta",
      el("span.q-targets", it.targets.map((t) => el("code.target", t)),
        it.target_count > it.targets.length ? el("span.muted.small", ` +${it.target_count - it.targets.length} more`) : null),
      el("span.small.muted", `${plural(it.records, "record")}${it.added ? `, ${it.added} this run` : ""} · ${it.harm_label} · since ${stampText(it.first_run)}`),
      el("span.q-spark", recordSpark(it.spark, name)),
      meter(it)),
    el("details.q-more",
      el("summary", "Why this place"),
      el("p.small.muted", "Band, then grade, then the worst target class, then leads no case covers; momentum orders what those leave tied."),
      el("table.dtable.factors",
        el("thead", el("tr", ["Part", "Points", "Reading"].map((h) => el("th", { scope: "col" }, h)))),
        el("tbody", it.factors.map((f) => el("tr",
          el("td", FACTOR_TEXT[f.name] || f.name),
          el("td.num", `${f.points} / ${f.max}`),
          el("td", f.detail))))),
      it.cases && it.cases.length ? null : command(it.open_case, "open a case")));
}

function attentionSection(d) {
  const a = d.attention;
  if (!a) {
    return section("attention", "Attention queue", null,
      none("The latest run wrote no attention.json; the next watch run ranks its clusters."));
  }
  const counts = a.by_band || {};
  const shown = a.items.filter((it) => state.band === "all" || it.band === state.band);
  const filter = el("div.row-actions.band-filter", { role: "group", "aria-label": "Show a band" },
    ["all", "urgent", "look", "watch"].map((b) => el("button.btn.small" + (state.band === b ? ".on" : ""), {
      type: "button", "aria-pressed": state.band === b ? "true" : "false",
      onclick: () => { state.band = b; UI.prefs.set(BAND, b); render(); },
    }, b === "all" ? `All (${a.total})` : `${BAND_TEXT[b]} (${counts[b] || 0})`)));
  return section("attention", "Attention queue",
    "Every cluster above noise in the window, ranked. The band comes from facts in combination: grade, the worst target reached, the scope finding, interaction. Momentum only orders leads those leave tied.",
    filter,
    shown.length ? el("ol.queue", shown.map(queueItem))
      : none(state.band === "all" ? "No cluster above noise in the window." : `No ${state.band} lead.`),
    a.total > a.items.length ? el("p.small.muted", `${a.total - a.items.length} more at the bottom of the queue; attention.json in the run directory holds them all.`) : null);
}

// ---- activity timeline --------------------------------------------------------------

const SVGNS = "http://www.w3.org/2000/svg";

function svg(tag, attrs, ...kids) {
  const e = document.createElementNS(SVGNS, tag);
  for (const [k, v] of Object.entries(attrs || {})) if (v != null) e.setAttribute(k, String(v));
  for (const k of kids.flat()) if (k != null) e.append(k instanceof Node ? k : document.createTextNode(String(k)));
  return e;
}

function svgTitle(text) { return svg("title", null, text); }

function timelineSection(d) {
  const tl = d.timeline;
  const sub = "One row per cluster followed across runs (the ledger), in queue order, then others seen in the window. A bar is one run: its height the cluster's records, its colour the band, solid when that run collected records for it. Dots mark events.";
  if (!tl || !tl.rows.length) {
    return section("timeline", "Activity timeline", sub, none(tl ? "No cluster above noise in the window." : "No ledger yet; the next watch run starts one."));
  }
  const W = 1000, LABEL = 190, ROW = 24, AXIS = 22, RIGHT = 12;
  const span = Math.max(1, tl.to - tl.from);
  const x = (t) => LABEL + ((t - tl.from) / span) * (W - LABEL - RIGHT);
  const H = tl.rows.length * ROW + AXIS;
  const root = svg("svg", { viewBox: `0 0 ${W} ${H}`, class: "tl", role: "img",
    "aria-label": `Activity of ${tl.rows.length} clusters over the window, one bar per run` });
  const days = span / 86400;
  const step = days > 20 ? 7 : days > 6 ? 2 : 1;
  for (let t = tl.to; t >= tl.from; t -= step * 86400) {
    const xx = x(t);
    root.append(svg("line", { x1: xx, x2: xx, y1: 0, y2: H - AXIS, class: "tl-grid" }),
      svg("text", { x: xx, y: H - 6, class: "tl-axis", "text-anchor": "middle" },
        new Date(t * 1000).toISOString().slice(5, 10)));
  }
  tl.rows.forEach((r, i) => {
    const y = i * ROW;
    const g = svg("g", { class: "tl-row" + (r.band ? " b-" + r.band : "") });
    g.append(svgTitle(`${r.id || ""} ${r.key}: ${r.trajectory}, peak ${r.peak_grade}${r.merged_into ? `, merged into ${r.merged_into}` : ""}`));
    const label = `${r.rank ? "#" + r.rank + " " : ""}${r.id || "–"} ${r.key}`;
    g.append(svg("text", { x: 4, y: y + 16, class: "tl-label" + (r.trajectory === "dormant" ? " dim" : "") }, label));
    const pts = r.points;
    if (pts.length) {
      g.append(svg("line", { x1: x(pts[0].t), x2: x(pts[pts.length - 1].t), y1: y + ROW - 4, y2: y + ROW - 4, class: "tl-span" }));
    }
    const max = Math.max(1, ...pts.map((p) => p.records));
    const at = {};
    for (const p of pts) {
      const h = Math.max(3, ((ROW - 8) * p.records) / max);
      at[p.run] = p;
      g.append(svg("rect", {
        x: x(p.t) - 2, y: y + ROW - 4 - h, width: 4, height: h, rx: 1,
        class: "tl-pt b-" + (p.band || "none") + (p.added ? " added" : ""),
      }, svgTitle(`${p.run}: ${p.records} records, ${p.added} collected that run, ${p.tier}, ${p.grade}${p.band ? ", " + p.band : ""}`)));
    }
    for (const e of r.events || []) {
      const p = at[e.run];
      if (!p) continue;
      g.append(svg("circle", { cx: x(p.t), cy: y + 4, r: 3, class: "tl-ev k-" + e.kind },
        svgTitle(`${e.run}: ${e.kind.replace("_", " ")}: ${e.detail}`)));
    }
    root.append(g);
  });
  const legend = el("div.tl-legend.small.muted",
    ["urgent", "look", "watch"].map((b) => el("span", el("i.sw.b-" + b), BAND_TEXT[b])),
    el("span", el("i.sw.hollow"), "nothing collected that run"),
    el("span", el("i.dot-ev"), "event: new key, merge, split, rise, return"));
  return section("timeline", "Activity timeline", sub,
    el("div.table-wrap.tl-wrap", root),
    legend,
    tl.total > tl.rows.length ? el("p.small.muted", `${tl.total - tl.rows.length} more clusters in the ledger are not drawn.`) : null);
}

// ---- link graph -------------------------------------------------------------------

const GRAPH_VIEW = "dashboard.graph";
const GRAPH_TEXT = { all: "All links", swarm: "Interaction only", fleet: "Fleets only" };
const SWARM_W = { weak: 1.5, moderate: 2.5, strong: 3.5 };

// A force layout with no randomness: each group of tied clusters is laid
// out on its own, nodes starting on a circle in queue order, then the
// groups are packed into rows, largest first. The same overview always
// draws the same picture.
const TIE = 90, PAD = 46;

function layoutGroup(ids, ends) {
  const n = ids.length;
  const p = ids.map((_, i) => {
    const a = (2 * Math.PI * i) / n;
    const r = n === 1 ? 0 : TIE * 0.6 * Math.sqrt(n);
    return { x: r * Math.cos(a), y: r * Math.sin(a) };
  });
  for (let step = 0; step < 300; step++) {
    const f = p.map((q) => ({ x: -q.x * 0.03, y: -q.y * 0.03 }));
    for (let i = 0; i < n; i++) {
      for (let j = i + 1; j < n; j++) {
        const dx = p[i].x - p[j].x, dy = p[i].y - p[j].y;
        const r = (TIE * TIE) / Math.max(1, dx * dx + dy * dy);
        f[i].x += dx * r; f[i].y += dy * r; f[j].x -= dx * r; f[j].y -= dy * r;
      }
    }
    // Ties pull like springs, stronger ties harder.
    for (const [i, j, w] of ends) {
      const a = (Math.hypot(p[i].x - p[j].x, p[i].y - p[j].y) * w) / TIE;
      const dx = (p[i].x - p[j].x) * a, dy = (p[i].y - p[j].y) * a;
      f[i].x -= dx; f[i].y -= dy; f[j].x += dx; f[j].y += dy;
    }
    const temp = 20 * (1 - step / 300) + 0.5;
    for (let i = 0; i < n; i++) {
      const m = Math.hypot(f[i].x, f[i].y) || 1;
      p[i].x += (f[i].x / m) * Math.min(m, temp);
      p[i].y += (f[i].y / m) * Math.min(m, temp);
    }
  }
  return p;
}

function layout(nodes, links, W) {
  const at = new Map(nodes.map((nd, i) => [nd.id, i]));
  const parent = nodes.map((_, i) => i);
  const find = (x) => (parent[x] === x ? x : (parent[x] = find(parent[x])));
  for (const l of links) parent[find(at.get(l.a))] = find(at.get(l.b));
  const groups = new Map();
  nodes.forEach((_, i) => {
    const r = find(i);
    if (!groups.has(r)) groups.set(r, []);
    groups.get(r).push(i);
  });
  const boxes = [...groups.values()].sort((a, b) => b.length - a.length || a[0] - b[0]).map((g) => {
    const local = new Map(g.map((i, k) => [i, k]));
    const ends = links.filter((l) => local.has(at.get(l.a)))
      .map((l) => [local.get(at.get(l.a)), local.get(at.get(l.b)), Math.max(0.3, l.soft_strength || 0, l.swarm_strength ? 0.6 : 0)]);
    const p = layoutGroup(g, ends);
    const x0 = Math.min(...p.map((q) => q.x)), y0 = Math.min(...p.map((q) => q.y));
    return {
      g, p: p.map((q) => ({ x: q.x - x0 + PAD, y: q.y - y0 + PAD })),
      w: Math.max(...p.map((q) => q.x)) - x0 + 2 * PAD,
      h: Math.max(...p.map((q) => q.y)) - y0 + 2 * PAD,
    };
  });
  // Pack into rows: as many groups as fit across, each row as tall as its
  // tallest group; a row is centred in the width.
  const pos = new Map();
  let y = 0, row = [];
  const place = () => {
    const used = row.reduce((s, b) => s + b.w, 0);
    let x = Math.max(0, (W - used) / 2);
    const h = Math.max(...row.map((b) => b.h));
    for (const b of row) {
      const dy = (h - b.h) / 2;
      b.g.forEach((i, k) => pos.set(nodes[i].id, { x: x + b.p[k].x, y: y + dy + b.p[k].y }));
      x += b.w;
    }
    y += h;
    row = [];
  };
  for (const b of boxes) {
    if (b.w > W) {
      // Too wide for a row: scaled down to fit.
      const s = W / b.w;
      b.p = b.p.map((q) => ({ x: q.x * s, y: q.y * s }));
      b.w = W; b.h *= s;
    }
    if (row.length && row.reduce((s, x) => s + x.w, 0) + b.w > W) place();
    row.push(b);
  }
  if (row.length) place();
  return { pos, height: Math.max(160, y) };
}

// The convex hull of points, for a fleet's outline.
function hull(pts) {
  const s = [...pts].sort((a, b) => a.x - b.x || a.y - b.y);
  if (s.length < 3) return s;
  const cross = (o, a, b) => (a.x - o.x) * (b.y - o.y) - (a.y - o.y) * (b.x - o.x);
  const lo = [], hi = [];
  for (const q of s) { while (lo.length >= 2 && cross(lo[lo.length - 2], lo[lo.length - 1], q) <= 0) lo.pop(); lo.push(q); }
  for (const q of s.reverse()) { while (hi.length >= 2 && cross(hi[hi.length - 2], hi[hi.length - 1], q) <= 0) hi.pop(); hi.push(q); }
  return lo.slice(0, -1).concat(hi.slice(0, -1));
}

function nodeRadius(nd) { return Math.min(22, 6 + 2.2 * Math.sqrt(nd.records)); }

function linkText(l) {
  const parts = [];
  if (l.soft.length) parts.push(`soft ${l.soft_strength}: ${l.soft.map((s) => s.label).join(", ")}`);
  if (l.swarm.length) parts.push(`interaction (${l.swarm_strength}): ${l.swarm.map((s) => s.kind + " " + s.label).join(", ")}`);
  return `${l.a} to ${l.b}: ${parts.join("; ")}`;
}

function linkRows(l) {
  return [
    ...l.swarm.map((s) => el("tr.k-swarm",
      el("td", el("b", s.kind), " ", s.label), el("td", s.strength), el("td.small", s.runs.join(" to "), s.detail ? ": " + s.detail : ""))),
    ...l.soft.map((s) => el("tr",
      el("td", s.label), el("td.num", s.strength.toFixed(2)), el("td.small", s.detail || "–"))),
  ];
}

function linkTable(links) {
  return el("table.dtable.glinks",
    el("thead", el("tr", ["Tie", "Strength", "Detail"].map((h) => el("th", { scope: "col" }, h)))),
    el("tbody", links.flatMap((l) => [
      el("tr.pair", el("th", { colspan: "3", scope: "rowgroup" },
        `${l.a} and ${l.b}`, l.fleet ? el("span.chip.outline", "fleet " + l.fleet) : null,
        l.soft_strength != null ? el("span.muted.small", ` combined soft ${l.soft_strength.toFixed(2)}`) : null)),
      ...linkRows(l),
    ])));
}

function graphDetail(g, sel) {
  if (!sel) return el("p.small.muted", "Select a cluster or a line for what ties it.");
  if (sel.node) {
    const nd = g.nodes.find((x) => x.id === sel.node);
    const ls = g.links.filter((l) => l.a === nd.id || l.b === nd.id);
    return el("div.gd",
      el("div.q-head",
        nd.rank ? el("span.q-rank.muted", "#" + nd.rank) : null,
        bandChip(nd.band),
        el("span.cl-id", tierDot(nd.tier), el("b", nd.id), " ", el("code.muted", nd.key)),
        gradeChip({ code: nd.grade, label: nd.grade_label }),
        nd.fleet ? el("span.chip.outline", "fleet " + nd.fleet) : null,
        nd.inner ? el("span.chip.outline", { title: "Interaction between strands of one run inside the cluster" }, plural(nd.inner, "inner edge")) : null),
      el("p.small.muted", `${plural(nd.records, "record")}, ${plural(nd.targets, "target host")}`,
        nd.top_target ? [", most often ", el("code.target", nd.top_target)] : null, "."),
      ls.length ? linkTable(ls) : null);
  }
  const l = g.links.find((x) => x.a === sel.a && x.b === sel.b);
  return l ? linkTable([l]) : null;
}

function graphSection(d) {
  const g = d.graph;
  const sub = "Clusters above noise that something ties together. Grey lines are soft links (thicker is stronger, combined per pair); red dashed lines are possible interaction (S1 to S6). Shaded areas are candidate fleets. None of it merges clusters or changes a score: each tie is a lead to check.";
  if (!g || !g.nodes.length) {
    return section("graph", "Link graph", sub, none(g ? `No ties between the ${plural(g.clusters, "cluster")} above noise.` : "The latest run has no analysis to draw."));
  }
  const view = UI.prefs.get(GRAPH_VIEW) || "all";
  const keep = (l) => view === "all" || (view === "swarm" ? l.swarm.length > 0 : l.fleet != null);
  const links = g.links.filter(keep);
  const ends = new Set(links.flatMap((l) => [l.a, l.b]));
  const nodes = view === "all" ? g.nodes : g.nodes.filter((nd) => ends.has(nd.id) || (view === "swarm" && nd.inner));
  const W = 1000;
  const { pos, height: H } = layout(nodes, links, W);
  const root = svg("svg", { viewBox: `0 0 ${W} ${H}`, class: "graph", role: "img",
    "aria-label": `${plural(nodes.length, "cluster")} and ${plural(links.length, "tie")}; the table below lists them` });
  const shown = new Set(nodes.map((nd) => nd.id));
  // Fleets rest on soft links: outlined only where those are drawn.
  for (const f of view === "swarm" ? [] : g.fleets) {
    const pts = f.clusters.filter((c) => shown.has(c)).map((c) => pos.get(c));
    if (pts.length < 2) continue;
    const h = hull(pts);
    root.append(svg("polygon", { points: h.map((q) => `${q.x},${q.y}`).join(" "), class: "g-fleet" },
      svgTitle(`${f.id}: ${f.clusters.join(", ")}; ${f.kinds.join(", ")}; weakest pair ${f.strength}`)));
    const top = h.reduce((a, b) => (b.y < a.y ? b : a));
    root.append(svg("text", { x: top.x, y: Math.max(12, top.y - 28), class: "g-flabel", "text-anchor": "middle" }, f.id));
  }
  const detail = el("div.graph-detail");
  let sel = null;
  const select = (s, target) => {
    sel = s;
    for (const e of root.querySelectorAll(".on")) e.classList.remove("on");
    if (target) target.classList.add("on");
    detail.replaceChildren(graphDetail(g, sel));
  };
  for (const l of links) {
    const a = pos.get(l.a), b = pos.get(l.b);
    const grp = svg("g", { class: "g-link", tabindex: "0", role: "button", "aria-label": linkText(l) }, svgTitle(linkText(l)));
    grp.append(svg("line", { x1: a.x, y1: a.y, x2: b.x, y2: b.y, class: "g-hit" }));
    if (l.soft.length) {
      grp.append(svg("line", { x1: a.x, y1: a.y, x2: b.x, y2: b.y, class: "g-soft",
        "stroke-width": 1 + 5 * l.soft_strength, "stroke-opacity": 0.35 + 0.6 * l.soft_strength }));
    }
    if (l.swarm.length) {
      grp.append(svg("line", { x1: a.x, y1: a.y, x2: b.x, y2: b.y, class: "g-swarm", "stroke-width": SWARM_W[l.swarm_strength] || 1.5 }));
    }
    const pick = () => select({ a: l.a, b: l.b }, grp);
    grp.addEventListener("click", pick);
    grp.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); pick(); } });
    root.append(grp);
  }
  for (const nd of nodes) {
    const p = pos.get(nd.id), r = nodeRadius(nd);
    const label = `${nd.rank ? "#" + nd.rank + " " : ""}${nd.id} ${nd.key}: ${nd.band || "no band"}, ${nd.grade}, ${plural(nd.records, "record")}, ${plural(nd.links, "tie")}`;
    const grp = svg("g", { class: "g-node b-" + (nd.band || "none"), tabindex: "0", role: "button", "aria-label": label }, svgTitle(label));
    if (nd.inner) grp.append(svg("circle", { cx: p.x, cy: p.y, r: r + 4, class: "g-inner" }));
    grp.append(svg("circle", { cx: p.x, cy: p.y, r, class: "g-dot" }),
      svg("text", { x: p.x, y: p.y + r + 13, class: "g-label", "text-anchor": "middle" }, nd.id),
      nd.rank ? svg("text", { x: p.x, y: p.y + 4, class: "g-rank", "text-anchor": "middle" }, nd.rank) : null);
    const pick = () => select({ node: nd.id }, grp);
    grp.addEventListener("click", pick);
    grp.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); pick(); } });
    root.append(grp);
  }
  detail.replaceChildren(graphDetail(g, sel));
  const filter = el("div.row-actions", { role: "group", "aria-label": "Which ties to draw" },
    Object.entries(GRAPH_TEXT).map(([v, t]) => el("button.btn.small" + (view === v ? ".on" : ""), {
      type: "button", "aria-pressed": view === v ? "true" : "false",
      onclick: () => { UI.prefs.set(GRAPH_VIEW, v); render(); },
    }, t)));
  const legend = el("div.tl-legend.small.muted",
    ["urgent", "look", "watch"].map((b) => el("span", el("i.gsw.b-" + b), BAND_TEXT[b])),
    el("span", el("i.gline.soft"), "soft link"),
    el("span", el("i.gline.swarm"), "possible interaction"),
    el("span", el("i.gsw.ring"), "interaction inside the cluster"),
    el("span", el("i.gsw.fleet"), "candidate fleet"));
  return section("graph", "Link graph", sub,
    filter,
    links.length ? el("div.table-wrap.tl-wrap", root) : none(`No ${GRAPH_TEXT[view].toLowerCase().replace(" only", "")} in this analysis.`),
    legend,
    detail,
    g.linked > g.nodes.length ? el("p.small.muted", `${g.linked - g.nodes.length} more tied clusters are not drawn; the queue's top ones are.`) : null,
    el("details.q-more", el("summary", `All ${plural(g.links.length, "tie")} as a table`), linkTable(g.links)));
}

// ---- autonomy ---------------------------------------------------------------------

const LEVEL_TEXT = { interrupt: "Interrupt", watch_harder: "Watch harder", draft_case: "Draft case" };
const LEVEL_DOES = {
  interrupt: "raise the run's priority to high so the digest reaches you now",
  watch_harder: "pull the lead's sources more often and watch its targets, passively",
  draft_case: "open a draft case, find contacts, draft the provider report",
};
const OUTCOME = {
  agreed: { cls: "benign", text: "agreed" },
  disagreed: { cls: "agent", text: "disagreed" },
  pending: { cls: "outline", text: "pending" },
  held_back: { cls: "unsure", text: "held back" },
};

function pct(x) { return x == null ? "–" : `${Math.round(x * 100)}%`; }

function autonomySection(d) {
  const a = d.autonomy;
  if (!a) return null;
  const levels = el("div.table-wrap", el("table.dtable.autonomy",
    el("thead", el("tr", ["Level", "Mode", "Lines", "Agreed", "Disagreed", "Pending", "Agreement", "Held back", "Never proposed"].map((h) => el("th", { scope: "col" }, h)))),
    el("tbody", a.levels.map((l) => el("tr",
      el("th", { scope: "row" }, el("div", LEVEL_TEXT[l.level] || l.level), el("div.muted.small", LEVEL_DOES[l.level] || "")),
      el("td", el("span.chip." + (l.mode === "on" ? "agent" : l.mode === "shadow" ? "outline" : "unsure"), l.mode)),
      el("td.num", String(l.decisions)),
      el("td.num", String(l.agreed)),
      el("td.num", String(l.disagreed)),
      el("td.num", String(l.pending)),
      el("td.num", el("b", pct(l.agreement))),
      el("td.num", String(l.suppressed)),
      el("td.num", l.missed == null ? "–" : String(l.missed)))))));
  const recent = a.recent.length ? el("div.table-wrap", el("table.dtable",
    el("thead", el("tr", ["Time", "Level", "Cluster", "Trigger", "Would do", "Outcome"].map((h) => el("th", { scope: "col" }, h)))),
    el("tbody", a.recent.map((x) => {
      const o = OUTCOME[x.outcome] || { cls: "outline", text: x.outcome };
      return el("tr",
        el("td.nowrap.muted.small", x.time),
        el("td", LEVEL_TEXT[x.level] || x.level, el("div.muted.small", x.mode)),
        el("td", el("div.cl-id", el("b", x.cluster), " ", el("code.muted", x.key)), el("div.small", bandChip(x.band), " ", x.grade)),
        el("td.small", x.trigger),
        el("td.small", x.proposal, x.suppressed ? el("div.muted", "held back: " + x.suppressed) : null),
        el("td", el("span.chip." + o.cls, o.text)));
    }))))
    : none("No level has fired yet. A level fires only on leads at grade L2 or higher.");
  return section("autonomy", "Autonomy",
    "What each level did, or in shadow would have done, read against what you decided later: a case on the lead, or an agent label on its records, agrees; labels with no agent, or no case two weeks after a draft-case line, disagree. Switch a level on only when its record earns it. Modes are set in the watchlist's [autonomy]; only interrupt can be on, and nothing here sends, publishes or opens a case.",
    levels,
    el("h3", `Latest lines (${a.recent.length} of ${a.lines})`),
    recent);
}

// ---- health ---------------------------------------------------------------------

/** Bars of the records pulled on each kept successful run, oldest first. */
function spark(pulled, name) {
  if (!pulled || !pulled.length) return el("span.muted.small", "no history");
  const max = Math.max(1, ...pulled);
  const box = el("span.spark", { role: "img", "aria-label": `${name}: records pulled on the last ${pulled.length} runs: ${pulled.join(", ")}` });
  pulled.forEach((n, i) => {
    const b = el("span.bar" + (i === pulled.length - 1 ? ".last" : "") + (n === 0 ? ".zero" : ""),
      { title: `${i === pulled.length - 1 ? "latest kept run" : `${pulled.length - 1 - i} run(s) earlier`}: ${n}` });
    b.style.height = `${Math.max(8, (100 * n) / max)}%`;
    box.append(b);
  });
  return el("span.spark-wrap", box, el("span.small.muted", String(pulled[pulled.length - 1])));
}

function healthSection(d) {
  const h = d.health;
  const ran = h.sources.filter((s) => s.status !== "never-run");
  const never = h.sources.filter((s) => s.status === "never-run");
  const rows = ran.map((s) => el("tr.s-" + s.status,
    el("th", { scope: "row" }, el("div", s.name), s.kind ? el("div.muted.small", s.kind) : null),
    el("td", statusChip(s.status)),
    el("td", spark(s.pulled, s.name)),
    el("td.num", String(s.new_latest)),
    el("td.nowrap.muted.small", s.last_run ? stampText(s.last_run) : "never"),
    el("td.small", detail(s))));
  const lvl = { ok: "All sources ran; no failures, collapses or rule drift.", warn: "Running, with something to check.", alert: "Something failed or drifted." }[h.level];
  return section("health", "Monitoring health", lvl,
    h.alerts.length ? el("div.callout" + (h.level === "alert" ? ".danger" : ".warn"),
      el("div.callout-title", "From the latest digest"),
      el("ul.alerts", h.alerts.map((a) => el("li", ticks(a))))) : null,
    h.submit_time_ran === false && !h.alerts.some((a) => a.includes("submit-time source")) ? el("p.small.lost", icon("alert"), " No submit-time source ran on the latest run: timing links, pace and agent grades above L2 are unavailable.") : null,
    el("h3", "Sources"),
    ran.length ? el("div.table-wrap", el("table.dtable.sources",
      el("thead", el("tr", ["Source", "Status", "Pulled, recent runs", "New", "Last run", "Detail"].map((x) => el("th", { scope: "col" }, x)))),
      el("tbody", rows))) : none("No source has run yet."),
    never.length ? el("details.never", el("summary", `${plural(never.length, "source")} in the watchlist not run yet`),
      el("p.small", never.map((s) => el("code.chip.outline", s.name)))) : null,
    !h.watchlist_read ? el("p.small.muted", "The watchlist was not read, so source kinds and lost capability are unknown; pass --watchlist.") : null,
    el("h3", `Rule drift (${h.drift.length})`),
    h.drift.length ? el("div.table-wrap", el("table.dtable",
      el("thead", el("tr", ["Rule", "Source", "This run", "Baseline"].map((x) => el("th", { scope: "col" }, x)))),
      el("tbody", h.drift.map((x) => el("tr",
        el("td", el("code", x.rule)), el("td", x.source),
        el("td.num", `${x.hits} of ${x.records} (${x.rate_pct}%)`),
        el("td.num.muted", `${x.baseline_hits} of ${x.baseline_records} (${x.baseline_rate_pct}%)`))))))
      : none(h.drift_rules_version ? `No rule fired well above its baseline (rules ${h.drift_rules_version}).` : "No drift baseline yet."));
}

function detail(s) {
  const bits = [];
  if (s.reason) bits.push(el("div", s.reason));
  if (s.status === "failing") bits.push(el("div.muted", `${plural(s.errors_in_row, "run")} in a row`));
  if (s.status === "quiet") bits.push(el("div.muted", `nothing pulled in ${s.empty_runs} runs${s.ever_pulled ? "" : ", and never has"}`));
  if (s.status === "skipped") bits.push(el("div.muted", `skipped ${plural(s.skipped_runs, "run")} in a row`));
  if (s.pending) bits.push(el("div.muted", "a long pull continues next run"));
  if (s.lost) bits.push(el("div.lost", "Lost: " + s.lost));
  return bits.length ? bits : el("span.muted", "–");
}

// ---- waiting --------------------------------------------------------------------

function reviewCard(r) {
  if (!r) return el("div.card.pad", none("No analysis to queue from yet."));
  if (r.error) return el("div.card.pad", el("p", "Review file not read: " + r.error));
  const lw = r.labelled_in_window || {};
  const done = (lw.agent || 0) + (lw.benign || 0) + (lw.unsure || 0);
  const total = r.flagged_in_window || 0;
  const lt = r.labelled_total || {};
  return el("div.card.pad.review",
    el("div.big", el("b", String(r.unreviewed)), " unreviewed ", el("span.muted", `in ${plural(r.groups, "group")}`)),
    el("div.chips", Object.entries(r.unreviewed_by_tier || {}).map(([t, n]) => el("span.tier." + t, tierDot(t), `${n} ${t}`)),
      r.with_suggestion ? el("span.chip.outline", `${r.with_suggestion} with a model suggestion`) : null),
    progress([{ cls: "agent", n: lw.agent }, { cls: "benign", n: lw.benign }, { cls: "unsure", n: lw.unsure }],
      total, `${done} of ${total} flagged records in the window labelled`),
    el("p.small.muted", `All time: ${lt.agent || 0} agent, ${lt.benign || 0} benign, ${lt.unsure || 0} unsure in the default review file; ${r.reviewed_any_labeller} records reviewed by any labeller.`),
    belowRule(r.agent_below_rule),
    command(r.command, "review page"),
    el("details", el("summary.small", "Counts and agreement"), command(r.stats_command, "review stats")));
}

// Agent labels below L2 are exceptions to the labelling rule: counted apart,
// so the agent total above is never read as ordinary agent labels alone.
function belowRule(b) {
  if (!b || !b.total) return null;
  const parts = [`${b.with_reason} with a reason noted`];
  if (b.graded_now) parts.push(`${b.graded_now} graded now, their lines storing no grade`);
  return el("div.callout.warn.below-rule", { role: "note" },
    el("p.small", icon("alert"), " ", el("b", `${plural(b.total, "agent label")} below L2`),
      ` of ${b.agents}: exceptions to the labelling rule (agent needs L2 or higher). ${parts.join("; ")}. The review page and review stats show each with its grade.`));
}

function caseCard(c) {
  if (c.error) return el("div.card.pad", el("p", "Cases not read: " + c.error));
  return el("article.card.pad.case",
    el("div.case-head",
      el("div", el("h3", c.title), el("code.muted.small", c.id)),
      el("div.chips", el("span.chip.outline", c.status), el("span.chip.outline", "notice " + c.notice),
        c.watch_hits ? el("span.chip" + (c.watch_hits_new ? ".agent" : ".outline"), `${c.watch_hits} watch hit${c.watch_hits === 1 ? "" : "s"}${c.watch_hits_new ? `, ${c.watch_hits_new} new` : ""}`) : null)),
    el("div.case-grid",
      el("div",
        el("div.section-title", "Clocks"),
        c.notice_not_before ? el("p.small", "Indicator notice not before ", el("b", c.notice_not_before)) : null,
        c.naming_ready ? el("p.small", el("b", plural(c.naming_ready, "operator")), " may be named now") : null,
        el("ul.clock", c.clock.map((l) => el("li.small", l)))),
      el("div",
        el("div.section-title", `Needs (${c.needs.length})`),
        c.needs.length ? el("ol.needs", c.needs.map((n) => el("li", el("div.small", n.text), command(n.command, n.text)))) : none("Nothing listed."))),
    command(c.status_command, "case status"));
}

function waitingSection(d) {
  const cases = d.waiting.cases || [];
  return el("div.dstack",
    section("waiting", "Waiting on you: review", "Leads at suggestive or above in the latest run's analysis that the default review file has no label for.",
      reviewCard(d.waiting.review)),
    section("cases", "Waiting on you: open cases", ticks("Each case's clocks and what `case status` says it still needs."),
      cases.length ? el("div.cases", cases.map(caseCard)) : none("No open case in this data directory.")));
}

// ---- runs and digest ----------------------------------------------------------

function runsSection(d) {
  const r = d.run;
  return section("runs", "Runs", null,
    el("div.runs",
      r.runs.map((s, i) => el("button.btn.small" + (s === (d.since && d.since.stamp) ? ".on" : "") + (i === 0 ? ".latest" : ""), {
        type: "button", title: `Show what is new since ${stampText(s)}`,
        onclick: () => setSince(s),
      }, stampText(s), i === 0 ? el("span.muted", " latest") : null))),
    el("p.small.muted", "Pick a run to count what later runs collected as new. Kept runs follow the watch's retention."),
    el("div.row-actions",
      el("button.btn.small", { type: "button", onclick: () => showDigest(r.latest) }, "Read the latest digest"),
      command(r.digest_command, "print the digest")));
}

async function showDigest(stamp) {
  let res;
  try { res = await api.get("digest/" + stamp); }
  catch (e) { toast("Digest not read: " + e.message, { error: true }); return; }
  const back = document.activeElement;
  const close = () => { o.remove(); if (back && back.isConnected) back.focus(); };
  const closeBtn = el("button.btn.ghost.small.icon-only", { type: "button", "aria-label": "Close", title: "Close (Esc)", onclick: close }, icon("close"));
  const card = el("div.card.digest", { role: "dialog", "aria-modal": "true", "aria-labelledby": "digest-title" },
    el("div.dialog-head", el("h2#digest-title", "Digest " + stampText(res.stamp)), closeBtn),
    el("pre.mono", res.text));
  const o = el("div.overlay", { onclick: (e) => { if (e.target === o) close(); } }, card);
  card.addEventListener("keydown", (e) => { if (e.key === "Escape") { e.stopPropagation(); close(); } });
  document.body.append(o);
  closeBtn.focus();
}

// ---- page -----------------------------------------------------------------------

function topbar(d) {
  const r = d.run;
  const meta = r ? `run ${stampText(r.latest)} · ${ago(r.age_hours)}${r.rules_version ? " · rules " + r.rules_version : ""}` : "no watch run yet";
  return el("header.topbar",
    el("div.brand", el("span.brand-mark", "swarmchase"), el("span.brand-sub", "Monitoring")),
    el("div.spacer"),
    el("div.meta" + (r && r.stale ? ".stale" : ""), { title: d.data_dir }, meta),
    el("div.toolbar",
      el("button.btn.ghost.small", { type: "button", onclick: () => load(true), title: "Reload from the data directory (r)" }, "Refresh"),
      el("button.btn.ghost.small.icon-only", { type: "button", onclick: UI.help, title: "Keyboard shortcuts (?)", "aria-label": "Keyboard shortcuts" }, icon("keyboard")),
      settings()));
}

// The digest's priority and the local model's suggestions, from run.json.
function priorityBanner(d) {
  const r = d.run;
  if (!r || !r.priority) return null;
  const reasons = r.reasons || [];
  return el("section.card.priority.p-" + r.priority, { "aria-label": "Digest priority" },
    el("div.priority-head",
      el("span.chip.prio", r.priority.toUpperCase()),
      el("span", reasons.length ? "Needs attention, as the digest says:" : "Nothing in the latest run needs attention.")),
    reasons.length ? el("ul.reasons", reasons.map((x) => el("li", el("span.chip.small", x.level), " ", ticks(x.text)))) : null);
}

function suggestionsSection(d) {
  const r = d.run;
  const list = (r && r.suggestions) || [];
  const t = r && r.triage;
  if (!list.length && !(t && t.enabled)) return null;
  return section("triage", "Model triage", "A local model's view of the run's new leads. Suggestions, never labels; agent needs grade L2 or higher.",
    t && t.note ? el("p.small.muted", t.note) : null,
    list.length ? el("ul.suggestions", list.map((s) => el("li" + (s.conflict ? ".conflict" : ""),
      el("code", s.id), " ", s.grade ? gradeChip({ code: s.grade, label: "" }) : null, " ",
      el("span.chip.small." + s.label, s.label),
      s.conflict ? el("span.chip.small.unsure", icon("alert"), " against the labelling rule") : null,
      el("div.small.muted", ticks(s.reason || ""), s.model ? ` (${s.model})` : ""))))
      : none("The model was asked about nothing new this run."));
}

function render() {
  const d = state.data;
  const app = document.getElementById("app");
  const y = window.scrollY;
  const body = d.run
    ? [priorityBanner(d), tiles(d), actions(d), attentionSection(d), newSection(d), timelineSection(d), graphSection(d), suggestionsSection(d), healthSection(d), waitingSection(d), autonomySection(d), runsSection(d)]
    : [actions(d), emptyState({
      title: "No watch run here yet",
      body: ["The dashboard reads what a watch run leaves in the data directory.", el("code", d.data_dir)],
      icon: "inbox",
    }), healthSection(d), waitingSection(d)];
  app.replaceChildren(topbar(d), el("main.dash", body, el("footer.foot.small.muted",
    `Read-only. Generated ${d.generated} from `, el("code", d.data_dir),
    `. The same document: swarmchase dashboard --json${d.since && d.since.requested ? " --since " + d.since.requested : ""}`)));
  // Each cell names its column, for the stacked layout on a narrow screen.
  for (const t of app.querySelectorAll(".dtable")) {
    const heads = [...t.querySelectorAll("thead th")].map((h) => h.textContent);
    for (const tr of t.querySelectorAll("tbody tr")) [...tr.children].forEach((c, i) => { c.dataset.label = heads[i] || ""; });
  }
  window.scrollTo(0, y);
}

async function load(manual = false) {
  if (state.loading) return;
  state.loading = true;
  try {
    const path = state.since ? "overview/since/" + state.since : "overview";
    state.data = await api.get(path);
    state.at = Date.now();
    render();
    if (manual) toast("Up to date");
  } catch (e) {
    if (state.data) toast("Not refreshed: " + e.message, { error: true });
    else document.getElementById("app").replaceChildren(emptyState({
      title: "The overview did not load", body: [e.message], icon: "alert", kind: "error",
      extra: el("button.btn", { type: "button", onclick: () => load(true) }, "Try again"),
    }));
  } finally { state.loading = false; }
}

function setSince(stamp) {
  state.since = stamp;
  UI.prefs.set(SEEN, stamp);
  load();
}

function markSeen() {
  const r = state.data && state.data.run;
  if (!r) return;
  setSince(r.latest);
  toast(`Marked ${stampText(r.latest)} seen; later runs will show as new`);
}

function forget() {
  state.since = null;
  UI.prefs.set(SEEN, null);
  load();
}

function jump(id) {
  const t = document.getElementById(id);
  if (!t) return;
  t.scrollIntoView({ behavior: "smooth", block: "start" });
  t.setAttribute("tabindex", "-1");
  t.focus({ preventScroll: true });
}

keys([
  { keys: ["r"], label: "refresh from the data directory", run: () => load(true) },
  { keys: ["s"], label: "mark the latest run seen", run: markSeen },
  { keys: ["d"], label: "read the latest digest", run: () => state.data && state.data.run && showDigest(state.data.run.latest) },
  { keys: ["1"], label: "next steps", run: () => jump("next") },
  { keys: ["2"], label: "attention queue", run: () => jump("attention") },
  { keys: ["3"], label: "new since you last looked", run: () => jump("new") },
  { keys: ["4"], label: "activity timeline", run: () => jump("timeline") },
  { keys: ["5"], label: "monitoring health", run: () => jump("health") },
  { keys: ["6"], label: "review queue and cases", run: () => jump("waiting") },
  { keys: ["7"], label: "autonomy", run: () => jump("autonomy") },
  { keys: ["8"], label: "link graph", run: () => jump("graph") },
]);

// Refresh while the page is visible, so a finished watch run shows up.
setInterval(() => { if (!document.hidden && Date.now() - state.at >= REFRESH_MS) load(); }, 15000);
document.addEventListener("visibilitychange", () => { if (!document.hidden && Date.now() - state.at >= REFRESH_MS) load(); });

load();
