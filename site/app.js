// Swarmchasing toolkit UI. All analysis is done by sc-wasm in this tab.
// Record contents are untrusted: they are only ever inserted with textContent,
// URLs are shown defanged, and nothing from a record becomes a link.
import init, * as sc from "./pkg/sc_wasm.js";
import "./case.js";

const $ = (id) => document.getElementById(id);
const RULES_KEY = "swarmchase.rules";
let state = { analysis: null, cluster: null, dateTags: {} };

// Attributes that load or navigate. Only blob: URLs the page made itself.
const URL_ATTRS = new Set(["href", "src", "action", "formaction", "xlink:href"]);

function el(tag, attrs = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") e.className = v;
    // Styles go through CSSOM: the CSP blocks style attributes.
    else if (k === "style") Object.assign(e.style, v);
    else if (k.startsWith("on")) {
      if (typeof v !== "function") throw new Error(`${k}: handler must be a function`);
      e.addEventListener(k.slice(2), v);
    } else if (URL_ATTRS.has(k.toLowerCase()) && !String(v).startsWith("blob:")) {
      throw new Error(`${k}: only blob: URLs`);
    } else e.setAttribute(k, v);
  }
  for (const k of kids.flat()) if (k != null) e.append(k instanceof Node ? k : String(k));
  return e;
}

const store = {
  get(k) { try { return localStorage.getItem(k); } catch { return null; } },
  set(k, v) { try { localStorage.setItem(k, v); } catch {} },
  del(k) { try { localStorage.removeItem(k); } catch {} },
};

const fmtTs = (t) => (t > 0 ? new Date(t * 1000).toISOString().replace("T", " ").slice(0, 19) + " UTC" : "unknown");
const dur = (s) => (s < 120 ? `${s}s` : s < 7200 ? `${Math.round(s / 60)}m` : `${(s / 3600).toFixed(1)}h`);
const rulesText = () => $("rules").value;
const pill = (tier) => el("span", { class: `pill ${tier}` }, tier);
const trunc = (s, n) => (s.length > n ? s.slice(0, n) + "…" : s);
// Record-derived text for display: defanged, then cut short.
const safe = (s, n = 120) => trunc(sc.defang(String(s ?? "")), n);
// Older analysis JSON lacks newer fields; read everything through these.
const arr = (x) => (Array.isArray(x) ? x : []);
const obj = (x) => (x && typeof x === "object" && !Array.isArray(x) ? x : {});
const num = (x) => (typeof x === "number" && Number.isFinite(x) ? x : null);
const pct = (x) => (num(x) == null ? "n/a" : `${(x * 100).toFixed(1)}%`);
const signed = (x) => (x >= 0 ? `+${x}` : `${x}`);

function showError(target, err) {
  target.replaceChildren(el("p", { class: "hint warn" }, String(err?.message ?? err)));
}

// ── Tabs ────────────────────────────────────────────────────────────────────
function showTab(name) {
  document.querySelectorAll(".tabs button").forEach((x) => x.setAttribute("aria-selected", x.dataset.tab === name));
  document.querySelectorAll(".tab").forEach((t) => (t.hidden = t.id !== `tab-${name}`));
  if (name === "notices") showNotices();
}
document.querySelectorAll(".tabs button").forEach((b) => b.addEventListener("click", () => showTab(b.dataset.tab)));

// ── Analyze ─────────────────────────────────────────────────────────────────
function runAnalysis() {
  const warn = $("warnings");
  warn.hidden = true;
  let out;
  try {
    out = JSON.parse(sc.analyze($("input").value, $("format").value, $("map").value, rulesText()));
  } catch (e) {
    warn.hidden = false;
    warn.textContent = String(e?.message ?? e);
    return;
  }
  const notes = [];
  if (out.redacted) notes.push(`${out.redacted} secret value(s) such as cookies or tokens were replaced with hashes.`);
  if (out.warnings.length) notes.push(`${out.warnings.length} warning(s): ${out.warnings.slice(0, 3).join("; ")}`);
  if (notes.length) {
    warn.hidden = false;
    warn.textContent = notes.join(" ");
  }
  state = { analysis: out.analysis, cluster: null, dateTags: obj(out.cluster_date_tags) };
  render();
}

function render() {
  const a = state.analysis;
  $("results").hidden = false;
  const t = (k) => a.tier_counts[k] ?? 0;
  $("tiles").replaceChildren(
    ...[
      [a.total, "records"],
      [a.flagged, "flagged"],
      [t("significant"), "significant"],
      [t("suggestive"), "suggestive"],
      [a.clusters.length, "clusters"],
      [a.max_concurrent_clusters, "max concurrent runs"],
    ].map(([v, k]) => el("div", { class: "tile" }, el("div", { class: "v" }, v.toLocaleString()), el("div", { class: "k" }, k))),
  );

  const notes = [];
  if (a.timing.count) notes.push(`${fmtTs(a.timing.start)} → ${fmtTs(a.timing.end)}`);
  if (a.timing.median_gap_secs != null) notes.push(`median gap ${dur(Math.round(a.timing.median_gap_secs))}`);
  if (a.timing.pauses.length) notes.push(`${a.timing.pauses.length} pause(s), shaded`);
  const d = a.date_tags;
  if (d.consistent && d.ahead > 0) notes.push(`date tags ahead of UTC in ${d.ahead}/${d.tagged} → operator clock UTC+${d.min_hours}…UTC+${d.max_hours}`);
  if (a.asns.length) notes.push(a.asns.slice(0, 3).map((s) => `AS${s.asn}${s.org ? ` ${s.org}` : ""} (${s.count})`).join(", "));
  $("timing-notes").textContent = notes.join(" · ");

  drawChart(a.timing);
  renderClusters();
  renderLinks();
  renderEndpoints();
  renderRecords();
  renderReport();
}

function drawChart(timing) {
  const box = $("chart");
  const data = timing.hourly;
  if (!data.length) {
    box.replaceChildren(el("p", { class: "hint" }, "No timestamps on flagged records."));
    return;
  }
  const W = 1000, H = 220, L = 40, R = 8, T = 8, B = 28;
  const max = Math.max(1, ...data.map((d) => d[1]));
  const step = (W - L - R) / data.length;
  const bw = Math.max(1, step - 2); // 2px gap between bars
  const y = (v) => T + (H - T - B) * (1 - v / max);
  const x0 = data[0][0], span = data.length * 3600;
  const xs = (t) => L + ((t - x0) / span) * (W - L - R);
  const ns = "http://www.w3.org/2000/svg";
  const s = (tag, attrs) => {
    const e = document.createElementNS(ns, tag);
    for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v);
    return e;
  };
  const svg = s("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": "Flagged records per hour, UTC" });

  const grid = s("g", { class: "grid" });
  const axis = s("g", { class: "axis" });
  const ticks = [0, Math.round(max / 2), max].filter((v, i, arr) => arr.indexOf(v) === i);
  for (const v of ticks) {
    grid.append(s("line", { x1: L, x2: W - R, y1: y(v), y2: y(v) }));
    const tx = s("text", { x: L - 6, y: y(v) + 4, "text-anchor": "end" });
    tx.textContent = v;
    axis.append(tx);
  }
  const labelEvery = Math.max(1, Math.ceil(data.length / 8));
  data.forEach(([h], i) => {
    if (i % labelEvery) return;
    const tx = s("text", { x: L + i * step + step / 2, y: H - 8, "text-anchor": "middle" });
    const dt = new Date(h * 1000).toISOString();
    tx.textContent = data.length > 24 ? `${dt.slice(5, 10)} ${dt.slice(11, 13)}h` : `${dt.slice(11, 13)}:00`;
    axis.append(tx);
  });
  svg.append(grid);

  for (const p of timing.pauses) {
    svg.append(s("rect", { class: "pause", x: xs(p.start), y: T, width: Math.max(1, xs(p.end) - xs(p.start)), height: H - T - B }));
  }

  const tip = $("tip");
  data.forEach(([h, c], i) => {
    const x = L + i * step + 1;
    const g = s("g", {});
    const hit = s("rect", { class: "hit", x: L + i * step, y: T, width: step, height: H - T - B });
    const bar = c ? s("rect", { class: "bar", x, y: y(c), width: bw, height: H - B - y(c), rx: Math.min(4, bw / 2) }) : null;
    hit.addEventListener("mousemove", (ev) => {
      tip.hidden = false;
      tip.textContent = `${fmtTs(h).slice(0, 16)} UTC — ${c} flagged`;
      tip.style.left = `${ev.clientX + 12}px`;
      tip.style.top = `${ev.clientY + 12}px`;
      bar?.classList.add("active");
    });
    hit.addEventListener("mouseleave", () => {
      tip.hidden = true;
      bar?.classList.remove("active");
    });
    if (bar) g.append(bar);
    g.append(hit);
    svg.append(g);
  });
  svg.append(axis);
  box.replaceChildren(svg);
}

function topEntries(obj, n) {
  return Object.entries(obj).sort((a, b) => b[1] - a[1]).slice(0, n);
}

function renderClusters() {
  const a = state.analysis;
  const head = el("thead", {}, el("tr", {}, ["", "Tier", "Records", "Runs", "First seen", "Last seen", "Targets", "Top rules"].map((h) => el("th", {}, h))));
  const body = el("tbody");
  if (!a.clusters.length) body.append(el("tr", {}, el("td", { colspan: 8, class: "hint" }, "No clusters. Records need shared identifiers or close timing to link.")));
  a.clusters.forEach((c, i) => {
    const tr = el(
      "tr",
      { class: state.cluster === i ? "sel" : "", onclick: () => { state.cluster = state.cluster === i ? null : i; renderClusters(); renderRecords(); renderReport(); } },
      el("td", {}, c.id),
      el("td", {}, pill(c.tier)),
      el("td", { class: "num" }, c.members.length),
      el("td", { class: "num" }, c.runs.length),
      el("td", {}, fmtTs(c.start)),
      el("td", {}, fmtTs(c.end)),
      el("td", {}, topEntries(c.target_hosts, 3).map(([h, n]) => el("span", { class: "chip" }, `${sc.defang("https://" + h).slice(8)} ×${n}`))),
      el("td", {}, topEntries(c.rules, 4).map(([r]) => el("span", { class: "chip" }, r))),
    );
    body.append(tr);
  });
  $("clusters").replaceChildren(head, body);
  renderClusterDetail();
}

// ── Cluster detail: timing and hints ────────────────────────────────────────
// Wording follows the CLI report (sc-core report.rs). Every hint is descriptive:
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
  if (d.consistent && d.ahead > 0) return `ahead of UTC in ${d.ahead}/${d.tagged} tagged records → operator clock UTC${signed(num(d.min_hours) ?? 0)}…UTC${signed(num(d.max_hours) ?? 0)}`;
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

const chips = (list) => list.map((x) => el("span", { class: "chip" }, x));

function renderClusterDetail() {
  const box = $("cluster-detail");
  const a = state.analysis;
  const c = state.cluster != null ? a.clusters[state.cluster] : null;
  if (!c) {
    box.hidden = true;
    box.replaceChildren();
    return;
  }
  const rows = [];
  const row = (k, ...v) => rows.push(el("dt", {}, k), el("dd", {}, ...v));
  const t = obj(c.timing);
  const runs = arr(c.runs);
  row("Runs", runs.length ? el("ul", {}, runs.slice(0, 6).map((r) => el("li", {}, `${span(r)}, ${r.count ?? 0} record(s)`)), runs.length > 6 ? el("li", { class: "hint" }, `${runs.length - 6} more`) : null) : "none");
  row("Daily rhythm", rhythmText(t.rhythm) ?? el("span", { class: "hint" }, "too little data to say (needs 3 days, 20 records)"));
  row("Offset from date tags", offsetText(state.dateTags[c.id]));
  row("Stale date tags", staleText(t.stale_dates) ?? el("span", { class: "hint" }, "none"));

  const enc = topEntries(obj(c.encodings), 6);
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
  const variants = topEntries(obj(d.variants), 12);
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
  if (cuts.length)
    row("Cut lengths", cuts.join("; "), el("div", { class: "hint" }, "consistent with a model or tool output limit, not evidence on its own (rule out the source's own display limit first)"));

  const lf = arr(c.link_features);
  if (lf.length) row("Linked by", chips(lf.slice(0, 10).map((f) => safe(f, 90))), lf.length > 10 ? el("span", { class: "hint" }, ` ${lf.length - 10} more`) : null);

  const mine = new Set(arr(c.members));
  const chains = arr(a.chains).filter((ch) => arr(ch.members).some((m) => mine.has(m)));
  if (chains.length) row("Probe chains", el("ul", {}, chains.slice(0, 10).map((ch) => el("li", {}, chainLine(ch)))), el("div", { class: "hint" }, "the pace is a hint, not evidence"));

  box.hidden = false;
  box.replaceChildren(el("h3", {}, `Cluster ${c.id}: timing and hints`), el("dl", { class: "kv" }, rows));
}

// Shared pauses and probe chains across the whole analysis.
function renderLinks() {
  const a = state.analysis;
  const clusterOf = (m) => a.results[m]?.cluster;
  const ids = (ch) => [...new Set(arr(ch.members).map(clusterOf).filter((x) => x != null))].map((i) => a.clusters[i]?.id ?? "?");
  const pauses = arr(a.shared_pauses);
  const chains = arr(a.chains);
  const out = [];
  out.push(el("h3", {}, "Shared pauses"));
  out.push(pauses.length
    ? el("ul", {}, pauses.map((sp) => el("li", {}, el("strong", {}, `${sp.a} and ${sp.b}`), ` went quiet together: ${sp.reason ?? ""}. Their records share no identifier; a link to check, not a merge.`,
        num(sp.p_chance) != null ? el("span", { class: "hint" }, ` (chance ${sp.p_chance.toExponential(1)})`) : null)))
    : el("p", { class: "hint" }, "No pair of clusters went quiet together more often than chance allows."));
  const dp = arr(a.dialect_pairs);
  out.push(el("h3", {}, "Shared payload dialects"));
  out.push(dp.length
    ? el("ul", {}, dp.map((p) => el("li", {}, el("strong", {}, `${p.a} and ${p.b}`), ` use the same uncommon mix of test payloads (Jaccard ${(num(p.jaccard) ?? 0).toFixed(2)}): `,
        chips(arr(p.shared).slice(0, 12).map((v) => safe(v, 40))), " A link to check, not a merge.")))
    : el("p", { class: "hint" }, "No pair of clusters shares an uncommon mix of test payloads."));
  out.push(el("h3", {}, "Probe chains"));
  if (chains.length) {
    const head = el("thead", {}, el("tr", {}, ["Host and path (defanged)", "Variants", "Varied", "Pace", "Span", "Clusters"].map((h) => el("th", {}, h))));
    const body = el("tbody", {}, chains.slice(0, 100).map((ch) =>
      el("tr", {},
        el("td", { class: "url" }, safe(`https://${ch.host ?? ""}${ch.path ?? ""}`, 120).replace(/^hxxps:\/\//, "")),
        el("td", { class: "num" }, ch.variants ?? "?"),
        el("td", {}, chips(arr(ch.varied).slice(0, 6).map((v) => safe(v, 40)))),
        el("td", {}, PACE[ch.pace] ?? "unknown", num(ch.retries_after_error) ? el("div", { class: "hint" }, `${ch.retries_after_error} after an error`) : null),
        el("td", {}, dur(Math.max(0, (ch.end ?? 0) - (ch.start ?? 0)))),
        el("td", {}, ids(ch).join(", ") || "–"))));
    out.push(el("div", { class: "scroll" }, el("table", {}, head, body)));
    if (chains.length > 100) out.push(el("p", { class: "hint" }, `${chains.length - 100} more not shown.`));
  } else out.push(el("p", { class: "hint" }, "No probe chains: no runs of three or more variants of one request."));
  $("links").replaceChildren(...out);
}

function renderEndpoints() {
  const a = state.analysis;
  let views;
  try {
    views = JSON.parse(sc.endpoints(JSON.stringify(a), ""));
  } catch (e) {
    showError($("endpoints"), e);
    return;
  }
  const head = el("thead", {}, el("tr", {}, ["Host", "Tier", "Hits", "First seen", "Last seen", "Status", "Attack payloads", "Clusters"].map((h) => el("th", {}, h))));
  const body = el("tbody");
  if (!views.length) body.append(el("tr", {}, el("td", { colspan: 8, class: "hint" }, "No target host has a suggestive or significant hit.")));
  for (const v of views) {
    body.append(
      el(
        "tr",
        {},
        el("td", { class: "url" }, sc.defang("https://" + v.host).slice(8)),
        el("td", {}, pill(v.max_tier)),
        el("td", { class: "num" }, `${v.hits} / ${v.records}`),
        el("td", {}, fmtTs(v.first_seen)),
        el("td", {}, fmtTs(v.last_seen)),
        el("td", {}, v.activity),
        el("td", {}, v.payloads ? Object.keys(v.payload_rules).map((r) => el("span", { class: "chip" }, r)) : el("span", { class: "hint" }, "none seen")),
        el("td", {}, v.clusters.join(", ") || "–"),
      ),
    );
  }
  $("endpoints").replaceChildren(head, body);
}

function renderRecords() {
  const a = state.analysis;
  let idx = a.results.map((_, i) => i).filter((i) => a.results[i].score > 0);
  if (state.cluster != null) idx = a.clusters[state.cluster].members;
  idx = [...idx].sort((x, y) => a.results[y].score - a.results[x].score || a.results[x].obs.ts - a.results[y].obs.ts);
  $("rec-scope").textContent = state.cluster != null ? `· cluster ${a.clusters[state.cluster].id}` : `· all (${idx.length})`;
  const shown = idx.slice(0, 300);
  const head = el("thead", {}, el("tr", {}, ["Tier", "Score", "Time", "Cluster", "URL (defanged)", "Rules"].map((h) => el("th", {}, h))));
  const body = el(
    "tbody",
    {},
    shown.map((i) => {
      const r = a.results[i];
      return el(
        "tr",
        {},
        el("td", {}, pill(r.tier)),
        el("td", { class: "num" }, r.score),
        el("td", {}, fmtTs(r.obs.ts)),
        el("td", {}, r.cluster != null ? a.clusters[r.cluster].id : "–"),
        el("td", { class: "url" }, sc.defang(trunc(r.obs.url, 300))),
        el("td", {}, r.hits.map((h) => el("span", { class: "chip", title: sc.defang(h.matched) }, h.rule_id))),
      );
    }),
  );
  if (idx.length > shown.length) body.append(el("tr", {}, el("td", { colspan: 6, class: "hint" }, `${idx.length - shown.length} more not shown; download the analysis JSON for all.`)));
  $("records").replaceChildren(head, body);
}

// Claims from the box, checked by sc-wasm against the schema the CLI reads.
// An invalid box blocks the draft rather than drafting without the claims.
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
  const a = state.analysis;
  const claims = readClaims();
  if (claims == null) {
    $("report").textContent = "Fix the claims JSON to draft a report.";
    return;
  }
  const opts = {
    audience: $("audience").value,
    cluster: state.cluster != null ? a.clusters[state.cluster].id : null,
    reporter: $("reporter").value || null,
    generated: new Date().toISOString().slice(0, 10),
    max_evidence: 10,
    min_named: $("min-named").value,
    claims,
  };
  try {
    $("report").textContent = sc.report(JSON.stringify(a), JSON.stringify(opts));
  } catch (e) {
    $("report").textContent = String(e?.message ?? e);
  }
}

function download(name, text, type) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = el("a", { href: url, download: name });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

$("run").addEventListener("click", runAnalysis);
$("example").addEventListener("click", () => {
  $("input").value = sc.example_records();
  $("format").value = "ndjson";
  $("map").value = "";
  $("example-note").hidden = false;
  runAnalysis();
});
$("input").addEventListener("input", () => ($("example-note").hidden = true));
$("file").addEventListener("change", async (e) => {
  const f = e.target.files[0];
  if (f) {
    $("example-note").hidden = true;
    $("input").value = await f.text();
    runAnalysis();
  }
});
$("audience").addEventListener("change", () => state.analysis && renderReport());
$("reporter").addEventListener("input", () => state.analysis && renderReport());
$("min-named").addEventListener("change", () => state.analysis && renderReport());
$("claims").addEventListener("input", () => (state.analysis ? renderReport() : readClaims()));
$("copy-report").addEventListener("click", () => navigator.clipboard?.writeText($("report").textContent));
$("dl-report").addEventListener("click", () => download("swarmchase-report.md", $("report").textContent, "text/markdown"));
$("dl-json").addEventListener("click", () => state.analysis && download("swarmchase-analysis.json", JSON.stringify(state.analysis, null, 2), "application/json"));

// ── Unwrap ──────────────────────────────────────────────────────────────────
$("unwrap-run").addEventListener("click", () => {
  const out = $("unwrap-out");
  let x;
  try {
    x = JSON.parse(sc.unwrap($("unwrap-url").value.trim(), rulesText()));
  } catch (e) {
    return showError(out, e);
  }
  const byLayer = {};
  for (const h of x.hits) (byLayer[h.layer] ??= []).push(h);
  out.replaceChildren(
    el("p", {}, `Score ${x.score} · target `, el("code", {}, x.target_host ? sc.defang("https://" + x.target_host).slice(8) : "unknown")),
    ...x.layers.map((l, i) =>
      el(
        "div",
        { class: "layer", style: { marginLeft: `${l.depth * 16}px` } },
        el("div", { class: "via" }, `[${i}] ${l.via}${l.host ? " · " + sc.defang("https://" + l.host).slice(8) : ""}`),
        el("code", {}, sc.defang(trunc(l.text, 400))),
        el("div", {}, (byLayer[i] ?? []).map((h) => el("span", { class: "chip", title: sc.defang(h.matched) }, `${h.rule_id} +${h.weight}`))),
      ),
    ),
  );
});

// ── Rules ───────────────────────────────────────────────────────────────────
$("rules").addEventListener("input", () => store.set(RULES_KEY, rulesText()));
$("rules-check").addEventListener("click", () => {
  try {
    const r = JSON.parse(sc.check_rules(rulesText()));
    $("rules-status").textContent = `OK: ${r.rules} rules, ${r.asns} ASN hints (version ${r.version})`;
  } catch (e) {
    $("rules-status").textContent = String(e?.message ?? e);
  }
});
$("rules-reset").addEventListener("click", () => {
  $("rules").value = sc.default_rules();
  store.del(RULES_KEY);
  $("rules-status").textContent = "Reset to bundled rules.";
});

// Bundled vs edited rules on the labelled set compiled into sc-wasm.
const TIER_RANK = { noise: 0, suggestive: 1, significant: 2 };
$("rules-eval").addEventListener("click", () => {
  const out = $("eval-out");
  let base, edited;
  try {
    base = JSON.parse(sc.eval_labelled(""));
    edited = JSON.parse(sc.eval_labelled(rulesText()));
  } catch (e) {
    return showError(out, e);
  }
  out.replaceChildren(...renderEval(base, edited));
});

function renderEval(base, edited) {
  const files = arr(base.files).map(String).join(", ");
  const parts = [
    el("p", { class: "hint" }, `${base.labelled ?? 0} labelled records (${base.agents ?? 0} agent, ${base.benign ?? 0} benign) from samples/eval: ${files}. The rules were tuned on this set, so it is a regression floor, not an estimate of real-world precision.`),
  ];
  const tierRow = (name, r, other) => {
    const th = new Map(arr(other?.thresholds).map((t) => [t.tier, t]));
    return arr(r.thresholds).map((t) => {
      const o = th.get(t.tier);
      const cell = (k, text, cls = "num") => el("td", { class: o && o[k] !== t[k] ? `${cls} changed` : cls }, text);
      return el("tr", {},
        el("td", {}, `${t.tier} or above`), el("td", {}, name),
        cell("tp", t.tp ?? 0), cell("fp", t.fp ?? 0), cell("fn", t.fn ?? 0),
        cell("precision", pct(t.precision)), cell("recall", pct(t.recall)));
    });
  };
  parts.push(el("div", { class: "scroll" }, el("table", { class: "eval" },
    el("thead", {}, el("tr", {}, ["Threshold", "Rules", "TP", "FP", "FN", "Precision", "Recall"].map((h) => el("th", {}, h)))),
    el("tbody", {}, tierRow(`bundled ${base.rules_version ?? ""}`, base, null), tierRow(`edited ${edited.rules_version ?? ""}`, edited, base)))));

  // Records whose tier moved. Up on an agent record, or down on a benign one, is better.
  const before = new Map(arr(base.records).map((r) => [r.id, r]));
  const moved = arr(edited.records)
    .map((r) => [before.get(r.id), r])
    .filter(([b, r]) => b && b.tier !== r.tier);
  const rescored = arr(edited.records).filter((r) => { const b = before.get(r.id); return b && b.tier === r.tier && b.score !== r.score; }).length;
  parts.push(el("h3", {}, "What changed"));
  if (!moved.length) parts.push(el("p", { class: "hint" }, `No labelled record changed tier.${rescored ? ` ${rescored} changed score within its tier.` : ""}`));
  else {
    parts.push(el("ul", { class: "changes" }, moved.map(([b, r]) => {
      const up = TIER_RANK[r.tier] > TIER_RANK[b.tier];
      const better = (r.label === "agent") === up;
      return el("li", {}, el("span", { class: better ? "better" : "worse" }, better ? "better" : "worse"), ` ${safe(r.id, 80)} (${r.label}): ${b.tier} ${b.score} → ${r.tier} ${r.score} `, el("code", {}, safe(r.url, 140)));
    })));
    if (rescored) parts.push(el("p", { class: "hint" }, `${rescored} more changed score within their tier.`));
  }

  const mis = arr(edited.misclassified);
  parts.push(el("h3", {}, `Misclassified with the edited rules (${mis.length})`));
  parts.push(el("p", { class: "hint" }, "Benign records flagged suggestive or above, and agent records left as noise."));
  if (mis.length) {
    parts.push(el("div", { class: "scroll" }, el("table", {},
      el("thead", {}, el("tr", {}, ["Record", "Label", "Tier", "Score", "Rules", "URL (defanged)"].map((h) => el("th", {}, h)))),
      el("tbody", {}, mis.slice(0, 200).map((m) => el("tr", {},
        el("td", {}, safe(m.id, 80)), el("td", { class: "nowrap" }, String(m.label ?? "")), el("td", {}, pill(String(m.tier ?? "noise"))),
        el("td", { class: "num" }, m.score ?? 0), el("td", {}, chips(arr(m.rules).map((x) => safe(x, 40)))),
        el("td", { class: "url" }, safe(m.url, 160))))))));
  }
  return parts;
}

// ── Contacts / defang ───────────────────────────────────────────────────────
$("sectxt-run").addEventListener("click", () => {
  const s = JSON.parse(sc.parse_security_txt($("sectxt").value));
  const rows = [
    ["Contact", s.contact], ["Policy", s.policy], ["Encryption", s.encryption],
    ["Expires", s.expires ? [s.expires] : []], ["Languages", s.preferred_languages ? [s.preferred_languages] : []],
    ["Signed", [s.signed ? "yes (PGP)" : "no"]],
  ];
  $("sectxt-out").replaceChildren(
    el("table", {}, el("tbody", {}, rows.map(([k, v]) => el("tr", {}, el("th", {}, k), el("td", {}, v.length ? v.join("\n") : "–"))))),
  );
});
$("defang-in").addEventListener("input", () => ($("defang-out").textContent = sc.defang($("defang-in").value)));

// ── Notices ─────────────────────────────────────────────────────────────────
// Built from notices/*.md by `swarmchase notice build`. The body arrives as
// plain blocks and spans; every span is inserted as text.
const SLUG = /^[a-z0-9][a-z0-9-]{0,63}$/;
let noticeIndex = null;

async function fetchJson(path) {
  try {
    const r = await fetch(path);
    return r.ok ? await r.json() : null;
  } catch {
    return null;
  }
}

const spans = (c) => (c ?? []).map((s) => (s.t === "strong" ? el("strong", {}, s.v) : s.t === "code" ? el("code", {}, s.v) : String(s.v)));

function blocks(list) {
  return (list ?? []).map((b) => {
    switch (b.t) {
      case "heading":
        return el(`h${Math.min(6, Number(b.level) + 1)}`, {}, spans(b.c));
      case "para":
        return el("p", {}, spans(b.c));
      case "quote":
        return el("blockquote", {}, b.lines.map((l) => el("p", {}, spans(l))));
      case "list":
        return el(b.ordered ? "ol" : "ul", {}, b.items.map((it) =>
          el("li", {}, spans(it.c), it.sub?.length ? el("ul", {}, it.sub.map((s) => el("li", {}, spans(s)))) : null)));
      case "table":
        return el("div", { class: "scroll" }, el("table", {},
          el("thead", {}, el("tr", {}, b.head.map((h) => el("th", {}, spans(h))))),
          el("tbody", {}, b.rows.map((r) => el("tr", {}, r.map((c) => el("td", {}, spans(c))))))));
      default:
        return null;
    }
  });
}

const statusPill = (s) => el("span", { class: `pill ${s}` }, s);
const KIND = { published: "Published", update: "Update", status: "Status change", correction: "Correction", reply: "Statement", retraction: "Retraction" };

async function showNotices() {
  noticeIndex ??= (await fetchJson("notices/index.json")) ?? [];
  renderNoticeList();
  const m = /^#notice=(.+)$/.exec(location.hash);
  if (m && SLUG.test(m[1])) openNotice(m[1]);
}

function renderNoticeList() {
  const st = $("nf-status").value;
  const q = $("nf-q").value.trim().toLowerCase();
  const rows = noticeIndex.filter((n) =>
    (!st || n.status === st) &&
    (!q || [n.id, n.title, ...n.providers, ...n.affected].some((x) => String(x).toLowerCase().includes(q))));
  if (!noticeIndex.length) {
    $("notice-list").replaceChildren(el("p", { class: "hint" }, "No notices published yet."));
    return;
  }
  const head = el("thead", {}, el("tr", {}, ["Notice", "Status", "Provider", "Affected", "Updated"].map((h) => el("th", {}, h))));
  const body = el("tbody", {}, rows.map((n) =>
    el("tr", { class: "pick", tabindex: "0", onclick: () => openNotice(n.id), onkeydown: (e) => e.key === "Enter" && openNotice(n.id) },
      el("td", {}, n.title, n.retracted ? el("span", { class: "chip" }, "retracted") : n.corrected ? el("span", { class: "chip" }, "corrected") : null),
      el("td", {}, statusPill(n.status)),
      el("td", {}, n.providers.join(", ") || "–"),
      el("td", {}, n.affected.map((h) => el("span", { class: "chip" }, h.replaceAll(".", "[.]")))),
      el("td", {}, n.updated))));
  $("notice-list").replaceChildren(rows.length ? el("div", { class: "scroll" }, el("table", {}, head, body)) : el("p", { class: "hint" }, "No notices match."));
}

async function openNotice(id) {
  if (!SLUG.test(id)) return;
  const page = await fetchJson(`notices/${id}.json`);
  const box = $("notice-page");
  box.hidden = false;
  if (!page) {
    box.replaceChildren(el("p", { class: "hint warn" }, `Notice ${id} not found.`));
    return;
  }
  history.replaceState(null, "", `#notice=${id}`);
  const m = page.meta;
  const updates = [...m.update ?? []].reverse().map((u) =>
    el("li", { class: u.kind === "correction" || u.kind === "retraction" ? "flagged" : "" },
      el("strong", {}, `${u.date} · ${KIND[u.kind] ?? u.kind}`),
      u.kind === "reply" ? el("blockquote", {}, el("p", {}, `Statement from ${u.from}:`), el("p", { class: "verbatim" }, u.text)) : el("p", {}, u.text)));
  box.replaceChildren(
    el("h2", {}, m.title),
    el("p", { class: "meta" }, statusPill(m.status), ` Published ${m.published} · updated ${m.updated} · rules ${m.rules_version} · toolkit ${m.toolkit}`),
    el("h3", {}, "Updates"),
    el("ol", { class: "updates", reversed: "" }, updates),
    ...blocks(page.blocks),
  );
  box.scrollIntoView({ block: "start" });
}

$("nf-status").addEventListener("change", () => noticeIndex && renderNoticeList());
$("nf-q").addEventListener("input", () => noticeIndex && renderNoticeList());

// ── Boot ────────────────────────────────────────────────────────────────────
await init();
$("ver").textContent = sc.version();
{
  const ev = JSON.parse(sc.evidence_levels());
  $("min-named").replaceChildren(...ev.levels.map((l) => el("option", { value: l.id }, l.label)));
  $("min-named").value = ev.default;
}
$("rules").value = store.get(RULES_KEY) ?? sc.default_rules();
if (/^#notice=/.test(location.hash)) showTab("notices");
