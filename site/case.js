// Case tab: check an evidence bundle written by `swarmchase case bundle`.
// The files are read in this tab: the manifest hashes are checked with Web
// Crypto and the analysis is re-run by sc-wasm. Nothing is uploaded. Record
// contents are untrusted and are only inserted as text, defanged.
import init, * as sc from "./pkg/sc_wasm.js";

const $ = (id) => document.getElementById(id);
const FILES = ["records.ndjson", "analysis.json", "stamp.json"];
const MANIFEST = "MANIFEST.sha256";
const MAX_ROWS = 500;

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

const fmtTs = (t) => (t > 0 ? new Date(t * 1000).toISOString().replace("T", " ").slice(0, 19) + " UTC" : "unknown");
const pill = (tier) => el("span", { class: `pill ${tier}` }, tier);
const trunc = (s, n) => (s.length > n ? s.slice(0, n) + "…" : s);
const host = (h) => sc.defang("https://" + h).slice(8);
const rulesText = () => $("rules")?.value ?? "";

async function sha256(buf) {
  const d = await crypto.subtle.digest("SHA-256", buf);
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// The same reading as the CLI: `<hash>  <name>` per line.
function parseManifest(text) {
  const out = new Map();
  for (const line of text.split("\n")) {
    const i = line.indexOf("  ");
    if (i >= 0) out.set(line.slice(i + 2).trim(), line.slice(0, i).trim());
  }
  return out;
}

async function checkManifest(byName) {
  const diffs = [];
  const m = byName.get(MANIFEST);
  if (!m) return [`${MANIFEST}: not picked`];
  if (!globalThis.crypto?.subtle) return ["hashes not checked: Web Crypto needs https or localhost"];
  const listed = parseManifest(await m.text());
  for (const f of FILES) {
    const want = listed.get(f);
    if (!want) diffs.push(`${f}: not in the manifest`);
    else if (!byName.has(f)) diffs.push(`${f}: not picked`);
    else if ((await sha256(await byName.get(f).arrayBuffer())) !== want) diffs.push(`${f}: SHA-256 differs from the manifest`);
  }
  return diffs;
}

async function load(files) {
  const out = $("case-out");
  out.hidden = false;
  // A folder pick carries paths; the bundle's files are matched by name.
  const byName = new Map([...files].map((f) => [f.name, f]));
  $("case-picked").textContent = [...byName.keys()].filter((n) => FILES.includes(n) || n === MANIFEST).join(", ");
  const missing = ["records.ndjson", "stamp.json"].filter((f) => !byName.has(f));
  if (missing.length) {
    out.replaceChildren(el("div", { class: "card" }, el("p", { class: "hint warn" }, `Pick ${missing.join(" and ")} (and the rest of the bundle).`)));
    return;
  }
  let res;
  try {
    await init();
    const text = (f) => (byName.has(f) ? byName.get(f).text() : "");
    const [records, analysis, stamp] = await Promise.all(FILES.map(text));
    const hashDiffs = await checkManifest(byName);
    res = JSON.parse(sc.verify_bundle(records, analysis, stamp, rulesText()));
    res.differences = [...hashDiffs, ...res.differences];
  } catch (e) {
    out.replaceChildren(el("div", { class: "card" }, el("p", { class: "hint warn" }, String(e?.message ?? e))));
    return;
  }
  render(res);
}

function render(res) {
  const st = res.stamp;
  const a = res.analysis;
  const ok = res.differences.length === 0;
  const summary = el(
    "div",
    { class: "card" },
    el("p", { class: `verdict ${ok ? "ok" : "bad"}` }, ok ? "Verified: manifest, tiers and clusters match the stamp." : `Does not verify: ${res.differences.length} difference(s).`),
    ok ? null : el("ul", { class: "diffs" }, res.differences.map((d) => el("li", {}, d))),
    res.notes.length ? el("ul", { class: "hint" }, res.notes.map((n) => el("li", {}, n))) : null,
    el(
      "table",
      { class: "kv" },
      el(
        "tbody",
        {},
        [
          ["Case", st.case],
          ["Generated", st.generated],
          ["Rules", `${st.rules_version}${st.rules_version === res.rules_version ? "" : ` (checked with ${res.rules_version})`}`],
          ["Toolkit", `${st.toolkit_version}${st.toolkit_commit ? ` (${st.toolkit_commit})` : ""}`],
          ["Records", `${st.records} · ${Object.keys(st.flagged).length} flagged · ${st.clusters.length} cluster(s)`],
        ].map(([k, v]) => el("tr", {}, el("th", {}, k), el("td", {}, v))),
      ),
    ),
  );
  $("case-out").replaceChildren(
    summary,
    el("div", { class: "card" }, el("h2", {}, "Runs per cluster (UTC)"), el("p", { class: "hint" }, "Each bar is one run: a stretch of a cluster's activity without a long pause."), timeline(a)),
    el("div", { class: "card" }, el("h2", {}, "Clusters"), el("div", { class: "scroll" }, clusterTable(a))),
    el("div", { class: "card" }, el("h2", {}, "Records"), el("div", { class: "scroll" }, recordTable(a))),
  );
}

function timeline(a) {
  const rows = a.clusters.filter((c) => c.runs.some((r) => r.start > 0));
  if (!rows.length) return el("p", { class: "hint" }, "No clusters with timestamps.");
  const t0 = Math.min(...rows.flatMap((c) => c.runs.map((r) => r.start)));
  const t1 = Math.max(...rows.flatMap((c) => c.runs.map((r) => r.end)));
  const span = Math.max(1, t1 - t0);
  const RH = 22, W = 1000, L = 70, R = 8, T = 8, B = 28;
  const H = T + B + rows.length * RH;
  const x = (t) => L + ((t - t0) / span) * (W - L - R);
  const ns = "http://www.w3.org/2000/svg";
  const s = (tag, attrs, text) => {
    const e = document.createElementNS(ns, tag);
    for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v);
    if (text != null) e.textContent = text;
    return e;
  };
  const svg = s("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": "Runs per cluster over time, UTC" });
  const grid = s("g", { class: "grid" });
  const axis = s("g", { class: "axis" });
  for (let i = 0; i <= 4; i++) {
    const t = t0 + (span * i) / 4;
    grid.append(s("line", { x1: x(t), x2: x(t), y1: T, y2: H - B }));
    const dt = new Date(t * 1000).toISOString();
    axis.append(s("text", { x: x(t), y: H - 8, "text-anchor": i === 0 ? "start" : i === 4 ? "end" : "middle" }, `${dt.slice(5, 10)} ${dt.slice(11, 16)}`));
  }
  svg.append(grid);
  const tip = $("tip");
  rows.forEach((c, i) => {
    const y = T + i * RH;
    axis.append(s("text", { x: L - 6, y: y + RH / 2 + 4, "text-anchor": "end" }, c.id));
    for (const r of c.runs) {
      const bar = s("rect", { class: "bar", x: x(r.start), y: y + 4, width: Math.max(3, x(r.end) - x(r.start)), height: RH - 8, rx: 3 });
      bar.addEventListener("mousemove", (ev) => {
        if (!tip) return;
        tip.hidden = false;
        tip.textContent = `${c.id} · ${fmtTs(r.start).slice(0, 16)} → ${fmtTs(r.end).slice(11, 16)} UTC · ${r.count} record(s)`;
        tip.style.left = `${ev.clientX + 12}px`;
        tip.style.top = `${ev.clientY + 12}px`;
        bar.classList.add("active");
      });
      bar.addEventListener("mouseleave", () => {
        if (tip) tip.hidden = true;
        bar.classList.remove("active");
      });
      svg.append(bar);
    }
  });
  svg.append(axis);
  return el("div", { class: "chart" }, svg);
}

function clusterTable(a) {
  const head = el("thead", {}, el("tr", {}, ["", "Tier", "Records", "Runs", "First seen", "Last seen", "Targets"].map((h) => el("th", {}, h))));
  const body = el("tbody");
  if (!a.clusters.length) body.append(el("tr", {}, el("td", { colspan: 7, class: "hint" }, "No clusters.")));
  for (const c of a.clusters) {
    const targets = Object.entries(c.target_hosts).sort((x, y) => y[1] - x[1]).slice(0, 3);
    body.append(
      el(
        "tr",
        {},
        el("td", {}, c.id),
        el("td", {}, pill(c.tier)),
        el("td", { class: "num" }, c.members.length),
        el("td", { class: "num" }, c.runs.length),
        el("td", {}, fmtTs(c.start)),
        el("td", {}, fmtTs(c.end)),
        el("td", {}, targets.map(([h, n]) => el("span", { class: "chip" }, `${host(h)} ×${n}`))),
      ),
    );
  }
  return el("table", {}, head, body);
}

function recordTable(a) {
  const idx = a.results.map((_, i) => i).sort((x, y) => a.results[x].obs.ts - a.results[y].obs.ts);
  const shown = idx.slice(0, MAX_ROWS);
  const head = el("thead", {}, el("tr", {}, ["Tier", "Time", "Cluster", "ID", "URL (defanged)", "Rules"].map((h) => el("th", {}, h))));
  const body = el(
    "tbody",
    {},
    shown.map((i) => {
      const r = a.results[i];
      return el(
        "tr",
        {},
        el("td", {}, pill(r.tier)),
        el("td", {}, fmtTs(r.obs.ts)),
        el("td", {}, r.cluster != null ? a.clusters[r.cluster].id : "–"),
        el("td", {}, trunc(r.obs.id, 40)),
        el("td", { class: "url" }, sc.defang(trunc(r.obs.url, 300))),
        el("td", {}, r.hits.map((h) => el("span", { class: "chip", title: sc.defang(h.matched) }, h.rule_id))),
      );
    }),
  );
  if (idx.length > shown.length) body.append(el("tr", {}, el("td", { colspan: 6, class: "hint" }, `${idx.length - shown.length} more not shown.`)));
  return el("table", {}, head, body);
}

for (const id of ["case-files", "case-dir"]) {
  $(id)?.addEventListener("change", (e) => e.target.files.length && load(e.target.files));
}
