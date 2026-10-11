// Tools: check an evidence bundle (`swarmchase case bundle`), read a
// security.txt, defang. Files are read in this page: the manifest hashes
// are checked with Web Crypto and the analysis is re-run by the tools module.
// Record contents, stamps and claims are untrusted: inserted as text, URLs
// defanged.
import { $, el, showError } from "../lib/dom.js";
import { arr, obj, num, pct, dur, fmtTs, topEntries, trunc } from "../lib/fmt.js";
import { tools, host, pageRules } from "../lib/wasm.js";
import { figure, swimlanes, tierLegend } from "../lib/charts.js";
import { fleetItems, route } from "../lib/hints.js";
import { layersTable } from "../lib/layers.js";

const FILES = ["records.ndjson", "analysis.json", "stamp.json"];
const MANIFEST = "MANIFEST.sha256";
// Optional: the claims from case work, as `report --claims` reads them.
const CLAIMS = "claims.json";
const MAX_ROWS = 500;
const pill = (t) => el("span", { class: `pill ${t}` }, t);

const sc = await tools();
const rules = await pageRules(sc, null);

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
  const byName = new Map([...files].map((f) => [f.name, f]));
  $("case-picked").textContent = [...byName.keys()].filter((n) => FILES.includes(n) || n === MANIFEST || n === CLAIMS).join(", ");
  const missing = ["records.ndjson", "stamp.json"].filter((f) => !byName.has(f));
  if (missing.length) return showError(out, `Pick ${missing.join(" and ")} (and the rest of the bundle).`);
  let res;
  try {
    const text = (f) => (byName.has(f) ? byName.get(f).text() : "");
    const [records, analysis, stamp] = await Promise.all(FILES.map(text));
    const claims = byName.has(CLAIMS) ? await byName.get(CLAIMS).text() : "";
    const hashDiffs = await checkManifest(byName);
    res = JSON.parse(sc.verify_bundle(records, analysis, stamp, rules, claims));
    res.claimsFile = byName.has(CLAIMS);
    res.differences = [...hashDiffs, ...res.differences];
  } catch (e) {
    return showError(out, e);
  }
  render(res);
}

function render(res) {
  const st = res.stamp;
  const a = res.analysis;
  const ok = res.differences.length === 0;
  const kv = [
    ["Case", st.case],
    ["Generated", st.generated],
    ["Rules", `${st.rules_version}${st.rules_version === res.rules_version ? "" : ` (checked with ${res.rules_version})`}`],
    ["Toolkit", `${st.toolkit_version}${st.toolkit_commit ? ` (${st.toolkit_commit})` : ""}`],
    ["Records", `${st.records} · ${Object.keys(st.flagged).length} flagged · ${st.clusters.length} cluster(s)`],
    ["Method", st.method ? String(st.method) : el("span", { class: "hint" }, "not stated (a bundle from before stamps cited the method)")],
    ["Evaluation at stamp time", evalText(st.eval)],
  ];
  const lanes = a.clusters
    .filter((c) => c.runs.some((r) => r.start > 0))
    .map((c) => ({ key: c.key || c.id, label: c.id, tier: c.tier, runs: c.runs.filter((r) => r.start > 0) }));
  const chart = swimlanes({ lanes, pauses: a.timing?.pauses ?? [], width: $("case-out").clientWidth - 8, label: "Runs per cluster over time, UTC" });
  const runRows = lanes.flatMap((l) => l.runs.map((r) => [l.label, pill(l.tier), fmtTs(r.start), fmtTs(r.end), String(r.count)]));
  $("case-out").replaceChildren(...[
    el("p", { class: `verdict ${ok ? "ok" : "bad"}`, role: "status" }, ok ? "Verified: manifest, tiers and clusters match the stamp." : `Does not verify: ${res.differences.length} difference(s).`),
    ok ? null : el("ul", { class: "diffs" }, res.differences.map((d) => el("li", {}, d))),
    res.notes.length ? el("ul", { class: "hint" }, res.notes.map((n) => el("li", {}, n))) : null,
    el("dl", { class: "kv" }, kv.flatMap(([k, v]) => [el("dt", {}, k), el("dd", {}, v)])),
    el("h3", {}, "Attribution"),
    ...attribution(res),
    el("h3", {}, "Runs per cluster (UTC)"),
    figure({ chart, legend: tierLegend(), caption: "Each bar is one run: a stretch of a cluster's activity without a long pause.", head: ["Cluster", "Tier", "Start", "End", "Records"], rows: runRows }),
    el("h3", {}, "Clusters"),
    el("div", { class: "scroll" }, el("table", {},
      el("thead", {}, el("tr", {}, ["Cluster", "Tier", "Records", "Runs", "First seen", "Last seen", "Targets"].map((h) => el("th", { scope: "col" }, h)))),
      el("tbody", {}, a.clusters.length ? a.clusters.map((c) => el("tr", {},
        el("td", {}, c.id), el("td", {}, pill(c.tier)), el("td", { class: "num" }, c.members.length), el("td", { class: "num" }, c.runs.length),
        el("td", {}, fmtTs(c.start)), el("td", {}, fmtTs(c.end)),
        el("td", {}, topEntries(c.target_hosts, 3).map(([h, n]) => el("span", { class: "chip" }, `${host(sc, h)} ×${n}`))))) : el("tr", {}, el("td", { colspan: 7, class: "hint" }, "No clusters."))))),
    ...hints(a),
    el("h3", {}, "Records"),
    recordTable(a),
  ].filter((x) => x != null));
}

/** The stamp's evaluation snapshot, or why there is none. */
function evalText(ev) {
  ev = obj(ev);
  if (!num(ev.labelled)) return el("span", { class: "hint" }, "not recorded (the maker had no labelled set, or an older toolkit)");
  const at = (t) => `${t}: precision ${pct(ev[`${t}_precision`])}, recall ${pct(ev[`${t}_recall`])}`;
  return [`rules ${trunc(String(ev.rules_version ?? "?"), 40)} on ${ev.labelled} labelled records; ${at("suggestive")}; ${at("significant")}`,
    el("div", { class: "hint" }, "a regression floor on the committed set, not an estimate for this case")];
}

/** The attribution layers the re-run supports, with claims from case work. */
function attribution(res) {
  return [
    el("p", { class: "hint" }, `What the records support at each layer${res.claimsFile ? ", with the claims from claims.json" : " (pick the case's claims.json too to include case work)"}. The label follows the evidence; the word after it is the strongest likelihood a report may use.${res.withheld ? ` ${res.withheld} developer candidate(s) below the naming gate are not shown.` : ""}`),
    layersTable(res.layers),
  ];
}

/** Candidate fleets and escalations, when the analysis has them. */
function hints(a) {
  const out = [];
  const fleets = arr(a.candidate_fleets);
  if (fleets.length) {
    out.push(el("h3", {}, `Candidate fleets (${fleets.length})`),
      el("p", { class: "hint" }, "Clusters joined by soft links: hints to check, not a merge, and never part of the stamp."),
      el("ul", {}, fleetItems(fleets.slice(0, 20))));
  }
  const esc = arr(a.escalations);
  if (esc.length) {
    out.push(el("h3", {}, `Escalations (${esc.length})`),
      el("ul", {}, esc.slice(0, 20).map((e) => el("li", {},
        el("code", {}, host(sc, `${e.host ?? ""}${e.path ?? ""}`).slice(0, 90)),
        `: ${arr(e.steps).map((s) => route(s.route)).join(" → ")} over ${dur(Math.max(0, (e.end ?? 0) - (e.start ?? 0)))}`,
        arr(e.clusters).length ? ` (clusters ${arr(e.clusters).map((x) => trunc(String(x), 20)).join(", ")})` : "",
        e.time_basis === "capture" ? el("span", { class: "hint" }, " capture-timed") : null))));
  }
  return out;
}

function recordTable(a) {
  const idx = a.results.map((_, i) => i).sort((x, y) => a.results[x].obs.ts - a.results[y].obs.ts);
  const shown = idx.slice(0, MAX_ROWS);
  return el("div", { class: "scroll" }, el("table", {},
    el("thead", {}, el("tr", {}, ["Tier", "Time", "Cluster", "ID", "URL (defanged)", "Rules"].map((h) => el("th", { scope: "col" }, h)))),
    el("tbody", {}, shown.map((i) => {
      const r = a.results[i];
      return el("tr", {},
        el("td", {}, pill(r.tier)), el("td", { class: "nowrap" }, fmtTs(r.obs.ts)),
        el("td", {}, r.cluster != null ? a.clusters[r.cluster].id : "–"),
        el("td", {}, trunc(String(r.obs.id), 40)),
        el("td", { class: "url" }, sc.defang(trunc(String(r.obs.url), 300))),
        el("td", {}, r.hits.map((h) => el("span", { class: "chip", title: sc.defang(String(h.matched)) }, h.rule_id))));
    }), idx.length > shown.length ? el("tr", {}, el("td", { colspan: 6, class: "hint" }, `${idx.length - shown.length} more not shown.`)) : null)));
}

for (const id of ["case-files", "case-dir"]) $(id).addEventListener("change", (e) => e.target.files.length && load(e.target.files));

$("sectxt-run").addEventListener("click", () => {
  const s = JSON.parse(sc.parse_security_txt($("sectxt").value));
  const rows = [
    ["Contact", s.contact], ["Policy", s.policy], ["Encryption", s.encryption],
    ["Expires", s.expires ? [s.expires] : []], ["Languages", s.preferred_languages ? [s.preferred_languages] : []],
    ["Signed", [s.signed ? "yes (PGP)" : "no"]],
  ];
  // Values are shown defanged: a security.txt is text from elsewhere, not a link.
  $("sectxt-out").replaceChildren(el("dl", { class: "kv" }, rows.flatMap(([k, v]) => [el("dt", {}, k), el("dd", {}, (v ?? []).length ? (v ?? []).map((x) => sc.defang(String(x))).join("\n") : "–")])));
});
$("defang-in").addEventListener("input", () => ($("defang-out").textContent = sc.defang($("defang-in").value)));
