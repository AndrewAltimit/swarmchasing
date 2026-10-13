// Tools: check an evidence bundle (`swarmchase case bundle`), read a
// security.txt, defang. Each card loads its module on first use, and says
// in its own status line while it loads or if it fails, so one module that
// does not load leaves the other cards working: the bundle check and
// security.txt run in the tools module, defang in the engine. Files are read in
// this page: the manifest hashes are checked with Web Crypto, and the
// manifest's signature (against the keys this site publishes) and the
// analysis by the tools module. Record contents, stamps and claims
// are untrusted: inserted as text, URLs defanged.
import { $, el, showError, fetchRoot } from "../lib/dom.js";
import { arr, obj, num, pct, dur, fmtTs, topEntries, trunc } from "../lib/fmt.js";
import { tools, engine, host, pageRules } from "../lib/wasm.js";
import { figure, swimlanes, tierLegend } from "../lib/charts.js";
import { fleetItems, route } from "../lib/hints.js";
import { layersTable } from "../lib/layers.js";

const FILES = ["records.ndjson", "analysis.json", "stamp.json"];
const MANIFEST = "MANIFEST.sha256";
// Optional: the manifest's Ed25519 signature. The keys it is checked
// against are the ones this site's descriptor lists.
const SIGNATURE = "MANIFEST.sha256.sig";
const DESCRIPTOR = ".well-known/swarm-report.json";
// Optional: the claims from case work, as `report --claims` reads them.
const CLAIMS = "claims.json";
// The synthetic bundle the site build makes from the showcase records.
const SHOWCASE = "assets/showcase-bundle/";
const MAX_ROWS = 500;
const pill = (t) => el("span", { class: `pill ${String(t).replace(/[^a-z]/g, "")}` }, String(t));

// The tools module, once the first bundle is picked; render() reads it.
let sc = null;

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

/** The keys this site publishes, as key file lines, from the descriptor
 * every build writes (`bundle_signing`), so a site without a key file is
 * never asked for one. */
async function publishedKeys() {
  try {
    const d = await fetchRoot(DESCRIPTOR);
    return arr(obj(d.bundle_signing).keys).map((k) => `ed25519 ${String(obj(k).public_key)} ${String(obj(k).key_id)}`).join("\n");
  } catch {
    return "";
  }
}

/** The signature check, or null without a manifest. With no published
 * key, a signature is reported unchecked. */
async function checkSignature(byName) {
  const m = byName.get(MANIFEST);
  if (!m) return null;
  const sig = byName.has(SIGNATURE) ? await byName.get(SIGNATURE).text() : "";
  return JSON.parse(sc.verify_signature(await m.text(), sig, await publishedKeys()));
}

/** Check the picked files. `synthetic` marks the showcase bundle as such. */
async function load(files, synthetic = false) {
  const out = $("case-out");
  const byName = new Map([...files].map((f) => [f.name, f]));
  $("case-picked").textContent = [...byName.keys()].filter((n) => FILES.includes(n) || n === MANIFEST || n === SIGNATURE || n === CLAIMS).join(", ");
  const missing = ["records.ndjson", "stamp.json"].filter((f) => !byName.has(f));
  if (missing.length) return showError(out, `Pick ${missing.join(" and ")} (and the rest of the bundle).`);
  try {
    sc = await tools();
  } catch {
    // The card's status line says the module did not load.
    return out.replaceChildren();
  }
  let res;
  try {
    const rules = await pageRules(sc, null);
    const text = (f) => (byName.has(f) ? byName.get(f).text() : "");
    const [records, analysis, stamp] = await Promise.all(FILES.map(text));
    const claims = byName.has(CLAIMS) ? await byName.get(CLAIMS).text() : "";
    const hashDiffs = await checkManifest(byName);
    res = JSON.parse(sc.verify_bundle(records, analysis, stamp, rules, claims));
    res.claimsFile = byName.has(CLAIMS);
    res.signature = await checkSignature(byName);
    const sigDiffs = res.signature?.status === "invalid" ? [res.signature.line] : [];
    res.differences = [...sigDiffs, ...hashDiffs, ...res.differences];
  } catch (e) {
    return showError(out, e);
  }
  render(res, synthetic);
}

/** The showcase bundle, fetched from this site as files a visitor would pick. */
async function loadShowcase() {
  const btn = $("case-example");
  btn.disabled = true;
  try {
    const files = await Promise.all([...FILES, MANIFEST].map(async (n) => new File([await fetchRoot(SHOWCASE + n, "text")], n)));
    for (const id of ["case-files", "case-dir"]) $(id).value = "";
    await load(files, true);
  } catch (e) {
    showError($("case-out"), e);
  } finally {
    btn.disabled = false;
  }
}

function render(res, synthetic) {
  const st = res.stamp;
  const a = res.analysis;
  const ok = res.differences.length === 0;
  const signed = res.signature?.status === "signed";
  const kv = [
    ["Signature", signatureText(res.signature)],
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
  const chart = swimlanes({ lanes, pauses: a.timing?.pauses ?? [], width: Math.max(320, $("case-out").clientWidth - 8), label: "Runs per cluster over time, UTC" });
  const runRows = lanes.flatMap((l) => l.runs.map((r) => [l.label, pill(l.tier), fmtTs(r.start), fmtTs(r.end), String(r.count)]));
  $("case-out").replaceChildren(...[
    synthetic ? el("p", { class: "hint note" }, "Synthetic example: the showcase bundle, built with this site from the showcase records. None of it was collected; target hosts are placeholders and networks documentation ASNs.") : null,
    el("p", { class: `verdict ${ok ? "ok" : "bad"}`, role: "status" }, ok ? `Verified: ${signed ? "signature, " : ""}manifest, tiers and clusters match the stamp.` : `Does not verify: ${res.differences.length} difference(s).`),
    ok ? null : el("ul", { class: "diffs" }, res.differences.map((d) => el("li", {}, d))),
    res.notes.length ? el("ul", { class: "hint" }, res.notes.map((n) => el("li", {}, n))) : null,
    el("dl", { class: "kv" }, kv.flatMap(([k, v]) => [el("dt", {}, k), el("dd", {}, v)])),
    el("h3", {}, "Attribution"),
    ...attribution(res),
    el("h3", {}, "Runs per cluster (UTC)"),
    figure({ chart, legend: tierLegend(), caption: "Each bar is one run: a stretch of a cluster's activity without a long pause.", head: ["Cluster", "Tier", "Start", "End", "Records"], rows: runRows }),
    el("h3", {}, "Clusters"),
    clusterTable(a),
    ...hints(a),
    el("h3", {}, "Records"),
    recordTable(a),
  ].filter((x) => x != null));
}

/** What the signature check found, in a line. Key ids are hex from the
 * module, inserted as text. */
function signatureText(sig) {
  if (!sig) return el("span", { class: "hint" }, "not checked: no manifest picked");
  const id = String(sig.key_id ?? "");
  switch (sig.status) {
    case "signed":
      return `Signed by key ${id}, the key this site publishes.`;
    case "unchecked":
      return el("span", { class: "hint" }, `Signed by key ${id}, not checked: this site publishes no signing key.`);
    case "unsigned":
      return el("span", { class: "hint" }, `Unsigned: no ${SIGNATURE}. A signature shows who made the bundle; the checks below still hold without one.`);
    default:
      return `Signature invalid: ${String(sig.reason ?? "")}`;
  }
}

/** The stamp's evaluation snapshot, or why there is none. */
function evalText(ev) {
  ev = obj(ev);
  if (!num(ev.labelled)) return el("span", { class: "hint" }, "not recorded (the maker had no labelled set, or an older toolkit)");
  const at = (t) => el("li", {}, `${t[0].toUpperCase()}${t.slice(1)}: precision ${pct(ev[`${t}_precision`])}, recall ${pct(ev[`${t}_recall`])}`);
  return [`Rules ${trunc(String(ev.rules_version ?? "?"), 40)} on ${ev.labelled} labelled records:`,
    el("ul", {}, at("suggestive"), at("significant")),
    el("div", { class: "hint" }, "A regression floor on the committed set, not an estimate for this case. The stamp keeps the rates only, without the counts an interval needs.")];
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

const CLUSTER_HEAD = ["Cluster", "Tier", "Records", "Runs", "First seen", "Last seen", "Targets"];

/** The clusters; each cell carries its column name, so on phones the rows stack as cards. */
function clusterTable(a) {
  const td = (col, attrs, ...kids) => el("td", { ...attrs, "data-label": CLUSTER_HEAD[col] }, ...kids);
  return el("div", { class: "scroll" }, el("table", { class: "cards" },
    el("thead", {}, el("tr", {}, CLUSTER_HEAD.map((h) => el("th", { scope: "col" }, h)))),
    el("tbody", {}, a.clusters.length ? a.clusters.map((c) => el("tr", {},
      td(0, { class: "rc-head" }, el("strong", {}, c.id)), td(1, { class: "rc-head" }, pill(c.tier)),
      td(2, { class: "num rc-head rc-lab" }, c.members.length), td(3, { class: "num rc-head rc-lab" }, c.runs.length),
      td(4, {}, fmtTs(c.start)), td(5, {}, fmtTs(c.end)),
      td(6, {}, topEntries(c.target_hosts, 3).map(([h, n]) => el("span", { class: "chip" }, `${host(sc, h)} ×${n}`))))) : el("tr", {}, el("td", { colspan: 7, class: "hint" }, "No clusters.")))));
}

const RECORD_HEAD = ["Tier", "Time", "Cluster", "ID", "URL (defanged)", "Rules"];
// Phones show the first few records, with a button for the rest.
const PHONE_ROWS = 10;

function recordTable(a) {
  const idx = a.results.map((_, i) => i).sort((x, y) => a.results[x].obs.ts - a.results[y].obs.ts);
  const all = idx.slice(0, MAX_ROWS);
  const few = matchMedia("(max-width: 720px)").matches && all.length > PHONE_ROWS + 2;
  // Each cell carries its column name: on phones the rows stack as cards,
  // opening on one line with the tier, time and cluster.
  const td = (col, attrs, ...kids) => el("td", { ...attrs, "data-label": RECORD_HEAD[col] }, ...kids);
  const row = (i) => {
    const r = a.results[i];
    return el("tr", {},
      td(0, { class: "rc-head" }, pill(r.tier)), td(1, { class: "nowrap rc-head" }, fmtTs(r.obs.ts)),
      td(2, { class: "rc-head rc-lab" }, r.cluster != null ? a.clusters[r.cluster].id : "–"),
      td(3, {}, trunc(String(r.obs.id), 40)),
      td(4, { class: "url" }, sc.defang(trunc(String(r.obs.url), 300))),
      td(5, {}, r.hits.map((h) => el("span", { class: "chip", title: sc.defang(String(h.matched)) }, h.rule_id))));
  };
  const body = el("tbody", {}, (few ? all.slice(0, PHONE_ROWS) : all).map(row),
    idx.length > all.length ? el("tr", {}, el("td", { colspan: 6, class: "hint" }, `${idx.length - all.length} more not shown.`)) : null);
  const box = el("div", {}, el("div", { class: "scroll" }, el("table", { class: "records" },
    el("thead", {}, el("tr", {}, RECORD_HEAD.map((h) => el("th", { scope: "col" }, h)))), body)));
  if (few) {
    const more = el("button", { type: "button", class: "more-rows" }, `Show all ${all.length} records`);
    more.addEventListener("click", () => {
      const rows = all.slice(PHONE_ROWS).map(row);
      body.replaceChildren(...[...body.children].slice(0, PHONE_ROWS), ...rows, ...[...body.children].slice(PHONE_ROWS));
      more.remove();
      rows[0]?.querySelector("td")?.setAttribute("tabindex", "-1");
      rows[0]?.querySelector("td")?.focus();
    });
    box.append(more);
  }
  return box;
}

for (const id of ["case-files", "case-dir"]) $(id).addEventListener("change", (e) => e.target.files.length && load(e.target.files));
$("case-example").addEventListener("click", loadShowcase);

// security.txt runs in the tools module and defang in the engine, each
// loaded when its card is first used. A failed load is said in the card's
// status line and retried on next use. A button waiting on its module is
// marked busy.
async function using(load, fn, busy = null) {
  busy?.setAttribute("aria-busy", "true");
  let m;
  try {
    m = await load();
  } catch {
    return;
  } finally {
    busy?.removeAttribute("aria-busy");
  }
  fn(m);
}
$("sectxt").addEventListener("focus", () => tools().catch(() => {}), { once: true });
$("defang-in").addEventListener("focus", () => engine().catch(() => {}), { once: true });

$("sectxt-run").addEventListener("click", () => using(tools, (m) => {
  let s;
  try {
    s = JSON.parse(m.parse_security_txt($("sectxt").value));
  } catch (err) {
    return showError($("sectxt-out"), err);
  }
  const rows = [
    ["Contact", s.contact], ["Policy", s.policy], ["Encryption", s.encryption],
    ["Expires", s.expires ? [s.expires] : []], ["Languages", s.preferred_languages ? [s.preferred_languages] : []],
    ["Signed", [s.signed ? "yes (PGP)" : "no"]],
  ];
  // Values are shown defanged: a security.txt is text from elsewhere, not a link.
  $("sectxt-out").replaceChildren(el("dl", { class: "kv" }, rows.flatMap(([k, v]) => [el("dt", {}, k), el("dd", {}, (v ?? []).length ? (v ?? []).map((x) => m.defang(String(x))).join("\n") : "–")])));
}, $("sectxt-run")));
// Each change is defanged once the engine is there; the latest text wins.
$("defang-in").addEventListener("input", () => using(engine, (m) => ($("defang-out").textContent = m.defang($("defang-in").value))));
