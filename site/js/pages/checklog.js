// Check my logs: one access log, two checks, one summary. The tools module
// runs the workbench's analysis (format access_log, the operator's host in
// the field map) and the identity check on the same text, with the
// providers' files this site was built with. Nothing is uploaded or
// fetched beyond the site's own files. Log contents are untrusted: inserted
// as text, hosts and URLs defanged, never links.
import { $, el, fetchRoot, ruleLink, showAlert } from "../lib/dom.js";
import { arr, obj, num, str, trunc, plural, fmtShort, topEntries } from "../lib/fmt.js";
import { tools, pageRules } from "../lib/wasm.js";
import { EXAMPLE_FILES, EXAMPLE_HOST, PROBE_LOG } from "../lib/idexample.js";

const MAX_LISTED = 8;
let example = false;
let snapshot = null; // the providers' files the build embedded, once read

/** Check is offered once there is a log. */
const sync = () => ($("cl-run").disabled = !$("cl-input").value.trim());

async function providerFiles() {
  if (example) return EXAMPLE_FILES;
  if (!snapshot) {
    try {
      const s = await fetchRoot("assets/identity-snapshot.json");
      snapshot = { ranges: obj(s.ranges), directories: obj(s.directories) };
    } catch {
      snapshot = { ranges: {}, directories: {} };
    }
  }
  return snapshot;
}

/** `www.example.org`, a pasted URL or `host=...`: the bare host name. */
function hostOf(text) {
  const t = str(text).trim().replace(/^host=/i, "");
  return t.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "").split(/[/?#\s]/)[0].toLowerCase();
}

async function check() {
  $("cl-alert").hidden = true;
  const input = $("cl-input").value;
  if (!input.trim()) return;
  const host = hostOf($("cl-host").value);
  let sc;
  try {
    sc = await tools();
  } catch {
    return; // the status line says the module did not load
  }
  const rules = await pageRules(sc, $("rules-note"));
  const map = host ? `host=${host}` : "";
  let analysis, ident;
  try {
    const out = JSON.parse(sc.analyze(input, "access_log", map, rules));
    analysis = obj(out.analysis);
    ident = JSON.parse(sc.identity_check(input, "access_log", map, JSON.stringify(await providerFiles())));
  } catch (e) {
    showAlert($("cl-alert"), "The log could not be read.", ["First problem: ", el("code", {}, trunc(String(e?.message ?? e), 300))],
      "The page reads web server access logs in Common or Combined Log Format.");
    return;
  }
  if (!num(analysis.total)) {
    showAlert($("cl-alert"), "Nothing was read from this input: no line held a request.",
      "The page reads web server access logs in Common or Combined Log Format, one request per line.");
    return;
  }
  render(sc, analysis, ident, host);
}

/** Identity records grouped by address and declared agent, in first-seen order. */
function bySource(records) {
  const out = new Map();
  for (const r of records) {
    const k = `${str(r.ip)}\u0000${str(r.provider)}\u0000${str(r.agent)}`;
    const g = out.get(k) ?? { r, n: 0 };
    g.n++;
    out.set(k, g);
  }
  return out;
}

function render(sc, a, ident, host) {
  const df = (s) => sc.defang(str(s));
  const shownHost = host ? sc.defang(`https://${host}`).slice(8) : "your host";
  const results = arr(a.results);
  const flagged = results.map((r, i) => [r, i]).filter(([r]) => r.tier === "significant" || r.tier === "suggestive")
    .sort(([x], [y]) => y.score - x.score || x.obs.ts - y.obs.ts);
  const sig = flagged.filter(([r]) => r.tier === "significant").length;
  const counts = obj(ident.counts);
  const records = arr(ident.records);
  const spoofed = records.filter((r) => r.class === "spoofed");
  const verified = (num(counts.ip_verified) ?? 0) + (num(counts.signature_verified) ?? 0);
  const claims = (num(counts.claimed) ?? 0) + (num(counts.signature_present) ?? 0);
  const failed = num(counts.signature_failed) ?? 0;
  const rulesHit = {};
  for (const [r] of flagged) for (const h of arr(r.hits)) rulesHit[h.rule_id] = (rulesHit[h.rule_id] ?? 0) + 1;

  const parts = [];
  parts.push(el("p", { class: "verdict-line" }, el("strong", {}, `${plural(a.total, "request")} read for ${shownHost}. `),
    flagged.length
      ? `${plural(flagged.length, "request")} matched the indicator rules (${sig} significant, ${flagged.length - sig} suggestive).`
      : "No request matched the indicator rules strongly enough to flag.",
    " ",
    spoofed.length
      ? `${plural(spoofed.length, "request")} passed as an AI provider's agent from outside that provider's published addresses.`
      : verified || claims
        ? "No request passed as a provider's agent from outside its published addresses."
        : "No request declared an AI provider's agent."));

  // Flagged requests.
  parts.push(el("h3", {}, "Flagged requests"));
  if (flagged.length) {
    const clusters = arr(a.clusters).filter((c) => c.tier === "significant" || c.tier === "suggestive");
    parts.push(el("p", {}, `They fall into ${plural(clusters.length, "cluster")}: requests linked by shared tags, identifiers or close timing. The rules they matched most: `,
      topEntries(rulesHit, 6).map(([id, n]) => el("span", { class: "chip" }, ruleLink(id, "rule-link"), ` ×${n}`)), "."));
    parts.push(el("div", { class: "scroll" }, el("table", { class: "records" },
      el("thead", {}, el("tr", {}, ["Tier", "Score", "Rules", "Request (defanged)", "Time (UTC)"].map((h) => el("th", { scope: "col" }, h)))),
      el("tbody", {}, flagged.slice(0, MAX_LISTED).map(([r]) => el("tr", {},
        el("td", { class: "rc-head", "data-label": "Tier" }, el("span", { class: `pill ${str(r.tier).replace(/[^a-z]/g, "")}` }, str(r.tier))),
        el("td", { class: "num rc-head rc-lab", "data-label": "Score" }, String(r.score)),
        el("td", { class: "rules", "data-label": "Rules" }, arr(r.hits).map((h) => ruleLink(h.rule_id))),
        el("td", { class: "url", "data-label": "Request (defanged)" }, trunc(df(r.obs.url), 300)),
        el("td", { class: "nowrap rc-head", "data-label": "Time (UTC)" }, fmtShort(r.obs.ts))))))));
    if (flagged.length > MAX_LISTED) parts.push(el("p", { class: "hint" }, `${flagged.length - MAX_LISTED} more in the workbench.`));
  } else {
    parts.push(el("p", { class: "hint" }, "Nothing here looks like the agent activity the rules describe. The rules see only what a log line carries: a request body or a page an agent read is out of their sight."));
  }

  // Agent identities.
  parts.push(el("h3", {}, "Agents that name themselves"));
  const held = example ? Object.keys(EXAMPLE_FILES.ranges).length : Object.keys(obj(snapshot?.ranges)).length + Object.keys(obj(snapshot?.directories)).length;
  const lines = [];
  if (verified) lines.push(`${plural(verified, "request")} verified: declared and from the provider's published addresses or keys.`);
  if (claims) lines.push(`${plural(claims, "request")} declared an agent the page could not check${held ? "" : " (this site holds no providers' files)"}: a claim only.`);
  if (failed) lines.push(`${plural(failed, "request")} carried a signature that failed.`);
  if (!lines.length && !spoofed.length) lines.push("No request declared an AI provider's agent.");
  parts.push(el("ul", {}, lines.map((t) => el("li", {}, t))));
  if (spoofed.length) {
    parts.push(el("div", { class: "alert" },
      el("p", {}, el("strong", {}, `${plural(spoofed.length, "request")} passed as a provider's agent from outside its published ranges`)),
      el("p", {}, "Something else is using the provider's name: a scraper or another agent passing as a known one. Check that your log has the real client address before you act on it."),
      el("ul", {}, [...bySource(spoofed).values()].slice(0, MAX_LISTED).map(({ r, n }) => el("li", {}, el("code", {}, str(r.ip) || "–"), ` as ${str(r.provider) || "a provider"} `,
        r.agent ? el("code", {}, trunc(df(r.agent), 80)) : null, n > 1 ? ` (${plural(n, "request")})` : null)))));
  }
  if (example) parts.push(el("p", { class: "hint" }, `The example's host is ${sc.defang("https://" + EXAMPLE_HOST.slice(5)).slice(8)}; its range files are synthetic.`));

  $("cl-summary").replaceChildren(...parts);
  $("cl-result").hidden = false;
  $("cl-next").hidden = false;
  $("cl-result-h").focus({ preventScroll: true });
  $("cl-result").scrollIntoView({ block: "start" });
}

function leaveExample() {
  example = false;
  $("cl-example-note").hidden = true;
}

$("cl-run").addEventListener("click", check);
$("cl-input").addEventListener("input", () => {
  if (example) leaveExample();
  sync();
});
// Signs of input start the download, so the module is ready by Check.
const warm = () => tools().catch(() => {});
$("cl-input").addEventListener("focus", warm, { once: true });
$("cl-example").addEventListener("pointerenter", warm, { once: true });
$("cl-example").addEventListener("click", () => {
  example = true;
  $("cl-input").value = PROBE_LOG;
  $("cl-host").value = EXAMPLE_HOST.slice(5);
  $("cl-example-note").hidden = false;
  sync();
  check();
});

async function loadFile(f) {
  const status = $("cl-drop-status");
  try {
    $("cl-input").value = await f.text();
  } catch (err) {
    status.textContent = `${trunc(String(f.name), 80)} could not be read: ${String(err?.message ?? err)}`;
    status.hidden = false;
    return;
  }
  status.hidden = true;
  leaveExample();
  sync();
  if ($("cl-host").value.trim()) check();
  else $("cl-host").focus();
}
$("cl-file").addEventListener("change", async (e) => {
  const f = e.target.files[0];
  if (f) await loadFile(f);
  e.target.value = "";
});
// A file dropped on the log area is read in the page, as a picked one is.
{
  const zone = $("cl-drop");
  const has = (e) => [...(e.dataTransfer?.types ?? [])].includes("Files");
  let depth = 0;
  zone.addEventListener("dragenter", (e) => {
    if (!has(e)) return;
    e.preventDefault();
    depth++;
    zone.classList.add("over");
  });
  zone.addEventListener("dragover", (e) => {
    if (!has(e)) return;
    e.preventDefault();
    e.dataTransfer.dropEffect = "copy";
  });
  zone.addEventListener("dragleave", () => {
    depth = Math.max(0, depth - 1);
    if (!depth) zone.classList.remove("over");
  });
  zone.addEventListener("drop", async (e) => {
    if (!has(e)) return;
    e.preventDefault();
    depth = 0;
    zone.classList.remove("over");
    const f = e.dataTransfer.files[0];
    if (f) await loadFile(f);
  });
}
sync();
