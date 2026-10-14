// Check my logs: access logs in, two checks, one summary. The tools module
// runs the workbench's analysis (the operator's host in the field map) and
// the identity check on the same records, with the providers' files this
// site was built with. A pasted log is one text; a set of files (several,
// a folder, archives) is unpacked in the page and analysed as one input
// (lib/fileset.js). Both run in a worker when one starts (lib/runner.js),
// so a large set leaves the page responsive and can be cancelled. Nothing is uploaded or fetched beyond the site's own
// files. Log contents and file names are untrusted: inserted as text,
// hosts and URLs defanged, never links.
import { $, el, busy, fetchRoot, readFile, ruleLink, showAlert, HANDOFF_KEY } from "../lib/dom.js";
import { arr, obj, num, str, trunc, plural, fmtShort, topEntries } from "../lib/fmt.js";
import { tools, pageRules } from "../lib/wasm.js";
import { EXAMPLE_FILES, EXAMPLE_HOST, PROBE_LOG } from "../lib/idexample.js";
import { bigSetOk, dropZone, fileOf, logFormat, needsSet, picked, runProgress, setPanel, setSummary } from "../lib/fileset.js";
import { runner, Cancelled } from "../lib/runner.js";

const MAX_LISTED = 8;
/** The most text a set carries over to the workbench: about what a tab's session storage holds. */
const HANDOFF_CHARS = 4 * 1024 * 1024;
let example = false;
let snapshot = null; // the providers' files the build embedded, once read
// The last logs checked, for the workbench: { log, map } for pasted text,
// { files: [{ name, text }], map } for a set, { tooBig: true } for a set
// past what the hand-over carries.
let checked = null;
let set = null; // the files picked, when a set replaces the text box
let bigOk = null; // the set the visitor said to read although it is big

// The workbench takes the logs checked here through this tab's session
// storage, never the URL: the link carries only #preset=access-log&from=check-logs,
// and the workbench reads them once and removes them.
const WORKBENCH = "../analyze/#preset=access-log";

/** Open the workbench with the logs checked here; false when they do not fit. */
function toWorkbench() {
  if (!checked) return false;
  const tooBig = () => {
    showAlert($("cl-alert"), "These logs are too large to carry over to the workbench.",
      "The browser keeps only a few MB for a tab. Open the workbench's access-log preset and load the same files, folder or archive there; they stay in your browser.");
    $("cl-alert").scrollIntoView({ block: "nearest" });
    return false;
  };
  if (checked.tooBig) return tooBig();
  try {
    const payload = checked.files ? { v: 2, files: checked.files, map: checked.map } : { v: 1, log: checked.log, map: checked.map };
    sessionStorage.setItem(HANDOFF_KEY, JSON.stringify(payload));
  } catch {
    return tooBig();
  }
  location.assign(new URL(`${WORKBENCH}&from=check-logs`, location.href).href);
  return true;
}

/** Check is offered once there is a log or a set. */
const sync = () => ($("cl-run").disabled = !set && !$("cl-input").value.trim());

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

// The analysis and the identity check run where the analysis is held: in a
// worker, or on the page when none starts. The page's own module defangs.
const engine = runner(tools);
const progress = runProgress($("cl-run").parentElement, () => engine.cancel());

/** A check the visitor cancelled: nothing is shown, the input stays. */
function cancelled() {
  progress.end("Check cancelled.");
  $("cl-result").hidden = true;
  $("cl-next").hidden = true;
  const status = $("cl-drop-status");
  status.replaceChildren("Check cancelled. Press Check my log to run it again.");
  status.hidden = false;
}

/** Check the logs, with the button busy while it runs. */
const runCheck = () => busy($("cl-run"), "Checking…", check);

const FORMATS = "The page reads web server access logs in Common or Combined Log Format, one request per line, and JSON logs with a url field.";

async function check() {
  $("cl-alert").hidden = true;
  if (set) return checkSet();
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
  const format = logFormat(input);
  let analysis, ident;
  $("cl-drop-status").hidden = true;
  try {
    const files = JSON.stringify(await providerFiles());
    const out = JSON.parse(await engine.analyze(input, format, map, rules, progress.show));
    analysis = obj(out.analysis);
    progress.show({ stage: "check" });
    ident = JSON.parse(await engine.call("identity_check", input, format, map, files));
    progress.end(`Checked ${plural(num(analysis.total) ?? 0, "request")}.`);
  } catch (e) {
    if (e instanceof Cancelled) return cancelled();
    progress.end();
    showAlert($("cl-alert"), "The log could not be read.", ["First problem: ", el("code", {}, trunc(String(e?.message ?? e), 300))], FORMATS);
    return;
  }
  if (!num(analysis.total)) {
    showAlert($("cl-alert"), "Nothing was read from this input: no line held a request.", FORMATS);
    return;
  }
  checked = { log: input, map };
  document.body.dataset.analysedIn = engine.mode;
  render(sc, analysis, ident, host, null);
}

/** Check a set of files: unpacked, read one by one, analysed as one. */
async function checkSet() {
  const status = $("cl-drop-status");
  if (bigOk !== set && !bigSetOk(set, status, () => {
    bigOk = set;
    runCheck();
  })) return;
  const host = hostOf($("cl-host").value);
  let sc;
  try {
    sc = await tools();
  } catch {
    return;
  }
  const rules = await pageRules(sc, $("rules-note"));
  const map = host ? `host=${host}` : "";
  let read, ident;
  status.hidden = true;
  try {
    const files = JSON.stringify(await providerFiles());
    // Each file is read as an access log, or detected when it starts as JSON.
    read = await engine.readSet(set, { format: "access_log", map, rules, keep: HANDOFF_CHARS }, progress.show);
    if (read.out) {
      progress.show({ stage: "check" });
      ident = JSON.parse(await engine.call("identity_check_held", files));
    }
  } catch (e) {
    if (e instanceof Cancelled) return cancelled();
    progress.end();
    showAlert($("cl-alert"), "The files could not be read.", ["First problem: ", el("code", {}, trunc(String(e?.message ?? e), 300))], FORMATS);
    return;
  }
  progress.end(`Read ${plural(read.files.length, "file")}, ${plural(num(read.out?.analysis?.total) ?? 0, "request")} checked.`);
  const analysis = obj(read.out?.analysis);
  if (!num(analysis.total)) {
    showAlert($("cl-alert"), "Nothing was read from these files: no line held a request.", FORMATS, setSummary(read));
    return;
  }
  checked = read.kept ? { files: read.kept, map } : { tooBig: true };
  document.body.dataset.analysedIn = engine.mode;
  render(sc, analysis, ident, host, read);
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

/** The summary. `read` is the set's per-file account, or null for pasted text. */
function render(sc, a, ident, host, read) {
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
  const files = read?.files ?? null;
  const fileCell = (id) => trunc(fileOf(id, files) ?? "", 60);
  const these = files ? "these logs" : "this log";

  const parts = [];
  parts.push(el("p", { class: "verdict-line" }, el("strong", {}, `${plural(a.total, "request")} read${files ? ` from ${plural(files.length, "file")}` : ""} for ${shownHost}. `),
    flagged.length
      ? `${plural(flagged.length, "request")} matched the indicator rules (${sig} significant, ${flagged.length - sig} suggestive).`
      : "No request matched the indicator rules strongly enough to flag.",
    " ",
    spoofed.length
      ? `${plural(spoofed.length, "request")} passed as an AI provider's agent from outside that provider's published addresses.`
      : verified || claims
        ? "No request passed as a provider's agent from outside its published addresses."
        : "No request declared an AI provider's agent."));
  if (read) parts.push(setSummary(read));

  // Flagged requests.
  parts.push(el("h3", {}, "Flagged requests"));
  if (flagged.length) {
    const clusters = arr(a.clusters).filter((c) => c.tier === "significant" || c.tier === "suggestive");
    parts.push(el("p", {}, `They fall into ${plural(clusters.length, "cluster")}: requests linked by shared tags, identifiers or close timing${files && files.length > 1 ? ", across files" : ""}. The rules they matched most: `,
      topEntries(rulesHit, 6).map(([id, n]) => el("span", { class: "chip" }, ruleLink(id, "rule-link"), ` ×${n}`)), "."));
    const head = ["Tier", "Score", "Rules", "Request (defanged)", "Time (UTC)", ...(files ? ["File"] : [])];
    parts.push(el("div", { class: "scroll" }, el("table", { class: "records" },
      el("thead", {}, el("tr", {}, head.map((h) => el("th", { scope: "col" }, h)))),
      el("tbody", {}, flagged.slice(0, MAX_LISTED).map(([r]) => el("tr", {},
        el("td", { class: "rc-head", "data-label": "Tier" }, el("span", { class: `pill ${str(r.tier).replace(/[^a-z]/g, "")}` }, str(r.tier))),
        el("td", { class: "num rc-head rc-lab", "data-label": "Score" }, String(r.score)),
        el("td", { class: "rules", "data-label": "Rules" }, arr(r.hits).map((h) => ruleLink(h.rule_id))),
        el("td", { class: "url", "data-label": "Request (defanged)" }, trunc(df(r.obs.url), 300)),
        el("td", { class: "nowrap rc-head", "data-label": "Time (UTC)" }, fmtShort(r.obs.ts)),
        files ? el("td", { class: "file-name", "data-label": "File" }, fileCell(r.obs.id)) : null))))));
    if (flagged.length > MAX_LISTED) {
      const more = el("button", { type: "button", class: "link-button" }, `${flagged.length - MAX_LISTED} more in the workbench`);
      more.addEventListener("click", toWorkbench);
      parts.push(el("p", { class: "hint" }, more, `, with ${these} carried over in this tab.`));
    }
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
        r.agent ? el("code", {}, trunc(df(r.agent), 80)) : null, n > 1 ? ` (${plural(n, "request")})` : null,
        files && fileOf(r.id, files) ? ` in ${fileCell(r.id)}` : null)))));
  }
  if (example) parts.push(el("p", { class: "hint" }, `The example's host is ${sc.defang("https://" + EXAMPLE_HOST.slice(5)).slice(8)}; its range files are synthetic.`));

  $("cl-summary").replaceChildren(...parts);
  $("cl-result").hidden = false;
  $("cl-next").hidden = false;
  $("cl-result-h").focus({ preventScroll: true });
  $("cl-result").scrollIntoView({ block: "start" });
}

/** The build's notice that spoofing cannot be checked, when it has one, stands outside the example. */
function syncNoFiles() {
  const none = $("no-provider-files");
  if (none) none.hidden = example;
}

function leaveExample() {
  example = false;
  $("cl-example-note").hidden = true;
  syncNoFiles();
}

$("cl-run").addEventListener("click", runCheck);
// The next steps' workbench link takes the logs checked, when there are some.
for (const a of document.querySelectorAll(`#cl-next a[href="${WORKBENCH}"]`)) {
  a.addEventListener("click", (ev) => {
    if (checked) {
      ev.preventDefault();
      toWorkbench();
    }
  });
}
$("cl-input").addEventListener("input", () => {
  if (example) leaveExample();
  sync();
});
// Signs of input start the download, so the module is ready by Check.
const warm = () => tools().catch(() => {});
$("cl-input").addEventListener("focus", warm, { once: true });
$("cl-example").addEventListener("pointerenter", warm, { once: true });
$("cl-example").addEventListener("click", () => {
  clearSet();
  example = true;
  $("cl-input").value = PROBE_LOG;
  $("cl-host").value = EXAMPLE_HOST.slice(5);
  $("cl-example-note").hidden = false;
  syncNoFiles();
  sync();
  runCheck();
});

/** One plain file into the log box. */
async function loadFile(f) {
  const status = $("cl-drop-status");
  let text;
  try {
    text = await readFile(f, status, use);
  } catch (err) {
    status.textContent = `${trunc(String(f.name), 80)} could not be read: ${String(err?.message ?? err)}`;
    status.hidden = false;
    return;
  }
  if (text != null) {
    status.hidden = true;
    use(text);
  }
}

/** The checked state follows the input: checked again when the host is known, else the host is asked for. */
function checkOrAsk() {
  leaveExample();
  sync();
  if ($("cl-host").value.trim()) runCheck();
  else $("cl-host").focus();
}

/** A file's text into the log box. */
function use(text) {
  clearSet();
  $("cl-input").value = text;
  checkOrAsk();
}

/** Files picked or dropped: one plain file to the box, anything else as a set. */
async function take(sources) {
  if (!sources.length) return;
  warm();
  $("cl-drop-status").hidden = true;
  if (!(await needsSet(sources.map((s) => s.blob)))) return loadFile(sources[0].blob);
  set = sources;
  bigOk = null;
  $("cl-input").hidden = true;
  setPanel($("cl-set"), sources, () => {
    clearSet();
    $("cl-input").focus();
  });
  checkOrAsk();
}

/** Back to the text box. */
function clearSet() {
  if (!set) return;
  set = null;
  bigOk = null;
  $("cl-set").hidden = true;
  $("cl-set").replaceChildren();
  $("cl-input").hidden = false;
  $("cl-drop-status").hidden = true;
  sync();
}

for (const id of ["cl-file", "cl-folder"]) {
  $(id).addEventListener("change", async (e) => {
    const files = picked(e.target);
    e.target.value = "";
    await take(files);
  });
}
// Files and folders dropped on the log area are read in the page, as picked ones are.
dropZone($("cl-drop"), take);
sync();
