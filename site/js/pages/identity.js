// Agent identity: an operator checks the agents its own log declares
// (ChatGPT-User, Claude-User, a Web Bot Auth signature) against the address
// ranges and signing keys the providers publish, with the tools module's
// identity_check, as `swarmchase identity check` does.
//
// The page fetches nothing from the providers: the CSP allows this site's
// own files only, and a request from the operator's browser would tell a
// provider who is checking. It starts with the snapshot the site build
// embedded (assets/identity-snapshot.json: the catalog, and the files
// `identity refresh` held, with their fetch dates) and takes copies the
// operator loads. Log contents are untrusted: inserted as text, hosts and
// URLs defanged.
import { $, el, fetchRoot, showAlert } from "../lib/dom.js";
import { arr, obj, num, str, trunc, plural } from "../lib/fmt.js";
import { tools } from "../lib/wasm.js";
import { EXAMPLE_FILES, EXAMPLE_HOST, EXAMPLE_LOG } from "../lib/idexample.js";

const MAX_ROWS = 500;
// In the order the page lists them: strongest first, then the failures.
const CLASSES = [
  ["signature_verified", "Signature verified", "signed with a key from the provider's published directory"],
  ["ip_verified", "Address verified", "declared, from the provider's published range"],
  ["in_range", "In range, undeclared", "from a provider's published range, no declaration"],
  ["signature_present", "Signature unchecked", "signed, but the key directory is not held or the signature could not be checked"],
  ["claimed", "User agent claim only", "declared in the user agent, nothing to check it against"],
  ["signature_failed", "Signature failed", "invalid, expired or malformed signature"],
  ["spoofed", "Spoofed", "declares a product from outside its provider's exhaustive range file"],
  ["none", "None", "no declared identity"],
];
const LABEL = Object.fromEntries(CLASSES.map(([id, label]) => [id, label]));
const pill = (c) => el("span", { class: `pill id-${str(c).replace(/[^a-z_]/g, "")}` }, LABEL[c] ?? str(c));

// The snapshot as built, the operator's own copies (by catalog id), and
// whether the example's synthetic files are in use instead.
let snap = { catalog: {}, files: [], ranges: {}, directories: {} };
const own = { ranges: {}, directories: {}, names: {} };
let example = false;

const catalog = () => obj(snap.catalog);
const rangeFiles = () => arr(catalog().range_file);
const directories = () => arr(catalog().directory);
const kindOf = (id) => (rangeFiles().some((f) => f.id === id) ? "ranges" : directories().some((d) => d.id === id) ? "directories" : null);

/** The files a check uses: the example's, else the operator's over the snapshot's. */
function filesInUse() {
  if (example) return EXAMPLE_FILES;
  return {
    ranges: { ...obj(snap.ranges), ...own.ranges },
    directories: { ...obj(snap.directories), ...own.directories },
  };
}

/** Whole days from a yyyy-mm-dd date to today, or null. */
function ageDays(date) {
  const t = Date.parse(`${date}T00:00:00Z`);
  return Number.isFinite(t) ? Math.max(0, Math.floor((Date.now() - t) / 86400000)) : null;
}

const fetchedOf = (id) => arr(snap.files).find((f) => f.id === id);

function sayFiles(text, warn = false) {
  const s = $("id-files-status");
  s.hidden = !text;
  s.textContent = text;
  s.className = warn ? "warn" : "hint";
}

// ── The providers' files ─────────────────────────────────────────────────
function renderSnapshotLine() {
  const files = arr(snap.files);
  const dates = files.map((f) => str(f.fetched)).sort();
  const node = $("id-snapshot");
  if (!files.length) {
    node.textContent = "This site was built without the providers' files. Until you load copies, user agents stay claims: nothing is verified or called spoofed.";
    return;
  }
  const oldest = dates[0], newest = dates[dates.length - 1];
  const age = ageDays(oldest);
  const span = oldest === newest ? `fetched ${oldest}` : `fetched between ${oldest} and ${newest}`;
  node.textContent = `This site was built with ${plural(files.length, "provider file")} of ${rangeFiles().length + directories().length}, ${span}${age != null ? ` (the oldest ${plural(age, "day")} ago)` : ""}. Providers change these files: for a recent log, load fresh copies; for an old log, say how far apart the log and the files are.`;
}

function fileRow(id, provider, kind, url, extra) {
  let using;
  if (example) using = EXAMPLE_FILES[kind][id] ? el("span", { class: "chip" }, "synthetic example") : el("span", { class: "hint" }, "none");
  else if (own[kind][id] != null) using = el("span", {}, "your copy ", el("span", { class: "chip" }, trunc(own.names[id] ?? "", 60)));
  else if (fetchedOf(id)) {
    const f = fetchedOf(id);
    const age = ageDays(f.fetched);
    using = el("span", {}, `snapshot, fetched ${f.fetched}`, age != null ? el("span", { class: "hint" }, ` (${plural(age, "day")} ago)`) : null, el("span", { class: "hint" }, `, ${plural(num(f.entries) ?? 0, kind === "ranges" ? "prefix" : "key", kind === "ranges" ? "prefixes" : "keys")}`));
  } else using = el("span", { class: "hint" }, "none");
  const input = el("input", { type: "file", accept: ".json,.txt", "aria-label": `Load your copy of ${id}` });
  input.addEventListener("change", async () => {
    const f = input.files[0];
    if (f) await loadOwn(id, f);
    input.value = "";
  });
  return el("tr", {},
    el("td", { "data-label": "File" }, el("code", {}, id)),
    el("td", { "data-label": "Provider" }, provider),
    el("td", { "data-label": "Kind" }, kind === "ranges" ? "address ranges" : "signing keys", extra ? el("span", { class: "hint" }, ` (${extra})`) : null),
    el("td", { "data-label": "Published at", class: "url" }, el("code", {}, url)),
    el("td", { "data-label": "In use" }, using),
    el("td", { "data-label": "Load" }, el("label", { class: "file button" }, "Load", input)));
}

function renderFileTable() {
  const rows = [
    ...rangeFiles().map((f) => fileRow(f.id, f.provider, "ranges", f.url, f.exhaustive === false ? "not documented as complete" : null)),
    ...directories().map((d) => fileRow(d.id, d.provider, "directories", d.url, `for ${d.signature_agent}`)),
  ];
  $("id-file-table").replaceChildren(rows.length
    ? el("div", { class: "scroll" }, el("table", { class: "records id-files" },
      el("thead", {}, el("tr", {}, ["File", "Provider", "Kind", "Published at", "In use", "Load"].map((h) => el("th", { scope: "col" }, h)))),
      el("tbody", {}, rows)))
    : el("p", { class: "warn" }, "The catalog did not load; reload the page."));
  $("id-reset").disabled = example || !Object.keys(own.names).length;
  // The build's notice that spoofing cannot be checked (present only when
  // the site holds no provider's files) stands while nothing else is in use.
  const none = $("no-provider-files");
  if (none) none.hidden = example || Object.keys(own.ranges).length + Object.keys(own.directories).length > 0;
}

/** Read one file the operator picked as the catalog file `id`. */
async function loadOwn(id, file) {
  const kind = kindOf(id);
  if (!kind) return;
  own[kind][id] = await file.text();
  own.names[id] = file.name;
  if (example) leaveExample();
  sayFiles(`Loaded ${file.name} as ${id}. It is checked when the log is; a file that does not read as ${kind === "ranges" ? "a range file" : "a key directory"} is reported there.`);
  renderFileTable();
  if (lastRun) check();
}

/**
 * The catalog id a picked file is for: `<id>.json` as `identity refresh`
 * names it, else the last part of the one catalog URL it matches.
 */
function idForName(name) {
  const all = [...rangeFiles(), ...directories()];
  const byId = all.find((f) => `${f.id}.json` === name || f.id === name);
  if (byId) return { id: byId.id };
  const hits = all.filter((f) => str(f.url).split("/").pop() === name);
  if (hits.length === 1) return { id: hits[0].id };
  return { ambiguous: hits.map((f) => f.id) };
}

async function loadPicked(files) {
  const done = [], skipped = [];
  for (const f of files) {
    const m = idForName(f.name);
    if (m.id) {
      const kind = kindOf(m.id);
      own[kind][m.id] = await f.text();
      own.names[m.id] = f.name;
      done.push(`${f.name} as ${m.id}`);
    } else skipped.push(m.ambiguous?.length ? `${f.name} (could be ${m.ambiguous.join(" or ")}: load it from its row)` : `${f.name} (not a file in the catalog: load it from its row)`);
  }
  if (done.length && example) leaveExample();
  sayFiles([done.length ? `Loaded ${done.join(", ")}.` : "", skipped.length ? `Not loaded: ${skipped.join("; ")}.` : ""].filter(Boolean).join(" "), skipped.length > 0);
  renderFileTable();
  if (lastRun && done.length) check();
}

function leaveExample() {
  example = false;
  $("id-example-note").hidden = true;
}

// ── The check ────────────────────────────────────────────────────────────
let lastRun = false;

async function check() {
  $("id-alert").hidden = true;
  const input = $("id-input").value;
  if (!input.trim()) {
    showAlert($("id-alert"), "There is nothing to check yet.", "Paste or load your access log, or press Try an example.");
    return;
  }
  let sc;
  try {
    sc = await tools();
  } catch {
    // The status line says the module did not load.
    return;
  }
  let res;
  try {
    res = JSON.parse(sc.identity_check(input, $("id-format").value, $("id-map").value, JSON.stringify(filesInUse())));
  } catch (e) {
    showAlert($("id-alert"), "The log could not be read.", ["First problem: ", el("code", {}, trunc(String(e?.message ?? e), 300))]);
    return;
  }
  lastRun = true;
  render(sc, res);
}

function render(sc, res) {
  const counts = obj(res.counts);
  const total = Object.values(counts).reduce((a, b) => a + (num(b) ?? 0), 0);
  const records = arr(res.records);
  const out = $("id-out");
  if (!total) {
    out.replaceChildren(el("p", { class: "hint" }, "Check a log to see each record's class here."));
    showAlert($("id-alert"), "Nothing was read from this input: no line held a record.",
      arr(res.warnings)[0] ? ["First problem: ", el("code", {}, trunc(str(res.warnings[0]), 300))] : null,
      "The page reads web server access logs (Common or Combined Log Format), NDJSON and JSON arrays. If auto-detect guessed wrong, pick the format.");
    return;
  }
  const files = filesInUse();
  const held = Object.keys(files.ranges).length + Object.keys(files.directories).length;
  const df = (s) => sc.defang(str(s));
  const declared = total - (num(counts.none) ?? 0);

  const parts = [];
  parts.push(el("p", {}, `${plural(total, "record")} read; ${plural(declared, "record")} with a declared identity or a provider's address.`,
    example ? " Checked against the example's synthetic files." : held ? ` Checked against ${plural(held, "provider file")}.` : ""));
  if (!held) parts.push(el("p", { class: "warn" }, "No providers' files in use: every declaration stays a claim, and nothing is verified or called spoofed. Load the providers' files above."));
  if (arr(res.warnings).length) parts.push(el("ul", { class: "warn" }, res.warnings.slice(0, 20).map((w) => el("li", {}, df(w)))));

  // Counts per class.
  parts.push(el("h3", {}, "By class"));
  parts.push(el("dl", { class: "stats wide id-counts" }, CLASSES.flatMap(([id, label, what]) => [
    el("dt", {}, pill(id)),
    el("dd", { class: id === "spoofed" && counts[id] ? "id-alarm" : null }, el("span", { class: "big" }, String(num(counts[id]) ?? 0)), el("span", {}, what)),
  ])));

  // Spoofed records first, highlighted.
  const spoofed = records.filter((r) => r.class === "spoofed");
  if (spoofed.length) {
    parts.push(el("div", { class: "alert id-spoofed" },
      el("h3", {}, `${plural(spoofed.length, "record")} declare a provider's product from outside its published ranges`),
      el("p", {}, "Something else is using the provider's name: a scraper or another agent passing as a known one. The provider's own agents send from the ranges it publishes. Check that the files are current and that your log has the real client address before you act on it."),
      recordTable(spoofed, df, true)));
  }

  // Per provider product.
  const byProduct = new Map();
  for (const r of records) {
    const key = `${str(r.provider) || "unknown provider"}\u0000${str(r.agent) || "(undeclared)"}`;
    const m = byProduct.get(key) ?? {};
    m[r.class] = (m[r.class] ?? 0) + 1;
    byProduct.set(key, m);
  }
  if (byProduct.size) {
    const cols = CLASSES.filter(([id]) => id !== "none" && records.some((r) => r.class === id));
    parts.push(el("h3", {}, "By provider and product"));
    parts.push(el("div", { class: "scroll" }, el("table", { class: "records id-products" },
      el("thead", {}, el("tr", {}, el("th", { scope: "col" }, "Provider"), el("th", { scope: "col" }, "Product or signer"), cols.map(([id]) => el("th", { scope: "col", class: "num" }, LABEL[id])))),
      el("tbody", {}, [...byProduct.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1)).map(([key, m]) => {
        const [provider, agent] = key.split("\u0000");
        return el("tr", { class: m.spoofed ? "id-row-spoofed" : null },
          el("td", { "data-label": "Provider" }, provider),
          el("td", { "data-label": "Product" }, el("code", {}, df(agent))),
          cols.map(([id]) => el("td", { class: "num", "data-label": LABEL[id] }, m[id] ? String(m[id]) : "–")));
      })))));
  }

  // Every record with a declared identity.
  parts.push(el("h3", {}, "Records"));
  parts.push(records.length ? recordTable(records, df, false) : el("p", { class: "hint" }, "No record declares an agent identity or comes from a provider's published range."));
  if (num(counts.none)) parts.push(el("p", { class: "hint" }, `${plural(counts.none, "record")} with no declared identity ${counts.none === 1 ? "is" : "are"} counted, not listed.`));
  out.replaceChildren(...parts);
}

function recordTable(records, df, compact) {
  const shown = records.slice(0, MAX_ROWS);
  const head = ["Record", "Client address", "Class", "Provider", "Product or signer", "Decided by", "Detail"];
  return el("div", { class: "scroll" }, el("table", { class: `records id-records${compact ? " compact" : ""}` },
    el("thead", {}, el("tr", {}, head.map((h) => el("th", { scope: "col" }, h)))),
    el("tbody", {}, shown.map((r) => el("tr", { class: r.class === "spoofed" ? "id-row-spoofed" : null },
      el("td", { "data-label": "Record" }, trunc(str(r.id), 80)),
      el("td", { "data-label": "Client address", class: "nowrap" }, str(r.ip) || "–"),
      el("td", { "data-label": "Class" }, pill(r.class)),
      el("td", { "data-label": "Provider" }, str(r.provider) || "–"),
      el("td", { "data-label": "Product or signer" }, r.agent ? el("code", {}, trunc(df(r.agent), 120)) : "–"),
      el("td", { "data-label": "Decided by" }, r.basis ? el("code", {}, str(r.basis)) : "–"),
      el("td", { "data-label": "Detail" }, trunc(df(r.detail), 300) || "–"))),
    records.length > shown.length ? el("tr", {}, el("td", { colspan: head.length, class: "hint" }, `${records.length - shown.length} more not shown.`)) : null)));
}

// ── Wiring ───────────────────────────────────────────────────────────────
$("id-run").addEventListener("click", () => {
  check();
});
$("id-example").addEventListener("click", () => {
  example = true;
  $("id-input").value = EXAMPLE_LOG;
  $("id-format").value = "access_log";
  $("id-map").value = EXAMPLE_HOST;
  $("id-example-note").hidden = false;
  sayFiles("");
  renderFileTable();
  check();
});
$("id-input").addEventListener("input", () => {
  if (example) {
    leaveExample();
    renderFileTable();
  }
});
$("id-file").addEventListener("change", async (e) => {
  const f = e.target.files[0];
  if (!f) return;
  if (example) leaveExample();
  $("id-input").value = await f.text();
  e.target.value = "";
  renderFileTable();
  check();
});
$("id-files").addEventListener("change", async (e) => {
  const picked = [...e.target.files];
  e.target.value = "";
  if (picked.length) await loadPicked(picked);
});
$("id-reset").addEventListener("click", () => {
  for (const k of ["ranges", "directories", "names"]) own[k] = {};
  sayFiles("Your loaded files are forgotten; the snapshot this site was built with is in use.");
  renderFileTable();
  if (lastRun) check();
});

try {
  const s = await fetchRoot("assets/identity-snapshot.json");
  snap = { catalog: obj(s.catalog), files: arr(s.files), ranges: obj(s.ranges), directories: obj(s.directories) };
} catch (e) {
  sayFiles(`The catalog of providers' files did not load (${e?.message ?? e}); reload the page.`, true);
}
renderSnapshotLine();
renderFileTable();
