// Report a swarm: build an SC-Submission v1 document from the form, check it
// as the schema does, and offer it to copy or download. Nothing is sent: the
// page makes no request, and the JSON is shown as text only.
import { $, el, download, store } from "../lib/dom.js";

const SPEC = "SC-Submission v1";
const DRAFT_KEY = "sc-submit-draft";

// Each public source and the fields that name a record in it.
const SOURCES = {
  urlquery: { label: "urlquery.net report", needs: ["id"] },
  urlscan: { label: "urlscan.io result", needs: ["id"] },
  wayback: { label: "Wayback Machine capture", needs: ["url", "timestamp"] },
  arquivo: { label: "Arquivo.pt capture", needs: ["url", "timestamp"] },
  commoncrawl: { label: "Common Crawl capture", needs: ["url", "timestamp", "crawl"] },
  gharchive: { label: "GH Archive event", needs: ["id", "timestamp"] },
  npm: { label: "npm release", needs: ["package", "version"] },
  pypi: { label: "PyPI release", needs: ["package", "version"] },
  ctlog: { label: "CT log entry (crt.sh id)", needs: ["id", "domain"] },
};
const RECORD_FIELDS = [
  ["id", "Id (report uuid, event id, crt.sh id)"],
  ["url", "URL (never opened)"],
  ["timestamp", "Time (RFC 3339 or 14-digit capture time)"],
  ["crawl", "Crawl (CC-MAIN-2026-39)"],
  ["package", "Package"],
  ["version", "Version"],
  ["domain", "A DNS name on the certificate"],
];

const HOST = /^[a-z0-9-]+(\.[a-z0-9-]+)+$/;
const isTime = (s) => /^\d{14}$/.test(s) || !Number.isNaN(Date.parse(s));

let items = [];

function blank(type) {
  switch (type) {
    case "public_record": return { type, source: "wayback" };
    case "log_lines": return { type, format: "access_log", lines: "" };
    case "signed": return { type, scheme: "http_message_signature", content: "" };
    default: return { type: "indicator", kind: "inbox", value: "" };
  }
}

const text = (v) => String(v ?? "").trim();

function field(item, key, label, opts = {}) {
  const input = opts.rows
    ? el("textarea", { rows: opts.rows, spellcheck: "false" })
    : el("input", { spellcheck: "false", placeholder: opts.placeholder ?? "" });
  input.value = item[key] ?? "";
  input.addEventListener("input", () => { item[key] = input.value; update(); });
  return el("label", { class: "grow" }, label, input);
}

function select(item, key, label, options) {
  const s = el("select", {}, ...Object.entries(options).map(([v, t]) => el("option", { value: v }, t)));
  s.value = item[key];
  s.addEventListener("change", () => { item[key] = s.value; render(); });
  return el("label", {}, label, s);
}

function renderItem(item, i) {
  const remove = el("button", { type: "button", onclick: () => { items.splice(i, 1); render(); } }, "Remove");
  const rows = [];
  if (item.type === "public_record") {
    const need = SOURCES[item.source]?.needs ?? [];
    rows.push(el("div", { class: "row" }, select(item, "source", "Source", Object.fromEntries(Object.entries(SOURCES).map(([k, v]) => [k, v.label])))));
    rows.push(el("div", { class: "row" }, ...RECORD_FIELDS.filter(([k]) => need.includes(k) || k === "url").map(([k, l]) => field(item, k, need.includes(k) ? `${l} *` : l))));
  } else if (item.type === "log_lines") {
    rows.push(el("div", { class: "row" },
      select(item, "format", "Format", { access_log: "Access log", ndjson: "NDJSON records", lines: "One URL per line" }),
      field(item, "host", "Host the log belongs to", { placeholder: "www.example.org" })));
    rows.push(el("div", { class: "row" }, field(item, "lines", "Lines *", { rows: 5 })));
  } else if (item.type === "signed") {
    rows.push(el("div", { class: "row" },
      select(item, "scheme", "Scheme", { http_message_signature: "HTTP message signature (RFC 9421)", dkim: "DKIM-signed mail", other: "Other signed export" }),
      field(item, "signer", "Signer (d= domain, key id)")));
    rows.push(el("div", { class: "row" }, field(item, "content", "Signed content with its signature headers *", { rows: 5 })));
  } else {
    rows.push(el("div", { class: "row" },
      select(item, "kind", "Kind", { inbox: "Callback inbox id (never contacted)", run_tag: "Run tag", payload: "Payload", user_agent: "User agent", url: "URL (never opened)", ip: "IP address", other: "Other" }),
      field(item, "value", "Value *")));
  }
  rows.push(el("div", { class: "row" }, field(item, "note", "Note")));
  return el("div", { class: "card ev-item" }, el("p", {}, el("strong", {}, `${i}. ${item.type.replace("_", " ")}`), " ", remove), ...rows);
}

function render() {
  $("ev-list").replaceChildren(...(items.length ? items.map(renderItem) : [el("p", { class: "hint" }, "No evidence yet. Add at least one item.")]));
  update();
}

/** The document and the problems the schema would find. */
function build() {
  const problems = [];
  const opt = (v) => (text(v) ? text(v) : undefined);
  const agent = $("sub-agent").value === "true";
  // A datetime-local value has no zone: read it in this browser's zone, or
  // as UTC when the visitor says so. The document always holds UTC.
  const utc = $("sub-tz").value === "utc";
  const time = (id, name) => {
    const v = $(id).value;
    if (!v) return undefined;
    const d = new Date(utc ? `${v}Z` : v);
    if (Number.isNaN(d.getTime())) { problems.push(`${name} is not a time`); return undefined; }
    return d.toISOString().replace(/\.\d{3}Z$/, "Z");
  };
  const agents = $("sub-agents").value ? Number($("sub-agents").value) : undefined;
  if (agents !== undefined && !(Number.isInteger(agents) && agents >= 1)) problems.push("Number of agents must be a whole number of at least 1");
  const targets = $("sub-targets").value.split(/[\s,]+/).map((h) => h.trim().toLowerCase()).filter(Boolean);
  for (const h of targets) if (!HOST.test(h)) problems.push(`Target ${h} is not a plain host name`);
  const summary = text($("sub-summary").value);
  if (!summary) problems.push("Write a summary of what you saw");
  const evidence = items.map((it, i) => {
    const out = { type: it.type };
    if (it.type === "public_record") {
      out.source = it.source;
      for (const [k] of RECORD_FIELDS) if (opt(it[k])) out[k] = text(it[k]);
      for (const k of SOURCES[it.source].needs) if (!out[k]) problems.push(`Item ${i}: a ${SOURCES[it.source].label} needs ${k}`);
      if (out.url && !/^https?:\/\//.test(out.url)) problems.push(`Item ${i}: the URL must start with http:// or https://`);
      if (out.timestamp && !isTime(out.timestamp)) problems.push(`Item ${i}: the time is not RFC 3339 or 14 digits`);
      if (out.id && ["urlquery", "urlscan"].includes(it.source) && !/^[0-9a-fA-F-]{8,64}$/.test(out.id)) problems.push(`Item ${i}: the id is not a report uuid`);
      if (out.id && ["gharchive", "ctlog"].includes(it.source) && !/^[0-9]+$/.test(out.id)) problems.push(`Item ${i}: the id must be digits`);
      if (out.crawl && !/^CC-MAIN-\d{4}-\d{2}$/.test(out.crawl)) problems.push(`Item ${i}: the crawl is not CC-MAIN-yyyy-ww`);
      if (out.domain && !HOST.test(out.domain)) problems.push(`Item ${i}: the domain is not a plain host name`);
    } else if (it.type === "log_lines") {
      out.format = it.format;
      if (opt(it.host)) out.host = text(it.host).toLowerCase();
      out.lines = String(it.lines ?? "").split(/\r?\n/).filter((l) => l.trim());
      if (!out.lines.length) problems.push(`Item ${i}: no log lines`);
      if (out.host && !HOST.test(out.host)) problems.push(`Item ${i}: the host is not a plain host name`);
    } else if (it.type === "signed") {
      out.scheme = it.scheme;
      out.content = String(it.content ?? "");
      if (opt(it.signer)) out.signer = text(it.signer);
      if (!text(out.content)) problems.push(`Item ${i}: no signed content`);
    } else {
      out.kind = it.kind;
      out.value = text(it.value);
      if (!out.value) problems.push(`Item ${i}: no value`);
    }
    if (opt(it.note)) out.note = text(it.note);
    return out;
  });
  if (!evidence.length) problems.push("Add at least one evidence item");
  const submitter = { ai_agent: agent };
  for (const [k, id] of [["role", "sub-role"], ["name", "sub-name"], ["contact", "sub-contact"]]) if (opt($(id).value)) submitter[k] = text($(id).value);
  if (agent) for (const [k, id] of [["operator", "sub-operator"], ["model", "sub-model"]]) if (opt($(id).value)) submitter[k] = text($(id).value);
  const claim = { summary, kind: $("sub-kind").value };
  const first = time("sub-first", "First seen");
  const last = time("sub-last", "Last seen");
  if (first) claim.first_seen = first;
  if (last) claim.last_seen = last;
  const zone = utc ? "UTC" : (Intl.DateTimeFormat().resolvedOptions().timeZone || "this browser's time zone");
  $("sub-time-note").textContent = first || last
    ? `Read as ${zone}; the report stores UTC: ${[first && `first seen ${first}`, last && `last seen ${last}`].filter(Boolean).join(", ")}.`
    : `The report stores times in UTC. Times you enter are read as ${zone}.`;
  if (agents !== undefined) claim.agents = agents;
  if (targets.length) claim.targets = targets;
  const doc = { spec: SPEC, submitted: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"), submitter, claim, evidence };
  return { doc, problems };
}

let current = "";

function update() {
  $("sub-agent-row").hidden = $("sub-agent").value !== "true";
  const { doc, problems } = build();
  current = JSON.stringify(doc, null, 2);
  $("sub-json").textContent = current;
  const box = $("sub-problems");
  box.hidden = problems.length === 0;
  box.replaceChildren(...(problems.length ? [el("p", {}, el("strong", {}, "Not ready to send yet")), el("ul", {}, ...problems.map((p) => el("li", {}, p)))] : []));
  $("sub-copy").disabled = $("sub-dl").disabled = problems.length > 0;
  store.set(DRAFT_KEY, JSON.stringify({ items }));
}

function restore() {
  try {
    const d = JSON.parse(store.get(DRAFT_KEY) ?? "null");
    if (d && Array.isArray(d.items)) items = d.items.filter((x) => x && typeof x === "object" && typeof x.type === "string").map((x) => ({ ...blank(x.type), ...x }));
  } catch {
    items = [];
  }
}

for (const id of ["sub-agent", "sub-role", "sub-kind", "sub-first", "sub-last", "sub-tz"]) $(id).addEventListener("change", update);
for (const id of ["sub-name", "sub-contact", "sub-operator", "sub-model", "sub-summary", "sub-agents", "sub-targets"]) $(id).addEventListener("input", update);
$("ev-add").addEventListener("click", () => { items.push(blank($("ev-type").value)); render(); });
$("sub-copy").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(current);
    $("sub-copy").textContent = "Copied";
    setTimeout(() => { $("sub-copy").textContent = "Copy JSON"; }, 1500);
  } catch {
    $("sub-copy").textContent = "Copy failed: select the text below";
  }
});
$("sub-dl").addEventListener("click", () => download("sc-submission.json", current, "application/json"));
restore();
render();
