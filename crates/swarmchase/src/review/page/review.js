// Lead review: a queue of groups on the left, the selected group on the
// right. Labelling a group moves to the next one; `z` undoes.
//
// The queue can be sorted and filtered (grade, tier, source, suggestion,
// checks), remembered per browser. The labelling rule (agent needs L2 or
// higher) comes from the server as flags on each record and group: a
// suggestion of agent below L2 is never accepted, and labelling agent below
// L2 asks twice. A session panel (`p`) counts labels, agreement with the
// suggestions and how far the labels are from a precision estimate.
//
// Extensions (guide.js, context.js, ...) load after this file and add to the
// `Review` registries below; boot.js starts the page last. Every element that
// shows a model suggestion carries the class `suggestion-ui`, so a blind
// review mode can hide them all.
"use strict";

const { el, api, toast, keys, help, progress, plural, copy, icon, emptyState, settings, prefs } = UI;
const VERDICTS = [
  { label: "agent", key: "a", name: "Agent" },
  { label: "benign", key: "b", name: "Benign" },
  { label: "unsure", key: "u", name: "Unsure" },
];
const TABS = [
  { id: "todo", name: "To do", test: (g) => g.items.some((i) => !i.label) },
  { id: "disagree", name: "Disagree", test: (g) => g.items.some(differs) },
  { id: "done", name: "Done", test: (g) => g.items.every((i) => i.label) },
  { id: "all", name: "All", test: () => true },
];
const SORTS = [
  { id: "queue", name: "Queue order" },
  { id: "attention", name: "Needs attention first" },
  { id: "largest", name: "Largest groups first" },
  { id: "grade-high", name: "Highest grade first" },
  { id: "grade-low", name: "Lowest grade first" },
];
const GRADES = [["allowed", "L2 or higher"], ["below", "Below L2"], ...["L0", "L1", "L2", "L3", "L4", "L5"].map((c) => [c, c]), ["none", "No grade"]];
const CHECKS = [
  ["conflict", "Suggests agent below L2"],
  ["breaks", "Labelled agent below L2"],
  ["split", "Split suggestions"],
  ["mixed", "Mixed or differing labels"],
];
const NO_FILTER = { grade: "", tier: "", source: "", sug: "", check: "" };
const KINDS = {
  exploit: "Exploit", exfil: "Exfil", agent_marker: "Marker", carrier: "Carrier", relay: "Relay",
  self_id: "Self-ID", cache_buster: "Cache buster", header: "Header", outcome: "Outcome",
  anti_bot: "Anti-bot", infra: "Infra",
};

function loadPref(name, fallback) {
  try { const v = JSON.parse(prefs.get(name, "null")); return v == null ? fallback : v; }
  catch { return fallback; }
}
const savedSort = loadPref("review.sort", "queue");

const state = {
  data: null,
  tab: "todo",
  query: "",
  sel: null, // selected group key
  showAll: new Set(), // group keys with every record shown
  undo: [],
  touched: new Set(), // ids labelled in this session
  sort: SORTS.some((x) => x.id === savedSort) ? savedSort : "queue",
  filters: { ...NO_FILTER, ...loadPref("review.filters", {}) },
  filtersOpen: !!loadPref("review.filtersOpen", false),
  started: Date.now(),
  firstLabel: null, // time of this session's first label
  index: new Map(), // group key -> position in the server's order
};

function differs(i) { return i.label && i.suggested && i.label !== i.suggested.label; }
function count(list, f) {
  const c = {};
  for (const x of list) { const k = f(x); if (k) c[k] = (c[k] || 0) + 1; }
  return c;
}
function allItems() { return state.data.groups.flatMap((g) => g.items); }
function tierOf(g) { return g.cluster ? g.cluster.tier : g.items[0].tier; }
function gradeCode(g) { return g.level == null ? "no grade" : "L" + g.level; }
/** Unlabelled records whose suggestion says agent below L2: never to accept. */
function conflicts(g) { return g.items.filter((i) => i.conflict && !i.label); }
/** Records labelled agent below L2. */
function breaks(g) { return g.items.filter((i) => i.breaks_rule); }
function split(g) { const s = suggestionOf(g); return !!s && Object.keys(s.by).length > 1; }

// Higher needs a look sooner: a rule conflict, split suggestions, then
// mixed labels or labels that differ from a suggestion.
function attention(g) {
  if (conflicts(g).length || breaks(g).length) return 3;
  if (split(g)) return 2;
  if (verdictOf(g) === "mixed" || g.items.some(differs)) return 1;
  return 0;
}

function passes(g) {
  const f = state.filters;
  if (f.grade) {
    const ok = f.grade === "allowed" ? g.agent_allowed
      : f.grade === "below" ? !g.agent_allowed
        : f.grade === "none" ? g.level == null
          : g.level === Number(f.grade.slice(1));
    if (!ok) return false;
  }
  if (f.tier && tierOf(g) !== f.tier) return false;
  if (f.source && !g.items.some((i) => i.source === f.source)) return false;
  if (f.sug) {
    const s = suggestionOf(g);
    if (f.sug === "none" ? s : !s || s.label !== f.sug) return false;
  }
  if (f.check) {
    const test = {
      conflict: () => conflicts(g).length > 0, breaks: () => breaks(g).length > 0, split: () => split(g),
      mixed: () => verdictOf(g) === "mixed" || g.items.some(differs),
    }[f.check];
    if (test && !test()) return false;
  }
  return true;
}
function activeFilters() { return Object.values(state.filters).filter(Boolean).length; }

function matches(g, q) {
  if (!q) return true;
  const hay = [g.title, ...g.items.flatMap((i) => [i.url, i.id, ...i.hits.map((h) => h.rule)])].join(" ").toLowerCase();
  return q.toLowerCase().split(/\s+/).every((w) => hay.includes(w));
}

function visible() {
  const tab = TABS.find((t) => t.id === state.tab);
  const list = state.data.groups.filter((g) => tab.test(g) && matches(g, state.query) && passes(g));
  const lvl = (g) => (g.level == null ? -1 : g.level);
  const by = {
    attention: (a, b) => attention(b) - attention(a),
    largest: (a, b) => b.items.length - a.items.length,
    "grade-high": (a, b) => lvl(b) - lvl(a),
    "grade-low": (a, b) => lvl(a) - lvl(b),
  }[state.sort];
  if (by) list.sort((a, b) => by(a, b) || state.index.get(a.key) - state.index.get(b.key));
  return list;
}

function current() {
  return state.data.groups.find((g) => g.key === state.sel) || null;
}

function verdictOf(g) {
  const c = count(g.items, (i) => i.label);
  const ks = Object.keys(c);
  if (ks.length === 1 && c[ks[0]] === g.items.length) return ks[0];
  return ks.length ? "mixed" : null;
}

function suggestionOf(g) {
  const s = g.items.filter((i) => i.suggested);
  if (!s.length) return null;
  const by = count(s, (i) => i.suggested.label);
  const top = Object.entries(by).sort((a, b) => b[1] - a[1])[0];
  const reasons = count(s, (i) => i.suggested.reason);
  return {
    label: top[0], n: top[1], of: g.items.length, with: s.length, by,
    reasons: Object.entries(reasons).sort((a, b) => b[1] - a[1]).slice(0, 3),
    model: s[0].suggested.model,
  };
}

// ---- actions --------------------------------------------------------------

async function apply(ids, label, note, { record = true, restore = false } = {}) {
  const before = state.data.groups.flatMap((g) => g.items).filter((i) => ids.includes(i.id))
    .map((i) => ({ id: i.id, label: i.label, note: i.note }));
  const res = await api.post("label", { ids, label, note: note || null, restore });
  for (const g of state.data.groups) {
    g.items = g.items.map((i) => res.items[i.id] || i);
    g.rule_breaks = breaks(g).length;
  }
  if (res.stored) state.data.stored = res.stored;
  if (record) state.undo.push(before);
  if (label !== "clear" && !restore) {
    ids.forEach((id) => state.touched.add(id));
    state.firstLabel ||= Date.now();
  }
  return Object.keys(res.items).length;
}

// The labelling rule: agent needs L2 or higher. Below it the page asks
// twice: a second press within a few seconds, or the toast's button.
let armed = null; // {scope, until}
function guardAgent(scope, records, run) {
  const below = records.filter((i) => !i.agent_allowed);
  if (!below.length) return true;
  if (armed && armed.scope === scope && Date.now() < armed.until) { armed = null; return true; }
  armed = { scope, until: Date.now() + 6000 };
  const g = current();
  const grade = g ? gradeCode(g) : "its grade";
  toast(`${plural(below.length, "record")} at ${grade}: agent needs L2 or higher, so unsure is the most the evidence allows. Press again to label agent anyway.`,
    { kind: "unsure", action: "Label agent", onAction: () => { armed = null; run(); }, ms: 6000 });
  return false;
}

/** Label the selected group; `rest` labels only its unlabelled records. */
async function labelGroup(label, { rest = false, force = false } = {}) {
  const g = current();
  if (!g) return;
  const items = rest ? g.items.filter((i) => !i.label) : g.items;
  if (!items.length) { toast(rest ? "Every record here has a label" : "Nothing to label"); return; }
  if (label === "agent" && !force && !guardAgent((rest ? "rest:" : "group:") + g.key, items, () => labelGroup(label, { rest, force: true }))) return;
  const note = document.getElementById("note")?.value.trim();
  const order = visible().map((x) => x.key);
  try {
    const n = await apply(items.map((i) => i.id), label, note);
    toast(label === "clear" ? `Cleared ${plural(n, "label")}` : `${plural(n, "record")} labelled ${label}${rest ? ", the rest of the group" : ""}`,
      { action: "Undo", onAction: undo, kind: label === "clear" ? undefined : label });
    advance(order, g.key);
  } catch (e) { toast("Not saved: " + e.message, { error: true }); }
}

async function labelOne(id, label, force = false) {
  const i = allItems().find((x) => x.id === id);
  if (label === "agent" && i && !force && !guardAgent("rec:" + id, [i], () => labelOne(id, label, true))) return;
  try { await apply([id], label, null); render(); }
  catch (e) { toast("Not saved: " + e.message, { error: true }); }
}

/** Relabel the group's agent-below-L2 records unsure. Undoable. */
async function fixBreaks(g) {
  const ids = breaks(g).map((i) => i.id);
  if (!ids.length) return;
  try {
    await apply(ids, "unsure", null);
    toast(`${plural(ids.length, "record")} relabelled unsure`, { action: "Undo", onAction: undo, kind: "unsure" });
    render();
  } catch (e) { toast("Not saved: " + e.message, { error: true }); }
}

// Accepts this group's suggestions only, never across groups, and never a
// suggestion of agent below L2.
async function acceptSuggestions() {
  const g = current();
  if (!g) return;
  const by = {};
  let skipped = 0;
  for (const i of g.items) {
    if (!i.suggested || i.label) continue;
    if (i.conflict) { skipped++; continue; }
    (by[i.suggested.label] ||= []).push(i.id);
  }
  if (!Object.keys(by).length) {
    toast(skipped ? `Not accepted: ${plural(skipped, "suggestion")} say agent below L2. Label the group yourself.` : "No unlabelled record here has a suggestion");
    return;
  }
  const order = visible().map((x) => x.key);
  const batch = [];
  try {
    for (const [l, ids] of Object.entries(by)) {
      await apply(ids, l, null);
      batch.push(...state.undo.pop());
    }
    state.undo.push(batch);
    toast(`Accepted ${plural(batch.length, "suggestion")}` + (skipped ? `; ${skipped} saying agent below L2 left unlabelled` : ""), { action: "Undo", onAction: undo });
    advance(order, g.key);
  } catch (e) { toast("Not saved: " + e.message, { error: true }); }
}

async function undo() {
  const last = state.undo.pop();
  if (!last) { toast("Nothing to undo"); return; }
  // Restore each record's label and note as they were.
  const groups = {};
  for (const r of last) (groups[JSON.stringify([r.label || "clear", r.note || null])] ||= []).push(r.id);
  try {
    for (const [k, ids] of Object.entries(groups)) {
      const [label, note] = JSON.parse(k);
      await apply(ids, label, note, { record: false, restore: true });
    }
    const g = state.data.groups.find((g) => g.items.some((i) => i.id === last[0].id));
    if (g) state.sel = g.key;
    toast("Undone");
    render();
  } catch (e) { toast("Undo failed: " + e.message, { error: true }); }
}

// After a group is labelled, select the group that followed it in the list
// as it was, so the queue flows forward.
function advance(order, key) {
  const vis = visible().map((g) => g.key);
  const from = order.indexOf(key);
  const next = order.slice(from + 1).find((k) => vis.includes(k)) || order.slice(0, from).reverse().find((k) => vis.includes(k));
  state.sel = vis.includes(key) && state.tab !== "todo" ? (next || key) : (next || null);
  render();
}

function move(d) {
  const vis = visible();
  if (!vis.length) return;
  const i = vis.findIndex((g) => g.key === state.sel);
  const n = Math.max(0, Math.min(vis.length - 1, i < 0 ? 0 : i + d));
  state.sel = vis[n].key;
  render();
  announceGroup(vis[n], n, vis.length);
}

function announceGroup(g, n, of) {
  const v = verdictOf(g);
  UI.announce(`Group ${n + 1} of ${of}: ${g.title}. ${plural(g.items.length, "record")}, ${gradeCode(g)}, ${v ? (v === "mixed" ? "mixed labels" : "labelled " + v) : "unlabelled"}.`);
}

// ---- rendering ------------------------------------------------------------

function topbar() {
  const items = allItems();
  const c = count(items, (i) => i.label);
  const done = items.filter((i) => i.label).length;
  const session = items.filter((i) => i.label && state.touched.has(i.id)).length;
  const pct = items.length ? Math.round((100 * done) / items.length) : 0;
  const broken = items.filter((i) => i.breaks_rule).length;
  return el("header.topbar",
    el("div.brand", el("span.brand-mark", "swarmchase"), el("span.brand-sub", "Lead review")),
    progress([{ cls: "agent", n: c.agent }, { cls: "benign", n: c.benign }, { cls: "unsure", n: c.unsure }],
      items.length, `${done} of ${items.length} labelled`),
    el("span.pct", { "aria-hidden": "true" }, `${pct}%`),
    el("div.tally", { "aria-label": "Labels so far" },
      VERDICTS.map((v) => el("span.chip." + v.label, el("b", c[v.label] || 0), " " + v.label)),
      session ? el("span.chip.outline", `${session} this session`) : null),
    broken ? el("button.chip.rulebreak", {
      type: "button", "data-focus": "top-breaks", onclick: showBreaks,
      title: "Records labelled agent below L2, against the labelling rule. Show them.",
    }, icon("alert"), `${broken} agent below L2`) : null,
    el("div.spacer"),
    Review.topbarItems.map((f) => f()),
    el("button.btn.ghost.small", { type: "button", onclick: openSession, "data-focus": "top-session", title: "Session: labels, agreement with suggestions, precision estimate (P)", "aria-keyshortcuts": "p" },
      "Session", el("kbd", "P")),
    el("div.meta", { title: state.data.file }, `${state.data.labeller} · rules ${state.data.rules_version}`),
    el("div.toolbar.tools",
      settings(),
      el("button.btn.ghost.small.icon-only", { type: "button", onclick: help, title: "Keyboard shortcuts (?)", "aria-label": "Keyboard shortcuts", "aria-keyshortcuts": "?" }, el("kbd", { "aria-hidden": "true" }, "?"))));
}

function setSort(id) {
  state.sort = id;
  prefs.set("review.sort", JSON.stringify(id));
  render();
}

function setFilter(name, value) {
  state.filters[name] = value;
  prefs.set("review.filters", JSON.stringify(state.filters));
  state.sel = null;
  render();
}

function clearFilters() {
  state.filters = { ...NO_FILTER };
  prefs.set("review.filters", null);
  state.sel = null;
  render();
}

function showBreaks() {
  state.filters = { ...NO_FILTER, check: "breaks" };
  state.filtersOpen = true;
  state.tab = "all";
  state.sel = null;
  prefs.set("review.filters", JSON.stringify(state.filters));
  render();
}

function select(id, label, value, options, onchange, cls = "") {
  return el("label.tri-field" + cls, { for: id },
    el("span.tri-name", label),
    el("select.input.small#" + id, { onchange: (e) => onchange(e.target.value), "data-focus": id },
      options.map(([v, name]) => el("option", { value: v, selected: v === value }, name))));
}

// Sort, and the filters behind a toggle, both remembered per browser.
function triage() {
  const n = activeFilters();
  const sources = [...new Set(allItems().map((i) => i.source))].sort();
  const tiers = [...new Set(state.data.groups.map(tierOf))];
  const f = state.filters;
  const any = [["", "Any"]];
  const toggle = el("button.btn.ghost.small.tri-toggle" + (n ? ".on" : ""), {
    type: "button", "aria-expanded": String(state.filtersOpen), "aria-controls": "filters", "data-focus": "tri-toggle",
    "aria-keyshortcuts": "f", title: "Filter the queue by grade, tier, source, suggestion or check (F)",
    onclick: () => { state.filtersOpen = !state.filtersOpen; prefs.set("review.filtersOpen", JSON.stringify(state.filtersOpen)); renderRail(); },
  }, "Filters", n ? el("span.tri-n", { "aria-label": `${n} active` }, String(n)) : null, el("kbd", { "aria-hidden": "true" }, "F"));
  const head = el("div.tri-row",
    select("sort", "Sort", state.sort, SORTS.map((x) => [x.id, x.name]), setSort, ".tri-sort"),
    toggle);
  if (!state.filtersOpen) return el("div.triage", head);
  const panel = el("div.tri-panel#filters", { role: "group", "aria-label": "Queue filters" },
    select("f-grade", "Grade", f.grade, any.concat(GRADES), (v) => setFilter("grade", v)),
    select("f-tier", "Tier", f.tier, any.concat(tiers.map((t) => [t, t])), (v) => setFilter("tier", v)),
    select("f-source", "Source", f.source, any.concat(sources.map((s) => [s, s])), (v) => setFilter("source", v)),
    select("f-sug", "Suggestion", f.sug, any.concat(VERDICTS.map((v) => [v.label, v.label]), [["none", "None"]]), (v) => setFilter("sug", v), ".suggestion-ui"),
    select("f-check", "Check", f.check, any.concat(CHECKS), (v) => setFilter("check", v), ".wide"),
    el("div.tri-actions", el("button.btn.ghost.small", { type: "button", onclick: clearFilters, disabled: !n, "data-focus": "tri-clear" }, "Clear filters")));
  return el("div.triage", head, panel);
}

function rail() {
  const vis = visible();
  const tabs = el("div.tabs", { role: "group", "aria-label": "Queue filter" }, TABS.map((t, n) => el("button" + (t.id === state.tab ? ".on" : ""),
    { type: "button", "aria-pressed": String(t.id === state.tab), title: `${t.name} (${n + 1})`, "data-focus": "tab-" + t.id, onclick: () => { state.tab = t.id; state.sel = null; render(); } },
    t.name, el("span.n", state.data.groups.filter((g) => t.test(g) && matches(g, state.query) && passes(g)).length))));
  const search = el("input.input#search", {
    type: "search", placeholder: "Filter by rule, host, id…", value: state.query, "aria-label": "Filter the queue",
    "aria-keyshortcuts": "/", autocomplete: "off", spellcheck: "false",
    oninput: (e) => { state.query = e.target.value; renderRail(); },
  });
  const list = el("div.queue", { role: "list" }, vis.map((g) => el("div.qitem", { role: "listitem" }, row(g))));
  if (!vis.length) {
    list.append(state.query || activeFilters()
      ? el("div.rail-empty", el("p", "No groups match " + (state.query && activeFilters() ? "the search and filters." : state.query ? "this search." : "these filters.")),
        el("button.btn.small", { type: "button", onclick: () => { state.query = ""; clearFilters(); } }, "Show every group"))
      : el("div.rail-empty", el("p", state.tab === "todo" ? "Nothing left to label here." : "Nothing here.")));
  }
  const note = activeFilters() || state.sort !== "queue"
    ? el("p.tri-status", { "aria-live": "polite" }, `${plural(vis.length, "group")}`, state.sort !== "queue" ? ` · ${SORTS.find((x) => x.id === state.sort).name.toLowerCase()}` : "")
    : null;
  return el("aside.rail#rail", { "aria-label": "Review queue" },
    el("div.rail-head", tabs, el("div.search", icon("search"), search, el("kbd.search-key", { "aria-hidden": "true" }, "/")), triage(), note), list);
}

// The group's labels as a thin stacked bar: a glance at how far it got.
function miniBar(g) {
  const n = g.items.length;
  const c = count(g.items, (i) => i.label);
  const bar = el("span.qbar", { "aria-hidden": "true" });
  for (const v of VERDICTS) {
    if (!c[v.label]) continue;
    const s = el("span." + v.label);
    s.style.width = `${(100 * c[v.label]) / n}%`;
    bar.append(s);
  }
  return bar;
}

function row(g) {
  const v = verdictOf(g);
  const done = g.items.filter((i) => i.label).length;
  const tier = g.cluster ? g.cluster.tier : g.items[0].tier;
  const s = suggestionOf(g);
  const on = g.key === state.sel;
  const status = v === "mixed" ? el("span.chip.mixed", `${done}/${g.items.length}`)
    : v ? el("span.chip." + v, v)
      : g.items.length > 1 ? el("span.qcount", `0/${g.items.length}`) : null;
  const conflict = conflicts(g).length;
  const broken = breaks(g).length;
  return el("button.qrow.t-" + tier + (on ? ".on" : "") + (v && v !== "mixed" ? ".labelled" : ""), {
    type: "button", "aria-current": on ? "true" : null,
    onclick: () => { state.sel = g.key; render(); }, dataset: { key: g.key },
  },
    el("span.dot." + tier, { title: tier }),
    el("span.qmain",
      el("span.qtitle", g.title),
      el("span.qsub",
        el("span.sr-only", tier + ", "),
        plural(g.items.length, "record"),
        g.grade ? ` · ${g.grade.code}` : "",
        s ? el("span.suggestion-ui", " · ", el("span." + s.label, `suggests ${s.label}`)) : ""),
      broken || conflict ? el("span.qflags",
        broken ? el("span.flag.break", { title: "Labelled agent below L2, against the labelling rule" }, icon("alert"), `${broken} agent below L2`) : null,
        conflict ? el("span.flag.conflict.suggestion-ui", { title: "The suggestion says agent below L2: do not accept it" }, icon("alert"), `${conflict} agent ${conflict === 1 ? "suggestion" : "suggestions"} below L2`) : null) : null,
      g.items.length > 1 && done ? miniBar(g) : null),
    status);
}

function detail() {
  const g = current();
  if (!g) {
    const left = allItems().filter((i) => !i.label).length;
    return el("main.detail#detail", left
      ? emptyState({ title: "Pick a group", body: ["Use j and k, or click a group in the queue."], icon: "inbox" })
      : emptyState({
        title: "All caught up", kind: "done", icon: "check",
        body: ["Every record in this queue is labelled. Measure the rules against your labels:"],
        extra: el("pre.mono", `swarmchase eval ${state.data.file}`),
      }));
  }
  const v = verdictOf(g);
  const s = suggestionOf(g);
  const tier = g.cluster ? g.cluster.tier : g.items[0].tier;
  const head = el("div.dhead",
    el("div.dtitle", el("span.tier." + tier, el("span.dot." + tier), tier), el("h1", g.title)),
    el("div.dmeta", headMeta(g)));
  const done = g.items.filter((i) => i.label).length;
  const left = g.items.length - done;
  const gated = !g.agent_allowed;
  const acceptable = g.items.filter((i) => i.suggested && !i.label && !i.conflict).length;
  const bar = el("div.verdicts", { role: "toolbar", "aria-label": "Label this group" },
    el("div.vbtns",
      VERDICTS.map((x) => {
        const gate = x.label === "agent" && gated;
        return el("button.btn.verdict." + x.label + (v === x.label ? ".on" : "") + (gate ? ".gated" : ""), {
          type: "button", "aria-pressed": String(v === x.label), "aria-keyshortcuts": x.key, "data-focus": "verdict-" + x.label,
          title: gate ? `Agent needs L2 or higher; this group is ${gradeCode(g)}. Asks again before labelling (${x.key})` : `Label every record in the group ${x.label} (${x.key})`,
          "aria-describedby": gate ? "gate-note" : null,
          onclick: () => labelGroup(x.label),
        }, x.name, gate ? el("span.gate", { "aria-hidden": "true" }, "< L2") : null, el("kbd", x.key.toUpperCase()));
      })),
    el("div.vmore",
      s ? el("button.btn.suggestion-ui", {
        type: "button", onclick: acceptSuggestions, "aria-keyshortcuts": "s", "data-focus": "accept", disabled: !acceptable,
        title: conflicts(g).length ? "Accepts this group's suggestions, except any that say agent below L2 (S)" : "Accept this group's suggestions (S)",
      }, "Accept suggestion", el("kbd", "S")) : null,
      el("button.btn.ghost", { type: "button", onclick: () => labelGroup("clear"), disabled: !g.items.some((i) => i.label), "aria-keyshortcuts": "x", "data-focus": "clear" }, "Clear", el("kbd", "X"))),
    el("input.input.note#note", { placeholder: "Note for this group (N)", value: commonNote(g), "aria-label": "Note for this group, saved with the next label", "aria-keyshortcuts": "n" }),
    el("span.vstate" + (v ? "." + v : ""),
      v === "mixed" ? `Mixed · ${done} of ${g.items.length}` : v ? `Labelled ${v}` : "Unlabelled"),
    gated ? el("span.sr-only#gate-note", `Agent needs L2 or higher; this group is ${gradeCode(g)}.`) : null,
    done && left ? el("div.vrest", { role: "group", "aria-label": "Label the rest of the group" },
      el("span.vrest-n", `${plural(left, "record")} left:`),
      VERDICTS.map((x) => el("button.btn.small.rest." + x.label, {
        type: "button", "aria-keyshortcuts": "Shift+" + x.key.toUpperCase(), "data-focus": "rest-" + x.label,
        title: `Label only the unlabelled records ${x.label} (Shift+${x.key.toUpperCase()})`, onclick: () => labelGroup(x.label, { rest: true }),
      }, x.name, el("kbd", "\u21e7" + x.key.toUpperCase())))) : null);

  const cards = el("div.summary");
  if (s) cards.append(suggestionCard(s));
  if (g.grade) cards.append(gradeCard(g));
  cards.append(evidenceCard(g));

  const n = g.items.length;
  const limit = state.showAll.has(g.key) ? n : Math.min(n, 3);
  const recs = el("section.records", { "aria-label": "Records" },
    el("div.records-head", el("h2.section-title", plural(n, "record"), limit < n ? el("span.muted", ` · showing ${limit}`) : null),
      n > 3 ? el("button.btn.ghost.small", { type: "button", onclick: () => toggleAll(g), "aria-keyshortcuts": "e" },
        state.showAll.has(g.key) ? "Show fewer" : `Show all ${n}`, el("kbd", "E")) : null),
    g.items.slice(0, limit).map(record));
  const extra = Review.panels.map((f) => f(g));
  return el("main.detail#detail", { "aria-label": "Selected group" }, head, bar, ruleNotes(g), cards, extra, recs);
}

// The labelling rule, said plainly where the decision is made.
function ruleNotes(g) {
  const broken = breaks(g);
  const conflict = conflicts(g);
  if (!broken.length && !conflict.length) return null;
  return el("div.rule-notes",
    broken.length ? el("div.callout.danger.rule-note", { role: "note" },
      icon("alert"),
      el("p", el("b", `${plural(broken.length, "record")} labelled agent at ${gradeCode(g)}.`),
        " Agent needs an agent grade of L2 or higher; below it, unsure is the most the evidence allows."),
      el("button.btn.small", { type: "button", onclick: () => fixBreaks(g), "data-focus": "fix-breaks" }, `Relabel ${broken.length === 1 ? "it" : "them"} unsure`)) : null,
    conflict.length ? el("div.callout.warn.rule-note.suggestion-ui", { role: "note" },
      icon("alert"),
      el("p", el("b", `The suggestion says agent for ${plural(conflict.length, "record")}, but the grade is ${gradeCode(g)}.`),
        " It breaks the labelling rule, so it is not one to accept; Accept suggestion leaves those records for you.")) : null);
}

function headMeta(g) {
  const c = g.cluster;
  const bits = [];
  if (c) {
    bits.push(`${c.id} · ${plural(c.size, "member")}`);
    bits.push(c.start === c.end ? c.start : `${c.start} → ${c.end}`);
    if (c.targets.length) bits.push(`targets ${c.targets.join(", ")}`);
  } else {
    const t = [...new Set(g.items.map((i) => i.target).filter(Boolean))];
    bits.push("unclustered, grouped by shape");
    if (t.length) bits.push(`targets ${t.slice(0, 4).join(", ")}`);
  }
  const src = Object.entries(count(g.items, (i) => i.source)).map(([k, n]) => `${k} ${n}`).join(", ");
  bits.push(src);
  return bits.map((b) => el("span", b));
}

function commonNote(g) {
  const notes = [...new Set(g.items.map((i) => i.note || ""))];
  return notes.length === 1 ? notes[0] : "";
}

function suggestionCard(s) {
  return el("section.card.scard.suggestion-ui",
    el("h3.section-title", "Suggestion"),
    el("p.big", el("span.chip." + s.label, s.label), ` for ${s.n} of ${plural(s.of, "record")}`,
      s.with < s.of ? el("span.muted", ` (${s.of - s.with} without)`) : null),
    el("ul.reasons", s.reasons.map(([r, n]) => el("li", r, n > 1 ? el("span.muted", ` ×${n}`) : null))),
    el("p.muted.small", `${s.model} · a suggestion, never the label`));
}

function gradeCard(group) {
  const g = group.grade;
  const basis = group.grade_basis === "records"
    ? (group.items.length > 1 ? "lowest of its records, each graded alone" : "this record alone")
    : null;
  return el("section.card.gcard",
    el("h3.section-title", "Agent grade"),
    basis ? el("p.muted.small", `Unclustered: ${basis}. One record shows no pace or retries, so it stops at L2.`) : null,
    el("p.big", el("span.grade", g.code), " ", g.label),
    g.signals.length ? el("ul.signals", g.signals.map((x) => el("li", el("span.plus", { "aria-label": "for" }, "+"), x.label, el("span.muted", ` · ${plural(x.records, "record")}`)))) : el("p.muted.small", "No agent signals beyond the payloads."),
    g.counter.length ? el("ul.signals", g.counter.map((x) => el("li", el("span.minus", { "aria-label": "against" }, "−"), x.label, el("span.muted", ` · ${plural(x.records, "record")}`)))) : null,
    g.caps.map((cap) => el("p.cap.small", cap)));
}

function evidenceCard(g) {
  const rules = {};
  for (const i of g.items) for (const h of i.hits) {
    const r = (rules[h.rule] ||= { kind: h.kind, weight: h.weight, n: 0 });
    r.n++;
  }
  const sorted = Object.entries(rules).sort((a, b) => b[1].weight - a[1].weight || b[1].n - a[1].n);
  return el("section.card.ecard",
    el("h3.section-title", "Evidence"),
    sorted.length ? el("div.rules", sorted.map(([id, r]) => el("span.rule.k-" + r.kind, { title: KINDS[r.kind] || r.kind },
      el("span.kdot"), id, el("span.w", `+${r.weight}`), r.n > 1 ? el("span.muted", `×${r.n}`) : null)))
      : el("p.muted.small", "No rule fired (unflagged sample)."));
}

function record(i) {
  const verdict = el("div.seg", { role: "group", "aria-label": "Label this record" }, VERDICTS.map((v) => {
    const on = i.label === v.label;
    const gate = v.label === "agent" && !on && !i.agent_allowed;
    return el("button" + (on ? ".on." + v.label : "") + (gate ? ".gated" : ""), {
      type: "button", "aria-pressed": String(on), "data-focus": `rec-${i.id}-${v.label}`,
      onclick: () => labelOne(i.id, on ? "clear" : v.label),
      title: on ? "Clear this record's label" : gate ? "Agent needs L2 or higher; asks again before labelling" : `Label this record ${v.label}`,
      "aria-label": `${v.name}, record ${i.id}`,
    }, v.name);
  }));
  const marks = i.hits.map((h) => h.matched);
  const body = el("div.rbody",
    field("URL", el("pre.mono.url", UI.highlight(i.url, marks))),
    i.layers.map((l, n) => field(i.layers.length > 1 ? `Layer ${n + 1} · ${l.via}` : `Decoded · ${l.via}`, el("pre.mono.clamp.layer", UI.highlight(l.text, marks)))),
    i.hits.length ? field("Rules", el("table.hits", el("tbody", i.hits.map((h) => el("tr",
      el("td.r", el("span.rule.k-" + h.kind, { title: KINDS[h.kind] || h.kind }, el("span.kdot"), h.rule)),
      el("td.w", `+${h.weight}`),
      el("td.m", el("code", h.matched))))))) : null,
    i.target ? field("Target", el("code", i.target)) : null,
    i.final ? field("Final URL", el("code", i.final)) : null,
    i.reference ? field("Record", el("span.ref", el("code", i.reference), el("button.btn.ghost.small", { type: "button", onclick: () => copy(i.reference), title: "Copy (defanged)", "aria-label": "Copy the record reference (defanged)" }, icon("copy"), "Copy"))) : null,
    i.note ? field("Note", el("span", i.note)) : null,
    i.suggested ? el("div.suggestion-ui", field("Suggests", el("span", el("span.chip." + i.suggested.label, i.suggested.label), " ", i.suggested.reason))) : null,
    Review.recordExtras.map((f) => f(i)));
  return el("article.card.rec" + (differs(i) ? ".disagree" : "") + (i.label ? ".is-" + i.label : ""),
    el("div.rhead",
      el("span.tier." + i.tier, el("span.dot." + i.tier), i.tier),
      el("span.rmeta", `score ${i.score} · ${i.source} · ${i.time}`),
      el("span.rid", { title: i.id }, i.id),
      differs(i) ? el("span.chip.unsure.suggestion-ui", { title: `Suggestion was ${i.suggested.label}` }, "differs") : null,
      i.breaks_rule ? el("span.flag.break", { title: "Labelled agent below L2, against the labelling rule" }, icon("alert"), "agent below L2") : null,
      i.conflict && !i.label ? el("span.flag.conflict.suggestion-ui", { title: "The suggestion says agent below L2: do not accept it" }, icon("alert"), "suggestion breaks L2 rule") : null,
      el("div.spacer"),
      verdict),
    body);
}

function field(name, value) {
  return el("div.field", el("div.fname", name), el("div.fval", value));
}

function toggleAll(g) {
  state.showAll.has(g.key) ? state.showAll.delete(g.key) : state.showAll.add(g.key);
  render();
}

function renderRail() {
  const old = document.getElementById("rail");
  const focused = document.activeElement && document.activeElement.id === "search";
  const pos = focused ? document.activeElement.selectionStart : 0;
  const fk = focused ? null : focusKey();
  const fresh = rail();
  old.replaceWith(fresh);
  if (focused) { const s = document.getElementById("search"); s.focus(); s.setSelectionRange(pos, pos); }
  fresh.querySelector(".qrow.on")?.scrollIntoView({ block: "nearest" });
  restoreFocus(fk);
}

// What had focus, so a render (which rebuilds the page) can put it back:
// the same control by id or `data-focus`, or the selected queue row.
function focusKey() {
  const a = document.activeElement;
  if (!a || a === document.body || !document.getElementById("app").contains(a)) return null;
  if (a.classList.contains("qrow")) return { row: true };
  if (a.dataset.focus) return { sel: `[data-focus="${CSS.escape(a.dataset.focus)}"]` };
  if (a.id) return { sel: "#" + CSS.escape(a.id) };
  return null;
}
function restoreFocus(k) {
  if (!k || (document.activeElement && document.activeElement !== document.body)) return;
  const t = k.row ? document.querySelector(".qrow.on") : document.querySelector(k.sel);
  if (t && !t.disabled) t.focus({ preventScroll: true });
  else document.querySelector(".qrow.on")?.focus({ preventScroll: true });
}

function render() {
  const fk = focusKey();
  const vis = visible();
  if (state.sel && !vis.some((g) => g.key === state.sel) && state.tab === "todo") state.sel = null;
  if (!state.sel && vis.length && state.tab) state.sel = vis[0].key;
  const app = document.getElementById("app");
  const scroll = document.getElementById("detail")?.scrollTop;
  const prevSel = app.dataset.sel;
  // Remember the progress widths so the new bar can grow from them.
  const widths = {};
  for (const s of app.querySelectorAll(".topbar .progress-track > span")) widths[s.className] = s.style.width;
  app.replaceChildren(topbar(), el("div.layout", rail(), detail()));
  app.dataset.sel = state.sel || "";
  for (const s of app.querySelectorAll(".topbar .progress-track > span")) {
    const to = s.style.width;
    s.style.width = widths[s.className] || "0%";
    void s.offsetWidth;
    s.style.width = to;
  }
  const changed = prevSel !== undefined && prevSel !== app.dataset.sel;
  if (prevSel !== app.dataset.sel) for (const f of Review.onSelect) f(current());
  const d = document.getElementById("detail");
  if (d && changed) d.classList.add("enter");
  if (d && prevSel === app.dataset.sel && scroll) d.scrollTop = scroll;
  document.querySelector(".qrow.on")?.scrollIntoView({ block: "nearest" });
  restoreFocus(fk);
}

// ---- session ----------------------------------------------------------------

/** Wilson score interval for k of n at 95%: [low, high], or null for n = 0. */
function wilson(k, n, z = 1.96) {
  if (!n) return null;
  const p = k / n, z2 = z * z, d = 1 + z2 / n;
  const c = (p + z2 / (2 * n)) / d;
  const h = (z * Math.sqrt((p * (1 - p)) / n + z2 / (4 * n * n))) / d;
  return [Math.max(0, c - h), Math.min(1, c + h)];
}

/** Decided labels needed for a Wilson half-width of `half` at share `p`. */
function needed(p, half) {
  for (let n = 1; n <= 5000; n++) {
    const w = wilson(Math.round(p * n), n);
    if ((w[1] - w[0]) / 2 <= half) return n;
  }
  return 5000;
}

const pctOf = (x) => `${Math.round(100 * x)}%`;

function sessionBody() {
  const items = allItems();
  const mine = items.filter((i) => i.label && state.touched.has(i.id));
  const c = count(mine, (i) => i.label);
  const done = items.filter((i) => i.label).length;
  const left = items.length - done;
  const mins = state.firstLabel ? (Date.now() - state.firstLabel) / 60000 : 0;
  const rate = mins >= 1 ? mine.length / mins : null;
  const session = el("section.ss-sec",
    el("h3.section-title", "This session"),
    el("p.ss-big", el("b", mine.length), ` ${mine.length === 1 ? "record" : "records"} labelled`,
      rate ? el("span.muted", ` · about ${rate < 10 ? rate.toFixed(1) : Math.round(rate)} a minute`) : null),
    mine.length ? el("div.ss-chips", VERDICTS.map((v) => el("span.chip." + v.label, el("b", c[v.label] || 0), " " + v.label))) : null,
    el("p.muted.small", `${done} of ${items.length} in this queue labelled, ${left} left` +
      (rate && left ? `; at this pace about ${Math.max(1, Math.round(left / rate))} more minutes.` : ".")));

  const st = state.data.stored || { total: 0, by_label: {}, flagged: {} };
  const file = el("section.ss-sec",
    el("h3.section-title", "Review file"),
    el("p", el("b", st.total), ` ${st.total === 1 ? "review" : "reviews"} in `, el("code", state.data.file), " (this queue and earlier ones)."),
    el("div.ss-chips", VERDICTS.map((v) => el("span.chip." + v.label, el("b", st.by_label[v.label] || 0), " " + v.label))));

  // Agreement: the admin's label against the suggestion, where both exist.
  const both = items.filter((i) => i.label && i.suggested);
  const agree = both.filter((i) => i.label === i.suggested.label).length;
  const cell = (l, s) => both.filter((i) => i.label === l && i.suggested.label === s).length;
  const table = el("table.ss-table",
    el("caption.sr-only", "Your labels by row, suggestions by column"),
    el("thead", el("tr", el("th", { scope: "col" }, el("span.muted", "You \u2193 · suggestion \u2192")), VERDICTS.map((v) => el("th", { scope: "col" }, v.label)))),
    el("tbody", VERDICTS.map((l) => el("tr", el("th", { scope: "row" }, el("span.chip." + l.label, l.label)),
      VERDICTS.map((sv) => {
        const n = cell(l.label, sv.label);
        return el("td" + (!n ? "" : l.label === sv.label ? ".diag" : ".off"), n || el("span.muted", "0"));
      })))));
  const pending = items.filter((i) => !i.label && i.suggested).length;
  const agreement = el("section.ss-sec",
    el("h3.section-title", "Agreement with suggestions"),
    both.length
      ? [el("p", el("b", pctOf(agree / both.length)), ` agree: ${agree} of ${plural(both.length, "labelled record")} with a suggestion.`), table]
      : el("p.muted.small", "No labelled record in this queue has a suggestion yet."),
    pending ? el("p.muted.small", `${plural(pending, "suggested record")} not labelled yet.`) : null);

  // Rule checks.
  const broken = items.filter((i) => i.breaks_rule).length;
  const conflictsLeft = items.filter((i) => i.conflict && !i.label).length;
  const checks = el("section.ss-sec",
    el("h3.section-title", "Labelling rule"),
    el("p", broken ? el("span.ss-bad", `${plural(broken, "record")} labelled agent below L2. `) : "No agent label below L2. ",
      broken ? el("button.btn.small", { type: "button", onclick: () => { UI.closeDialog(); showBreaks(); } }, "Show them") : null),
    conflictsLeft ? el("p.muted.small", `${plural(conflictsLeft, "unlabelled record")} with a suggestion of agent below L2, never accepted by the page.`) : null);

  // Precision of the flagged queue: agent share of decided flagged labels.
  const f = st.flagged || {};
  const k = f.agent || 0, n = k + (f.benign || 0);
  const w = wilson(k, n);
  const half = w ? (w[1] - w[0]) / 2 : 0.5;
  const need = needed(n ? k / n : 0.5, 0.1);
  const cmd = `swarmchase eval ${state.data.file}`;
  const precision = el("section.ss-sec",
    el("h3.section-title", "Precision estimate"),
    n ? el("p", "Agent share of decided flagged records: ", el("b", pctOf(k / n)),
      ` (${k} of ${n}; 95% interval ${pctOf(w[0])} to ${pctOf(w[1])}, \u00b1${Math.round(100 * half)} points).`)
      : el("p", "No flagged record has an agent or benign label yet."),
    el("div.ss-meter", { role: "img", "aria-label": `${n} of about ${need} decided labels for plus or minus 10 points` },
      el("span.ss-fill", { dataset: { w: String(Math.min(1, n / need)) } })),
    el("p.muted.small", half <= 0.1
      ? "Within \u00b110 points: enough for a first estimate. Unsure labels are left out; the eval command measures the rules against every label."
      : `About ${Math.max(0, need - n)} more agent or benign labels on flagged records for \u00b110 points. Unsure labels are left out.`),
    el("div.ss-cmd", el("pre.mono", cmd), el("button.btn.ghost.small", { type: "button", onclick: () => copy(cmd), title: "Copy the command" }, icon("copy"), "Copy")));
  return el("div.ss-grid", session, precision, agreement, checks, file);
}

function openSession() {
  const card = UI.dialog({ id: "session", title: "Session", body: sessionBody(), wide: true });
  // CSSOM, not a style attribute: the content security policy allows only this.
  for (const s of card ? card.querySelectorAll(".ss-fill") : []) s.style.width = `${100 * Number(s.dataset.w)}%`;
}

keys([
  { keys: ["j", "ArrowDown"], label: "next group", run: () => move(1) },
  { keys: ["k", "ArrowUp"], label: "previous group", run: () => move(-1) },
  { keys: ["a"], label: "label the group agent", run: () => labelGroup("agent") },
  { keys: ["b"], label: "label the group benign", run: () => labelGroup("benign") },
  { keys: ["u"], label: "label the group unsure", run: () => labelGroup("unsure") },
  { keys: ["s"], label: "accept the group's suggestions", run: acceptSuggestions },
  { keys: ["A"], label: "label the rest of the group agent", run: () => labelGroup("agent", { rest: true }) },
  { keys: ["B"], label: "label the rest of the group benign", run: () => labelGroup("benign", { rest: true }) },
  { keys: ["U"], label: "label the rest of the group unsure", run: () => labelGroup("unsure", { rest: true }) },
  { keys: ["x"], label: "clear the group's labels", run: () => labelGroup("clear") },
  { keys: ["z"], label: "undo", run: undo },
  { keys: ["e"], label: "show every record in the group", run: () => { const g = current(); if (g) toggleAll(g); } },
  { keys: ["n"], label: "write a note, then label", run: () => document.getElementById("note")?.focus() },
  { keys: ["/"], label: "search the queue", run: () => document.getElementById("search")?.focus() },
  { keys: ["f"], label: "filter the queue by grade, tier, source, suggestion", run: () => {
    if (!state.filtersOpen) { state.filtersOpen = true; prefs.set("review.filtersOpen", "true"); renderRail(); }
    document.getElementById("f-grade")?.focus();
  } },
  { keys: ["o"], label: "next sort order", run: () => {
    const n = SORTS.findIndex((x) => x.id === state.sort);
    setSort(SORTS[(n + 1) % SORTS.length].id);
    toast("Sorted: " + SORTS.find((x) => x.id === state.sort).name.toLowerCase());
  } },
  { keys: ["p"], label: "session: labels, agreement, precision", run: openSession },
  { keys: ["1", "2", "3", "4"], label: "switch tab: to do, disagree, done, all", run: (e) => { state.tab = TABS[Number(e.key) - 1].id; state.sel = null; render(); } },
]);

document.addEventListener("keydown", (e) => {
  // Enter in the note field labels nothing; it just leaves the field.
  if (e.key === "Enter" && e.target.id === "note") e.target.blur();
});

// The page's extension points. Each registry entry is called on every
// render and returns a node or null; `onSelect` runs when the selected group
// changes, for loading context lazily.
const Review = {
  state, render, current, verdictOf, suggestionOf, differs, field, count, VERDICTS, conflicts, breaks,
  /** fn(group) -> Node: a section in the detail pane, after the summary cards. */
  panels: [],
  /** fn(item) -> Node: extra fields at the end of a record's body. */
  recordExtras: [],
  /** fn() -> Node: controls in the top bar, before the meta line. */
  topbarItems: [],
  /** fn(group | null): the selected group changed. */
  onSelect: [],
  /** fn(data): the queue loaded, before the first render. */
  onLoad: [],
  boot() {
    api.get("queue")
      .then((d) => {
        state.data = d;
        state.index = new Map(d.groups.map((g, n) => [g.key, n]));
        for (const f of Review.onLoad) f(d);
        render();
      })
      .catch((e) => {
        document.getElementById("app").replaceChildren(emptyState({
          title: "Could not load the queue", kind: "error", icon: "alert",
          body: [e.message, "Check that swarmchase review --serve is still running, then try again."],
          extra: el("button.btn.primary", { type: "button", onclick: () => location.reload() }, "Try again"),
        }));
      });
  },
};
