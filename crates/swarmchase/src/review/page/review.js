// Lead review: a queue of groups on the left, the selected group on the
// right. Labelling a group moves to the next one; `z` undoes.
//
// Extensions (guide.js, context.js, ...) load after this file and add to the
// `Review` registries below; boot.js starts the page last. Every element that
// shows a model suggestion carries the class `suggestion-ui`, so a blind
// review mode can hide them all.
"use strict";

const { el, api, toast, keys, help, progress, plural, copy, icon, emptyState, settings } = UI;
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
const KINDS = {
  exploit: "Exploit", exfil: "Exfil", agent_marker: "Marker", carrier: "Carrier", relay: "Relay",
  self_id: "Self-ID", cache_buster: "Cache buster", header: "Header", outcome: "Outcome",
  anti_bot: "Anti-bot", infra: "Infra",
};

const state = {
  data: null,
  tab: "todo",
  query: "",
  sel: null, // selected group key
  showAll: new Set(), // group keys with every record shown
  undo: [],
  touched: new Set(), // ids labelled in this session
};

function differs(i) { return i.label && i.suggested && i.label !== i.suggested.label; }
function count(list, f) {
  const c = {};
  for (const x of list) { const k = f(x); if (k) c[k] = (c[k] || 0) + 1; }
  return c;
}
function allItems() { return state.data.groups.flatMap((g) => g.items); }

function matches(g, q) {
  if (!q) return true;
  const hay = [g.title, ...g.items.flatMap((i) => [i.url, i.id, ...i.hits.map((h) => h.rule)])].join(" ").toLowerCase();
  return q.toLowerCase().split(/\s+/).every((w) => hay.includes(w));
}

function visible() {
  const tab = TABS.find((t) => t.id === state.tab);
  return state.data.groups.filter((g) => tab.test(g) && matches(g, state.query));
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
  for (const g of state.data.groups) g.items = g.items.map((i) => res.items[i.id] || i);
  if (record) state.undo.push(before);
  if (label !== "clear" && !restore) ids.forEach((id) => state.touched.add(id));
  return Object.keys(res.items).length;
}

async function labelGroup(label) {
  const g = current();
  if (!g) return;
  const note = document.getElementById("note")?.value.trim();
  const order = visible().map((x) => x.key);
  try {
    const n = await apply(g.items.map((i) => i.id), label, note);
    toast(label === "clear" ? `Cleared ${plural(n, "label")}` : `${plural(n, "record")} labelled ${label}`,
      { action: "Undo", onAction: undo, kind: label === "clear" ? undefined : label });
    advance(order, g.key);
  } catch (e) { toast("Not saved: " + e.message, { error: true }); }
}

async function labelOne(id, label) {
  try { await apply([id], label, null); render(); }
  catch (e) { toast("Not saved: " + e.message, { error: true }); }
}

async function acceptSuggestions() {
  const g = current();
  if (!g) return;
  const by = {};
  for (const i of g.items) if (i.suggested && !i.label) (by[i.suggested.label] ||= []).push(i.id);
  if (!Object.keys(by).length) { toast("No unlabelled record here has a suggestion"); return; }
  const order = visible().map((x) => x.key);
  const batch = [];
  try {
    for (const [l, ids] of Object.entries(by)) {
      await apply(ids, l, null);
      batch.push(...state.undo.pop());
    }
    state.undo.push(batch);
    toast(`Accepted ${plural(batch.length, "suggestion")}`, { action: "Undo", onAction: undo });
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
  state.sel = vis[Math.max(0, Math.min(vis.length - 1, i < 0 ? 0 : i + d))].key;
  render();
}

// ---- rendering ------------------------------------------------------------

function topbar() {
  const items = allItems();
  const c = count(items, (i) => i.label);
  const done = items.filter((i) => i.label).length;
  const session = items.filter((i) => i.label && state.touched.has(i.id)).length;
  const pct = items.length ? Math.round((100 * done) / items.length) : 0;
  return el("header.topbar",
    el("div.brand", el("span.brand-mark", "swarmchase"), el("span.brand-sub", "Lead review")),
    progress([{ cls: "agent", n: c.agent }, { cls: "benign", n: c.benign }, { cls: "unsure", n: c.unsure }],
      items.length, `${done} of ${items.length} labelled`),
    el("span.pct", { "aria-hidden": "true" }, `${pct}%`),
    el("div.tally", { "aria-label": "Labels so far" },
      VERDICTS.map((v) => el("span.chip." + v.label, el("b", c[v.label] || 0), " " + v.label)),
      session ? el("span.chip.outline", `${session} this session`) : null),
    el("div.spacer"),
    Review.topbarItems.map((f) => f()),
    el("div.meta", { title: state.data.file }, `${state.data.labeller} · rules ${state.data.rules_version}`),
    el("div.toolbar.tools",
      settings(),
      el("button.btn.ghost.small.icon-only", { type: "button", onclick: help, title: "Keyboard shortcuts (?)", "aria-label": "Keyboard shortcuts", "aria-keyshortcuts": "?" }, el("kbd", { "aria-hidden": "true" }, "?"))));
}

function rail() {
  const vis = visible();
  const tabs = el("div.tabs", { role: "group", "aria-label": "Queue filter" }, TABS.map((t, n) => el("button" + (t.id === state.tab ? ".on" : ""),
    { type: "button", "aria-pressed": String(t.id === state.tab), title: `${t.name} (${n + 1})`, onclick: () => { state.tab = t.id; state.sel = null; render(); } },
    t.name, el("span.n", state.data.groups.filter((g) => t.test(g) && matches(g, state.query)).length))));
  const search = el("input.input#search", {
    type: "search", placeholder: "Filter by rule, host, id…", value: state.query, "aria-label": "Filter the queue",
    "aria-keyshortcuts": "/", autocomplete: "off", spellcheck: "false",
    oninput: (e) => { state.query = e.target.value; renderRail(); },
  });
  const list = el("div.queue", { role: "list" }, vis.map((g) => el("div.qitem", { role: "listitem" }, row(g))));
  if (!vis.length) {
    list.append(state.query
      ? el("div.rail-empty", el("p", "No groups match this filter."),
        el("button.btn.small", { type: "button", onclick: () => { state.query = ""; render(); } }, "Clear filter"))
      : el("div.rail-empty", el("p", state.tab === "todo" ? "Nothing left to label here." : "Nothing here.")));
  }
  return el("aside.rail#rail", { "aria-label": "Review queue" },
    el("div.rail-head", tabs, el("div.search", icon("search"), search, el("kbd.search-key", { "aria-hidden": "true" }, "/"))), list);
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
  const bar = el("div.verdicts", { role: "toolbar", "aria-label": "Label this group" },
    el("div.vbtns",
      VERDICTS.map((x) => el("button.btn.verdict." + x.label + (v === x.label ? ".on" : ""),
        { type: "button", "aria-pressed": String(v === x.label), "aria-keyshortcuts": x.key, title: `Label every record in the group ${x.label} (${x.key})`, onclick: () => labelGroup(x.label) },
        x.name, el("kbd", x.key.toUpperCase())))),
    el("div.vmore",
      s ? el("button.btn.suggestion-ui", { type: "button", onclick: acceptSuggestions, "aria-keyshortcuts": "s" }, "Accept suggestion", el("kbd", "S")) : null,
      el("button.btn.ghost", { type: "button", onclick: () => labelGroup("clear"), disabled: !g.items.some((i) => i.label), "aria-keyshortcuts": "x" }, "Clear", el("kbd", "X"))),
    el("input.input.note#note", { placeholder: "Note for this group (N)", value: commonNote(g), "aria-label": "Note for this group", "aria-keyshortcuts": "n" }),
    el("span.vstate" + (v ? "." + v : ""), { "aria-live": "polite" },
      v === "mixed" ? `Mixed · ${done} of ${g.items.length}` : v ? `Labelled ${v}` : "Unlabelled"));

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
  return el("main.detail#detail", { "aria-label": "Selected group" }, head, bar, cards, extra, recs);
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
    return el("button" + (on ? ".on." + v.label : ""), {
      type: "button", "aria-pressed": String(on),
      onclick: () => labelOne(i.id, on ? "clear" : v.label),
      title: on ? "Clear this record's label" : `Label this record ${v.label}`,
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
  const fresh = rail();
  old.replaceWith(fresh);
  if (focused) { const s = document.getElementById("search"); s.focus(); s.setSelectionRange(pos, pos); }
  fresh.querySelector(".qrow.on")?.scrollIntoView({ block: "nearest" });
}

function render() {
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
}

keys([
  { keys: ["j", "ArrowDown"], label: "next group", run: () => move(1) },
  { keys: ["k", "ArrowUp"], label: "previous group", run: () => move(-1) },
  { keys: ["a"], label: "label the group agent", run: () => labelGroup("agent") },
  { keys: ["b"], label: "label the group benign", run: () => labelGroup("benign") },
  { keys: ["u"], label: "label the group unsure", run: () => labelGroup("unsure") },
  { keys: ["s"], label: "accept the group's suggestions", run: acceptSuggestions },
  { keys: ["x"], label: "clear the group's labels", run: () => labelGroup("clear") },
  { keys: ["z"], label: "undo", run: undo },
  { keys: ["e"], label: "show every record in the group", run: () => { const g = current(); if (g) toggleAll(g); } },
  { keys: ["n"], label: "write a note, then label", run: () => document.getElementById("note")?.focus() },
  { keys: ["/"], label: "filter the queue", run: () => document.getElementById("search")?.focus() },
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
  state, render, current, verdictOf, suggestionOf, differs, field, count, VERDICTS,
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
      .then((d) => { state.data = d; for (const f of Review.onLoad) f(d); render(); })
      .catch((e) => {
        document.getElementById("app").replaceChildren(emptyState({
          title: "Could not load the queue", kind: "error", icon: "alert",
          body: [e.message, "Check that swarmchase review --serve is still running, then try again."],
          extra: el("button.btn.primary", { type: "button", onclick: () => location.reload() }, "Try again"),
        }));
      });
  },
};
