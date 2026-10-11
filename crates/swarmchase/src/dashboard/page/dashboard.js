// Monitoring dashboard: what is new since the admin last looked, whether
// monitoring is healthy, what waits on the admin, and the command for each
// next step. Read-only: everything comes from GET /api/overview, the same
// document `swarmchase dashboard --json` prints. Which run the admin last
// looked at is remembered in this browser only (UI.prefs).
"use strict";

const { el, api, toast, keys, plural, copy, icon, emptyState, settings, progress } = UI;
const SEEN = "dashboard.seen";
const REFRESH_MS = 120000;

const state = { data: null, since: UI.prefs.get(SEEN), loading: false, at: 0 };

// ---- formatting -------------------------------------------------------------

/** `20261011T060000Z` as `2026-10-11 06:00 UTC`. */
function stampText(s) {
  if (!s || s.length !== 16) return s || "";
  return `${s.slice(0, 4)}-${s.slice(4, 6)}-${s.slice(6, 8)} ${s.slice(9, 11)}:${s.slice(11, 13)} UTC`;
}

function ago(hours) {
  if (hours == null) return "";
  if (hours < 1) return "under an hour ago";
  if (hours < 48) return `${plural(hours, "hour")} ago`;
  return `${plural(Math.round(hours / 24), "day")} ago`;
}

/** Text with `code spans` as <code>, as nodes. */
function ticks(text) {
  return String(text || "").split("`").map((part, i) => (i % 2 ? el("code", part) : part));
}

function tierDot(t) { return el("span.dot." + t, { title: t, "aria-hidden": "true" }); }

function gradeChip(g) {
  if (!g) return null;
  return el("span.chip.grade.g-" + g.code.toLowerCase(), { title: `Agent grade: ${g.label}` }, el("b", g.code), " ", g.label);
}

const STATUS = {
  failing: { cls: "agent", icon: "alert", text: "failing" },
  skipped: { cls: "unsure", icon: "alert", text: "skipped" },
  quiet: { cls: "unsure", icon: "search", text: "quiet" },
  "catching-up": { cls: "outline", icon: "inbox", text: "catching up" },
  ok: { cls: "benign", icon: "check", text: "ok" },
  "never-run": { cls: "outline", icon: "inbox", text: "not run yet" },
};

function statusChip(s) {
  const m = STATUS[s] || { cls: "outline", icon: "inbox", text: s };
  return el("span.chip." + m.cls, icon(m.icon), m.text);
}

/** A copyable command line. */
function command(cmd, label) {
  if (!cmd) return null;
  return el("div.cmd",
    el("code.mono", cmd),
    el("button.btn.ghost.small.icon-only", {
      type: "button", title: "Copy command", "aria-label": `Copy command${label ? ": " + label : ""}`,
      onclick: () => copy(cmd),
    }, icon("copy")));
}

function section(id, title, sub, ...body) {
  return el("section.dsec#" + id, { "aria-labelledby": id + "-h" },
    el("div.dsec-head", el("h2#" + id + "-h", title), sub ? el("p.muted.small", sub) : null),
    ...body);
}

function none(text) { return el("p.none.muted", text); }

// ---- tiles --------------------------------------------------------------------

function tile(target, label, value, sub, cls = "") {
  return el("a.tile.card" + (cls ? "." + cls : ""), {
    href: "#" + target,
    onclick: (e) => { e.preventDefault(); jump(target); },
  }, el("span.tile-label", label), el("span.tile-value", value), el("span.tile-sub", sub));
}

function tiles(d) {
  const n = d.new;
  const h = d.health;
  const r = d.waiting.review;
  const cases = (d.waiting.cases || []).filter((c) => c.id);
  const fresh = n ? n.clusters.length + n.lone_total : 0;
  const counts = h.counts || {};
  const trouble = (counts.failing || 0) + (h.drift || []).length;
  const healthText = h.level === "ok" ? "Healthy" : h.level === "alert" ? "Needs attention" : "Watch";
  const healthSub = [
    counts.failing ? `${counts.failing} failing` : null,
    (h.drift || []).length ? plural(h.drift.length, "drifting rule") : null,
    counts.skipped ? `${counts.skipped} skipped` : null,
    counts.quiet ? `${counts.quiet} quiet` : null,
  ].filter(Boolean).join(" · ") || "every source ran";
  const needs = cases.reduce((a, c) => a + (c.needs || []).length, 0);
  return el("div.tiles",
    tile("new", "New since " + (d.since && d.since.stamp ? stampText(d.since.stamp) : "the first run"),
      n ? String(fresh) : "–",
      n ? `${plural(n.clusters.length, "cluster")} · ${n.lone_total} lone · ${plural(n.records, "record")} collected` : "no analysis yet",
      fresh ? "hot" : ""),
    tile("health", "Monitoring", healthText, healthSub, "lvl-" + h.level + (trouble ? ".hot" : "")),
    tile("waiting", "Review queue", r ? String(r.unreviewed) : "–",
      r ? `unreviewed in ${plural(r.groups, "group")}` : "no analysis yet"),
    tile("cases", "Open cases", String(cases.length), cases.length ? plural(needs, "open item") : "none open"));
}

// ---- next steps ---------------------------------------------------------------

const KIND = { health: "Health", drift: "Drift", watch: "Watch", new: "New", review: "Review", case: "Case", "case-proposal": "Proposal" };

function actions(d) {
  const list = d.actions || [];
  return section("next", "Next steps", "Most urgent first. Nothing here runs by itself; copy a command into a terminal.",
    list.length ? el("ol.actions", list.map((a) => el("li.action.k-" + a.kind,
      el("span.chip.kind", KIND[a.kind] || a.kind),
      el("div.action-main",
        el("div.action-title", a.title),
        a.detail ? el("div.action-detail.muted", ticks(a.detail)) : null,
        command(a.command, a.title)))))
      : el("div.calm", icon("check"), el("span", "Nothing waits on you. The next watch run will show up here.")));
}

// ---- new ------------------------------------------------------------------------

function sinceLine(d) {
  const s = d.since || {};
  const basis = {
    "previous-run": "the run before the latest (as the digest does)",
    requested: "the run you marked seen",
    "nearest-kept-run": "the nearest kept run before the one you marked seen",
    "before-kept-runs": "before every kept run, so everything kept counts as new",
    "first-run": "nothing: this is the first run",
  }[s.basis] || s.basis;
  return [s.stamp ? `Compared with ${stampText(s.stamp)}, ` : "Compared with ", basis, "."];
}

function newSection(d) {
  const n = d.new;
  if (!n) {
    return section("new", "New since you last looked", null,
      none("The latest run has no analysis.json; run the watch again."));
  }
  const seenNow = state.since && state.since === d.run.latest;
  const controls = el("div.row-actions",
    el("button.btn.small" + (seenNow ? "" : ".primary"), {
      type: "button", onclick: markSeen, disabled: seenNow ? true : null,
      title: "Count only what later runs collect as new (key s)",
    }, icon("check"), seenNow ? "Latest run marked seen" : "Mark latest run seen"),
    state.since ? el("button.btn.ghost.small", { type: "button", onclick: forget, title: "Compare with the run before the latest again" },
      "Show the latest run's changes") : null);
  const clusters = n.clusters.length
    ? el("div.table-wrap", el("table.dtable",
      el("thead", el("tr", ["Cluster", "Grade", "Change", "Records", "Span", "Targets", "Rules"].map((h) => el("th", { scope: "col" }, h)))),
      el("tbody", n.clusters.map(clusterRow))))
    : none(seenNow ? "No new or escalated cluster since you marked the latest run seen." : "No new or escalated cluster above noise.");
  const lone = n.lone.length
    ? el("div.table-wrap", el("table.dtable",
      el("thead", el("tr", ["Host", "Grade", "Score", "Rules", "Source", "Captured"].map((h) => el("th", { scope: "col" }, h)))),
      el("tbody", n.lone.map((r) => el("tr",
        el("td", el("span.host", tierDot(r.tier), el("code", r.host || "unknown"))),
        el("td", gradeChip(r.grade)),
        el("td.num", String(r.score)),
        el("td", el("span.rules", r.rules.map((x) => el("span.chip.outline.rule", x)))),
        el("td", r.source),
        el("td.nowrap.muted", r.time))))))
    : none("No new significant record outside a cluster.");
  const tierBits = Object.entries(n.clusters_by_tier || {}).map(([t, c]) => el("span.tier." + t, tierDot(t), `${c} ${t}`));
  const gradeBits = Object.entries(n.clusters_by_grade || {}).sort().reverse().map(([g, c]) => el("span.chip.outline", el("b", g), ` ${c}`));
  return section("new", "New since you last looked", sinceLine(d),
    controls,
    el("div.summary-line", el("span", plural(n.records, "record"), " collected"), tierBits, gradeBits),
    el("h3", `Clusters (${n.clusters.length})`),
    clusters,
    el("h3", `Significant records outside any cluster (${n.lone_total})`),
    lone,
    n.lone_total > n.lone.length ? el("p.muted.small", `${n.lone_total - n.lone.length} more; the digest and the review page list them all.`) : null,
    el("h3", `Endpoints newly hit (${n.endpoints_total})`),
    n.endpoints.length ? el("div.chips", n.endpoints.map((h) => el("code.chip.outline", h))) : none("None."));
}

function clusterRow(c) {
  const change = c.change === "escalated" ? `escalated from ${c.from_tier}` : "new";
  return el("tr",
    el("td",
      el("div.cl-id", tierDot(c.tier), el("b", c.id), " ", el("code.muted", c.cluster_key || c.key)),
      el("details.open-case", el("summary", "Open a case"), command(c.open_case, "open a case"))),
    el("td", gradeChip(c.grade)),
    el("td", el("span.chip" + (c.change === "escalated" ? ".unsure" : ".outline"), change)),
    el("td.num", String(c.records), c.new_records && c.new_records !== c.records ? el("span.muted.small", ` (${c.new_records} new)`) : null),
    el("td.nowrap.muted.small", c.start, el("br"), c.end),
    el("td", c.targets.map((t) => el("code.target", t))),
    el("td", el("span.rules", c.rules.map((x) => el("span.chip.outline.rule", x)))));
}

// ---- health ---------------------------------------------------------------------

/** Bars of the records pulled on each kept successful run, oldest first. */
function spark(pulled, name) {
  if (!pulled || !pulled.length) return el("span.muted.small", "no history");
  const max = Math.max(1, ...pulled);
  const box = el("span.spark", { role: "img", "aria-label": `${name}: records pulled on the last ${pulled.length} runs: ${pulled.join(", ")}` });
  pulled.forEach((n, i) => {
    const b = el("span.bar" + (i === pulled.length - 1 ? ".last" : "") + (n === 0 ? ".zero" : ""),
      { title: `${i === pulled.length - 1 ? "latest kept run" : `${pulled.length - 1 - i} run(s) earlier`}: ${n}` });
    b.style.height = `${Math.max(8, (100 * n) / max)}%`;
    box.append(b);
  });
  return el("span.spark-wrap", box, el("span.small.muted", String(pulled[pulled.length - 1])));
}

function healthSection(d) {
  const h = d.health;
  const ran = h.sources.filter((s) => s.status !== "never-run");
  const never = h.sources.filter((s) => s.status === "never-run");
  const rows = ran.map((s) => el("tr.s-" + s.status,
    el("th", { scope: "row" }, el("div", s.name), s.kind ? el("div.muted.small", s.kind) : null),
    el("td", statusChip(s.status)),
    el("td", spark(s.pulled, s.name)),
    el("td.num", String(s.new_latest)),
    el("td.nowrap.muted.small", s.last_run ? stampText(s.last_run) : "never"),
    el("td.small", detail(s))));
  const lvl = { ok: "All sources ran; no failures, collapses or rule drift.", warn: "Running, with something to check.", alert: "Something failed or drifted." }[h.level];
  return section("health", "Monitoring health", lvl,
    h.alerts.length ? el("div.callout" + (h.level === "alert" ? ".danger" : ".warn"),
      el("div.callout-title", "From the latest digest"),
      el("ul.alerts", h.alerts.map((a) => el("li", ticks(a))))) : null,
    h.submit_time_ran === false && !h.alerts.some((a) => a.includes("submit-time source")) ? el("p.small.lost", icon("alert"), " No submit-time source ran on the latest run: timing links, pace and agent grades above L2 are unavailable.") : null,
    el("h3", "Sources"),
    ran.length ? el("div.table-wrap", el("table.dtable.sources",
      el("thead", el("tr", ["Source", "Status", "Pulled, recent runs", "New", "Last run", "Detail"].map((x) => el("th", { scope: "col" }, x)))),
      el("tbody", rows))) : none("No source has run yet."),
    never.length ? el("details.never", el("summary", `${plural(never.length, "source")} in the watchlist not run yet`),
      el("p.small", never.map((s) => el("code.chip.outline", s.name)))) : null,
    !h.watchlist_read ? el("p.small.muted", "The watchlist was not read, so source kinds and lost capability are unknown; pass --watchlist.") : null,
    el("h3", `Rule drift (${h.drift.length})`),
    h.drift.length ? el("div.table-wrap", el("table.dtable",
      el("thead", el("tr", ["Rule", "Source", "This run", "Baseline"].map((x) => el("th", { scope: "col" }, x)))),
      el("tbody", h.drift.map((x) => el("tr",
        el("td", el("code", x.rule)), el("td", x.source),
        el("td.num", `${x.hits} of ${x.records} (${x.rate_pct}%)`),
        el("td.num.muted", `${x.baseline_hits} of ${x.baseline_records} (${x.baseline_rate_pct}%)`))))))
      : none(h.drift_rules_version ? `No rule fired well above its baseline (rules ${h.drift_rules_version}).` : "No drift baseline yet."));
}

function detail(s) {
  const bits = [];
  if (s.reason) bits.push(el("div", s.reason));
  if (s.status === "failing") bits.push(el("div.muted", `${plural(s.errors_in_row, "run")} in a row`));
  if (s.status === "quiet") bits.push(el("div.muted", `nothing pulled in ${s.empty_runs} runs${s.ever_pulled ? "" : ", and never has"}`));
  if (s.status === "skipped") bits.push(el("div.muted", `skipped ${plural(s.skipped_runs, "run")} in a row`));
  if (s.pending) bits.push(el("div.muted", "a long pull continues next run"));
  if (s.lost) bits.push(el("div.lost", "Lost: " + s.lost));
  return bits.length ? bits : el("span.muted", "–");
}

// ---- waiting --------------------------------------------------------------------

function reviewCard(r) {
  if (!r) return el("div.card.pad", none("No analysis to queue from yet."));
  if (r.error) return el("div.card.pad", el("p", "Review file not read: " + r.error));
  const lw = r.labelled_in_window || {};
  const done = (lw.agent || 0) + (lw.benign || 0) + (lw.unsure || 0);
  const total = r.flagged_in_window || 0;
  const lt = r.labelled_total || {};
  return el("div.card.pad.review",
    el("div.big", el("b", String(r.unreviewed)), " unreviewed ", el("span.muted", `in ${plural(r.groups, "group")}`)),
    el("div.chips", Object.entries(r.unreviewed_by_tier || {}).map(([t, n]) => el("span.tier." + t, tierDot(t), `${n} ${t}`)),
      r.with_suggestion ? el("span.chip.outline", `${r.with_suggestion} with a model suggestion`) : null),
    progress([{ cls: "agent", n: lw.agent }, { cls: "benign", n: lw.benign }, { cls: "unsure", n: lw.unsure }],
      total, `${done} of ${total} flagged records in the window labelled`),
    el("p.small.muted", `All time: ${lt.agent || 0} agent, ${lt.benign || 0} benign, ${lt.unsure || 0} unsure in the default review file; ${r.reviewed_any_labeller} records reviewed by any labeller.`),
    command(r.command, "review page"),
    el("details", el("summary.small", "Counts and agreement"), command(r.stats_command, "review stats")));
}

function caseCard(c) {
  if (c.error) return el("div.card.pad", el("p", "Cases not read: " + c.error));
  return el("article.card.pad.case",
    el("div.case-head",
      el("div", el("h3", c.title), el("code.muted.small", c.id)),
      el("div.chips", el("span.chip.outline", c.status), el("span.chip.outline", "notice " + c.notice),
        c.watch_hits ? el("span.chip" + (c.watch_hits_new ? ".agent" : ".outline"), `${c.watch_hits} watch hit${c.watch_hits === 1 ? "" : "s"}${c.watch_hits_new ? `, ${c.watch_hits_new} new` : ""}`) : null)),
    el("div.case-grid",
      el("div",
        el("div.section-title", "Clocks"),
        c.notice_not_before ? el("p.small", "Indicator notice not before ", el("b", c.notice_not_before)) : null,
        c.naming_ready ? el("p.small", el("b", plural(c.naming_ready, "operator")), " may be named now") : null,
        el("ul.clock", c.clock.map((l) => el("li.small", l)))),
      el("div",
        el("div.section-title", `Needs (${c.needs.length})`),
        c.needs.length ? el("ol.needs", c.needs.map((n) => el("li", el("div.small", n.text), command(n.command, n.text)))) : none("Nothing listed."))),
    command(c.status_command, "case status"));
}

function waitingSection(d) {
  const cases = d.waiting.cases || [];
  return el("div.dstack",
    section("waiting", "Waiting on you: review", "Leads at suggestive or above in the latest run's analysis that the default review file has no label for.",
      reviewCard(d.waiting.review)),
    section("cases", "Waiting on you: open cases", ticks("Each case's clocks and what `case status` says it still needs."),
      cases.length ? el("div.cases", cases.map(caseCard)) : none("No open case in this data directory.")));
}

// ---- runs and digest ----------------------------------------------------------

function runsSection(d) {
  const r = d.run;
  return section("runs", "Runs", null,
    el("div.runs",
      r.runs.map((s, i) => el("button.btn.small" + (s === (d.since && d.since.stamp) ? ".on" : "") + (i === 0 ? ".latest" : ""), {
        type: "button", title: `Show what is new since ${stampText(s)}`,
        onclick: () => setSince(s),
      }, stampText(s), i === 0 ? el("span.muted", " latest") : null))),
    el("p.small.muted", "Pick a run to count what later runs collected as new. Kept runs follow the watch's retention."),
    el("div.row-actions",
      el("button.btn.small", { type: "button", onclick: () => showDigest(r.latest) }, "Read the latest digest"),
      command(r.digest_command, "print the digest")));
}

async function showDigest(stamp) {
  let res;
  try { res = await api.get("digest/" + stamp); }
  catch (e) { toast("Digest not read: " + e.message, { error: true }); return; }
  const back = document.activeElement;
  const close = () => { o.remove(); if (back && back.isConnected) back.focus(); };
  const closeBtn = el("button.btn.ghost.small.icon-only", { type: "button", "aria-label": "Close", title: "Close (Esc)", onclick: close }, icon("close"));
  const card = el("div.card.digest", { role: "dialog", "aria-modal": "true", "aria-labelledby": "digest-title" },
    el("div.dialog-head", el("h2#digest-title", "Digest " + stampText(res.stamp)), closeBtn),
    el("pre.mono", res.text));
  const o = el("div.overlay", { onclick: (e) => { if (e.target === o) close(); } }, card);
  card.addEventListener("keydown", (e) => { if (e.key === "Escape") { e.stopPropagation(); close(); } });
  document.body.append(o);
  closeBtn.focus();
}

// ---- page -----------------------------------------------------------------------

function topbar(d) {
  const r = d.run;
  const meta = r ? `run ${stampText(r.latest)} · ${ago(r.age_hours)}${r.rules_version ? " · rules " + r.rules_version : ""}` : "no watch run yet";
  return el("header.topbar",
    el("div.brand", el("span.brand-mark", "swarmchase"), el("span.brand-sub", "Monitoring")),
    el("div.spacer"),
    el("div.meta" + (r && r.stale ? ".stale" : ""), { title: d.data_dir }, meta),
    el("div.toolbar",
      el("button.btn.ghost.small", { type: "button", onclick: () => load(true), title: "Reload from the data directory (r)" }, "Refresh"),
      el("button.btn.ghost.small.icon-only", { type: "button", onclick: UI.help, title: "Keyboard shortcuts (?)", "aria-label": "Keyboard shortcuts" }, icon("keyboard")),
      settings()));
}

// The digest's priority and the local model's suggestions, from run.json.
function priorityBanner(d) {
  const r = d.run;
  if (!r || !r.priority) return null;
  const reasons = r.reasons || [];
  return el("section.card.priority.p-" + r.priority, { "aria-label": "Digest priority" },
    el("div.priority-head",
      el("span.chip.prio", r.priority.toUpperCase()),
      el("span", reasons.length ? "Needs attention, as the digest says:" : "Nothing in the latest run needs attention.")),
    reasons.length ? el("ul.reasons", reasons.map((x) => el("li", el("span.chip.small", x.level), " ", ticks(x.text)))) : null);
}

function suggestionsSection(d) {
  const r = d.run;
  const list = (r && r.suggestions) || [];
  const t = r && r.triage;
  if (!list.length && !(t && t.enabled)) return null;
  return section("triage", "Model triage", "A local model's view of the run's new leads. Suggestions, never labels; agent needs grade L2 or higher.",
    t && t.note ? el("p.small.muted", t.note) : null,
    list.length ? el("ul.suggestions", list.map((s) => el("li" + (s.conflict ? ".conflict" : ""),
      el("code", s.id), " ", s.grade ? gradeChip({ code: s.grade, label: "" }) : null, " ",
      el("span.chip.small." + s.label, s.label),
      s.conflict ? el("span.chip.small.unsure", icon("alert"), " against the labelling rule") : null,
      el("div.small.muted", ticks(s.reason || ""), s.model ? ` (${s.model})` : ""))))
      : none("The model was asked about nothing new this run."));
}

function render() {
  const d = state.data;
  const app = document.getElementById("app");
  const y = window.scrollY;
  const body = d.run
    ? [priorityBanner(d), tiles(d), actions(d), newSection(d), suggestionsSection(d), healthSection(d), waitingSection(d), runsSection(d)]
    : [actions(d), emptyState({
      title: "No watch run here yet",
      body: ["The dashboard reads what a watch run leaves in the data directory.", el("code", d.data_dir)],
      icon: "inbox",
    }), healthSection(d), waitingSection(d)];
  app.replaceChildren(topbar(d), el("main.dash", body, el("footer.foot.small.muted",
    `Read-only. Generated ${d.generated} from `, el("code", d.data_dir),
    `. The same document: swarmchase dashboard --json${d.since && d.since.requested ? " --since " + d.since.requested : ""}`)));
  // Each cell names its column, for the stacked layout on a narrow screen.
  for (const t of app.querySelectorAll(".dtable")) {
    const heads = [...t.querySelectorAll("thead th")].map((h) => h.textContent);
    for (const tr of t.querySelectorAll("tbody tr")) [...tr.children].forEach((c, i) => { c.dataset.label = heads[i] || ""; });
  }
  window.scrollTo(0, y);
}

async function load(manual = false) {
  if (state.loading) return;
  state.loading = true;
  try {
    const path = state.since ? "overview/since/" + state.since : "overview";
    state.data = await api.get(path);
    state.at = Date.now();
    render();
    if (manual) toast("Up to date");
  } catch (e) {
    if (state.data) toast("Not refreshed: " + e.message, { error: true });
    else document.getElementById("app").replaceChildren(emptyState({
      title: "The overview did not load", body: [e.message], icon: "alert", kind: "error",
      extra: el("button.btn", { type: "button", onclick: () => load(true) }, "Try again"),
    }));
  } finally { state.loading = false; }
}

function setSince(stamp) {
  state.since = stamp;
  UI.prefs.set(SEEN, stamp);
  load();
}

function markSeen() {
  const r = state.data && state.data.run;
  if (!r) return;
  setSince(r.latest);
  toast(`Marked ${stampText(r.latest)} seen; later runs will show as new`);
}

function forget() {
  state.since = null;
  UI.prefs.set(SEEN, null);
  load();
}

function jump(id) {
  const t = document.getElementById(id);
  if (!t) return;
  t.scrollIntoView({ behavior: "smooth", block: "start" });
  t.setAttribute("tabindex", "-1");
  t.focus({ preventScroll: true });
}

keys([
  { keys: ["r"], label: "refresh from the data directory", run: () => load(true) },
  { keys: ["s"], label: "mark the latest run seen", run: markSeen },
  { keys: ["d"], label: "read the latest digest", run: () => state.data && state.data.run && showDigest(state.data.run.latest) },
  { keys: ["1"], label: "next steps", run: () => jump("next") },
  { keys: ["2"], label: "new since you last looked", run: () => jump("new") },
  { keys: ["3"], label: "monitoring health", run: () => jump("health") },
  { keys: ["4"], label: "review queue and cases", run: () => jump("waiting") },
]);

// Refresh while the page is visible, so a finished watch run shows up.
setInterval(() => { if (!document.hidden && Date.now() - state.at >= REFRESH_MS) load(); }, 15000);
document.addEventListener("visibilitychange", () => { if (!document.hidden && Date.now() - state.at >= REFRESH_MS) load(); });

load();
