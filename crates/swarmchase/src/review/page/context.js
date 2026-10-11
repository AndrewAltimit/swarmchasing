// Decision context: evidence loaded on demand from /api/context/. Registers with `Review`.
//
// For the selected group it fetches, once per labelling state, what the
// rules mean and how common they are (here and on the pre-era control),
// when the records happened, other records sharing a target or a linking
// feature, and earlier decisions on similar records. Each record also gets
// a program view of its decoded layers, as highlighted text, and copy
// helpers. Everything arrives defanged; nothing here is a link or HTML.
"use strict";

(() => {
  const { el, api, plural, copy } = UI;
  const cache = new Map(); // group key -> {status, data, sig, error}
  const open = new Set(["rules", "time", "earlier"]); // open sections, kept across renders
  const programs = new Set(); // record ids with the program view shown

  // A change of any label can change "related" and "earlier", so a cached
  // context is refetched when the labels differ from when it was fetched.
  function signature() {
    return Review.state.data.groups.map((g) => g.items.map((i) => i.label || "-").join("")).join("|");
  }

  async function load(g, force) {
    if (!g) return;
    const sig = signature();
    const hit = cache.get(g.key);
    if (hit && !force && (hit.status === "loading" || hit.sig === sig)) return;
    cache.set(g.key, { status: "loading", data: hit && hit.data, sig });
    try {
      const data = await api.get("context/group/" + encodeURIComponent(g.items[0].id));
      cache.set(g.key, { status: "ok", data, sig });
    } catch (e) {
      cache.set(g.key, { status: "error", error: e.message, data: hit && hit.data, sig });
    }
    if (Review.current() && Review.current().key === g.key) Review.render();
  }

  // ---- helpers ------------------------------------------------------------

  function pct(k, n) {
    if (!n) return "0%";
    const v = (100 * k) / n;
    return v > 0 && v < 1 ? "<1%" : `${Math.round(v)}%`;
  }

  function dur(s) {
    if (s == null) return "";
    if (s < 60) return `${s}s`;
    if (s < 3600) return `${Math.round(s / 60)}m`;
    if (s < 86400) { const h = Math.floor(s / 3600), m = Math.round((s % 3600) / 60); return m ? `${h}h ${m}m` : `${h}h`; }
    const d = Math.floor(s / 86400), h = Math.round((s % 86400) / 3600);
    return h ? `${d}d ${h}h` : `${d}d`;
  }

  function jump(key) {
    const st = Review.state;
    const g = st.data.groups.find((x) => x.key === key);
    if (!g) return;
    const todo = g.items.some((i) => !i.label);
    if ((st.tab === "todo" && !todo) || (st.tab === "done" && todo) || st.tab === "disagree") st.tab = "all";
    st.query = "";
    st.sel = key;
    Review.render();
    document.getElementById("detail")?.scrollTo({ top: 0 });
  }

  function section(id, title, count, body) {
    const d = el("details.cx-sec", { open: open.has(id) },
      el("summary", el("span.cx-sum", title), count != null ? el("span.cx-n", String(count)) : null),
      el("div.cx-body", body));
    d.addEventListener("toggle", () => { d.open ? open.add(id) : open.delete(id); });
    return d;
  }

  // ---- sections -----------------------------------------------------------

  function rulesSection(data) {
    const ctl = data.control;
    const rows = data.rules.map((r) => {
      const meta = [r.kind.replace("_", " "), `weight +${r.weight}`];
      if (r.tactic) meta.push(`${r.tactic.id} ${r.tactic.label}`);
      if (r.group) meta.push(`group ${r.group}`);
      if (r.significant) meta.push("significant alone");
      if (r.link) meta.push("links records");
      if (r.artifact) meta.push("model-written trace");
      const here = `Fires on ${r.fired} of ${plural(r.of, "record")} in this analysis (${pct(r.fired, r.of)}); ${r.flagged} of them flagged (${pct(r.flagged, r.fired)}). ${r.in_group} in this group.`;
      let control = null;
      if (r.control) {
        const c = r.control;
        const warn = c.flagged > 0 ? ".warn" : c.fired > 0 ? ".note" : ".ok";
        control = el("p.cx-ctl" + warn, "Pre-agent control: ",
          !c.fired ? `never fired on ${c.of} records.`
            : !c.flagged ? `fired on ${c.fired} of ${c.of} (${pct(c.fired, c.of)}), none of them flagged.`
              : `fired on ${c.fired} of ${c.of} (${pct(c.fired, c.of)}), ${c.flagged} flagged: false alarms on traffic from before agents existed.`);
      }
      return el("li.cx-rule",
        el("div.cx-rhead", el("span.rule.k-" + r.kind, el("span.kdot"), r.id), el("span.cx-meta", meta.join(" · "))),
        r.description ? el("p.cx-desc", r.description) : el("p.cx-desc.muted", "Not in the rules this analysis ran with."),
        el("p.cx-stat", here),
        control);
    });
    const foot = ctl
      ? el("p.muted.small", `Control: ${ctl.records} records before ${ctl.before || "the agent era"}, from ${ctl.path}.`,
        ctl.same_rules ? null : el("span.cx-warn", ` Measured with rules ${ctl.rules_version}, not ${Review.state.data.rules_version}.`))
      : el("p.muted.small", "No pre-era control loaded. ", el("code", "swarmchase eval pre-era"), " writes one; ", el("code", "--control <file>"), " picks another.");
    return section("rules", "What the rules mean", data.rules.length,
      data.rules.length ? [el("ul.cx-list", rows), foot] : el("p.muted.small", "No rule fired in this group."));
  }

  const BASIS = {
    capture: "archive capture times, not request times: the request happened at or before each",
    submit: "scan submission times",
    request: "request times",
    unknown: "times of unknown kind",
  };

  function timeSection(t) {
    if (!t.timed) return section("time", "Timeline", null, el("p.muted.small", "No record here has a time."));
    const kinds = Object.entries(t.basis).sort((a, b) => b[1] - a[1]);
    const capture = t.basis.capture;
    const basis = el("p" + (capture ? ".cx-ctl.note" : ".muted.small"),
      kinds.map(([k, n], i) => `${i ? "; " : ""}${kinds.length > 1 ? n + " " : ""}${BASIS[k] || k}`).join(""),
      capture ? (t.timed > 1 ? " (FM-6.1). Gaps and rhythm between captures say little about the sender." : " (FM-6.1).") : ".");
    if (t.timed === 1) {
      return section("time", "Timeline", null, [el("p.cx-stat", `One record, at ${t.start}`, t.untimed ? `; ${t.untimed} without a time` : "", "."), basis]);
    }
    const max = Math.max(...t.bins);
    const bars = el("div.cx-bars", { title: `${t.start} → ${t.end}` }, t.bins.map((n) => {
      const b = el("span" + (n ? "" : ".zero"), { title: n ? plural(n, "record") : "" });
      b.style.height = n ? `${Math.max(12, (100 * n) / max)}%` : "";
      return b;
    }));
    const lines = [
      el("div.cx-axis", el("span", t.start), t.span ? el("span", t.end) : null),
      el("p.cx-stat", `${plural(t.timed, "record")} over ${t.span ? dur(t.span) : "one instant"}`,
        t.median_step != null && t.timed > 2 ? `, median step ${dur(t.median_step)}` : "",
        t.untimed ? `, ${t.untimed} without a time` : "", "."),
      t.gaps.length && t.timed > 2 ? el("p.cx-stat", "Largest gaps: ", t.gaps.map((g, i) => [i ? ", " : "", el("span", { title: `${g.from} → ${g.to}` }, dur(g.secs))])) : null,
      basis,
    ];
    return section("time", "Timeline", null, [bars, lines]);
  }

  function recRow(r, extra) {
    return el("li.cx-row",
      el("div.cx-rowhead",
        el("span.tier." + r.tier, el("span.dot." + r.tier), r.tier),
        el("span.cx-id", { title: r.id }, r.id),
        r.label ? el("span.chip." + r.label, r.label) : el("span.chip.outline", "unlabelled"),
        el("div.spacer"),
        r.group ? el("button.btn.ghost.small", { onclick: () => jump(r.group), title: r.group_title || "" }, "Open group") : null),
      el("code.cx-url", r.url),
      extra);
  }

  function why(list) {
    return el("div.cx-why", list.map((w) => el("span.chip.outline", w)));
  }

  function relatedSection(rel) {
    const body = rel.total ? [
      el("p.cx-stat", `${plural(rel.total, "record")} outside this group share a target or linking feature; ${rel.labelled} labelled.`),
      rel.by_reason.length > 1 ? el("ul.cx-reasons", rel.by_reason.map((x) => el("li", el("span", x.why), el("span.muted", ` ${x.n}`)))) : null,
      el("ul.cx-list", rel.records.map((r) => recRow(r, [why(r.why), el("p.muted.small", `${r.source} · ${r.time}${r.cluster ? " · " + r.cluster : ""} · score ${r.score}`)]))),
      rel.total > rel.records.length ? el("p.muted.small", `Showing the ${rel.records.length} closest.`) : null,
    ] : el("p.muted.small", "No record outside this group shares its targets or linking features.");
    return section("related", "Related records", rel.total, body);
  }

  function earlierSection(e) {
    const body = e.total ? [
      el("div.cx-tally", Object.entries(e.by_label).map(([l, n]) => el("span.chip." + l, el("b", n), " " + l))),
      el("ul.cx-list", e.records.map((r) => recRow(r, [
        why(r.why),
        r.note ? el("p.cx-note", r.note) : null,
        el("p.muted.small", `reviewed ${r.reviewed_at} · rules ${r.rules.join(", ") || "none"}`),
      ]))),
      e.total > e.records.length ? el("p.muted.small", `Showing ${e.records.length} of ${e.total}.`) : null,
    ] : el("p.muted.small", "No reviewed record shares this group's rules, cluster or target.");
    return section("earlier", "Earlier decisions", e.total, body);
  }

  function copyBar(g) {
    const ids = g.items.map((i) => i.id);
    const refs = g.items.map((i) => i.reference).filter(Boolean);
    return el("div.cx-copy",
      el("button.btn.ghost.small", { onclick: () => copy(ids.join("\n")), title: "One record id per line, for a case" }, `Copy ${plural(ids.length, "id")}`),
      refs.length ? el("button.btn.ghost.small", { onclick: () => copy(refs.join("\n")), title: "Defanged record links, one per line" }, `Copy ${plural(refs.length, "reference")}`) : null);
  }

  function panel(g) {
    const c = cache.get(g.key);
    if (c && c.status !== "loading" && c.sig !== signature()) setTimeout(() => load(g, false));
    const head = el("div.cx-head", el("h3.section-title", "Context"),
      c && c.status === "loading" ? el("span.cx-loading", "Loading…") : null,
      c && c.status === "error" ? el("span.cx-error", "Not loaded: " + c.error, " ", el("button.btn.ghost.small", { onclick: () => load(g, true) }, "Retry")) : null,
      el("div.spacer"), copyBar(g));
    if (!c || !c.data) {
      return el("section.cx", head, c && c.status === "error" ? null : el("div.cx-skel", el("span"), el("span"), el("span")));
    }
    const d = c.data;
    return el("section.cx" + (c.status === "loading" ? ".stale" : ""), head,
      el("div.cx-grid", rulesSection(d), timeSection(d.timeline), earlierSection(d.earlier), relatedSection(d.related)));
  }

  // ---- program view -------------------------------------------------------

  // Calls that send data out or read what a page holds, defanged or not.
  const KEY = /\b(?:fetch|sendBeacon|XMLHttpRequest|WebSocket|EventSource|postMessage|importScripts|atob|btoa|eval)\b|\bdocument(?:\[\.\]|\.)(?:cookie|domain)\b|\b(?:localStorage|sessionStorage)\b|\bnavigator(?:\[\.\]|\.)\w+|\blocation(?:\[\.\]|\.)\w+|\bnew\s+Image\b/g;
  const CODE = /<script|<iframe|<img|<svg|onerror|onload|=>|function\s*\(|\b(fetch|XMLHttpRequest|sendBeacon|eval|atob)\s*\(|document(?:\[\.\]|\.)cookie/i;

  // A readable layout: one statement or tag per line, indented by braces.
  // Text only; nothing is parsed as HTML or run.
  function layout(src) {
    const s = src.replace(/\s*;\s*/g, ";\n").replace(/\s*\{\s*/g, " {\n").replace(/\s*\}\s*/g, "\n}\n").replace(/>\s*</g, ">\n<");
    let depth = 0;
    const out = [];
    for (let line of s.split("\n")) {
      line = line.trim();
      if (!line) continue;
      if (line.startsWith("}")) depth = Math.max(0, depth - 1);
      out.push("  ".repeat(Math.min(depth, 8)) + line);
      if (line.endsWith("{")) depth++;
    }
    return out.join("\n");
  }

  function highlight(text) {
    const pre = el("pre.mono.cx-prog");
    let last = 0;
    for (const m of text.matchAll(KEY)) {
      if (m.index > last) pre.append(text.slice(last, m.index));
      pre.append(el("mark.cx-call", m[0]));
      last = m.index + m[0].length;
    }
    pre.append(text.slice(last));
    return pre;
  }

  function programExtra(i) {
    const progs = i.layers.filter((l) => CODE.test(l.text));
    const field = Review.field;
    const tools = el("div.cx-copy",
      el("button.btn.ghost.small", { onclick: () => copy(i.id), title: "Copy the record id" }, "Copy id"),
      progs.length ? el("button.btn.ghost.small", {
        onclick: () => { programs.has(i.id) ? programs.delete(i.id) : programs.add(i.id); Review.render(); },
        title: "Lay out the decoded program as text, key calls marked",
      }, programs.has(i.id) ? "Hide program" : "Read as program") : null);
    const out = [field("Tools", tools)];
    if (progs.length && programs.has(i.id)) {
      for (const l of progs) {
        const text = layout(l.text);
        const calls = [...new Set([...text.matchAll(KEY)].map((m) => m[0]))];
        out.push(field(`Program · ${l.via}`, el("div.cx-progwrap",
          calls.length ? el("p.cx-calls", "Calls: ", calls.map((c, k) => [k ? ", " : "", el("mark.cx-call", c)])) : el("p.muted.small", "No call that sends data or reads the page."),
          highlight(text))));
      }
    }
    return out;
  }

  Review.panels.push((g) => panel(g));
  Review.recordExtras.push((i) => programExtra(i));
  Review.onSelect.push((g) => load(g, false));
})();
