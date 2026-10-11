// Shared helpers for swarmchase's local pages. Values from records are
// attacker-written: `el` only ever adds text nodes, and nothing here parses
// HTML or turns a value into a link.
"use strict";

const UI = (() => {
  const token = document.querySelector('meta[name="page-token"]').content;

  /** el("div#id.card.wide", {onclick, title, dataset}, ...children) */
  function el(spec, attrs, ...kids) {
    const parts = spec.split(/(?=[.#])/);
    const tag = parts[0] && !/^[.#]/.test(parts[0]) ? parts.shift() : "div";
    const e = document.createElement(tag);
    const classes = parts.filter((p) => p[0] === ".").map((p) => p.slice(1));
    const id = parts.find((p) => p[0] === "#");
    if (classes.length) e.className = classes.join(" ");
    if (id) e.id = id.slice(1);
    if (attrs != null && (attrs instanceof Node || typeof attrs !== "object" || Array.isArray(attrs))) {
      kids.unshift(attrs);
      attrs = null;
    }
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v == null || v === false) continue;
      if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
      else if (k === "dataset") Object.assign(e.dataset, v);
      else if (k === "class") e.className += " " + v;
      else e.setAttribute(k, v === true ? "" : String(v));
    }
    append(e, kids);
    return e;
  }

  function append(e, kids) {
    for (const k of kids.flat(Infinity)) {
      if (k == null || k === false) continue;
      e.append(k instanceof Node ? k : String(k));
    }
  }

  async function request(method, path, body) {
    const opts = { method, headers: {} };
    if (body !== undefined) {
      opts.headers["Content-Type"] = "application/json";
      opts.headers["X-Page-Token"] = token;
      opts.body = JSON.stringify(body);
    }
    const res = await fetch("/api/" + path, opts);
    let data = null;
    try { data = await res.json(); } catch { /* empty */ }
    if (!res.ok) throw new Error((data && data.error) || res.statusText);
    return data;
  }

  const api = {
    get: (path) => request("GET", path),
    post: (path, body) => request("POST", path, body),
  };

  // ---- preferences --------------------------------------------------------
  // Per-browser conveniences only. Storage can be missing or throw (private
  // windows, blocked site data), so every access is guarded and the page
  // works without it.
  const PREFIX = "swarmchase.";
  const prefs = {
    get(name, fallback = null) {
      try { const v = window.localStorage.getItem(PREFIX + name); return v == null ? fallback : v; }
      catch { return fallback; }
    },
    set(name, value) {
      try {
        if (value == null) window.localStorage.removeItem(PREFIX + name);
        else window.localStorage.setItem(PREFIX + name, String(value));
      } catch { /* not remembered */ }
    },
  };

  const THEMES = ["system", "light", "dark"];
  function setTheme(t) {
    if (!THEMES.includes(t)) t = "system";
    const root = document.documentElement;
    if (t === "system") delete root.dataset.theme; else root.dataset.theme = t;
    prefs.set("theme", t === "system" ? null : t);
    for (const b of document.querySelectorAll("[data-theme-set]")) {
      const on = b.dataset.themeSet === t;
      b.classList.toggle("on", on);
      b.setAttribute("aria-pressed", String(on));
    }
  }
  function theme() { return document.documentElement.dataset.theme || "system"; }

  function setDensity(d) {
    const compact = d === "compact";
    const root = document.documentElement;
    if (compact) root.dataset.density = "compact"; else delete root.dataset.density;
    prefs.set("density", compact ? "compact" : null);
    for (const b of document.querySelectorAll("[data-density]")) {
      b.setAttribute("aria-pressed", String(compact));
      b.classList.toggle("on", compact);
    }
  }
  function density() { return document.documentElement.dataset.density === "compact" ? "compact" : "comfortable"; }

  // Apply the remembered choices before the first render.
  setTheme(prefs.get("theme", "system"));
  setDensity(prefs.get("density", "comfortable"));

  // ---- icons --------------------------------------------------------------
  // Inline SVG, built node by node (no markup parsing, nothing external).
  const ICONS = {
    system: ["M3 5h18v11H3z", "M8 20h8", "M12 16v4"],
    light: ["M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8z", "M12 2v2", "M12 20v2", "M4.9 4.9l1.4 1.4", "M17.7 17.7l1.4 1.4", "M2 12h2", "M20 12h2", "M4.9 19.1l1.4-1.4", "M17.7 6.3l1.4-1.4"],
    dark: ["M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5z"],
    density: ["M4 6h16", "M4 10h16", "M4 14h16", "M4 18h16"],
    keyboard: ["M3 6h18v12H3z", "M7 10h.01", "M11 10h.01", "M15 10h.01", "M7 14h10"],
    close: ["M6 6l12 12", "M18 6L6 18"],
    check: ["M5 12.5l4.5 4.5L19 7.5"],
    alert: ["M12 3l9.5 17h-19z", "M12 10v4", "M12 17.5h.01"],
    search: ["M10.5 4a6.5 6.5 0 1 0 0 13 6.5 6.5 0 0 0 0-13z", "M20 20l-4.8-4.8"],
    inbox: ["M3 13l3-8h12l3 8", "M3 13v6h18v-6", "M3 13h5l1.5 2.5h5L16 13h5"],
    copy: ["M9 9h11v11H9z", "M5 15H4V4h11v1"],
  };
  const SVG = "http://www.w3.org/2000/svg";
  function icon(name) {
    const s = document.createElementNS(SVG, "svg");
    s.setAttribute("class", "icon");
    s.setAttribute("viewBox", "0 0 24 24");
    s.setAttribute("aria-hidden", "true");
    s.setAttribute("focusable", "false");
    for (const d of ICONS[name] || []) {
      const p = document.createElementNS(SVG, "path");
      p.setAttribute("d", d);
      s.append(p);
    }
    return s;
  }

  /** Theme (system, light, dark) and density controls, for a top bar. */
  function settings() {
    const names = { system: "Use the system theme", light: "Light theme", dark: "Dark theme" };
    const t = theme();
    const seg = el("div.seg.icons", { role: "group", "aria-label": "Theme" },
      THEMES.map((x) => el("button" + (x === t ? ".on" : ""), {
        type: "button", title: names[x], "aria-label": names[x], "aria-pressed": String(x === t),
        dataset: { themeSet: x }, onclick: () => setTheme(x),
      }, icon(x))));
    const compact = density() === "compact";
    const dens = el("button.btn.ghost.small.icon-only" + (compact ? ".on" : ""), {
      type: "button", title: "Compact density", "aria-label": "Compact density", "aria-pressed": String(compact),
      dataset: { density: "toggle" }, onclick: () => setDensity(density() === "compact" ? "comfortable" : "compact"),
    }, icon("density"));
    return el("div.toolbar", seg, dens);
  }

  // ---- toasts -------------------------------------------------------------
  /** toast(msg, {action, onAction, error, ms, kind}): kind tints the marker (agent, benign, unsure). */
  function toast(msg, { action, onAction, error = false, ms = 4500, kind } = {}) {
    const host = document.getElementById("toasts");
    const t = el("div.toast" + (error ? ".error" : "") + (kind ? "." + kind : ""), { role: error ? "alert" : null },
      el("span.tmsg", msg));
    const dismiss = () => {
      if (!t.isConnected || t.classList.contains("out")) return;
      t.classList.add("out");
      setTimeout(() => t.remove(), 170);
    };
    if (action) {
      t.append(el("button.btn.small", { type: "button", onclick: () => { onAction(); t.remove(); } }, action));
    }
    t.append(el("button.btn.ghost.small.icon-only", { type: "button", "aria-label": "Dismiss", title: "Dismiss", onclick: dismiss }, icon("close")));
    host.append(t);
    while (host.children.length > 3) host.firstChild.remove();
    setTimeout(dismiss, error ? Math.max(ms, 7000) : ms);
  }

  // ---- keyboard -----------------------------------------------------------
  // Keyboard map: [{keys: ["j", "ArrowDown"], label, run}], with a help
  // overlay on `?`. Keys are ignored while typing, except Escape.
  const bindings = [];
  function keys(list) { bindings.push(...list); }
  const NAMES = { ArrowDown: "↓", ArrowUp: "↑", ArrowLeft: "←", ArrowRight: "→", Enter: "↵", " ": "space" };
  function keyName(k) { return NAMES[k] || k; }
  let helpReturn = null;
  function closeOverlay() {
    const o = document.querySelector(".overlay");
    if (!o) return false;
    o.remove();
    if (helpReturn && helpReturn.isConnected) helpReturn.focus();
    helpReturn = null;
    return true;
  }
  function help() {
    if (document.querySelector(".overlay")) return;
    helpReturn = document.activeElement;
    const dl = el("dl.keys");
    for (const b of bindings.filter((b) => b.label)) {
      dl.append(el("dt", b.keys.slice(0, 2).map((k) => [el("kbd", keyName(k)), " "])), el("dd", b.label));
    }
    dl.append(el("dt", el("kbd", "?")), el("dd", "this help"), el("dt", el("kbd", "Esc")), el("dd", "close, or leave a field"));
    const closeBtn = el("button.btn.ghost.small.icon-only", { type: "button", "aria-label": "Close", title: "Close (Esc)", onclick: closeOverlay }, icon("close"));
    const card = el("div.card", { role: "dialog", "aria-modal": "true", "aria-labelledby": "help-title", tabindex: "-1" },
      el("div.dialog-head", el("h2#help-title", "Keyboard shortcuts"), closeBtn), dl);
    const o = el("div.overlay", { onclick: (e) => { if (e.target === o) closeOverlay(); } }, card);
    // Keep Tab inside the dialog.
    card.addEventListener("keydown", (e) => { if (e.key === "Tab") { e.preventDefault(); closeBtn.focus(); } });
    document.body.append(o);
    closeBtn.focus();
  }
  document.addEventListener("keydown", (e) => {
    const typing = e.target.matches("input, textarea, select");
    if (e.key === "Escape") {
      if (closeOverlay()) return;
      if (typing) { e.target.blur(); return; }
    }
    if (typing || e.ctrlKey || e.metaKey || e.altKey) return;
    if (e.key === "?") { help(); e.preventDefault(); return; }
    if (document.querySelector(".overlay")) return;
    const b = bindings.find((b) => b.keys.includes(e.key));
    if (b) { e.preventDefault(); b.run(e); }
  });

  /** A stacked progress bar: parts = [{cls, n}], of total. */
  function progress(parts, total, label) {
    const track = el("div.progress-track", { role: "img", "aria-label": label });
    for (const p of parts) {
      if (!p.n) continue;
      // CSSOM, not a style attribute: the content security policy allows only this.
      const s = el("span." + p.cls, { title: `${p.cls} ${p.n}` });
      s.style.width = `${(100 * p.n) / Math.max(total, 1)}%`;
      track.append(s);
    }
    return el("div.progress", track, el("span.progress-label", label));
  }

  function plural(n, one, many = one + "s") { return `${n} ${n === 1 ? one : many}`; }

  async function copy(text) {
    try { await navigator.clipboard.writeText(text); toast("Copied"); }
    catch { toast("Copy failed", { error: true }); }
  }

  /** Text with every case-insensitive occurrence of `needles` wrapped in <mark>, as nodes. */
  function highlight(text, needles) {
    const s = String(text);
    const low = s.toLowerCase();
    const spans = [];
    for (const n of needles || []) {
      const q = String(n || "").toLowerCase();
      if (q.length < 3) continue;
      for (let i = low.indexOf(q); i >= 0; i = low.indexOf(q, i + q.length)) spans.push([i, i + q.length]);
    }
    if (!spans.length) return [s];
    spans.sort((a, b) => a[0] - b[0]);
    const merged = [spans[0].slice()];
    for (const [a, b] of spans.slice(1)) {
      const last = merged[merged.length - 1];
      if (a <= last[1]) last[1] = Math.max(last[1], b); else merged.push([a, b]);
    }
    const out = [];
    let at = 0;
    for (const [a, b] of merged) {
      if (a > at) out.push(s.slice(at, a));
      out.push(el("mark", s.slice(a, b)));
      at = b;
    }
    if (at < s.length) out.push(s.slice(at));
    return out;
  }

  /** A centred empty, done or error state: {title, body, icon, kind, action}. */
  function emptyState({ title, body, icon: name = "inbox", kind = "", extra = null } = {}) {
    return el("div.empty" + (kind ? "." + kind : ""), { role: kind === "error" ? "alert" : null },
      el("div", el("div.empty-mark", icon(name)), el("h2", title), body ? [body].flat().map((p) => p instanceof Node ? p : el("p", p)) : null, extra));
  }

  /** Placeholder blocks shown while a page loads. */
  function skeleton() {
    return el("div.skeleton", { "aria-busy": "true", "aria-label": "Loading" },
      el("span.skel.w-40.h-lg"), el("span.skel.w-80"), el("span.skel.w-60"), el("span.skel.h-xl"), el("span.skel.h-xl"));
  }

  return {
    el, append, api, toast, keys, keyName, help, progress, plural, copy,
    prefs, theme, setTheme, density, setDensity, settings, icon, highlight, emptyState, skeleton,
  };
})();
