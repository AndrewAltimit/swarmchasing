// DOM helpers shared by every page. Record contents are untrusted: they only
// ever reach the page through el()'s text children (textContent), never as
// HTML, and el() refuses URL attributes other than blob: URLs the page made
// and links to the site's own pages (a relative path and a fragment, such
// as ../rules/#rule-x), which carry no scheme and so can go nowhere else.

export const $ = (id) => document.getElementById(id);

// Attributes that load or navigate. Only blob: URLs the page made itself.
const URL_ATTRS = new Set(["href", "src", "action", "formaction", "xlink:href", "srcdoc", "data", "poster"]);
const SVG_NS = "http://www.w3.org/2000/svg";
// A link within the site: one or more ./ or ../, a lower-case page path,
// then a fragment of URL-encoded characters. Nothing else passes.
const SITE_LINK = /^(?:\.\.?\/)+[a-z0-9\-/]*#[A-Za-z0-9%._~!*'()\-]+$/;

function apply(e, attrs) {
  for (const [k, v] of Object.entries(attrs ?? {})) {
    if (v == null || v === false) continue;
    if (k === "class") e.setAttribute("class", v);
    // Styles go through CSSOM: the CSP blocks style attributes.
    else if (k === "style") Object.assign(e.style, v);
    else if (k.startsWith("on")) {
      if (typeof v !== "function") throw new Error(`${k}: handler must be a function`);
      e.addEventListener(k.slice(2), v);
    } else if (URL_ATTRS.has(k.toLowerCase()) && !String(v).startsWith("blob:") && !(k === "href" && SITE_LINK.test(String(v)))) {
      throw new Error(`${k}: only blob: URLs and links within the site`);
    } else e.setAttribute(k, v === true ? "" : String(v));
  }
}

function append(e, kids) {
  for (const k of kids.flat(Infinity)) if (k != null && k !== false) e.append(k instanceof Node ? k : String(k));
}

/** An HTML element. Children are nodes or text; text is inserted as text. */
export function el(tag, attrs = {}, ...kids) {
  const e = document.createElement(tag);
  apply(e, attrs);
  append(e, kids);
  return e;
}

/** An SVG element, under the same rules as el(). */
export function svg(tag, attrs = {}, ...kids) {
  const e = document.createElementNS(SVG_NS, tag);
  apply(e, attrs);
  append(e, kids);
  return e;
}

/**
 * A rule id as a link to its row on the rules page (`rules/#rule-<id>`).
 * The id is URL-encoded into the fragment and shown as text, so an id from
 * edited rules can only name a row, never a page elsewhere.
 */
export function ruleLink(id, cls = "chip rule-link") {
  const root = document.body.dataset.root || "./";
  const text = String(id ?? "");
  const href = `${root}rules/#rule-${encodeURIComponent(text)}`;
  return SITE_LINK.test(href) ? el("a", { class: cls, href, title: `Rule ${text} on the rules page` }, text) : el("span", { class: cls }, text);
}

/** Run fn on click, Enter and Space: for rows and marks that act as buttons. */
export function activate(node, fn) {
  // A link or control inside the node does its own job, not the node's.
  const own = (ev) => {
    const inner = ev.target.closest?.("a, button, input, select, textarea");
    return !inner || inner === node || !node.contains(inner);
  };
  node.addEventListener("click", (ev) => own(ev) && fn(ev));
  node.addEventListener("keydown", (ev) => {
    if (own(ev) && (ev.key === "Enter" || ev.key === " ")) {
      ev.preventDefault();
      fn(ev);
    }
  });
  return node;
}

/**
 * A roving tab stop over `nodes`, in order: one of them (index `current`)
 * is in the tab order, the arrow keys move focus along them (up and down
 * with `vertical`, left and right with `horizontal`), Home and End to the
 * ends. Whichever gets focus becomes the tab stop.
 */
export function roving(nodes, { current = 0, vertical = true, horizontal = true } = {}) {
  const list = nodes.filter(Boolean);
  if (!list.length) return;
  const set = (k) => list.forEach((n, i) => n.setAttribute("tabindex", i === k ? "0" : "-1"));
  set(Math.max(0, Math.min(list.length - 1, current)));
  list.forEach((n, i) => {
    n.addEventListener("focus", () => set(i));
    n.addEventListener("keydown", (ev) => {
      if (ev.target !== n) return;
      const k = ev.key;
      let j = null;
      if ((vertical && k === "ArrowDown") || (horizontal && k === "ArrowRight")) j = Math.min(list.length - 1, i + 1);
      else if ((vertical && k === "ArrowUp") || (horizontal && k === "ArrowLeft")) j = Math.max(0, i - 1);
      else if (k === "Home") j = 0;
      else if (k === "End") j = list.length - 1;
      if (j == null) return;
      ev.preventDefault();
      ev.stopPropagation();
      set(j);
      list[j].focus();
    });
  });
}

/**
 * The sessionStorage key under which Check my logs hands its log to the
 * workbench (`{ v: 1, log, map }`). The workbench reads it once, when its
 * address carries `from=check-logs`, and removes it. Never in the URL.
 */
export const HANDOFF_KEY = "swarmchase.handoff";

export const store = {
  get(k) { try { return localStorage.getItem(k); } catch { return null; } },
  set(k, v) { try { localStorage.setItem(k, v); } catch {} },
  del(k) { try { localStorage.removeItem(k); } catch {} },
};

export function showError(target, err) {
  target.replaceChildren(el("p", { class: "warn", role: "status" }, String(err?.message ?? err)));
}

/**
 * An alert card: what went wrong in bold, then what to do. Each of `parts`
 * is an element, or text (or an array of text and nodes) made a paragraph.
 * Shown in `target`, which is unhidden.
 */
export function showAlert(target, title, ...parts) {
  target.hidden = false;
  target.replaceChildren(
    el("p", {}, el("strong", {}, title)),
    ...parts.filter((x) => x != null && x !== false).map((x) => (x instanceof Element ? x : el("p", {}, x))),
  );
}

/**
 * A copy button: copies `text()` (a string, or a promise of one) and says
 * so on the button for a moment, or says to select the text when the
 * browser refuses.
 */
export function copyButton(btn, text, failed = "Copy failed: select the text") {
  const label = btn.textContent;
  let t = 0;
  btn.addEventListener("click", async () => {
    clearTimeout(t);
    try {
      await navigator.clipboard.writeText(await text());
      btn.textContent = "Copied";
    } catch {
      btn.textContent = failed;
    }
    t = setTimeout(() => (btn.textContent = label), 2000);
  });
  return btn;
}

/** Files above this many bytes are read only after the visitor says so. */
export const BIG_FILE = 50 * 1024 * 1024;

/**
 * Read a picked or dropped file, asking first when it is big: the page
 * holds it all in memory and the analysis can take a while. Shows the
 * question in `status` with a button that reads it anyway; resolves to the
 * text, or null when the visitor has not said yes yet (the button then
 * calls `then` with the text).
 */
export async function readFile(f, status, then) {
  if (f.size > BIG_FILE) {
    const mb = Math.round(f.size / (1024 * 1024));
    const go = el("button", { type: "button" }, "Read it anyway");
    go.addEventListener("click", async () => {
      status.hidden = true;
      then(await f.text());
    }, { once: true });
    status.replaceChildren(`This file is about ${mb} MB. The page reads it into memory and analyses it here, which can take a minute and slow the tab. `, go);
    status.hidden = false;
    return null;
  }
  return f.text();
}

/**
 * Run `fn` with `btn` disabled and marked busy, after the browser has
 * painted that state: an analysis may run on the main thread (when no
 * worker starts), and the label should show before it. A second press
 * while it runs does nothing, including one queued during the run.
 */
export async function busy(btn, label, fn) {
  if (btn.dataset.busy) return undefined;
  const text = btn.textContent;
  const wasDisabled = btn.disabled;
  btn.dataset.busy = "1";
  btn.disabled = true;
  btn.setAttribute("aria-busy", "true");
  btn.textContent = label;
  await new Promise((r) => {
    requestAnimationFrame(() => setTimeout(r, 0));
    setTimeout(r, 100);
  });
  try {
    return await fn();
  } finally {
    // Cleared after the input queued during the run has been handled.
    setTimeout(() => {
      delete btn.dataset.busy;
      btn.removeAttribute("aria-busy");
      btn.textContent = text;
      btn.disabled = wasDisabled;
    }, 0);
  }
}

/** Save text as a file through a blob: URL the page made. */
export function download(name, text, type) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = el("a", { href: url, download: name });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/** A same-origin JSON or text file, by a path relative to the site root. */
export async function fetchRoot(path, as = "json") {
  const root = document.body.dataset.root || "./";
  const r = await fetch(new URL(root + path, document.baseURI));
  if (!r.ok) throw new Error(`${path}: ${r.status}`);
  return as === "json" ? r.json() : r.text();
}
