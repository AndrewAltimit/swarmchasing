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
