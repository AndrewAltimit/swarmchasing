// Notices index: filter the pre-rendered rows. Reads data attributes only.
// The table is the whole index without this script; the form appears with
// it, and its state lives in the URL hash (#provider=…&from=2026-10-01) so a
// filtered view can be linked.
import { plural } from "../lib/fmt.js";

const form = document.querySelector("[data-notice-filters]");
if (form) {
  const KEYS = ["status", "provider", "sector", "host", "q", "from", "to"];
  const DATE = /^\d{4}-\d{2}-\d{2}$/;
  const rows = [...document.querySelectorAll(".notice-table tbody tr")];
  const count = document.querySelector("[data-notice-count]");
  const none = document.querySelector("[data-notice-none]");
  const norm = (s) => String(s ?? "").toLowerCase().replaceAll("[.]", ".");
  const field = (k) => form.elements.namedItem(k);

  // Hash to form. A select keeps a value only if it is one of its options;
  // dates must be dates; text is capped. Unknown keys are ignored.
  const readHash = () => {
    const p = new URLSearchParams(location.hash.slice(1));
    for (const k of KEYS) {
      const f = field(k);
      if (!f) continue;
      let v = (p.get(k) ?? "").slice(0, 200);
      if ((k === "from" || k === "to") && !DATE.test(v)) v = "";
      if (f.tagName === "SELECT" && ![...f.options].some((o) => o.value === v)) v = "";
      f.value = v;
    }
  };
  const writeHash = (f) => {
    const p = new URLSearchParams();
    for (const k of KEYS) if (f[k]) p.set(k, f[k]);
    const s = p.toString();
    history.replaceState(null, "", s ? `#${s}` : location.pathname + location.search);
  };

  const apply = (write = true) => {
    const f = Object.fromEntries(new FormData(form));
    const host = norm(f.host).trim();
    const q = norm(f.q).trim();
    let shown = 0;
    for (const r of rows) {
      const d = r.dataset;
      const ok =
        (!f.status || d.status === f.status) &&
        (!f.provider || d.providers.split("\n").includes(f.provider)) &&
        (!f.sector || d.sector === f.sector) &&
        (!host || norm(d.hosts).includes(host)) &&
        (!q || norm(d.text).includes(q)) &&
        (!f.from || d.updated >= f.from) &&
        (!f.to || d.updated <= f.to);
      r.hidden = !ok;
      if (ok) shown++;
    }
    count.textContent = shown === rows.length ? plural(rows.length, "notice") : `${shown} of ${plural(rows.length, "notice")}`;
    none.hidden = shown > 0;
    if (write) writeHash(f);
  };
  form.addEventListener("input", () => apply());
  form.addEventListener("submit", (e) => e.preventDefault());
  // `reset` fires before the fields clear.
  form.addEventListener("reset", () => setTimeout(() => apply()));
  window.addEventListener("hashchange", () => {
    readHash();
    apply(false);
  });
  readHash();
  apply(false);
  // The form sits in a fold: shown with this script, closed on a phone
  // unless the address already carries filters.
  const fold = form.closest("details.filters-fold");
  if (fold) {
    fold.hidden = false;
    if (window.matchMedia?.("(max-width: 720px)").matches && location.hash.length < 2) fold.open = false;
  }
}
