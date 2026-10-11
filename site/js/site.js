// Every page: the theme toggle, the nav menus, and glossary tooltips.
// Each press of the toggle flips the look between light and dark. A look
// other than the system's is kept in this browser; flipping back to the
// system's look forgets it, so the page follows the system again. The menus
// are <details> and work without this script; it only closes the others
// when one opens, and on Escape or a click outside.
import { store } from "./lib/dom.js";
import { tip } from "./lib/tip.js";

const KEY = "swarmchase.theme";
const root = document.documentElement;
const system = matchMedia("(prefers-color-scheme: dark)");
const systemLook = () => (system.matches ? "dark" : "light");
const chosen = () => (root.dataset.theme === "light" || root.dataset.theme === "dark" ? root.dataset.theme : null);
const look = () => chosen() ?? systemLook();
const changed = () => document.dispatchEvent(new CustomEvent("themechange"));

const toggles = [...document.querySelectorAll("[data-theme-toggle]")];
const label = () => {
  const now = look();
  const next = now === "dark" ? "light" : "dark";
  const auto = chosen() == null;
  const said = `Theme: ${now}${auto ? " (following the system)" : ""}. Switch to ${next}`;
  for (const b of toggles) {
    b.dataset.look = now;
    b.dataset.auto = String(auto);
    b.setAttribute("aria-label", said);
    b.title = said;
  }
};
label();
for (const b of toggles) {
  b.addEventListener("click", () => {
    const next = look() === "dark" ? "light" : "dark";
    if (next === systemLook()) {
      delete root.dataset.theme;
      store.del(KEY);
    } else {
      root.dataset.theme = next;
      store.set(KEY, next);
    }
    label();
    changed();
  });
}
// Following the system: redraw when it changes.
system.addEventListener?.("change", () => {
  label();
  if (chosen() == null) changed();
});

// Nav menus: one open at a time.
const menus = [...document.querySelectorAll("[data-nav-menu]")];
const closeAll = (except = null) => {
  for (const m of menus) if (m !== except) m.open = false;
};
for (const m of menus) {
  m.addEventListener("toggle", () => m.open && closeAll(m));
  m.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && m.open) {
      m.open = false;
      m.querySelector("summary")?.focus();
    }
  });
  m.addEventListener("focusout", (e) => {
    if (m.open && !m.contains(e.relatedTarget)) m.open = false;
  });
}
document.addEventListener("click", (e) => {
  if (!e.target.closest?.("[data-nav-menu]")) closeAll();
});

// Glossary terms in the Field Manual carry their short definition.
for (const a of document.querySelectorAll("a.gloss[data-def]")) {
  tip(a, a.dataset.def);
  a.setAttribute("aria-description", a.dataset.def);
}
