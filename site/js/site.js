// Every page: the theme toggle, the nav menus, and glossary tooltips.
// The toggle cycles system, light, dark. The theme follows the system until
// the toggle picks light or dark, which is kept in this browser; picking
// system again forgets it. The menus are <details> and work without this
// script; it only closes the others when one opens, and on Escape or a
// click outside.
import { store } from "./lib/dom.js";
import { tip } from "./lib/tip.js";

const KEY = "swarmchase.theme";
const root = document.documentElement;
const system = matchMedia("(prefers-color-scheme: dark)");
const MODES = ["system", "light", "dark"];
const mode = () => (root.dataset.theme === "light" || root.dataset.theme === "dark" ? root.dataset.theme : "system");
const changed = () => document.dispatchEvent(new CustomEvent("themechange"));

const toggles = [...document.querySelectorAll("[data-theme-toggle]")];
const label = () => {
  const now = mode();
  const next = MODES[(MODES.indexOf(now) + 1) % MODES.length];
  const shown = now === "system" ? ` (${system.matches ? "dark" : "light"} now)` : "";
  for (const b of toggles) {
    b.dataset.mode = now;
    b.setAttribute("aria-label", `Theme: ${now}${shown}. Switch to ${next}`);
    b.title = `Theme: ${now}${shown}`;
  }
};
label();
for (const b of toggles) {
  b.addEventListener("click", () => {
    const next = MODES[(MODES.indexOf(mode()) + 1) % MODES.length];
    if (next === "system") {
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
  if (mode() === "system") changed();
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
