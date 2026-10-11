// Every page: the light/dark toggle, the nav menus, and glossary tooltips.
// The theme follows the system until the toggle sets one, which is kept in
// this browser. The menus are <details> and work without this script; it
// only closes the others when one opens, and on Escape or a click outside.
import { store } from "./lib/dom.js";
import { tip } from "./lib/tip.js";

const KEY = "swarmchase.theme";
const root = document.documentElement;
const dark = () => root.dataset.theme === "dark" || (!root.dataset.theme && matchMedia("(prefers-color-scheme: dark)").matches);

for (const b of document.querySelectorAll("[data-theme-toggle]")) {
  const label = () => b.setAttribute("aria-label", dark() ? "Switch to light theme" : "Switch to dark theme");
  label();
  b.addEventListener("click", () => {
    const next = dark() ? "light" : "dark";
    root.dataset.theme = next;
    store.set(KEY, next);
    label();
    document.dispatchEvent(new CustomEvent("themechange"));
  });
}

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
