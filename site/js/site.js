// Every page: the light/dark toggle. The theme follows the system until the
// toggle sets one, which is kept in this browser.
import { store } from "./lib/dom.js";

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
