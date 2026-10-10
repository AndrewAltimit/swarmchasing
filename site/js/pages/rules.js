// Rules page: filter the pre-rendered cards; the editor loads the engine
// when it is opened.
import { $, showError, store } from "../lib/dom.js";
import { engine, RULES_KEY } from "../lib/wasm.js";
import { renderComparison, scoreBoth } from "../lib/evalview.js";

const form = document.querySelector("[data-rule-filters]");
if (form) {
  const cards = [...document.querySelectorAll(".rule-card")];
  const count = document.querySelector("[data-rule-count]");
  const none = document.querySelector("[data-rule-none]");
  const apply = () => {
    const f = new FormData(form);
    const q = String(f.get("q") ?? "").trim().toLowerCase();
    let shown = 0;
    for (const c of cards) {
      const d = c.dataset;
      const ok =
        (!q || d.text.includes(q)) &&
        (!f.get("kind") || d.kind === f.get("kind")) &&
        (!f.get("target") || d.target === f.get("target")) &&
        (!f.get("tactic") || d.tactic === f.get("tactic")) &&
        (!f.get("significant") || d.significant === "true") &&
        (!f.get("link") || d.link === "true");
      c.hidden = !ok;
      if (ok) shown++;
    }
    count.textContent = `${shown} of ${cards.length} rules`;
    none.hidden = shown > 0;
  };
  form.addEventListener("input", apply);
  form.addEventListener("submit", (e) => e.preventDefault());
  apply();
}

const editor = document.querySelector("[data-rules-editor]");
const text = $("rules-text");
const status = $("rules-status");
const bundled = text?.value ?? "";
const say = (msg) => (status.textContent = msg);

if (editor && text) {
  const saved = store.get(RULES_KEY);
  if (saved) {
    text.value = saved;
    editor.open = true;
    say("Showing the rules you saved in this browser.");
  }
  let sc = null;
  const load = async () => {
    try {
      sc = await engine();
    } catch {}
  };
  editor.addEventListener("toggle", () => editor.open && load());
  if (editor.open || location.hash === "#edit") {
    editor.open = true;
    load();
  }
  editor.addEventListener("click", async (ev) => {
    const act = ev.target.closest("button")?.dataset.act;
    if (!act) return;
    if (act === "reset") {
      text.value = bundled;
      store.del(RULES_KEY);
      say("Reset to the bundled rules; the site uses them again.");
      return;
    }
    if (!sc) return;
    if (act === "validate" || act === "save") {
      try {
        const r = JSON.parse(sc.check_rules(text.value));
        if (act === "save") {
          store.set(RULES_KEY, text.value);
          say(`Saved: ${r.rules} rules, version ${r.version}. The workbench and the unwrap tool now use them in this browser.`);
        } else say(`Valid: ${r.rules} rules, ${r.asns} ASN hints, version ${r.version}.`);
      } catch (e) {
        say(String(e?.message ?? e));
      }
    } else if (act === "eval") {
      const out = $("eval-out");
      say("Scoring the labelled set…");
      try {
        const [base, edited, files] = await scoreBoth(sc, text.value);
        out.replaceChildren(...renderComparison(base, edited, files));
        say("");
      } catch (e) {
        say("");
        showError(out, e);
      }
    }
  });
}
