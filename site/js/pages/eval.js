// Evaluation page: the numbers are pre-rendered; "Recompute" loads the
// engine and scores the bundled and the edited rules in this page.
import { $, showError } from "../lib/dom.js";
import { engine, editedRules } from "../lib/wasm.js";
import { renderComparison, scoreBoth } from "../lib/evalview.js";

const btn = document.querySelector('[data-act="recompute"]');
const src = $("rules-source");
src.textContent = editedRules() ? "Edited rules found in this browser." : "No edited rules in this browser: both columns will match.";
btn?.addEventListener("click", async () => {
  const out = $("eval-out");
  btn.disabled = true;
  try {
    const sc = await engine();
    const [base, edited, files] = await scoreBoth(sc, editedRules());
    out.replaceChildren(...renderComparison(base, edited, files));
  } catch (e) {
    showError(out, e);
  } finally {
    btn.disabled = false;
  }
});
