// Rules page: filter the pre-rendered cards (grouped by kind; on a phone
// each starts as a closed row); test a URL against one rule
// (the engine loads when a card's tester is first opened; the URL is
// decoded, never opened, and shown defanged); the editor loads the tools
// module (check and eval) when it is opened.
import { $, el, showError, store } from "../lib/dom.js";
import { arr, trunc } from "../lib/fmt.js";
import { engine, tools, host, rulesJson, pageRules, RULES_KEY } from "../lib/wasm.js";
import { renderComparison, scoreBoth } from "../lib/evalview.js";

const phone = window.matchMedia?.("(max-width: 720px)").matches;

// Every rule starts as its row, closed in the markup. On a wide screen the
// rows open; on a phone they stay rows and the filters fold: the page is a
// list to scan, and a row opens on a tap. A rule the address names opens
// either way, and is scrolled to once the rows above it have their height.
const target = () => (location.hash.startsWith("#rule-") ? document.getElementById(decodeURIComponent(location.hash.slice(1))) : null);
if (phone) {
  const fold = document.querySelector("details.filters-fold");
  if (fold) fold.open = false;
} else {
  for (const d of document.querySelectorAll(".rule-card > details.rule-fold")) d.open = true;
}
{
  const t = target();
  const d = t?.querySelector("details.rule-fold");
  if (d) {
    d.open = true;
    t.scrollIntoView({ block: "start" });
  }
}
window.addEventListener("hashchange", () => {
  const d = target()?.querySelector("details.rule-fold");
  if (d) d.open = true;
});

const form = document.querySelector("[data-rule-filters]");
if (form) {
  const cards = [...document.querySelectorAll(".rule-card")];
  const kinds = [...document.querySelectorAll("[data-rule-kind]")];
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
        (!f.get("link") || d.link === "true") &&
        (!f.get("artifact") || d.artifact === "true");
      c.hidden = !ok;
      if (ok) shown++;
    }
    // A kind with no rule left shown goes too, heading and all.
    for (const k of kinds) k.hidden = !k.querySelector(".rule-card:not([hidden])");
    count.textContent = `${shown} of ${cards.length} rules`;
    none.hidden = shown > 0;
    const note = document.querySelector("[data-tactic-note]");
    if (note) note.hidden = !["T8", "T9"].includes(String(f.get("tactic") ?? ""));
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
      sc = await tools();
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
    if (!sc) await load();
    if (!sc) return;
    if (act === "validate" || act === "save") {
      try {
        const r = JSON.parse(sc.check_rules(await rulesJson(text.value)));
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
        const [base, edited, files] = await scoreBoth(sc, await rulesJson(text.value));
        out.replaceChildren(...renderComparison(base, edited, files));
        say("");
      } catch (e) {
        say("");
        showError(out, e);
      }
    }
  });
}

// ── Test a URL against one rule ─────────────────────────────────────────
let engineRules = null;
async function testEngine() {
  const sc = await engine();
  engineRules ??= await pageRules(sc, null);
  return sc;
}

function testRule(details) {
  const id = details.dataset.ruleTest;
  const input = details.querySelector("input");
  const res = details.querySelector(".rt-out");
  const run = async () => {
    let sc, x;
    try {
      sc = await testEngine();
      x = JSON.parse(sc.unwrap(input.value.trim(), engineRules));
    } catch (e) {
      return showError(res, e);
    }
    const hits = arr(x.hits);
    const mine = hits.filter((h) => h.rule_id === id);
    const others = [...new Set(hits.filter((h) => h.rule_id !== id).map((h) => h.rule_id))];
    const layers = arr(x.layers);
    res.replaceChildren(
      el("p", { class: `verdict ${mine.length ? "ok" : "bad"}` }, mine.length ? `${id} fires` : `${id} does not fire`),
      mine.length ? el("ul", {}, mine.map((h) => el("li", {}, `on layer ${h.layer} (${layers[h.layer]?.via ?? "?"}), +${h.weight}: `, el("code", {}, trunc(sc.defang(String(h.matched ?? "")), 160))))) : null,
      el("p", { class: "hint" }, `Score ${x.score ?? 0} from every rule · target `, el("code", {}, x.target_host ? host(sc, x.target_host) : "unknown"),
        ` · ${layers.length} layer(s)`, others.length ? ` · also fires: ${others.join(", ")}` : ""),
    );
  };
  details.querySelector("[data-test-run]").addEventListener("click", run);
  input.addEventListener("keydown", (e) => e.key === "Enter" && run());
  details.addEventListener("toggle", () => {
    if (details.open) testEngine().catch(() => {});
  }, { once: true });
}
for (const d of document.querySelectorAll("[data-rule-test]")) testRule(d);
