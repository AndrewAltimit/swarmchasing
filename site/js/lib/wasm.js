// The analysis engine (sc-wasm), loaded once per page and only by pages that
// use it. While it loads, every [data-engine-status] says so and every
// [data-needs-engine] control stays disabled.

import { store } from "./dom.js";

export const RULES_KEY = "swarmchase.rules";
let loading = null;

function status(text, cls) {
  for (const s of document.querySelectorAll("[data-engine-status]")) {
    s.textContent = text;
    s.className = `hint ${cls ?? ""}`.trim();
  }
}

/** Load the engine; resolves to the module's exports. */
export function engine() {
  if (loading) return loading;
  const size = document.body.dataset.engineSize || "1.5 MB";
  status(`Loading analysis engine (~${size})…`, "loading");
  loading = (async () => {
    const mod = await import(new URL("../../pkg/sc_wasm.js", import.meta.url).href);
    await mod.default();
    for (const b of document.querySelectorAll("[data-needs-engine]")) b.disabled = false;
    status("");
    return mod;
  })().catch((e) => {
    status(`The analysis engine did not load: ${e?.message ?? e}`, "warn");
    loading = null;
    throw e;
  });
  return loading;
}

/** The rules edited on the rules page (kept in this browser), or "" for the bundled ones. */
export const editedRules = () => store.get(RULES_KEY) ?? "";

/** Show which rules a page runs, in `node`, when they are edited ones. */
export function rulesNote(sc, node) {
  const edited = editedRules();
  if (!node) return;
  if (!edited) {
    node.hidden = true;
    return;
  }
  let version = "?";
  try {
    version = JSON.parse(sc.check_rules(edited)).version;
  } catch {
    version = "invalid";
  }
  node.hidden = false;
  node.textContent = `Using the rules you edited on the rules page (version ${version}), kept in this browser. Reset them there to use the bundled rules.`;
}

/** A host, defanged. */
export const host = (sc, h) => sc.defang("https://" + String(h ?? "")).slice(8);
