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

/** The rules edited on the rules page (TOML, kept in this browser), or "". */
export const editedRules = () => store.get(RULES_KEY) ?? "";

// The engine reads rules as JSON. Edited rules are TOML, so a second, small
// module converts them; it loads only when there are edited rules.
let rulesModule = null;
/** Rules TOML as the engine's JSON; empty stays empty (the bundled rules). Throws on a TOML error. */
export async function rulesJson(toml) {
  if (!toml || !toml.trim()) return "";
  rulesModule ??= (async () => {
    const m = await import(new URL("../../pkg-rules/sc_rules_wasm.js", import.meta.url).href);
    await m.default();
    return m;
  })().catch((e) => {
    rulesModule = null;
    throw e;
  });
  return (await rulesModule).rules_json(toml);
}

/**
 * The rules a page runs: the edited ones as JSON when they convert and
 * compile, else the bundled ones. Says which in `node`.
 */
export async function pageRules(sc, node) {
  const edited = editedRules();
  if (!edited) {
    if (node) node.hidden = true;
    return "";
  }
  let json = "", msg;
  try {
    json = await rulesJson(edited);
    const v = JSON.parse(sc.check_rules(json)).version;
    msg = `Using the rules you edited on the rules page (version ${v}), kept in this browser. Reset them there to use the bundled rules.`;
  } catch (e) {
    json = "";
    msg = `Your edited rules do not load (${e?.message ?? e}); using the bundled rules. Fix or reset them on the rules page.`;
  }
  if (node) {
    node.hidden = false;
    node.textContent = msg;
  }
  return json;
}

/** A host, defanged. */
export const host = (sc, h) => sc.defang("https://" + String(h ?? "")).slice(8);
