// The WASM modules, each loaded once per page and only when needed:
//
//   engine()  the analysis engine (pkg/sc_wasm.js): analyze, unwrap,
//             endpoints. Pages that analyse load it on arrival; while it
//             loads, every [data-engine-status] says so and every
//             [data-needs-engine] control stays disabled.
//   tools()   the tools module (pkg/tools/sc_tools.js): report drafts, the
//             evidence bundle check, the labelled-set eval. Loaded only when
//             a visitor asks for one of those.
//   rules     the rules converter (pkg-rules), only for edited rules.
//
// Both engine and tools carry check_rules and defang.

import { store } from "./dom.js";

export const RULES_KEY = "swarmchase.rules";

function status(text, cls) {
  for (const s of document.querySelectorAll("[data-engine-status]")) {
    s.textContent = text;
    s.className = `hint ${cls ?? ""}`.trim();
  }
}

/** A loader for one module: resolves to its exports, retrying after a failure. */
function loader(path, what, sizeKey, fallback) {
  let loading = null;
  return () => {
    if (loading) return loading;
    const size = document.body.dataset[sizeKey] || fallback;
    status(`Loading ${what} (~${size})…`, "loading");
    loading = (async () => {
      const mod = await import(new URL(path, import.meta.url).href);
      await mod.default();
      for (const b of document.querySelectorAll("[data-needs-engine]")) b.disabled = false;
      status("");
      return mod;
    })().catch((e) => {
      status(`The ${what} did not load: ${e?.message ?? e}`, "warn");
      loading = null;
      throw e;
    });
    return loading;
  };
}

/** Load the analysis engine; resolves to the module's exports. */
export const engine = loader("../../pkg/sc_wasm.js", "analysis engine", "engineSize", "1.3 MB");

/** Load the tools module (reports, bundle check, labelled eval). */
export const tools = loader("../../pkg/tools/sc_tools.js", "report and evaluation tools", "toolsSize", "1.5 MB");

/** The rules edited on the rules page (TOML, kept in this browser), or "". */
export const editedRules = () => store.get(RULES_KEY) ?? "";

// The modules read rules as JSON. Edited rules are TOML, so a third, small
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
 * compile, else the bundled ones. Says which in `node`. `sc` is either
 * module (both check rules).
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
