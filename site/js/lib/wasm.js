// The WASM modules, each loaded once per page and only when needed:
//
//   engine()  the analysis engine (pkg/sc_wasm.js): analyze, unwrap,
//             endpoints. The unwrap page loads it on arrival; while it
//             loads, every [data-engine-status] says so and every
//             [data-needs-engine] control stays disabled.
//   tools()   the tools module (pkg/tools/sc_tools.js): report drafts, the
//             evidence bundle check, the labelled-set eval, and the
//             engine's bindings too. Loaded only when a visitor asks for one
//             of those. Its status goes to [data-tools-status] and it
//             enables [data-needs-tools]; a page without those uses the
//             engine's.
//   workbench()  the tools module under the engine's status lines: the
//             workbench analyses and drafts with it alone, loading it on
//             the first sign of input.
//   rules     the rules converter (pkg-rules), only for edited rules.
//
// Each module reports its own progress and failure, so one that fails to
// load leaves the controls of the other working. A failed load is retried
// on the next call. Both engine and tools carry check_rules and defang.

import { store } from "./dom.js";

export const RULES_KEY = "swarmchase.rules";

/** The elements an attribute marks, or those of `fallback` when there are none. */
function marked(attr, fallback) {
  const own = document.querySelectorAll(`[${attr}]`);
  return own.length || !fallback ? own : document.querySelectorAll(`[${fallback}]`);
}

/** A module's download size as the build measured it, " (about 0.5 MB to download)", or "". */
export function sizeNote(key) {
  const size = document.body.dataset[key];
  return size ? ` (about ${size} to download)` : "";
}

/**
 * A loader for one module: resolves to its exports, retrying after a
 * failure. `status` and `needs` name the attributes of its status lines and
 * of the controls it enables; `fallback` the engine's, for pages that mark
 * only those.
 */
function loader(path, what, sizeKey, status, needs, fallback) {
  let loading = null;
  const say = (text, cls) => {
    for (const s of marked(status, fallback?.status)) {
      s.textContent = text;
      s.classList.toggle("hint", cls !== "warn");
      s.classList.toggle("loading", cls === "loading");
      s.classList.toggle("warn", cls === "warn");
      s.dataset.state = cls === "warn" ? "error" : cls === "loading" ? "loading" : "ready";
    }
  };
  return () => {
    if (loading) return loading;
    say(`Loading the ${what}${sizeNote(sizeKey)}…`, "loading");
    loading = (async () => {
      const mod = await import(new URL(path, import.meta.url).href);
      await mod.default();
      for (const b of marked(needs, fallback?.needs)) {
        b.disabled = false;
        b.removeAttribute("aria-busy");
      }
      say("");
      return mod;
    })().catch((e) => {
      say(`The ${what} did not load: ${e?.message ?? e}. Try again, or reload the page.`, "warn");
      loading = null;
      throw e;
    });
    return loading;
  };
}

const ENGINE = { status: "data-engine-status", needs: "data-needs-engine" };

/** Load the analysis engine; resolves to the module's exports. */
export const engine = loader("../../pkg/sc_wasm.js", "analysis engine", "engineSize", ENGINE.status, ENGINE.needs);

/** Load the tools module (reports, bundle check, labelled eval). */
export const tools = loader("../../pkg/tools/sc_tools.js", "report and evaluation tools", "toolsSize", "data-tools-status", "data-needs-tools", ENGINE);

/**
 * The workbench's module: the tools module, which carries the engine's
 * analysis too, so a page that analyses and then drafts a report downloads
 * one module instead of both. Reports to the engine's status lines.
 */
export const workbench = loader("../../pkg/tools/sc_tools.js", "analysis engine and report tools", "toolsSize", ENGINE.status, ENGINE.needs);

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
