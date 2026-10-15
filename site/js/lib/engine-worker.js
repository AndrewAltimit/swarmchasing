// The analysis worker: the tools module, run off the page's thread so a
// large set does not freeze the tab. runner.js starts it as a module
// worker and talks to it in messages that carry text and results only:
//
//   in   { id, op: "load" }                          load the module
//        { id, op: "call", fn, args }                 one of CALLS, with string arguments
//        { id, op: "set", sources, opts }             readSet (inputs.js) over picked files
//   out  { id, ok: true, result }                     the call's result (text, or readSet's account)
//        { id, ok: false, error, crash }              its error, as text; crash when the module failed
//        { id, progress: { stage, files, bytes, records, name } }
//
// The worker holds the analysis it made, as the module does on the page,
// so a report, sightings or the identity check follow from it. It touches
// no DOM and makes no request beyond the module's own files.
import { readSet, engineCrash } from "./inputs.js";

/** The module functions the page may call here: the analysis and what reads it. */
const CALLS = new Set(["analyze", "endpoints", "held_results", "report", "sightings", "attribution", "identity_check", "identity_check_held"]);

let mod = null;
const load = () =>
  (mod ??= (async () => {
    const m = await import(new URL("../../pkg/tools/sc_tools.js", import.meta.url).href);
    await m.default();
    return m;
  })().catch((e) => {
    mod = null;
    throw e;
  }));

self.addEventListener("message", async ({ data }) => {
  const { id, op } = data ?? {};
  try {
    const sc = await load();
    let result = null;
    if (op === "call") {
      if (!CALLS.has(data.fn)) throw new Error(`not a call the worker runs: ${String(data.fn)}`);
      result = sc[data.fn](...(data.args ?? []).map(String));
    } else if (op === "set") {
      result = await readSet(sc, data.sources ?? [], { ...data.opts, onProgress: (progress) => self.postMessage({ id, progress }) });
    } else if (op !== "load") {
      throw new Error(`unknown request: ${String(op)}`);
    }
    self.postMessage({ id, ok: true, result });
  } catch (e) {
    self.postMessage({ id, ok: false, error: String(e?.message ?? e), crash: engineCrash(e) });
  }
});
