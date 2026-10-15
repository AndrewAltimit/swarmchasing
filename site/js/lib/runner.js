// Where the workbench and Check my logs run the analysis: in a module
// worker (engine-worker.js), so a large set leaves the tab responsive and
// can be cancelled, or on the page's own thread when no worker starts. The
// page keeps its own copy of the module for the quick helpers (defang,
// rules and claims checks); the analysis, and everything that reads it
// (endpoints, report, sightings, attribution, the identity check), run
// where the analysis was made. Messages carry text and results only.
import { readSet, engineCrash, crashText, Cancelled } from "./inputs.js";

export { Cancelled };

/** The module ran out of room: `message` says so in plain words. */
export class EngineCrash extends Error {
  constructor(message) {
    super(message);
    this.name = "EngineCrash";
  }
}

/**
 * The module's `analyze` result as the pages read it. A large analysis
 * arrives with only the records the pages list (`result_index` gives each
 * one's index among every record; see sc-wasm's engine): they go back to
 * their places in `analysis.results`, which keeps its length (`total`),
 * with gaps where the records not sent are, so an index means one record
 * everywhere. `analysis.result_index` lists the records held, and
 * `analysis.results_omitted` counts the flagged records not sent; both are
 * absent for an analysis sent whole.
 */
export function expand(out) {
  const a = out?.analysis;
  if (!a || !Array.isArray(out.result_index)) return out;
  const sent = Array.isArray(a.results) ? a.results : [];
  const results = [];
  results.length = Number(a.total) || 0;
  out.result_index.forEach((i, k) => {
    results[i] = sent[k];
  });
  a.results = results;
  a.result_index = out.result_index;
  a.results_omitted = Number(out.results_omitted) || 0;
  delete out.result_index;
  delete out.results_omitted;
  return out;
}

/** The indexes of the records an analysis holds: every one, or those sent. */
export const heldIndexes = (a) => a.result_index ?? a.results.map((_, i) => i);

const WORKER = "./engine-worker.js";

// The CSP requires Trusted Types at script sinks, and a worker's script URL
// is one: this policy passes the analysis worker's own URL and nothing else.
let policy;
function workerUrl() {
  const href = new URL(WORKER, import.meta.url).href;
  if (!globalThis.trustedTypes?.createPolicy) return href;
  policy ??= trustedTypes.createPolicy("sc-engine-worker", {
    createScriptURL: (u) => {
      if (u !== href) throw new TypeError("only the analysis worker's own script");
      return u;
    },
  });
  return policy.createScriptURL(href);
}

/**
 * The analysis runner. `local()` resolves to the page's own module, used
 * when no worker starts. Methods resolve to the module's text results;
 * `cancel()` stops the running work (the worker is ended, so whatever it
 * held is gone) and makes every pending call reject with `Cancelled`.
 * `mode` is "worker" or "page" once the first call has started.
 */
export function runner(local) {
  let worker = null;
  let started = null;
  let seq = 0;
  let stop = false; // cancel asked while running on the page
  const pending = new Map();
  const self = { mode: typeof Worker === "function" ? "worker" : "page" };

  const failAll = (err) => {
    for (const p of pending.values()) p.reject(err);
    pending.clear();
  };

  function spawn() {
    return new Promise((resolve, reject) => {
      let w;
      try {
        w = new Worker(workerUrl(), { type: "module" });
      } catch (e) {
        return reject(e);
      }
      worker = w;
      let up = false;
      w.addEventListener("message", ({ data }) => {
        const p = pending.get(data?.id);
        if (!p) return;
        if (data.progress) return p.onProgress?.(data.progress);
        pending.delete(data.id);
        if (data.ok) p.resolve(data.result);
        else p.reject(data.crash ? new EngineCrash(data.error) : new Error(data.error));
      });
      // A worker that never starts (an old browser without module workers,
      // a blocked script) fires error before its first answer.
      w.addEventListener("error", (e) => {
        e.preventDefault?.();
        const err = new Error(e.message || "the analysis worker stopped");
        if (worker === w) worker = null;
        w.terminate();
        if (!up) reject(err);
        else failAll(err);
        started = null;
      });
      const id = ++seq;
      pending.set(id, {
        resolve: () => {
          up = true;
          resolve(w);
        },
        reject,
      });
      w.postMessage({ id, op: "load" });
    });
  }

  /** The worker, started when needed; null when the page runs it instead. */
  async function ready() {
    if (self.mode !== "worker") return null;
    try {
      return await (started ??= spawn());
    } catch (e) {
      // Cancelled while it started: the next call starts another.
      if (e instanceof Cancelled) throw e;
      // No worker, or none that loads the module: the page runs it from
      // now on, and its own loader says so if the module fails there too.
      worker?.terminate();
      worker = null;
      started = null;
      self.mode = "page";
      return null;
    }
  }

  function post(w, msg, onProgress) {
    return new Promise((resolve, reject) => {
      const id = ++seq;
      pending.set(id, { resolve, reject, onProgress });
      w.postMessage({ id, ...msg });
    });
  }

  /**
   * A worker whose module failed holds nothing usable: it is ended, and the
   * next call starts another.
   */
  const crashed = (e) => {
    if (worker && (e instanceof EngineCrash || engineCrash(e))) {
      worker.terminate();
      worker = null;
      started = null;
    }
    return e instanceof EngineCrash || !engineCrash(e) ? e : new EngineCrash(crashText(0));
  };

  /** Call `fn` of the module with string arguments, where the analysis lives. */
  self.call = async (fn, ...args) => {
    try {
      const w = await ready();
      if (w) return await post(w, { op: "call", fn, args: args.map(String) });
      const sc = await local();
      return sc[fn](...args.map(String));
    } catch (e) {
      throw crashed(e);
    }
  };

  /**
   * Analyse one text: resolves to the module's result, parsed and expanded
   * (`expand`). `onProgress` hears the stage (`load`, then `analyse`).
   * Rejects with EngineCrash when the module runs out of room.
   */
  self.analyze = async (input, format, map, rules, onProgress = () => {}) => {
    stop = false;
    onProgress({ stage: "load" });
    const w = await ready();
    onProgress({ stage: "analyse" });
    let text;
    try {
      if (w) text = await post(w, { op: "call", fn: "analyze", args: [input, format, map, rules].map(String) });
      else {
        const sc = await local();
        await paint();
        if (stop) throw new Cancelled();
        text = sc.analyze(input, format, map, rules);
      }
    } catch (e) {
      throw crashed(e);
    }
    return expand(JSON.parse(text));
  };

  /**
   * Read a set of files (`{ name, blob | text }`) and analyse it as one;
   * resolves to readSet's account (inputs.js) with `out` parsed and
   * expanded. Blobs go to the worker as they are, unread. When the module
   * failed, `out` is null, `failed` says why and the worker is ended.
   */
  self.readSet = async (sources, opts, onProgress = () => {}) => {
    stop = false;
    onProgress({ stage: "load" });
    const w = await ready();
    const plain = { format: opts.format, map: opts.map, rules: opts.rules, keep: opts.keep ?? 0 };
    let read;
    try {
      read = w
        ? await post(w, { op: "set", sources: sources.map((s) => ({ name: s.name, blob: s.blob, text: s.text })), opts: plain }, onProgress)
        : await readSet(await local(), sources, { ...plain, cancelled: () => stop, onProgress });
    } catch (e) {
      throw crashed(e);
    }
    if (read.failed) crashed(new EngineCrash(read.failed));
    return { ...read, out: read.out ? expand(JSON.parse(read.out)) : null };
  };

  /**
   * Stop what runs now: the worker is ended (a new one starts on the next
   * call); on the page, a set stops before its next file.
   */
  self.cancel = () => {
    stop = true;
    if (!worker) return;
    worker.terminate();
    worker = null;
    started = null;
    failAll(new Cancelled());
  };

  return self;
}

/** A turn for the page to paint before a long call on its own thread. */
const paint = () =>
  new Promise((r) => {
    if (typeof requestAnimationFrame === "function") requestAnimationFrame(() => setTimeout(r, 0));
    else setTimeout(r, 0);
  });
