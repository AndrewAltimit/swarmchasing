// Where the workbench and Check my logs run the analysis: in a module
// worker (engine-worker.js), so a large set leaves the tab responsive and
// can be cancelled, or on the page's own thread when no worker starts. The
// page keeps its own copy of the module for the quick helpers (defang,
// rules and claims checks); the analysis, and everything that reads it
// (endpoints, report, sightings, attribution, the identity check), run
// where the analysis was made. Messages carry text and results only.
import { readSet, Cancelled } from "./inputs.js";

export { Cancelled };

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
        else p.reject(new Error(data.error));
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

  /** Call `fn` of the module with string arguments, where the analysis lives. */
  self.call = async (fn, ...args) => {
    const w = await ready();
    if (w) return post(w, { op: "call", fn, args: args.map(String) });
    const sc = await local();
    return sc[fn](...args.map(String));
  };

  /**
   * Analyse one text: resolves to the module's JSON text. `onProgress`
   * hears the stage (`load`, then `analyse`).
   */
  self.analyze = async (input, format, map, rules, onProgress = () => {}) => {
    stop = false;
    onProgress({ stage: "load" });
    const w = await ready();
    onProgress({ stage: "analyse" });
    if (w) return post(w, { op: "call", fn: "analyze", args: [input, format, map, rules].map(String) });
    const sc = await local();
    await paint();
    if (stop) throw new Cancelled();
    return sc.analyze(input, format, map, rules);
  };

  /**
   * Read a set of files (`{ name, blob | text }`) and analyse it as one;
   * resolves to readSet's account (inputs.js) with `out` parsed. Blobs go
   * to the worker as they are, unread.
   */
  self.readSet = async (sources, opts, onProgress = () => {}) => {
    stop = false;
    onProgress({ stage: "load" });
    const w = await ready();
    const plain = { format: opts.format, map: opts.map, rules: opts.rules, keep: opts.keep ?? 0 };
    const read = w
      ? await post(w, { op: "set", sources: sources.map((s) => ({ name: s.name, blob: s.blob, text: s.text })), opts: plain }, onProgress)
      : await readSet(await local(), sources, { ...plain, cancelled: () => stop, onProgress });
    return { ...read, out: read.out ? JSON.parse(read.out) : null };
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
