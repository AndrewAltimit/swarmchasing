// Reading a set of files into the module and analysing it as one input,
// without the DOM: the analysis worker (engine-worker.js) runs it, and so
// does the page itself when no worker starts (runner.js). `sc` is the
// tools module's exports. File and entry names stay here as labels; the
// module numbers files instead (`f2:log-17`).
import { unpack } from "./archive.js";

/**
 * The format Check my logs reads a file in: an access log, unless the
 * text starts as JSON, which the engine then detects (NDJSON or a JSON
 * array). Auto-detection alone reads a short log with a stray line as URL
 * lines.
 */
export const logFormat = (text) => (/^\s*[[{]/.test(text.slice(0, 64)) ? "auto" : "access_log");

/**
 * The format each file of a set is read in, from the one picked: under
 * `access_log` a file that starts as JSON is detected (a JSON log beside
 * the access logs); any other is used as it is.
 */
export const formatFor = (picked) => (picked === "access_log" ? logFormat : () => picked);

/** Fewest milliseconds between two progress reports of one stage. */
const PROGRESS_EVERY = 100;

/**
 * Read a set into the module and analyse it as one input. `format` is the
 * format picked (see formatFor); `map` the field map for every file;
 * `keep` how many characters of text to keep for a hand-over (0 keeps
 * none); `cancelled()` is asked between files. `onProgress({ stage,
 * files, bytes, records, name })` reports the stage (`read`, then
 * `analyse`), at most every 100 ms within a stage. Resolves to `{ out,
 * files, skipped, stopped, kept }`: the analysis as the module's JSON text
 * (null when no file read), a row per file read, the entries not read with
 * why, the reason the set stopped early (or null), and the texts kept
 * (null when they passed `keep`).
 */
export async function readSet(sc, sources, { format = "auto", map = "", rules = "", keep = 0, cancelled = () => false, onProgress = () => {} } = {}) {
  const fmtOf = formatFor(format);
  const files = [], skipped = [];
  let stopped = null, kept = keep ? [] : null, keptChars = 0, records = 0, last = 0;
  const report = (p, force = false) => {
    const now = Date.now();
    if (!force && now - last < PROGRESS_EVERY) return;
    last = now;
    onProgress({ stage: "read", ...p, records });
  };
  sc.inputs_clear();
  try {
    for await (const ev of unpack(sources, { onProgress: (p) => report(p) })) {
      if (cancelled()) throw new Cancelled();
      if (ev.type === "skip") skipped.push({ name: ev.name, reason: ev.reason });
      else if (ev.type === "stop") stopped = ev.reason;
      else {
        const row = JSON.parse(sc.inputs_add(ev.text, fmtOf(ev.text), map));
        records += Number(row.records) || 0;
        files.push({ ...row, name: ev.name, bytes: ev.bytes });
        if (kept) {
          keptChars += ev.text.length;
          if (keptChars > keep) kept = null;
          else kept.push({ name: ev.name, text: ev.text });
        }
        report({ files: files.length, bytes: files.reduce((n, f) => n + f.bytes, 0), name: ev.name });
      }
    }
  } catch (e) {
    sc.inputs_clear();
    throw e;
  }
  if (!files.length) {
    sc.inputs_clear();
    return { out: null, files, skipped, stopped, kept };
  }
  onProgress({ stage: "analyse", files: files.length, records });
  const out = sc.inputs_analyze(rules);
  return { out, files, skipped, stopped, kept };
}

/** An analysis the visitor stopped. */
export class Cancelled extends Error {
  constructor() {
    super("The analysis was cancelled.");
    this.name = "Cancelled";
  }
}
