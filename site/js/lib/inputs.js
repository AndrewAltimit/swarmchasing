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
 * The most records a set is read to. The module holds every record and the
 * analysis in at most 4 GB of memory, and a record of an ordinary access
 * log costs it a little over 1 kB: this many leave it about a third free.
 * The set stops here, inside the file that reaches it.
 */
export const RECORD_LIMIT = 2_100_000;

/** A file this long gets its own progress line while the module parses it. */
const PARSE_NOTE_CHARS = 4 * 1024 * 1024;

/**
 * Whether `e` is the module failing rather than refusing an input: a trap
 * (`unreachable`, out of memory) or an allocation the engine could not
 * make. A refusal is an Error with the engine's message.
 */
export const engineCrash = (e) =>
  (typeof WebAssembly === "object" && e instanceof WebAssembly.RuntimeError) || e instanceof RangeError || /^(unreachable|out of memory)/i.test(String(e?.message ?? ""));

/** The plain words for an engine that ran out of room. */
export const crashText = (records) =>
  `The analysis ran out of memory in the browser${records ? ` after ${records.toLocaleString("en")} records` : ""}. Split the set into smaller ones, or run the swarmchase CLI, which has no such limit.`;

/**
 * Read a set into the module and analyse it as one input. `format` is the
 * format picked (see formatFor); `map` the field map for every file;
 * `keep` how many characters of text to keep for a hand-over (0 keeps
 * none); `limit` the most records to read (RECORD_LIMIT by default);
 * `cancelled()` is asked between files. `onProgress({ stage, files,
 * bytes, records, name })` reports the stage (`read`, `parse` for a long
 * file, then `analyse`), at most every 100 ms within a stage. Resolves to
 * `{ out, files, skipped, stopped, kept, failed }`: the analysis as the
 * module's JSON text (null when no file read, or the analysis failed), a
 * row per file read, the entries not read with why, the reason the set
 * stopped early (or null), the texts kept (null when they passed
 * `keep`), and, when the module failed, why in plain words (else null).
 */
export async function readSet(sc, sources, { format = "auto", map = "", rules = "", keep = 0, limit = RECORD_LIMIT, cancelled = () => false, onProgress = () => {} } = {}) {
  const fmtOf = formatFor(format);
  const files = [], skipped = [];
  let stopped = null, kept = keep ? [] : null, keptChars = 0, records = 0, bytes = 0, last = 0, failed = null;
  const report = (p, force = false) => {
    const now = Date.now();
    if (!force && now - last < PROGRESS_EVERY) return;
    last = now;
    onProgress({ stage: "read", ...p, records });
  };
  const atLimit = () =>
    `The set holds more than ${limit.toLocaleString("en")} records, as many as the page analyses; it read ${plural(files.length, "file")} up to that many and stopped. Split the set, or run the swarmchase CLI on all of it.`;
  sc.inputs_clear();
  try {
    for await (const ev of unpack(sources, { onProgress: (p) => report(p) })) {
      if (cancelled()) throw new Cancelled();
      if (ev.type === "skip") skipped.push({ name: ev.name, reason: ev.reason });
      else if (ev.type === "stop") stopped ??= ev.reason;
      else {
        if (records >= limit) {
          stopped = atLimit();
          break;
        }
        if (ev.text.length >= PARSE_NOTE_CHARS) onProgress({ stage: "parse", files: files.length, bytes, records, name: ev.name, size: ev.bytes });
        let row;
        try {
          row = JSON.parse(sc.inputs_add(ev.text, fmtOf(ev.text), map, limit - records));
        } catch (e) {
          if (!engineCrash(e)) throw e;
          failed = crashText(records);
          break;
        }
        records += Number(row.records) || 0;
        bytes += ev.bytes;
        files.push({ ...row, name: ev.name, bytes: ev.bytes });
        if (kept) {
          keptChars += ev.text.length;
          if (keptChars > keep) kept = null;
          else kept.push({ name: ev.name, text: ev.text });
        }
        report({ files: files.length, bytes, name: ev.name });
        if (row.cut) {
          stopped = atLimit();
          break;
        }
      }
    }
  } catch (e) {
    sc.inputs_clear();
    throw e;
  }
  if (failed || !files.length) {
    sc.inputs_clear();
    return { out: null, files, skipped, stopped, kept, failed };
  }
  onProgress({ stage: "analyse", files: files.length, records });
  let out = null;
  try {
    out = sc.inputs_analyze(rules);
  } catch (e) {
    if (!engineCrash(e)) throw e;
    failed = crashText(records);
  }
  return { out, files, skipped, stopped, kept, failed };
}

const plural = (n, word) => `${n.toLocaleString("en")} ${word}${n === 1 ? "" : "s"}`;

/** An analysis the visitor stopped. */
export class Cancelled extends Error {
  constructor() {
    super("The analysis was cancelled.");
    this.name = "Cancelled";
  }
}
