// A set of log files on Check my logs and the workbench: picked several at
// once, as a folder, or dropped (files and folders), with archives unpacked
// in the page (archive.js). The set is read into the module one file at a
// time (inputs_add) and analysed as one input (inputs_analyze), so clusters
// and timing span files. File and entry names are labels shown as text;
// they never reach the module, which numbers files instead (`f2:log-17`).
import { el, BIG_FILE } from "./dom.js";
import { LIMITS, bytesText, needsSet, unpack } from "./archive.js";
import { plural, trunc } from "./fmt.js";

export { needsSet };

const byName = (x, y) => x.name.localeCompare(y.name, "en", { numeric: true });

/** The files of a file input: each by its path in a picked folder, or its name. */
export function picked(input) {
  return [...(input.files ?? [])].map((f) => ({ name: f.webkitRelativePath || f.name, blob: f })).sort(byName);
}

/** Every file under a dropped entry, by its path, until there are `cap`. */
async function walk(entry, path, out, cap) {
  if (out.length >= cap) return;
  if (entry.isFile) {
    const f = await new Promise((res, rej) => entry.file(res, rej));
    out.push({ name: path + entry.name, blob: f });
  } else if (entry.isDirectory) {
    const reader = entry.createReader();
    for (;;) {
      const batch = await new Promise((res, rej) => reader.readEntries(res, rej));
      if (!batch.length) break;
      for (const e of batch) await walk(e, `${path}${entry.name}/`, out, cap);
      if (out.length >= cap) break;
    }
  }
}

/**
 * The files of a drop, folders walked. The entries are taken before the
 * first await: the browser empties the drop's items once its handler
 * returns.
 */
export async function dropped(dt) {
  const entries = [...(dt.items ?? [])].filter((i) => i.kind === "file").map((i) => i.webkitGetAsEntry?.()).filter(Boolean);
  if (!entries.length) return [...(dt.files ?? [])].map((f) => ({ name: f.name, blob: f }));
  const out = [];
  for (const e of entries) {
    try {
      await walk(e, "", out, LIMITS.entries + 1);
    } catch {
      // A file the browser will not hand over is left out.
    }
  }
  return out.sort(byName);
}

/**
 * A drop area: `onDrop(sources)` with the dropped files, folders walked.
 * Only drags that carry files light it up.
 */
export function dropZone(zone, onDrop) {
  const has = (e) => [...(e.dataTransfer?.types ?? [])].includes("Files");
  let depth = 0;
  zone.addEventListener("dragenter", (e) => {
    if (!has(e)) return;
    e.preventDefault();
    depth++;
    zone.classList.add("over");
  });
  zone.addEventListener("dragover", (e) => {
    if (!has(e)) return;
    e.preventDefault();
    e.dataTransfer.dropEffect = "copy";
  });
  zone.addEventListener("dragleave", () => {
    depth = Math.max(0, depth - 1);
    if (!depth) zone.classList.remove("over");
  });
  zone.addEventListener("drop", async (e) => {
    if (!has(e)) return;
    e.preventDefault();
    depth = 0;
    zone.classList.remove("over");
    const files = await dropped(e.dataTransfer);
    if (files.length) await onDrop(files);
  });
}

/**
 * The format Check my logs reads a file in: an access log, unless the
 * text starts as JSON, which the engine then detects (NDJSON or a JSON
 * array). Auto-detection alone reads a short log with a stray line as URL
 * lines.
 */
export const logFormat = (text) => (/^\s*[[{]/.test(text.slice(0, 64)) ? "auto" : "access_log");

/** The file a record came from, by the number its id starts with (`f2:`), or null. */
export function fileOf(id, files) {
  const m = /^f(\d+):/.exec(String(id ?? ""));
  return m ? files?.[Number(m[1]) - 1]?.name ?? null : null;
}

/** "Read 3 files, 12 MB unpacked; now logs.zip/b.log". */
export const progressText = ({ files, bytes, name }) =>
  `Read ${plural(files, "file")}, ${bytesText(bytes)} unpacked${name ? `; now ${trunc(name, 80)}` : ""}…`;

/** Total size of the picked files, packed. */
export const setBytes = (sources) => sources.reduce((n, s) => n + (s.blob?.size ?? s.text?.length ?? 0), 0);

/**
 * Read a set into the module and analyse it as one input. `format(text)`
 * names each file's format; `map` is the field map for every file; `keep`
 * is how many characters of text to keep for a hand-over (0 keeps none).
 * Resolves to `{ out, files, skipped, stopped, kept }`: the analysis
 * (null when no file read), a row per file read, the entries not read with
 * why, the reason the set stopped early (or null), and the texts kept
 * (null when they passed `keep`).
 */
export async function analyseSet(sc, sources, { format, map, rules, keep = 0, onProgress = () => {} }) {
  const files = [], skipped = [];
  let stopped = null, kept = keep ? [] : null, keptChars = 0;
  sc.inputs_clear();
  try {
    for await (const ev of unpack(sources, { onProgress })) {
      if (ev.type === "skip") skipped.push({ name: ev.name, reason: ev.reason });
      else if (ev.type === "stop") stopped = ev.reason;
      else {
        const fmt = format(ev.text);
        const row = JSON.parse(sc.inputs_add(ev.text, fmt, map));
        files.push({ ...row, name: ev.name, bytes: ev.bytes });
        if (kept) {
          keptChars += ev.text.length;
          if (keptChars > keep) kept = null;
          else kept.push({ name: ev.name, text: ev.text });
        }
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
  const out = JSON.parse(sc.inputs_analyze(rules));
  return { out, files, skipped, stopped, kept };
}

const FORMAT_LABEL = { access_log: "access log", ndjson: "NDJSON", json: "JSON", lines: "URL lines" };

/**
 * The per-file summary: a row per file read (its name, the format it was
 * read as, its lines, records and lines skipped, and the first problem),
 * then the entries not read with why, and the reason the set stopped.
 */
export function setSummary({ files, skipped, stopped }) {
  const records = files.reduce((n, f) => n + f.records, 0);
  const rows = files.map((f) => el("tr", {},
    el("td", { class: "file-name", "data-label": "File" }, trunc(f.name, 160)),
    el("td", { "data-label": "Read as" }, FORMAT_LABEL[f.format] ?? String(f.format)),
    el("td", { class: "num", "data-label": "Lines" }, Number(f.lines).toLocaleString()),
    el("td", { class: "num", "data-label": "Records" }, Number(f.records).toLocaleString()),
    el("td", { class: "num", "data-label": "Skipped" }, Number(f.skipped).toLocaleString()),
    el("td", { class: "file-note", "data-label": "First problem" }, f.warnings?.[0] ? trunc(String(f.warnings[0]), 160) : "")));
  return el("details", { class: "file-summary", open: true },
    el("summary", {}, `${plural(files.length, "file")} read, ${plural(records, "record")}${skipped.length ? `; ${skipped.length} not read` : ""}`),
    stopped ? el("p", { class: "warn" }, stopped) : null,
    files.length ? el("div", { class: "scroll" }, el("table", { class: "files" },
      el("thead", {}, el("tr", {}, ["File", "Read as", "Lines", "Records", "Skipped", "First problem"].map((h, i) => el("th", { scope: "col", class: i >= 2 && i <= 4 ? "num" : null }, h)))),
      el("tbody", {}, rows))) : null,
    skipped.length ? [el("p", { class: "hint" }, "Not read:"),
      el("ul", { class: "skipped" }, skipped.slice(0, 200).map((s) => el("li", {}, el("code", {}, trunc(s.name, 160)), `: ${s.reason}`)),
        skipped.length > 200 ? el("li", { class: "hint" }, `and ${skipped.length - 200} more`) : null)] : null);
}

/**
 * The picked set in place of the text box: how many files, their total
 * size and the first names, a Clear button, and a status line for the
 * progress, which it returns.
 */
export function setPanel(box, sources, onClear) {
  const shown = sources.slice(0, 6).map((s) => trunc(s.name, 80));
  const clear = el("button", { type: "button", class: "small" }, "Clear files");
  clear.addEventListener("click", onClear);
  const progress = el("p", { class: "hint", role: "status", "aria-live": "polite" });
  box.replaceChildren(
    el("p", {}, el("strong", {}, `${plural(sources.length, "file")} picked`), `, ${bytesText(setBytes(sources))}: `,
      shown.join(", "), sources.length > shown.length ? ` and ${sources.length - shown.length} more` : ""),
    el("p", { class: "hint" }, "Archives (.zip, .tar, .tar.gz, .tgz, .gz) are unpacked in this page; nothing is uploaded. Each file is read on its own, and all of them are analysed as one."),
    el("div", { class: "row" }, clear),
    progress);
  box.hidden = false;
  return progress;
}

/**
 * Whether a set this big may be read now: true under the 50 MB mark;
 * otherwise the question goes in `status` with a button that calls `go`.
 */
export function bigSetOk(sources, status, go) {
  const n = setBytes(sources);
  if (n <= BIG_FILE) return true;
  const yes = el("button", { type: "button" }, "Read them anyway");
  yes.addEventListener("click", () => {
    status.hidden = true;
    go();
  }, { once: true });
  status.replaceChildren(`These files are about ${Math.round(n / (1024 * 1024))} MB. The page unpacks and analyses them here, which can take a while and slow the tab; it stops at ${bytesText(LIMITS.totalBytes)} unpacked. `, yes);
  status.hidden = false;
  return false;
}
