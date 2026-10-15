// A set of log files on Check my logs and the workbench: picked several at
// once, as a folder, or dropped (files and folders), with archives unpacked
// in the page (archive.js). The set is read into the module one file at a
// time (inputs_add) and analysed as one input (inputs_analyze), so clusters
// and timing span files; inputs.js does that, in the analysis worker or on
// the page (runner.js). File and entry names are labels shown as text;
// they never reach the module, which numbers files instead (`f2:log-17`).
import { el, BIG_FILE } from "./dom.js";
import { LIMITS, bytesText, needsSet, unpackedEstimate } from "./archive.js";
import { logFormat, RECORD_LIMIT } from "./inputs.js";
import { plural, trunc } from "./fmt.js";

export { needsSet, logFormat };

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

/** The file a record came from, by the number its id starts with (`f2:`), or null. */
export function fileOf(id, files) {
  const m = /^f(\d+):/.exec(String(id ?? ""));
  return m ? files?.[Number(m[1]) - 1]?.name ?? null : null;
}

/**
 * A progress report as a line: "Read 3 files, 12 MB unpacked, 4,210
 * records; now logs.zip/b.log…" while reading, "…; parsing big.log (40
 * MB)…" while a long file is parsed, "Analysing 4,210 records from 3
 * files…" after.
 */
export function progressText({ stage, files = 0, bytes = 0, records = 0, name, size = 0 }) {
  if (stage === "load") return "Starting the analysis engine…";
  if (stage === "analyse") return files ? `Analysing ${plural(records, "record")} from ${plural(files, "file")}…` : "Analysing…";
  if (stage === "check") return "Checking declared agents…";
  if (stage === "parse") return `Read ${plural(files, "file")}, ${plural(records, "record")}; parsing ${trunc(name ?? "", 80)} (${bytesText(size)})…`;
  return `Read ${plural(files, "file")}, ${bytesText(bytes)} unpacked, ${plural(records, "record")}${name ? `; now ${trunc(name, 80)}` : ""}…`;
}

/** What a screen reader hears of a stage: once per stage, not every update. */
const STAGE_SAID = { load: "Starting the analysis.", read: "Reading the files.", analyse: "Analysing the records.", check: "Checking declared agents." };

/**
 * The progress of a running analysis, put after `anchor`: a bar, the
 * stage with its counts, and a Cancel button that calls `onCancel`. The
 * line updates as reports arrive; a hidden status region says each stage
 * once and the outcome, so a screen reader is not read every count.
 * Returns `{ show(progress), end(text) }`; `end` hides the bar and says
 * the outcome.
 */
export function runProgress(anchor, onCancel) {
  const line = el("span", { class: "run-stage" });
  const bar = el("progress", { "aria-hidden": "true" });
  const cancel = el("button", { type: "button", class: "small" }, "Cancel");
  const box = el("div", { class: "run-progress", hidden: true }, bar, line, cancel);
  const said = el("p", { class: "sr-only", role: "status", "aria-live": "polite", "aria-atomic": "true" });
  anchor.after(box, said);
  let stage = null;
  cancel.addEventListener("click", () => {
    cancel.disabled = true;
    onCancel();
  });
  return {
    show(p) {
      if (box.hidden) {
        box.hidden = false;
        cancel.disabled = false;
      }
      line.textContent = progressText(p);
      // A long file's parse line is part of reading, not a stage of its own.
      const now = p.stage === "parse" ? "read" : p.stage;
      if (now !== stage) {
        stage = now;
        said.textContent = STAGE_SAID[stage] ?? "";
      }
    },
    end(text = "") {
      // Focus on Cancel would be lost with the box: it goes back to the anchor's row.
      const had = box.contains(document.activeElement);
      box.hidden = true;
      stage = null;
      said.textContent = text;
      if (had) anchor.querySelector("button")?.focus();
    },
  };
}

/** Total size of the picked files, packed. */
export const setBytes = (sources) => sources.reduce((n, s) => n + (s.blob?.size ?? s.text?.length ?? 0), 0);

let summaries = 0; // ids for the skipped lists' labels

const FORMAT_LABEL = { access_log: "access log", ndjson: "NDJSON", json: "JSON", lines: "URL lines" };

/** Most file rows the summary lists; the rest are counted. */
const FILE_ROWS = 100;
/** The summary opens by itself up to this many files. */
const OPEN_FILES = 24;

/** A file worth a look: something in it was not read, or nothing was. */
const troubled = (f) => Boolean(f.warning_count || f.skipped || f.cut || !f.records);

/**
 * The per-file summary: a row per file read (its name, the format it was
 * read as, its lines, records and lines skipped, and the first problem),
 * files with a problem first and at most 100 rows, then the entries not
 * read with why, and the reason the set stopped. It opens by itself for a
 * few dozen files or fewer.
 */
export function setSummary({ files, skipped, stopped }) {
  const records = files.reduce((n, f) => n + f.records, 0);
  const worth = files.filter(troubled);
  const listed = [...worth, ...files.filter((f) => !troubled(f))].slice(0, FILE_ROWS);
  const rows = listed.map((f) => el("tr", {},
    el("td", { class: "file-name", "data-label": "File" }, trunc(f.name, 160)),
    el("td", { "data-label": "Read as" }, FORMAT_LABEL[f.format] ?? String(f.format)),
    el("td", { class: "num", "data-label": "Lines" }, Number(f.lines).toLocaleString()),
    el("td", { class: "num", "data-label": "Records" }, Number(f.records).toLocaleString()),
    el("td", { class: "num", "data-label": "Skipped" }, Number(f.skipped).toLocaleString()),
    el("td", { class: "file-note", "data-label": "First problem" }, f.warnings?.[0] ? trunc(String(f.warnings[0]), 160) : f.cut ? "read up to the record limit" : "")));
  const more = files.length - listed.length;
  const moreWorth = Math.max(0, worth.length - FILE_ROWS);
  // Why the set stopped stays in sight when the list is folded.
  return el("div", {}, stopped ? el("p", { class: "warn" }, stopped) : null, el("details", { class: "file-summary", open: files.length <= OPEN_FILES },
    el("summary", {}, `${plural(files.length, "file")} read, ${plural(records, "record")}${skipped.length ? `; ${skipped.length.toLocaleString()} not read` : ""}`),
    files.length ? el("div", { class: "scroll", tabindex: "0", role: "region", "aria-label": "Files read" }, el("table", { class: "files cards" },
      el("caption", { class: "sr-only" }, "Files read, with the format each was read as and its counts"),
      el("thead", {}, el("tr", {}, ["File", "Read as", "Lines", "Records", "Skipped", "First problem"].map((h, i) => el("th", { scope: "col", class: i >= 2 && i <= 4 ? "num" : null }, h)))),
      el("tbody", {}, rows))) : null,
    more > 0 ? el("p", { class: "hint" }, `And ${plural(more, "more file")}, ${moreWorth ? `${moreWorth.toLocaleString()} of them with a problem` : "each read without a problem"}.`) : null,
    skipped.length ? [el("p", { class: "hint", id: `skipped-h-${++summaries}` }, "Not read:"),
      el("ul", { class: "skipped", "aria-labelledby": `skipped-h-${summaries}` }, skipped.slice(0, 200).map((s) => el("li", {}, el("code", {}, trunc(s.name, 160)), `: ${s.reason}`)),
        skipped.length > 200 ? el("li", { class: "hint" }, `and ${(skipped.length - 200).toLocaleString()} more`) : null)] : null));
}

/**
 * The picked set in place of the text box: how many files, their total
 * size and the first names, and a Clear button. The run's progress shows
 * under the page's run button (runProgress).
 */
export function setPanel(box, sources, onClear) {
  const shown = sources.slice(0, 6).map((s) => trunc(s.name, 80));
  const clear = el("button", { type: "button", class: "small" }, "Clear files");
  clear.addEventListener("click", onClear);
  box.replaceChildren(
    el("p", {}, el("strong", {}, `${plural(sources.length, "file")} picked`), `, ${bytesText(setBytes(sources))}: `,
      shown.join(", "), sources.length > shown.length ? ` and ${sources.length - shown.length} more` : ""),
    el("p", { class: "hint" }, "Archives (.zip, .tar, .tar.gz, .tgz, .gz) are unpacked in this page; nothing is uploaded. Each file is read on its own, and all of them are analysed as one."),
    el("div", { class: "row" }, clear));
  box.hidden = false;
}

/**
 * Whether a set this big may be read now: true when it unpacks to under
 * the 50 MB mark, as far as its files say (archive.js unpackedEstimate);
 * otherwise the question goes in `status` with a button that calls `go`.
 */
export async function bigSetOk(sources, status, go) {
  if ((await unpackedEstimate(sources, BIG_FILE)) <= BIG_FILE) return true;
  const n = await unpackedEstimate(sources);
  const yes = el("button", { type: "button" }, "Read them anyway");
  yes.addEventListener("click", () => {
    status.hidden = true;
    go();
  }, { once: true });
  const packed = setBytes(sources);
  const size = n > packed * 1.2 ? `unpack to about ${bytesText(n)}` : `are about ${bytesText(n)}`;
  status.replaceChildren(`These files ${size}. The page unpacks and analyses them here, which can take a while (you can cancel it); it stops at ${bytesText(LIMITS.totalBytes)} unpacked or ${RECORD_LIMIT.toLocaleString("en")} records. `, yes);
  status.hidden = false;
  return false;
}
