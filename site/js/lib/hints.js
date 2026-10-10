// Names for the analysis's descriptive hints, shared by the workbench and
// the bundle viewer. A kind this list does not know (a newer toolkit's) is
// shown by its id, so new kinds appear without a page change.
import { el } from "./dom.js";
import { arr, obj, num, trunc } from "./fmt.js";

export const SOFT_KINDS = {
  shared_pause: "shared pauses",
  dialect: "payload dialect",
  rerun: "rerun target list",
  preamble: "recon preamble",
  path_set: "unusual path set",
  encoding: "encoding style",
  fan_out: "fan-out width",
  cut_length: "cut length",
  header_set: "header set",
  escalation: "route escalation",
  common_feature: "common feature",
  shared_secret: "shared captured secret",
  relay_stack: "relay stack",
  callback_service: "callback service",
};

/** A safe class suffix and a label for a soft-link kind id. */
export const kindClass = (k) => String(k ?? "").toLowerCase().replace(/[^a-z0-9]+/g, "-").slice(0, 40) || "other";
export const kindLabel = (k) => SOFT_KINDS[k] ?? (trunc(String(k ?? "other").replace(/_/g, " "), 40) || "other");

export const TACTICS = {
  T1: "task retrieval", T2: "tool escalation", T3: "access-control circumvention", T4: "vulnerability probing",
  T5: "account or identity acquisition", T6: "credential reuse", T7: "callback or side channels", T8: "off-task targets", T9: "inter-agent coordination",
};
export const tactic = (t) => `${t} ${TACTICS[t] ?? ""}`.trim();

// Languages the engine's prose guess names (ISO 639-1). An unknown code is
// shown as itself.
export const LANGUAGES = {
  en: "English", de: "German", fr: "French", es: "Spanish", it: "Italian", pt: "Portuguese", nl: "Dutch",
  ru: "Russian", uk: "Ukrainian", el: "Greek", he: "Hebrew", ar: "Arabic", th: "Thai", hi: "Hindi",
  ko: "Korean", ja: "Japanese", zh: "Chinese",
};
export const language = (l) => LANGUAGES[l] ?? (trunc(String(l ?? "?"), 20) || "?");

export const ROUTES = { direct: "direct", relay: "relay", program: "program carrier", remote_browser: "remote browser" };
export const route = (r) => ROUTES[r] ?? trunc(String(r ?? "?").replace(/_/g, " "), 30);

/** Candidate fleets as list items: id, members, kinds, strength. */
export function fleetItems(fleets, idOf = String) {
  return arr(fleets).map((f) => {
    const o = Array.isArray(f) ? { clusters: f } : obj(f);
    const members = arr(o.clusters ?? o.members ?? o.keys).map((x) => idOf(String(x)));
    const kinds = arr(o.kinds).map(kindLabel);
    const s = num(o.strength);
    return el("li", {}, el("strong", {}, trunc(String(o.id ?? "candidate fleet"), 60)), ` ${members.length} clusters: ${members.slice(0, 12).join(", ")}${members.length > 12 ? "…" : ""}`,
      kinds.length ? el("span", { class: "hint" }, ` (${kinds.join(", ")}${s != null ? `; strength ${s.toFixed(2)}` : ""})`) : null);
  });
}
