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
  co_target: "shared rare targets",
  ordered_co_target: "ordered rare targets",
  scaffold_lineage: "scaffold lineage",
  prompt_echo: "prompt echo",
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

// ── Agent likelihood (SC-FM ladder) ─────────────────────────────────────
// The engine's AgentLevel, SignalKind and AgentCap, in its words. A kind
// this list does not know is shown by its id.
export const AGENT_LEVELS = [
  { id: "payloads_only", code: "L0", label: "payloads only", meaning: "Attack payloads were present; this alone does not show what sent them." },
  { id: "self_described", code: "L1", label: "self-described", meaning: "The requests name a model or vendor, or carry an agent test tag. Anyone can write this." },
  { id: "model_written", code: "L2", label: "model-written", meaning: "The requests carry content a language model writes. A person pasting model output leaves the same." },
  { id: "adaptive", code: "L3", label: "adaptive", meaning: "Model-written requests that change in answer to responses." },
  { id: "agent_likely", code: "L4", label: "agent likely", meaning: "Adaptive, model-written requests at a pace or scale beyond one person." },
  { id: "documented", code: "L5", label: "documented", meaning: "Documented by case work: operator logs matching an agent harness, or the provider's confirmation. Only an admin's case decision sets it." },
];
export const levelOf = (id) => AGENT_LEVELS.find((l) => l.id === id) ?? null;

/** Signal kind → [rung id or null for a counter-signal, label]. */
export const AGENT_SIGNALS = {
  self_id: ["self_described", "names a model or vendor, or carries an agent test tag (anyone can write this)"],
  residue: ["model_written", "model-output residue in requests"],
  prose: ["model_written", "natural-language prose in parameters"],
  fabricated_ids: ["model_written", "identifiers no generator produces"],
  cut_lengths: ["model_written", "URLs cut at one repeated length, like an output limit"],
  stale_knowledge: ["model_written", "retired endpoints or old client versions"],
  stale_dates: ["model_written", "date tags naming a consistent past date"],
  retry_after_error: ["adaptive", "a changed request right after an error response"],
  escalation: ["adaptive", "a route escalation to reach one page"],
  model_pace_chain: ["adaptive", "a probe chain at model pace"],
  machine_pace: ["agent_likely", "retries after errors at tool pace, faster than a person reads"],
  per_fetch_robots: ["agent_likely", "a /robots.txt request before every page, on the same host each time, as an uncached robots-respecting fetch tool sends"],
  rate_ceiling: ["agent_likely", "requests hitting one per-window ceiling again and again and never passing it, as a client-side rate limiter allows"],
  fan_out: ["agent_likely", "parallel fan-out of one fixed width"],
  round_the_clock: ["agent_likely", "activity round the clock"],
  declared_testing: [null, "declares authorised testing or research"],
  benchmark: [null, "public benchmark or practice targets"],
  scanner_pace: [null, "a probe chain at tool pace with no change after errors, as a scanner runs a list"],
  working_hours: [null, "activity in one time zone's working hours"],
};
export const signalLabel = (k) => AGENT_SIGNALS[k]?.[1] ?? (trunc(String(k ?? "?").replace(/_/g, " "), 60) || "?");
export const signalRung = (k) => AGENT_SIGNALS[k]?.[0] ?? null;

/** Cap id → [ceiling level id, label]. */
export const AGENT_CAPS = {
  capture_times: ["model_written", "capture times only: pace, retries and rhythm cannot be read, so the grade stops at L2"],
  human_pace: ["model_written", "a working-hours rhythm at slow pace: possibly human-operated with model help, so the grade stops at L2"],
  working_hours: ["adaptive", "a working-hours rhythm, which an unattended fleet need not keep, so the grade stops at L3"],
};
export const capLabel = (k) => AGENT_CAPS[k]?.[1] ?? trunc(String(k ?? "?").replace(/_/g, " "), 60);

// ── Interaction edges (SC-T9) ───────────────────────────────────────────
export const SWARM_KINDS = {
  shared_sink: { id: "S1", label: "shared sink", what: "runs, or strands of one run, writing to one inbox or artifact while sending requests differently" },
  handoff: { id: "S2", label: "hand-off", what: "an artifact one run writes and a later run fetches" },
  synchronized_start: { id: "S3", label: "synchronized start", what: "runs of different clients whose requests line up step by step at one offset, against two chance models" },
  role_sequence: { id: "S4", label: "role sequence", what: "a run that only reads a set of hosts, then another attacking them in the same order" },
  disjoint_partition: { id: "S5", label: "disjoint partition", what: "runs started together splitting one target family with almost no overlap (alone, a fleet signal)" },
  dispatch_star: { id: "S6", label: "dispatch star", what: "a run that two or more different-client runs each trail at their own consistent lag, as a planner dispatching workers (one upstream trigger does the same)" },
};
export const swarmKind = (k) => SWARM_KINDS[k] ?? { id: "S?", label: trunc(String(k ?? "?").replace(/_/g, " "), 40), what: "" };

// ── Provenance and corroboration ────────────────────────────────────────
export const PROVENANCE = {
  observed: "observed (a server recorded it)",
  "submit-anywhere": "submit-anywhere (anyone can submit the URL)",
  "publish-anywhere": "publish-anywhere (anyone can publish it)",
  reported: "reported (an outside submission states it)",
  unknown: "unknown source",
};
export const provenanceLabel = (k) => PROVENANCE[k] ?? trunc(String(k ?? "?"), 40);
export const CORROBORATION = {
  single_source: "single source",
  multi_source: "several kinds of source",
  operator_confirmed: "confirmed in operator logs",
};
export const corroborationLabel = (k) => CORROBORATION[k] ?? trunc(String(k ?? "?").replace(/_/g, " "), 40);

export const PLANT_KINDS = {
  provenance_monoculture: "provenance monoculture: every record from a service anyone can submit to",
  burned_identifier: "burned identifier: a value quoted in a public report, which anyone can copy",
  too_perfect: "too perfect: significant on many kinds of evidence with nothing ordinary around it",
  habit_mismatch: "habit mismatch: an identifier shared with an earlier cluster that worked differently",
  auto_submitted: "auto-submitted: ordinary links nearby fanned out to the same services, as a mail gateway or security product does",
};
export const plantLabel = (k) => PLANT_KINDS[k] ?? trunc(String(k ?? "?").replace(/_/g, " "), 60);
