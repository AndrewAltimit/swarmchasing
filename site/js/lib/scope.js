// A cluster's scope assessment (SC-FM chapter 15): the four independent
// questions, the task and target classes, and the S1–S7 tests with the
// records each rests on. Payload present is observed; out of scope is an
// inference from the tests, and tool use alone fails none of them, so the
// two are drawn differently. Test details are record-derived: `safe`
// defangs and cuts them, and they go in as text.
import { el } from "./dom.js";
import { arr, obj, num } from "./fmt.js";

export const SCOPE_TESTS = {
  S1: "Off-task target",
  S2: "Control circumvention",
  S3: "Sensitive paths",
  S4: "Unsanctioned probing",
  S5: "Identity and credentials",
  S6: "Data sent out",
  S7: "Coordination",
};
const TASKS = {
  data_retrieval: "data retrieval", search_reading: "search and reading", account_setup: "account setup",
  site_testing: "testing of a named site", unclear: "unclear",
};
const TARGETS = {
  public_content: "public content", interactive: "interactive", access_controlled: "access-controlled",
  sensitive: "sensitive", third_party_channel: "third-party channel", benchmark: "benchmark",
};
const FINDINGS = { in_scope: "in scope", scope_exceeded: "scope exceeded", not_assessable: "not assessable" };
const OUTCOMES = { pass: "pass", fail: "fail", not_assessable: "not assessable" };
const words = (map, k) => map[k] ?? String(k ?? "?").replace(/_/g, " ").slice(0, 40);
const cls = (k) => String(k ?? "").replace(/[^a-z_]/g, "");

/**
 * The four FM-15.1 questions as separate chips. Payload and agent are
 * answered by the tier and the grade; out of scope by the tests;
 * coordination by the interaction hints.
 */
export function scopeQuestions(s) {
  s = obj(s);
  const q = (key, label, yes, how) =>
    el("li", { class: `sq sq-${key} ${yes ? "yes" : "no"}` },
      el("span", { class: "sq-label" }, label), el("span", { class: "sq-ans" }, yes ? "yes" : "no"), el("span", { class: "sq-how" }, how));
  return el("ul", { class: "scope-qs", "aria-label": "Four questions" },
    q("payload", "Payload present", !!s.payload_present, "observed: the tier"),
    q("agent", "Agent present", !!s.agent_present, "the agent grade, L4 or above"),
    q("scope", "Out of scope", !!s.out_of_scope, "inference: the tests below"),
    q("coord", "Coordinated", !!s.coordinated, "an interaction hint touches it"));
}

/**
 * The scope section for one cluster. `pick(i)` selects a record (null for
 * no buttons); `fmLink` is a node linking FM chapter 15, or null.
 */
export function scopePanel(scope, { safe, pick = null, fmLink = null } = {}) {
  const s = obj(scope);
  const tests = arr(s.tests);
  const head = el("h4", {}, "Scope", el("span", { class: `scope-finding f-${cls(s.finding)}` }, words(FINDINGS, s.finding)));
  if (!tests.length) {
    return el("section", { class: "ctx-section scope-box", "aria-label": "Scope" }, head,
      el("p", { class: "hint" }, "No scope assessment for this cluster."));
  }
  const targets = Object.entries(obj(s.target_classes)).filter(([, n]) => num(n));
  const refs = (t) => {
    const recs = arr(t.records).filter((i) => Number.isInteger(i));
    if (!recs.length) return el("span", { class: "hint" }, "–");
    const shown = recs.slice(0, 8).map((i) => {
      if (!pick) return el("span", { class: "chip" }, `#${i}`);
      const b = el("button", { type: "button", class: "chip-btn rec-ref", "aria-label": `Select record ${i}` }, `#${i}`);
      b.addEventListener("click", () => pick(i));
      return b;
    });
    return [shown, recs.length > 8 ? el("span", { class: "hint" }, ` +${recs.length - 8} more`) : null];
  };
  // A list, not a table: the context pane is narrow.
  const items = tests.map((t) => el("li", { class: `st st-${cls(t.outcome)}` },
    el("div", { class: "st-head" },
      el("strong", {}, safe(t.id, 4)), ` ${words(SCOPE_TESTS, t.id)} `,
      el("span", { class: `outcome o-${cls(t.outcome)}` }, words(OUTCOMES, t.outcome))),
    el("div", { class: "st-detail" }, safe(t.detail ?? "", 200)),
    arr(t.records).length ? el("div", { class: "st-recs" }, el("span", { class: "hint" }, "Records: "), refs(t)) : null));
  return el("section", { class: "ctx-section scope-box", "aria-label": "Scope" },
    head,
    el("p", { class: "hint" }, "Four separate questions. A payload or a relay is tool use, not misbehaviour: whether the activity went beyond its evident task is judged only by the tests. An inference for review: never scored, never linked on.", fmLink ? [" ", fmLink] : null),
    scopeQuestions(s),
    el("dl", { class: "kv" },
      el("dt", {}, "Evident task"), el("dd", {}, words(TASKS, s.task_class)),
      el("dt", {}, "Targets reached"), el("dd", {}, targets.length ? targets.map(([k, n]) => el("span", { class: "chip" }, `${words(TARGETS, k)} ×${n}`)) : el("span", { class: "hint" }, "none recorded"))),
    el("ol", { class: "scope-tests", "aria-label": "Scope tests S1 to S7" }, items));
}
