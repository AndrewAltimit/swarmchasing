// The agent-likelihood ladder for one cluster: every rung from L0 to L5,
// the signals on each, counter-signals, and the cap that holds a grade
// below what its signals reach. Signal details are record-derived: `safe`
// defangs and cuts them, and they go in as text.
import { el } from "./dom.js";
import { arr, obj, num, plural } from "./fmt.js";
import { AGENT_LEVELS, AGENT_CAPS, levelOf, signalLabel, signalRung, signalGrades, capLabel } from "./hints.js";

const LEVEL_IDS = AGENT_LEVELS.map((l) => l.id);
const rank = (id) => LEVEL_IDS.indexOf(id);

/** The agent-likelihood ladder: every rung, the signals on each, the cap. */
export function agentLadder(ag, safe) {
  ag = obj(ag);
  const level = levelOf(ag.level) ?? AGENT_LEVELS[0];
  const signals = arr(ag.signals);
  const reach = Math.max(0, ...signals.filter((s) => signalGrades(s.kind)).map((s) => rank(signalRung(s.kind))).filter((x) => x >= 0));
  const caps = arr(ag.caps);
  const capAt = caps.length ? Math.min(...caps.map((k) => rank(AGENT_CAPS[k]?.[0])).filter((x) => x >= 0)) : -1;
  const sig = (s) => el("li", {}, signalLabel(s.kind), el("span", { class: "hint" }, ` · ${plural(num(s.records) ?? 0, "record")}${s.detail ? ` · ${safe(s.detail, 120)}` : ""}`));
  const rungs = [...AGENT_LEVELS].reverse().map((l) => {
    const r = rank(l.id);
    const mine = signals.filter((s) => signalRung(s.kind) === l.id);
    const cls = ["rung", r <= rank(level.id) ? "reached" : "", r === rank(level.id) ? "current" : "", r > rank(level.id) && r <= reach ? "held" : ""].filter(Boolean).join(" ");
    return el("li", { class: cls, "aria-current": r === rank(level.id) ? "true" : null },
      el("span", { class: "rung-code" }, l.code), el("span", { class: "rung-label" }, l.label),
      r === rank(level.id) ? el("span", { class: "badge" }, "this cluster") : null,
      r === capAt && r < reach ? el("span", { class: "badge cap" }, "capped here") : null,
      mine.length ? el("ul", { class: "rung-signals" }, mine.map(sig)) : null);
  });
  const notes = [];
  if (caps.length && reach > rank(level.id)) notes.push(el("p", { class: "hint" }, `Signals reach ${AGENT_LEVELS[reach]?.code ?? "?"}; held at ${level.code} by: `, caps.map(capLabel).join("; "), "."));
  else if (caps.length) notes.push(el("p", { class: "hint" }, "Caps on this cluster (none holds it lower here): ", caps.map(capLabel).join("; "), "."));
  if (arr(ag.counter).length) notes.push(el("div", { class: "hint" }, "Counter-signals (what points away from an agent): ", el("ul", {}, arr(ag.counter).map(sig))));
  return el("section", { class: "ladder-box", "aria-label": "Agent likelihood" },
    el("h4", {}, `Agent likelihood: ${level.code} ${level.label}`, el("span", { class: "badge" }, "unmeasured on held-out data")),
    el("p", { class: "hint" }, `${level.meaning} How likely an agent, not a person or a tool, sent the requests: descriptive, never scored or linked on, and not yet measured against held-out labels.`),
    el("ul", { class: "ladder" }, rungs),
    notes);
}

