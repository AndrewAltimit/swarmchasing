// Bundled rules against edited rules on the labelled set: tiers, what moved,
// and what is still misclassified. Used by the rules editor and the
// evaluation page. Record ids and rule ids are text; URLs arrive defanged.

import { el, fetchRoot } from "./dom.js";
import { arr, pct, trunc, wilson } from "./fmt.js";

const TIER_RANK = { noise: 0, suggestive: 1, significant: 2 };
const pill = (t) => el("span", { class: `pill ${String(t).replace(/[^a-z]/g, "")}` }, String(t));
const chips = (list) => list.map((x) => el("span", { class: "chip" }, x));
const ci = (k, n) => {
  const w = wilson(k, n);
  return w ? `${(w[0] * 100).toFixed(1)}–${(w[1] * 100).toFixed(1)}%` : "n/a";
};

let set = null;
/** The labelled set the site serves: { files, ndjson }. */
export async function labelledSet() {
  set ??= await fetchRoot("assets/eval-set.json");
  return set;
}

/** Score both rule sets; returns [bundled, edited]. */
export async function scoreBoth(sc, editedJson) {
  const s = await labelledSet();
  const base = JSON.parse(sc.eval_labelled("", s.ndjson));
  const edited = JSON.parse(sc.eval_labelled(editedJson, s.ndjson));
  return [base, edited, s.files];
}

export function renderComparison(base, edited, files) {
  const parts = [
    el("p", { class: "hint" }, `${base.labelled ?? 0} labelled records (${base.agents ?? 0} agent, ${base.benign ?? 0} benign) from ${arr(files).join(", ")}. The rules were tuned on this set: a regression floor, not an estimate of real-world precision.`),
  ];
  const tierRows = (name, r, other) => {
    const th = new Map(arr(other?.thresholds).map((t) => [t.tier, t]));
    return arr(r.thresholds).map((t) => {
      const o = th.get(t.tier);
      const cell = (k, text) => el("td", { class: o && o[k] !== t[k] ? "num changed" : "num" }, text);
      return el("tr", {},
        el("th", { scope: "row" }, `${t.tier} or above`), el("td", {}, name),
        cell("tp", t.tp ?? 0), cell("fp", t.fp ?? 0), cell("fn", t.fn ?? 0),
        cell("precision", pct(t.precision)), el("td", { class: "num hint" }, ci(t.tp, t.tp + t.fp)),
        cell("recall", pct(t.recall)), el("td", { class: "num hint" }, ci(t.tp, t.tp + t.fn)));
    });
  };
  parts.push(el("div", { class: "scroll" }, el("table", {},
    el("thead", {}, el("tr", {}, ["Threshold", "Rules", "TP", "FP", "FN", "Precision", "95% CI", "Recall", "95% CI"].map((h) => el("th", { scope: "col" }, h)))),
    el("tbody", {}, tierRows(`bundled ${base.rules_version ?? ""}`, base, null), tierRows(`edited ${edited.rules_version ?? ""}`, edited, base)))));

  // Records whose tier moved. Up on an agent record, or down on a benign one, is better.
  const before = new Map(arr(base.records).map((r) => [r.id, r]));
  const moved = arr(edited.records).map((r) => [before.get(r.id), r]).filter(([b, r]) => b && b.tier !== r.tier);
  const rescored = arr(edited.records).filter((r) => {
    const b = before.get(r.id);
    return b && b.tier === r.tier && b.score !== r.score;
  }).length;
  parts.push(el("h3", {}, "What changed"));
  if (!moved.length) parts.push(el("p", { class: "hint" }, `No labelled record changed tier.${rescored ? ` ${rescored} changed score within its tier.` : ""}`));
  else {
    parts.push(el("ul", { class: "changes" }, moved.map(([b, r]) => {
      const up = TIER_RANK[r.tier] > TIER_RANK[b.tier];
      const better = (r.label === "agent") === up;
      return el("li", {}, el("span", { class: better ? "better" : "worse" }, better ? "better" : "worse"),
        ` ${trunc(String(r.id), 80)} (${r.label}): ${b.tier} ${b.score} → ${r.tier} ${r.score} `, el("code", {}, trunc(String(r.url ?? ""), 140)));
    })));
    if (rescored) parts.push(el("p", { class: "hint" }, `${rescored} more changed score within their tier.`));
  }
  const mis = arr(edited.misclassified);
  parts.push(el("h3", {}, `Misclassified with the edited rules (${mis.length})`));
  parts.push(el("p", { class: "hint" }, "Benign records flagged suggestive or above, and agent records left as noise."));
  if (mis.length) {
    parts.push(el("div", { class: "scroll" }, el("table", {},
      el("thead", {}, el("tr", {}, ["Record", "Label", "Tier", "Score", "Rules", "URL (defanged)"].map((h) => el("th", { scope: "col" }, h)))),
      el("tbody", {}, mis.slice(0, 200).map((m) => el("tr", {},
        el("td", {}, trunc(String(m.id ?? ""), 80)), el("td", { class: "nowrap" }, String(m.label ?? "")), el("td", {}, pill(m.tier ?? "noise")),
        el("td", { class: "num" }, m.score ?? 0), el("td", {}, chips(arr(m.rules).map((x) => trunc(String(x), 40)))),
        el("td", { class: "url" }, trunc(String(m.url ?? ""), 160))))))));
  }
  return parts;
}
