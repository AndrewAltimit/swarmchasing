// Attribution layers as a table, shared by the bundle viewer and the
// workbench. Party names come from records and claims: inserted as text.
import { el } from "./dom.js";
import { arr, trunc } from "./fmt.js";

export const LAYERS = [
  ["developer", "Developer and operator"],
  ["host", "Hosting and runtime"],
  ["harness", "Harness and framework"],
  ["model_family", "Model family"],
];
export const EVIDENCE = {
  self_id: "self-identification", hosting_asn: "hosting network (ASN)", shared_identifiers: "identifiers shared with a confirmed incident",
  provider_infrastructure: "provider infrastructure", provider_confirmed: "confirmed by the provider",
};
const word = (s) => String(s ?? "").replace(/[^a-z_]/g, "");
const cap = (s) => (s ? s[0].toUpperCase() + s.slice(1) : s);

/** One row group per layer; a layer with no candidate says so. */
export function layersTable(layers) {
  layers = arr(layers);
  const rows = LAYERS.flatMap(([id, heading]) => {
    const mine = layers.filter((l) => l.layer === id);
    if (!mine.length) return [el("tr", {}, el("th", { scope: "row" }, heading), el("td", { colspan: 4, class: "hint" }, "no candidate"))];
    return mine.map((l, i) => el("tr", {},
      i === 0 ? el("th", { scope: "row", rowspan: mine.length }, heading) : null,
      el("td", {}, trunc(String(l.party ?? ""), 80), l.nameable ? null : el("span", { class: "hint" }, " (never named on this alone)")),
      el("td", {}, el("span", { class: `conf ${word(l.label)}` }, cap(word(l.label))), l.likelihood_word ? el("span", { class: "hint" }, ` ${trunc(String(l.likelihood_word), 30)}`) : null),
      el("td", {}, EVIDENCE[l.evidence] ?? trunc(String(l.evidence ?? ""), 40)),
      el("td", {}, el("span", { class: `claim-tag ${word(l.tag)}` }, cap(word(l.tag)))),
    ));
  });
  return el("div", { class: "scroll" }, el("table", { class: "layers" },
    el("thead", {}, el("tr", {}, ["Layer", "Party or candidate", "Label", "Evidence", "Tag"].map((h) => el("th", { scope: "col" }, h)))),
    el("tbody", {}, rows)));
}
