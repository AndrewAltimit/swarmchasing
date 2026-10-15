// Sharing sightings (SC-Sightings v1) from the workbench. The tools module
// turns the shown analysis into a sightings document; the page shows the
// exact text, and only a press on Download saves it, to this computer.
// Nothing is sent: the page has no way to send it anywhere.
import { $, el, download } from "./dom.js";
import { plural } from "./fmt.js";

const IDLE = "Analyse records, then press Prepare to see exactly what a sightings file would hold.";
let doc = null; // the text last shown, which is what Download saves
let seq = 0;

/** Clear the preview (a new analysis, or none). */
export function resetSightings() {
  seq++;
  doc = null;
  $("sight-preview").textContent = IDLE;
  $("sight-summary").replaceChildren();
  $("sight-dl").disabled = true;
}

/** What the document holds and leaves out, in a few lines. */
function summary(s) {
  const list = Array.isArray(s.sightings) ? s.sightings : [];
  const features = list.reduce((n, x) => n + (Array.isArray(x.features) ? x.features.length : 0), 0);
  const hours = list.reduce((n, x) => n + (Array.isArray(x.hours) ? x.hours.length : 0), 0);
  const items = [
    el("li", {}, `${plural(list.length, "flagged cluster")}, each with its tier, agent grade, record count and the hours it was active (UTC): ${plural(hours, "hour bucket")} in all.`),
    el("li", {}, `${plural(features, "keyed hash", "keyed hashes")} of run tags, inbox ids and captured secrets: the values themselves are not in the file.`),
    el("li", {}, "How the requests were made: relay stacks, payload variants, rule ids, tactics, header-name fingerprints and client networks (ASN only)."),
    el("li", {}, s.shares_hosts ? "Your host names, defanged, as you chose." : "No host names: tick the box above to include yours."),
    el("li", {}, "Never: URLs, paths, query values, IP addresses, user agents, cookies, or any visitor's request."),
  ];
  const out = [el("ul", {}, ...items)];
  if (Array.isArray(s.missing_epochs) && s.missing_epochs.length) {
    out.push(el("p", { class: "warn" }, `No published key yet for ${s.missing_epochs.join(", ")}: features from those quarters are left out. A newer copy of the toolkit may have the key.`));
  }
  if (!list.length) out.push(el("p", { class: "hint" }, "No cluster reached the suggestive tier, so there is nothing to share."));
  return out;
}

/**
 * Wire the panel. `prepared` resolves to an object whose `sightings(opts)`
 * gives the file (text, or a promise of it) from the analysis shown, or to
 * null when there is none.
 */
export function sightingsPanel(prepared) {
  resetSightings();
  const render = async () => {
    const my = ++seq;
    $("sight-dl").disabled = true;
    doc = null;
    const t = await prepared().catch((e) => {
      if (my === seq) $("sight-preview").textContent = String(e?.message ?? e);
      return undefined;
    });
    if (t === undefined || my !== seq) return;
    if (!t) {
      $("sight-preview").textContent = IDLE;
      return;
    }
    try {
      const opts = {
        include_hosts: $("sight-hosts").checked,
        operator: $("sight-operator").value.trim() || null,
        generated: new Date().toISOString().slice(0, 10),
      };
      const text = await t.sightings(JSON.stringify(opts));
      if (my !== seq) return;
      doc = text;
      $("sight-preview").textContent = text;
      $("sight-summary").replaceChildren(...summary(JSON.parse(text)));
      $("sight-dl").disabled = false;
    } catch (e) {
      if (my === seq) $("sight-preview").textContent = String(e?.message ?? e);
    }
  };
  $("sight-prepare").addEventListener("click", render);
  // A changed choice re-renders, so the preview is always what downloads.
  $("sight-hosts").addEventListener("change", () => doc !== null && render());
  $("sight-operator").addEventListener("input", () => doc !== null && render());
  $("sight-dl").addEventListener("click", () => doc && download("swarmchase-sightings.json", doc, "application/json"));
}
