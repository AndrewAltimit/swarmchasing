// Unwrap one URL: its layers and the rules each fires, and the score and
// tier the workbench would give it. The URL is never opened; its text is
// shown defanged.
import { $, el, showError } from "../lib/dom.js";
import { trunc } from "../lib/fmt.js";
import { engine, host, pageRules } from "../lib/wasm.js";

// A synthetic record from samples/showcase/: a relay in front of a
// placeholder host, with a request bin as the callback.
const EXAMPLE = "https://r.jina.ai/https://q0.transit-authority.example/schedule?uqtag=ag2y&hook=https://webhook.site/5e8d2c40-3333-4d1e-8f77-6a5b4c3d2e1f";

const sc = await engine();
const rules = await pageRules(sc, $("rules-note"));

const pill = (tier) => el("span", { class: `pill ${String(tier).replace(/[^a-z]/g, "")}` }, String(tier));

/** Why the text is not a URL the engine can read, or null. */
function problem(u) {
  if (!u) return "Paste a URL to unwrap.";
  if (!/^[a-z][a-z0-9+.-]*:/i.test(u)) return "That is not a URL: it has no scheme. Give the whole address, starting with https:// or http://, as it appears in the record.";
  if (!u.includes("://") && !/^data:/i.test(u)) return "That URL has no host after its scheme. Give the whole address, e.g. https://www.example.org/page.";
  return null;
}

/** The score and tier the workbench gives this URL as one record, or null. */
function graded(u) {
  try {
    const out = JSON.parse(sc.analyze(JSON.stringify([{ id: "unwrap", url: u }]), "json", "", rules));
    return out.analysis?.results?.[0] ?? null;
  } catch {
    return null;
  }
}

function run() {
  const out = $("unwrap-out");
  const u = $("unwrap-url").value.trim();
  const bad = problem(u);
  if (bad) return showError(out, bad);
  let x;
  try {
    x = JSON.parse(sc.unwrap(u, rules));
  } catch (e) {
    return showError(out, e);
  }
  const g = graded(u);
  const byLayer = {};
  for (const h of x.hits ?? []) (byLayer[h.layer] ??= []).push(h);
  const noHost = !x.target_host && !(x.layers ?? []).some((l) => l.host);
  out.replaceChildren(...[
    el("p", {}, `Score ${g?.score ?? x.score} `, g ? pill(g.tier) : null, " · target ", el("code", {}, x.target_host ? host(sc, x.target_host) : "unknown")),
    noHost ? el("p", { class: "warn", role: "status" }, "No host found in this URL, so there is no target. Check that it is the whole address.") : null,
    ...(x.layers ?? []).map((l, i) =>
      el("div", { class: `layer d${Math.min(4, Number(l.depth) || 0)}` },
        el("div", { class: "via" }, `[${i}] ${l.via}${l.host ? " · " + host(sc, l.host) : ""}`),
        el("code", {}, sc.defang(trunc(String(l.text ?? ""), 400))),
        el("div", {}, (byLayer[i] ?? []).map((h) => el("span", { class: "chip", title: sc.defang(String(h.matched ?? "")) }, `${h.rule_id} +${h.weight}`))))),
  ].filter((n) => n != null));
}

$("unwrap-run").addEventListener("click", run);
$("unwrap-url").addEventListener("keydown", (e) => e.key === "Enter" && run());
$("unwrap-example").addEventListener("click", () => {
  $("unwrap-url").value = EXAMPLE;
  run();
});
