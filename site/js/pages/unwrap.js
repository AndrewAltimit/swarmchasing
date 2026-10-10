// Unwrap one URL: its layers and the rules each fires. The URL is never
// opened; its text is shown defanged.
import { $, el, showError } from "../lib/dom.js";
import { trunc } from "../lib/fmt.js";
import { engine, host, pageRules } from "../lib/wasm.js";

const sc = await engine();
const rules = await pageRules(sc, $("rules-note"));

function run() {
  const out = $("unwrap-out");
  let x;
  try {
    x = JSON.parse(sc.unwrap($("unwrap-url").value.trim(), rules));
  } catch (e) {
    return showError(out, e);
  }
  const byLayer = {};
  for (const h of x.hits ?? []) (byLayer[h.layer] ??= []).push(h);
  out.replaceChildren(
    el("p", {}, `Score ${x.score} · target `, el("code", {}, x.target_host ? host(sc, x.target_host) : "unknown")),
    ...(x.layers ?? []).map((l, i) =>
      el("div", { class: `layer d${Math.min(4, Number(l.depth) || 0)}` },
        el("div", { class: "via" }, `[${i}] ${l.via}${l.host ? " · " + host(sc, l.host) : ""}`),
        el("code", {}, sc.defang(trunc(String(l.text ?? ""), 400))),
        el("div", {}, (byLayer[i] ?? []).map((h) => el("span", { class: "chip", title: sc.defang(String(h.matched ?? "")) }, `${h.rule_id} +${h.weight}`))))),
  );
}

$("unwrap-run").addEventListener("click", run);
$("unwrap-url").addEventListener("keydown", (e) => e.key === "Enter" && run());
