// The Field Manual's section index: search over the build-time index
// (assets/fm-index.json: ids, titles, chapters, text), matched in this
// page. Every section is already listed as a link; the search only hides
// the ones that do not match, so nothing here builds a URL.
import { fetchRoot } from "../lib/dom.js";
import { arr } from "../lib/fmt.js";

const form = document.querySelector("[data-fm-search]");
if (form) {
  const input = form.querySelector("input[name=q]");
  const count = form.querySelector("[data-fm-count]");
  const none = document.querySelector("[data-fm-none]");
  const items = [...document.querySelectorAll("[data-fm]")];
  const chapters = [...document.querySelectorAll("[data-fm-chapter]")];
  let index = new Map();
  const norm = (s) => String(s ?? "").toLowerCase().normalize("NFKD").replace(/[̀-ͯ]/g, "");
  const apply = () => {
    const words = norm(input.value).split(/\s+/).filter(Boolean);
    let shown = 0;
    for (const li of items) {
      const hay = index.get(li.dataset.fm) ?? norm(li.textContent);
      const ok = words.every((w) => hay.includes(w));
      li.hidden = !ok;
      if (ok) shown++;
    }
    for (const c of chapters) c.hidden = ![...c.querySelectorAll("[data-fm]")].some((li) => !li.hidden);
    count.textContent = words.length ? `${shown} of ${items.length} sections match` : `${items.length} sections`;
    none.hidden = shown > 0;
  };
  form.addEventListener("submit", (e) => e.preventDefault());
  input.addEventListener("input", apply);
  apply();
  fetchRoot("assets/fm-index.json")
    .then((entries) => {
      index = new Map(arr(entries).map((e) => [e.id, norm(`${e.id} ${e.title} ${e.chapter} ${e.text}`)]));
      apply();
    })
    .catch(() => {
      // Without the index, the search still matches ids and titles.
    });
  // A query in the address (#q=...) fills the box: links to a search.
  const q = new URLSearchParams(location.hash.slice(1)).get("q");
  if (q) {
    input.value = q.slice(0, 80);
    apply();
  }
}
