// Notices index: filter the pre-rendered rows. Reads data attributes only.
const form = document.querySelector("[data-notice-filters]");
if (form) {
  const rows = [...document.querySelectorAll(".notice-table tbody tr")];
  const count = document.querySelector("[data-notice-count]");
  const none = document.querySelector("[data-notice-none]");
  const norm = (s) => String(s ?? "").toLowerCase().replaceAll("[.]", ".");
  const apply = () => {
    const f = Object.fromEntries(new FormData(form));
    const host = norm(f.host).trim();
    const q = norm(f.q).trim();
    let shown = 0;
    for (const r of rows) {
      const d = r.dataset;
      const ok =
        (!f.status || d.status === f.status) &&
        (!f.provider || d.providers.split("\n").includes(f.provider)) &&
        (!host || norm(d.hosts).includes(host)) &&
        (!q || norm(d.text).includes(q)) &&
        (!f.from || d.updated >= f.from) &&
        (!f.to || d.updated <= f.to);
      r.hidden = !ok;
      if (ok) shown++;
    }
    count.textContent = `${shown} of ${rows.length} notices`;
    none.hidden = shown > 0;
  };
  form.addEventListener("input", apply);
  form.addEventListener("submit", (e) => e.preventDefault());
  apply();
}
