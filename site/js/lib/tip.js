// The shared tooltip (#tip, on every page): text near a node on hover,
// keyboard focus and tap. Text only; it never holds markup.

const tipBox = () => document.getElementById("tip");

/** Show `text()` near `node` on hover, focus and tap. */
export function tip(node, text) {
  const show = (ev) => {
    const t = tipBox();
    if (!t) return;
    t.textContent = typeof text === "function" ? text() : text;
    t.hidden = false;
    let x, y;
    if (ev && "clientX" in ev && ev.clientX) {
      x = ev.clientX + 12;
      y = ev.clientY + 14;
    } else {
      const r = node.getBoundingClientRect();
      x = r.left + r.width / 2;
      y = r.bottom + 8;
    }
    const w = t.offsetWidth || 200;
    t.style.left = `${Math.max(4, Math.min(x, window.innerWidth - w - 8))}px`;
    t.style.top = `${Math.min(y, window.innerHeight - (t.offsetHeight || 40) - 8)}px`;
  };
  const hide = () => {
    const t = tipBox();
    if (t) t.hidden = true;
  };
  node.addEventListener("mousemove", show);
  node.addEventListener("mouseleave", hide);
  node.addEventListener("focus", show);
  node.addEventListener("blur", hide);
  node.addEventListener("touchstart", (ev) => show(ev.touches?.[0] ?? null), { passive: true });
  return node;
}
