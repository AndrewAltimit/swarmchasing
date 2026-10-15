// The shared tooltip (#tip, on every page): text near a node on hover,
// keyboard focus and tap. Text only; it never holds markup. Escape and a
// tap or click outside the node it is for dismiss it (WCAG 1.4.13).

const tipBox = () => document.getElementById("tip");
let owner = null; // the node the shown tooltip is for

function hideTip() {
  const t = tipBox();
  if (t) t.hidden = true;
  owner = null;
}

// Escape with a tooltip shown dismisses it and does nothing else: a page's
// own Escape (the workbench clears its selection) waits for the next press.
document.addEventListener("keydown", (ev) => {
  if (ev.key !== "Escape" || !owner) return;
  const t = tipBox();
  if (t && !t.hidden) {
    hideTip();
    ev.stopPropagation();
  }
}, { capture: true });
document.addEventListener("pointerdown", (ev) => {
  if (owner && !owner.contains(ev.target)) hideTip();
}, { capture: true, passive: true });

/** Show `text()` near `node` on hover, focus and tap. */
export function tip(node, text) {
  const show = (ev) => {
    const t = tipBox();
    if (!t) return;
    owner = node;
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
    if (owner === node) hideTip();
  };
  node.addEventListener("mousemove", show);
  node.addEventListener("mouseleave", hide);
  node.addEventListener("focus", show);
  node.addEventListener("blur", hide);
  node.addEventListener("touchstart", (ev) => show(ev.touches?.[0] ?? null), { passive: true });
  return node;
}
