// Formatting helpers. Analysis JSON from older toolkit versions may lack
// newer fields, so pages read everything through arr/obj/num.

export const arr = (x) => (Array.isArray(x) ? x : []);
export const obj = (x) => (x && typeof x === "object" && !Array.isArray(x) ? x : {});
export const num = (x) => (typeof x === "number" && Number.isFinite(x) ? x : null);
export const str = (x) => (x == null ? "" : String(x));

export const fmtTs = (t) => (t > 0 ? new Date(t * 1000).toISOString().replace("T", " ").slice(0, 19) + " UTC" : "unknown");
export const fmtShort = (t) => (t > 0 ? new Date(t * 1000).toISOString().slice(5, 16).replace("T", " ") : "?");
export const dur = (s) => (s < 120 ? `${Math.round(s)}s` : s < 7200 ? `${Math.round(s / 60)}m` : s < 172800 ? `${(s / 3600).toFixed(1)}h` : `${(s / 86400).toFixed(1)}d`);
export const trunc = (s, n) => (s.length > n ? s.slice(0, n) + "…" : s);
export const pct = (x) => (num(x) == null ? "n/a" : `${(x * 100).toFixed(1)}%`);
export const signed = (x) => (x >= 0 ? `+${x}` : `${x}`);
export const plural = (n, one, many = one + "s") => `${n.toLocaleString()} ${n === 1 ? one : many}`;
export const topEntries = (o, n) => Object.entries(obj(o)).sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1)).slice(0, n);

/** The 95% Wilson score interval for k of n, or null. */
export function wilson(k, n) {
  if (!n) return null;
  const z = 1.959963984540054;
  const p = k / n;
  const d = 1 + (z * z) / n;
  const c = (p + (z * z) / (2 * n)) / d;
  const h = (z * Math.sqrt((p * (1 - p)) / n + (z * z) / (4 * n * n))) / d;
  return [Math.max(0, c - h), Math.min(1, c + h)];
}
