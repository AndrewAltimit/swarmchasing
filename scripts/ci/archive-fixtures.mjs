// Builders for the archive fixtures the site's checks make at run time:
// gzip, tar (ustar, GNU long names, links, pax headers) and zip (stored,
// deflate, encrypted flag, ZIP64 records), and synthetic access logs on
// .example hosts. Nothing here is committed data; check-archive.mjs and
// site-xss-check.mjs build what they need and throw it away.

import { deflateRawSync, gzipSync } from "node:zlib";

const enc = new TextEncoder();
const bytes = (d) => (typeof d === "string" ? enc.encode(d) : d);

/** gzip of a string or bytes. */
export const gzip = (d) => new Uint8Array(gzipSync(bytes(d)));

const CRC = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();
export function crc32(b) {
  let c = 0xffffffff;
  for (const x of b) c = CRC[(c ^ x) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function concat(parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

function tarBlock(name, size, type, extra = {}) {
  const b = new Uint8Array(512);
  const put = (s, at, len) => b.set(bytes(s).subarray(0, len), at);
  put(name, 0, 100);
  put("0000644\0", 100, 8);
  put("0000000\0", 108, 8);
  put("0000000\0", 116, 8);
  put(size.toString(8).padStart(11, "0") + "\0", 124, 12);
  put("14707330140\0", 136, 12);
  b[156] = type.charCodeAt(0);
  if (extra.link) put(extra.link, 157, 100);
  put("ustar\0", 257, 6);
  put("00", 263, 2);
  b.fill(32, 148, 156);
  const sum = b.reduce((s, x) => s + x, 0);
  put(sum.toString(8).padStart(6, "0") + "\0 ", 148, 8);
  return b;
}
const pad512 = (d) => concat([d, new Uint8Array((512 - (d.length % 512)) % 512)]);

/**
 * A tar archive. Each entry is `{ name, data, type }` (type "0" by default;
 * "5" a directory, "2" a symbolic link with `link`). A name over 100 bytes
 * goes in a GNU long-name record; `pax: true` puts it in a pax header.
 * Only a regular file carries its data, unless `body: true` gives another
 * kind of entry its data too (as a hostile archive may).
 */
export function tar(entries) {
  const parts = [];
  for (const e of entries) {
    const data = bytes(e.data ?? "");
    const type = e.type ?? "0";
    let name = e.name;
    if (e.pax) {
      // A record's length counts bytes, its own digits included.
      const rec = (k, v) => {
        const body = enc.encode(` ${k}=${v}\n`).length;
        let len = body + 1;
        while (String(len).length + body !== len) len = String(len).length + body;
        return `${len} ${k}=${v}\n`;
      };
      const pax = enc.encode(rec("path", name));
      parts.push(tarBlock("PaxHeader", pax.length, "x"), pad512(pax));
      name = "pax-short-name";
    } else if (enc.encode(name).length > 100) {
      const long = enc.encode(name + "\0");
      parts.push(tarBlock("././@LongLink", long.length, "L"), pad512(long));
      name = name.slice(0, 99);
    }
    const carries = type === "0" || e.body;
    parts.push(tarBlock(name, carries ? data.length : 0, type, { link: e.link }));
    if (carries) parts.push(pad512(data));
  }
  parts.push(new Uint8Array(1024));
  return concat(parts);
}

const le = (n, w) => {
  const b = new Uint8Array(w);
  let v = BigInt(n);
  for (let i = 0; i < w; i++) {
    b[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return b;
};

/**
 * A zip archive. Each entry is `{ name, data, method }` (8 deflate, the
 * default, or 0 stored), `encrypted: true` sets the flag (the data stays
 * plain), and a name ending in "/" is a directory. `zip64: true` writes
 * every size and offset through the ZIP64 extra field and end records.
 */
export function zip(entries, { zip64 = false } = {}) {
  const locals = [];
  const central = [];
  let offset = 0;
  for (const e of entries) {
    const data = bytes(e.data ?? "");
    const method = e.name.endsWith("/") ? 0 : e.method ?? 8;
    const packed = method === 8 ? new Uint8Array(deflateRawSync(data)) : data;
    const name = enc.encode(e.name);
    const flags = (e.encrypted ? 1 : 0) | 0x800;
    const crc = crc32(data);
    const big = (n) => (zip64 ? 0xffffffff : n);
    const extra = zip64 ? concat([le(1, 2), le(24, 2), le(data.length, 8), le(packed.length, 8), le(offset, 8)]) : new Uint8Array(0);
    const localExtra = zip64 ? concat([le(1, 2), le(16, 2), le(data.length, 8), le(packed.length, 8)]) : new Uint8Array(0);
    const local = concat([le(0x04034b50, 4), le(zip64 ? 45 : 20, 2), le(flags, 2), le(method, 2), le(0, 4), le(crc, 4),
      le(big(packed.length), 4), le(big(data.length), 4), le(name.length, 2), le(localExtra.length, 2), name, localExtra, packed]);
    central.push(concat([le(0x02014b50, 4), le(zip64 ? 45 : 20, 2), le(zip64 ? 45 : 20, 2), le(flags, 2), le(method, 2), le(0, 4), le(crc, 4),
      le(big(packed.length), 4), le(big(data.length), 4), le(name.length, 2), le(extra.length, 2), le(0, 2), le(0, 2), le(0, 2), le(0, 4),
      le(big(offset), 4), name, extra]));
    locals.push(local);
    offset += local.length;
  }
  const cd = concat(central);
  const tail = [];
  if (zip64) {
    const eocd64At = offset + cd.length;
    tail.push(concat([le(0x06064b50, 4), le(44, 8), le(45, 2), le(45, 2), le(0, 4), le(0, 4), le(entries.length, 8), le(entries.length, 8), le(cd.length, 8), le(offset, 8)]));
    tail.push(concat([le(0x07064b50, 4), le(0, 4), le(eocd64At, 8), le(1, 4)]));
  }
  const n16 = zip64 ? 0xffff : entries.length;
  tail.push(concat([le(0x06054b50, 4), le(0, 2), le(0, 2), le(n16, 2), le(n16, 2), le(zip64 ? 0xffffffff : cd.length, 4), le(zip64 ? 0xffffffff : offset, 4), le(0, 2)]));
  return concat([...locals, cd, ...tail]);
}

/**
 * A synthetic Combined Log Format access log: `n` requests from
 * documentation addresses, starting at `start` (Unix seconds) and `step`
 * seconds apart, with `paths` cycled. Hosts are on .example.
 */
export function accessLog({ n = 6, start = 1791101400, step = 7, ip = "203.0.113.7", paths = ["/"], ua = "Mozilla/5.0 (synthetic)" } = {}) {
  const lines = [];
  const mon = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  for (let i = 0; i < n; i++) {
    const d = new Date((start + i * step) * 1000);
    const p2 = (x) => String(x).padStart(2, "0");
    const t = `${p2(d.getUTCDate())}/${mon[d.getUTCMonth()]}/${d.getUTCFullYear()}:${p2(d.getUTCHours())}:${p2(d.getUTCMinutes())}:${p2(d.getUTCSeconds())} +0000`;
    lines.push(`${ip} - - [${t}] "GET ${paths[i % paths.length]} HTTP/1.1" 200 512 "-" "${ua}"`);
  }
  return lines.join("\n") + "\n";
}

/** Paths a scripted agent probes: a SQL injection and a cache-busted callback. */
export const PROBE_PATHS = [
  "/search?q=1%27%20UNION%20SELECT%20password%20FROM%20users--",
  "/search?q=%3Cscript%3Ealert(1)%3C/script%3E",
  "/login?next=https://webhook.site/0b6c1f0e-0000-4c2a-9a55-3f2e1d0c9b8a",
  "/.env",
];

/**
 * Three synthetic logs for one site, each a part of the same probe run
 * spread over files (a rotated log), plus a JSON log of the same requests.
 */
export function logSet() {
  const run = (k) => accessLog({ n: 4, start: 1791101400 + k * 40, step: 9, ip: `203.0.113.${20 + k}`, paths: PROBE_PATHS, ua: "python-httpx/0.27" });
  return {
    "access.log": run(0) + accessLog({ n: 3, start: 1791101300, step: 30, ip: "198.51.100.4" }),
    "access.log.1": run(1),
    "access.log.2": run(2),
    "app.json": PROBE_PATHS.map((p, i) => JSON.stringify({ ts: new Date((1791101520 + i * 9) * 1000).toISOString(), url: `https://www.example.org${p}`, ip: "203.0.113.23" })).join("\n") + "\n",
  };
}
