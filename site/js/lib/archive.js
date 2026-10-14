// Read a set of log files in the page: plain files, gzip, zip, tar and
// tar.gz, picked one by one, several at once or as a folder. Everything is
// unpacked here with the browser's own DecompressionStream; nothing is
// fetched or uploaded. This module touches no DOM, so the same code runs in
// Node for its tests (scripts/ci/check-archive.mjs).
//
// Archives are hostile input. An entry's name is a label for the page and
// never a path: nothing is written anywhere. Every value goes on as text.
// The reader stops when the set passes its limits (unpacked bytes, entries,
// one entry's size or compression ratio), skips entries that look binary,
// encrypted zip entries and tar entries that are not regular files, and
// says why for each.

export const MiB = 1024 * 1024;

/** The limits a set is read under. */
export const LIMITS = Object.freeze({
  /** Unpacked text, every file of the set together. */
  totalBytes: 512 * MiB,
  /** Files and archive entries, skipped ones included. */
  entries: 10000,
  /** One file or entry, unpacked. */
  entryBytes: 256 * MiB,
  /** Unpacked to packed, past `ratioAfter` bytes of output: a bomb, not a log. */
  ratio: 400,
  ratioAfter: 8 * MiB,
  /** Archives inside archives: one level. */
  depth: 1,
});

const SNIFF_BYTES = 8192;
/** Yield to the page after this many bytes of one entry. */
const YIELD_EVERY = 16 * MiB;

const u16 = (b, o) => b[o] | (b[o + 1] << 8);
const u32 = (b, o) => (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;
const u64 = (b, o) => u32(b, o) + u32(b, o + 4) * 2 ** 32;
const latin1 = (b) => String.fromCharCode(...b);
const utf8 = new TextDecoder("utf-8");

/** The page's turn to draw and take input. */
export const breathe = () => new Promise((r) => setTimeout(r, 0));

/** A size in bytes as "12 MB", "340 kB" or "15 bytes". */
export function bytesText(n) {
  if (n >= MiB) return `${(n / MiB).toFixed(n >= 100 * MiB ? 0 : 1)} MB`;
  if (n >= 1024) return `${Math.round(n / 1024)} kB`;
  return `${n} byte${n === 1 ? "" : "s"}`;
}

/**
 * An entry's name as a label: control characters shown as `?`, a leading
 * `./` or `/` dropped, cut to 300 characters. It names, it never locates.
 */
export function cleanName(name) {
  const s = String(name ?? "").replace(/[\u0000-\u001f\u007f]/g, "?").replace(/^(?:\.\/|\/)+/, "");
  return s.length > 300 ? `${s.slice(0, 297)}...` : s || "(no name)";
}

/** True when the bytes look like something other than text: a NUL, or many control bytes. */
export function looksBinary(head) {
  const n = Math.min(head.length, SNIFF_BYTES);
  let odd = 0;
  for (let i = 0; i < n; i++) {
    const c = head[i];
    if (c === 0) return true;
    if (c < 32 && c !== 9 && c !== 10 && c !== 12 && c !== 13 && c !== 27) odd++;
  }
  return odd * 10 > n;
}

/** A tar header block's checksum holds (the sum of its bytes, the checksum field read as spaces). */
function tarChecksumOk(b) {
  const want = parseInt(latin1(b.subarray(148, 156)).replace(/[\0 ]+$/, "").trim(), 8);
  if (!Number.isFinite(want)) return false;
  let sum = 0;
  for (let i = 0; i < 512; i++) sum += i >= 148 && i < 156 ? 32 : b[i];
  return sum === want;
}

/**
 * What the first bytes of a file are: `gzip`, `zip`, `tar`, `empty`,
 * `binary` or `text`. By the bytes, not the name.
 */
export function sniff(head) {
  if (!head.length) return "empty";
  if (head[0] === 0x1f && head[1] === 0x8b) return "gzip";
  if (head[0] === 0x50 && head[1] === 0x4b && ((head[2] === 3 && head[3] === 4) || (head[2] === 5 && head[3] === 6))) return "zip";
  if (head.length >= 512 && (latin1(head.subarray(257, 262)) === "ustar" || (head[0] !== 0 && tarChecksumOk(head)))) return "tar";
  return looksBinary(head) ? "binary" : "text";
}

/** A NUL-terminated field of a tar header. */
const tarField = (b, at, len) => {
  const f = b.subarray(at, at + len);
  const end = f.indexOf(0);
  return f.subarray(0, end < 0 ? len : end);
};

/** A tar size field: octal, or base-256 when its first bit is set. */
function tarSize(b) {
  if (b[124] & 0x80) {
    let n = 0;
    for (let i = 125; i < 136; i++) n = n * 256 + b[i];
    return n;
  }
  const v = parseInt(latin1(tarField(b, 124, 12)).trim() || "0", 8);
  return Number.isFinite(v) ? v : NaN;
}

/**
 * One tar header block: `{ name, size, type }`, `null` for the zero block
 * that ends the archive, or `{ bad: true }` when the checksum fails.
 */
export function tarHeader(b) {
  if (b.every((x) => x === 0)) return null;
  if (!tarChecksumOk(b)) return { bad: true };
  let name = utf8.decode(tarField(b, 0, 100));
  if (latin1(b.subarray(257, 262)) === "ustar") {
    const prefix = utf8.decode(tarField(b, 345, 155));
    if (prefix) name = `${prefix}/${name}`;
  }
  return { name, size: tarSize(b), type: String.fromCharCode(b[156] || 48) };
}

/**
 * The `path` of a pax extended header (`"<len> path=<name>\n"` records), or
 * null. Each record's length counts bytes, so the records are cut from the
 * bytes before any is decoded.
 */
export function paxPath(bytes) {
  let at = 0;
  while (at < bytes.length) {
    const sp = bytes.indexOf(0x20, at);
    if (sp < 0) break;
    const len = parseInt(latin1(bytes.subarray(at, sp)), 10);
    if (!(len > sp - at + 1) || at + len > bytes.length) break;
    const rec = utf8.decode(bytes.subarray(sp + 1, at + len - 1));
    if (rec.startsWith("path=")) return rec.slice(5);
    at += len;
  }
  return null;
}

/** The kinds of tar entry the reader skips, by type flag, with what they are. */
const TAR_SKIP = { 1: "a hard link", 2: "a symbolic link", 3: "a device", 4: "a device", 6: "a pipe" };

/**
 * Bytes from an async source of chunks, read on demand: whole blocks,
 * runs of a given length as chunks.
 */
export class ByteReader {
  constructor(chunks) {
    this.it = chunks[Symbol.asyncIterator]();
    this.buf = new Uint8Array(0);
    this.done = false;
  }
  async fill(n) {
    while (this.buf.length < n && !this.done) {
      const { value, done } = await this.it.next();
      if (done) this.done = true;
      else if (value?.length) this.buf = this.buf.length ? concat([this.buf, value]) : value;
    }
    return this.buf.length >= n;
  }
  /** The next `n` bytes without taking them (fewer at the end). */
  async peek(n) {
    await this.fill(n);
    return this.buf.subarray(0, n);
  }
  /** The next `n` bytes, or null when fewer remain. */
  async exact(n) {
    if (!(await this.fill(n))) return null;
    const out = this.buf.slice(0, n);
    this.buf = this.buf.subarray(n);
    return out;
  }
  /**
   * The next `n` bytes as chunks. `track.left` says how many of them were
   * not handed out, for a consumer that stops early.
   */
  async *take(n, track = {}) {
    track.left = n;
    while (track.left > 0) {
      if (!this.buf.length && !(await this.fill(1))) throw new Error("the archive ends inside an entry");
      const k = Math.min(track.left, this.buf.length);
      const chunk = this.buf.subarray(0, k);
      this.buf = this.buf.subarray(k);
      track.left -= k;
      yield chunk;
    }
  }
  /** The bytes held, or the next chunk; null at the end. */
  async chunk() {
    if (!this.buf.length && !(await this.fill(1))) return null;
    const out = this.buf;
    this.buf = new Uint8Array(0);
    return out;
  }
  /** Put bytes back in front. */
  unread(bytes) {
    this.buf = this.buf.length ? concat([bytes, this.buf]) : bytes;
  }
  /** Every byte left, as chunks. */
  async *rest() {
    if (this.buf.length) yield this.buf;
    this.buf = new Uint8Array(0);
    if (this.done) return;
    for (;;) {
      const { value, done } = await this.it.next();
      if (done) break;
      if (value?.length) yield value;
    }
    this.done = true;
  }
  async close() {
    await this.it.return?.();
  }
}

export function concat(parts) {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

/** A ReadableStream as an async iterable that cancels the stream when left early. */
export async function* chunksOf(stream) {
  const reader = stream.getReader();
  let finished = false;
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) {
        finished = true;
        return;
      }
      yield value;
    }
  } finally {
    if (!finished) await reader.cancel().catch(() => {});
    reader.releaseLock?.();
  }
}

/** Bytes through the browser's decompressor (`gzip` or `deflate-raw`). */
function inflate(chunks, format) {
  if (typeof DecompressionStream !== "function") throw new Error("this browser cannot unpack compressed files");
  const it = chunks[Symbol.asyncIterator]();
  const source = new ReadableStream({
    async pull(ctl) {
      const { value, done } = await it.next();
      if (done) ctl.close();
      else ctl.enqueue(value);
    },
    async cancel() {
      await it.return?.();
    },
  });
  return chunksOf(source.pipeThrough(new DecompressionStream(format)));
}

// ── gzip of several members ──────────────────────────────────────────────
// A gzip may hold several members one after another (logs joined with
// `cat`, bgzip, pigz), which reads as their texts joined. Some browsers'
// DecompressionStream stops at the first member and fails on the rest
// (Chrome: "Junk found after end of compressed data"), and some fail on
// zeros after the last. So the reader finds each member's end itself, in
// every browser alike: it parses the member's header, walks its deflate
// blocks to the last one without producing output, and hands the
// browser's decompressor exactly that member, header to trailer, so the
// browser still does the unpacking and checks the CRC and length.

/** Extra bits after each length symbol (257..285) and distance symbol (0..29). */
const LEN_EXTRA = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
const DIST_EXTRA = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];
const CL_ORDER = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

/**
 * A canonical Huffman code as a lookup table indexed by the next `bits`
 * input bits (least significant first): each entry is `symbol << 4 |
 * length`, 0 where no code matches.
 */
function huffman(lengths) {
  let bits = 0;
  for (const l of lengths) if (l > bits) bits = l;
  const table = new Uint16Array(1 << bits);
  const count = new Uint16Array(16);
  for (const l of lengths) if (l) count[l]++;
  const next = new Uint32Array(16);
  for (let l = 1, code = 0; l < 16; l++) {
    code = (code + count[l - 1]) << 1;
    next[l] = code;
  }
  for (let sym = 0; sym < lengths.length; sym++) {
    const l = lengths[sym];
    if (!l) continue;
    const code = next[l]++;
    if (code >= 1 << l) throw new Error("the compressed data is damaged (an oversubscribed code)");
    let rev = 0;
    for (let i = 0; i < l; i++) rev |= ((code >> i) & 1) << (l - 1 - i);
    for (let j = rev; j < table.length; j += 1 << l) table[j] = (sym << 4) | l;
  }
  return { table, bits };
}

let fixedCodes = null;
const fixed = () =>
  (fixedCodes ??= {
    lit: huffman(Array.from({ length: 288 }, (_, i) => (i < 144 ? 8 : i < 256 ? 9 : i < 280 ? 7 : 8))),
    dist: huffman(new Array(30).fill(5)),
  });

/** Bits a step may need, so the walk waits for input rather than reading past it. */
const STEP_BITS = 8192;

/**
 * Walks a deflate stream to its end without producing output, a chunk at
 * a time: `push(chunk)` adds input, `finish()` says the input ended.
 * `safe` is how many bytes, counted from the first pushed, certainly
 * belong to the stream; once `end` is known (not -1), it is the stream's
 * length in bytes.
 */
class DeflateEnd {
  constructor() {
    this.buf = new Uint8Array(0);
    this.base = 0; // bytes dropped from the front of buf
    this.bit = 0; // position in buf, in bits
    this.ended = false; // no more input
    this.state = "block"; // block | stored | codes
    this.final = false;
    this.stored = 0;
    this.lit = null;
    this.dist = null;
    this.end = -1; // the stream's length in bytes, once known
    this.pending = []; // chunks pushed and not yet in buf
    this.pendingBytes = 0;
  }
  get safe() {
    return this.end >= 0 ? this.end : this.base + (this.bit >> 3);
  }
  push(chunk) {
    // Small chunks wait until a step's worth is there, so each byte is
    // copied a bounded number of times.
    this.pending.push(chunk);
    this.pendingBytes += chunk.length;
    if (this.state !== "stored" && (this.buf.length + this.pendingBytes) * 8 - this.bit < STEP_BITS) return;
    this.gather();
    this.run();
  }
  gather() {
    const drop = Math.min(this.bit >> 3, this.buf.length);
    const rest = this.buf.subarray(drop);
    this.buf = rest.length ? concat([rest, ...this.pending]) : this.pending.length === 1 ? this.pending[0] : concat(this.pending);
    this.base += drop;
    this.bit -= drop * 8;
    this.pending = [];
    this.pendingBytes = 0;
  }
  finish() {
    this.ended = true;
    this.gather();
    this.run();
    if (this.end < 0) throw new Error("the compressed data ends early");
  }
  /** `n` bits (n <= 24) at the position, taken. */
  take(n) {
    const b = this.buf, i = this.bit >> 3;
    const w = (b[i] | (b[i + 1] << 8) | (b[i + 2] << 16) | (b[i + 3] << 24)) >>> (this.bit & 7);
    this.bit += n;
    if (this.bit > b.length * 8) throw new Error("the compressed data ends early");
    return w & ((1 << n) - 1);
  }
  /** One symbol of a code, taken. */
  symbol({ table, bits }) {
    const b = this.buf, i = this.bit >> 3;
    const w = (b[i] | (b[i + 1] << 8) | (b[i + 2] << 16)) >>> (this.bit & 7);
    const e = table[w & ((1 << bits) - 1)];
    if (!e) throw new Error("the compressed data is damaged (an unknown code)");
    this.bit += e & 15;
    if (this.bit > b.length * 8) throw new Error("the compressed data ends early");
    return e >> 4;
  }
  run() {
    const room = () => this.ended || this.buf.length * 8 - this.bit >= STEP_BITS;
    while (this.end < 0) {
      if (this.state === "stored") {
        const have = this.buf.length - (this.bit >> 3);
        const k = Math.min(have, this.stored);
        this.bit += k * 8;
        this.stored -= k;
        if (this.stored) {
          if (this.ended) throw new Error("the compressed data ends early");
          return;
        }
        this.state = "block";
        continue;
      }
      if (!room()) return;
      if (this.state === "block") {
        if (this.final) {
          this.end = this.base + ((this.bit + 7) >> 3);
          return;
        }
        this.final = this.take(1) === 1;
        const type = this.take(2);
        if (type === 0) {
          this.bit = (this.bit + 7) & ~7;
          const len = this.take(16);
          if ((len ^ this.take(16)) !== 0xffff) throw new Error("the compressed data is damaged (a stored block's length)");
          this.stored = len;
          this.state = "stored";
        } else if (type === 1) {
          ({ lit: this.lit, dist: this.dist } = fixed());
          this.state = "codes";
        } else if (type === 2) {
          this.dynamic();
          this.state = "codes";
        } else throw new Error("the compressed data is damaged (a reserved block type)");
        continue;
      }
      // Literals, lengths and distances, to the end-of-block symbol.
      for (;;) {
        if (!room()) return;
        const sym = this.symbol(this.lit);
        if (sym < 256) continue;
        if (sym === 256) break;
        if (sym > 285) throw new Error("the compressed data is damaged (a bad length)");
        this.take(LEN_EXTRA[sym - 257]);
        const d = this.symbol(this.dist);
        if (d > 29) throw new Error("the compressed data is damaged (a bad distance)");
        this.take(DIST_EXTRA[d]);
      }
      this.state = "block";
    }
  }
  /** A dynamic block's code lengths, read into its two codes. */
  dynamic() {
    const nlit = this.take(5) + 257, ndist = this.take(5) + 1, ncl = this.take(4) + 4;
    const cl = new Array(19).fill(0);
    for (let i = 0; i < ncl; i++) cl[CL_ORDER[i]] = this.take(3);
    const clCode = huffman(cl);
    const lengths = [];
    while (lengths.length < nlit + ndist) {
      const s = this.symbol(clCode);
      if (s < 16) lengths.push(s);
      else if (s === 16) {
        if (!lengths.length) throw new Error("the compressed data is damaged (a repeat with nothing before)");
        const prev = lengths.at(-1);
        for (let n = 3 + this.take(2); n > 0; n--) lengths.push(prev);
      } else for (let n = s === 17 ? 3 + this.take(3) : 11 + this.take(7); n > 0; n--) lengths.push(0);
    }
    if (lengths.length > nlit + ndist || !lengths[256]) throw new Error("the compressed data is damaged (bad code lengths)");
    this.lit = huffman(lengths.slice(0, nlit));
    this.dist = huffman(lengths.slice(nlit));
  }
}

/** A gzip member header's length from its first bytes, read through `r`. */
async function gzipHeaderLength(r) {
  const short = () => new Error("the compressed data ends early");
  let b = await r.peek(10);
  if (b.length < 10) throw short();
  if (b[0] !== 0x1f || b[1] !== 0x8b || b[2] !== 8 || b[3] & 0xe0) throw new Error("not a gzip member");
  const flags = b[3];
  let at = 10;
  if (flags & 4) {
    b = await r.peek(at + 2);
    if (b.length < at + 2) throw short();
    at += 2 + u16(b, at);
  }
  for (const flag of [8, 16]) {
    if (!(flags & flag)) continue;
    // A name or comment, to its NUL.
    for (let want = at + 256; ; want += 4096) {
      if (want > 1 << 16) throw new Error("a gzip header longer than 64 kB");
      b = await r.peek(want);
      const nul = b.indexOf(0, at);
      if (nul >= 0) {
        at = nul + 1;
        break;
      }
      if (b.length < want) throw short();
    }
  }
  if (flags & 2) at += 2;
  if ((await r.peek(at)).length < at) throw short();
  return at;
}

/**
 * A gzip's bytes unpacked member by member: each member found by its
 * header and its deflate blocks, then unpacked on its own. Bytes after the
 * last member that do not start another are left unread, as `gzip -d`
 * leaves them.
 */
export async function* gzipMembers(chunks) {
  const r = new ByteReader(chunks);
  try {
    for (let first = true; ; first = false) {
      const magic = await r.peek(2);
      if (!first && (magic.length < 2 || magic[0] !== 0x1f || magic[1] !== 0x8b)) return;
      const head = await gzipHeaderLength(r);
      const member = (async function* () {
        yield await r.exact(head);
        // Bytes go on once the walk has passed them; what follows the
        // stream's end goes back to the reader.
        const walk = new DeflateEnd();
        let held = [], heldAt = 0;
        while (walk.end < 0) {
          const c = await r.chunk();
          if (c) {
            walk.push(c);
            held.push(c);
          } else walk.finish();
          const k = walk.safe - heldAt;
          if (k > 0) {
            const all = held.length === 1 ? held[0] : concat(held);
            yield all.subarray(0, k);
            held = [all.subarray(k)];
            heldAt += k;
          }
        }
        const rest = concat(held);
        if (rest.length) r.unread(rest);
        const trailer = await r.exact(8);
        if (!trailer) throw new Error("the compressed data ends early");
        yield trailer;
      })();
      yield* inflate(member, "gzip");
    }
  } finally {
    await r.close();
  }
}

/** Chunks of a source, counting the bytes into `meter.packed`. */
async function* metered(chunks, meter) {
  for await (const c of chunks) {
    meter.packed += c.length;
    yield c;
  }
}

/**
 * A zip file's central directory: `{ entries: [{ name, method, flags,
 * packed, size, offset }] }`, or `{ error }`. ZIP64 sizes and offsets are
 * read; a split archive is refused.
 */
export async function zipDirectory(blob) {
  const read = async (at, n) => new Uint8Array(await blob.slice(at, at + n).arrayBuffer());
  const tailLen = Math.min(blob.size, 22 + 65535);
  const tail = await read(blob.size - tailLen, tailLen);
  let e = -1;
  for (let i = tail.length - 22; i >= 0; i--) {
    if (u32(tail, i) === 0x06054b50) {
      e = i;
      break;
    }
  }
  if (e < 0) return { error: "no zip directory found (a damaged or partial zip)" };
  if (u16(tail, e + 4) !== 0 || u16(tail, e + 6) !== 0) return { error: "a zip split over several files is not read" };
  let count = u16(tail, e + 10);
  let cdSize = u32(tail, e + 12);
  let cdAt = u32(tail, e + 16);
  if (count === 0xffff || cdSize === 0xffffffff || cdAt === 0xffffffff) {
    const loc = e - 20;
    if (loc < 0 || u32(tail, loc) !== 0x07064b50) return { error: "a ZIP64 archive without its locator" };
    const z = await read(u64(tail, loc + 8), 56);
    if (u32(z, 0) !== 0x06064b50) return { error: "a ZIP64 archive whose directory record is missing" };
    count = u64(z, 32);
    cdSize = u64(z, 40);
    cdAt = u64(z, 48);
  }
  if (cdAt + cdSize > blob.size) return { error: "the zip directory points past the end of the file" };
  const cd = await read(cdAt, cdSize);
  const entries = [];
  let p = 0;
  for (let k = 0; k < count && p + 46 <= cd.length; k++) {
    if (u32(cd, p) !== 0x02014b50) return { error: "a damaged zip directory", entries };
    const nameLen = u16(cd, p + 28);
    const extraLen = u16(cd, p + 30);
    const commentLen = u16(cd, p + 32);
    const ent = {
      name: utf8.decode(cd.subarray(p + 46, p + 46 + nameLen)),
      flags: u16(cd, p + 8),
      method: u16(cd, p + 10),
      packed: u32(cd, p + 20),
      size: u32(cd, p + 24),
      offset: u32(cd, p + 42),
    };
    // ZIP64 extra field: the 64-bit values, each present only where its
    // 32-bit field is saturated, in this order.
    let x = p + 46 + nameLen;
    const xEnd = x + extraLen;
    while (x + 4 <= xEnd) {
      const id = u16(cd, x);
      const len = u16(cd, x + 2);
      if (id === 0x0001) {
        let q = x + 4;
        for (const f of ["size", "packed", "offset"]) {
          if (ent[f] === 0xffffffff && q + 8 <= x + 4 + len) {
            ent[f] = u64(cd, q);
            q += 8;
          }
        }
      }
      x += 4 + len;
    }
    entries.push(ent);
    p += 46 + nameLen + extraLen + commentLen;
  }
  return { entries };
}

/** Where a zip entry's data starts, from its local header. */
async function zipDataStart(blob, ent) {
  const h = new Uint8Array(await blob.slice(ent.offset, ent.offset + 30).arrayBuffer());
  if (h.length < 30 || u32(h, 0) !== 0x04034b50) return -1;
  return ent.offset + 30 + u16(h, 26) + u16(h, 28);
}

/** Metadata a Mac adds to archives: not logs. */
const macJunk = (name) => /(^|\/)__MACOSX\//.test(name) || /(^|\/)\._[^/]*$/.test(name);

/** `name` without a compression suffix, for the file inside a .gz. */
export const gunzippedName = (name) => name.replace(/\.(?:gz|gzip)$/i, "") || name;

/**
 * Read a set of files as text, unpacking archives. `sources` are `{ name,
 * blob }` (a File or Blob) or `{ name, text }`. Yields, in order:
 *
 *   { type: "file", name, text, bytes }   a log read as text
 *   { type: "skip", name, reason }        an entry not read, and why
 *   { type: "stop", reason }              a limit of the whole set was hit; nothing after it is read
 *
 * `onProgress({ files, bytes, name })` is called as entries finish and
 * during long ones. The page gets a turn between entries.
 */
export async function* unpack(sources, { limits = LIMITS, onProgress = () => {} } = {}) {
  // `drained` counts bytes unpacked but not read as text (tar headers,
  // tar entries skipped or cut off, a nested zip held to be read): they
  // cost unpacking too, so they count against the set's limit.
  const st = { bytes: 0, drained: 0, entries: 0, files: 0, stop: null };
  const progress = (name) => onProgress({ files: st.files, bytes: st.bytes, name });
  /** One more entry; false, with st.stop set, past the limit. */
  const counted = () => {
    st.entries++;
    if (st.entries <= limits.entries) return true;
    st.stop = `The set holds more than ${limits.entries.toLocaleString("en")} files and entries; the page read the first ${limits.entries.toLocaleString("en")} and stopped.`;
    return false;
  };
  const bombText = `unpacks to over ${limits.ratio} times its packed size: an archive bomb, not a log`;

  /**
   * One entry's bytes: as a text file, a nested archive or a skip. `meter`
   * counts its packed bytes when it was compressed.
   */
  async function* entry(name, chunks, depth, meter = null) {
    if (!counted()) return;
    const r = new ByteReader(chunks);
    try {
      const head = await r.peek(SNIFF_BYTES);
      const kind = sniff(head);
      if (kind === "empty") return yield { type: "skip", name, reason: "empty" };
      if (kind === "binary") return yield { type: "skip", name, reason: "not text (binary content)" };
      if (kind !== "text") {
        if (depth > limits.depth) return yield { type: "skip", name, reason: `a ${kind} archive nested deeper than ${limits.depth === 1 ? "one level" : `${limits.depth} levels`}` };
        yield* container(name, kind, r, depth + 1, meter);
        return;
      }
      const dec = new TextDecoder("utf-8");
      const parts = [];
      let size = 0, since = 0;
      for await (const c of r.rest()) {
        size += c.length;
        since += c.length;
        if (st.bytes + size > limits.totalBytes) {
          st.stop = `The set unpacks to more than ${bytesText(limits.totalBytes)}; the page stopped at ${name} and read nothing after it.`;
          return;
        }
        if (size > limits.entryBytes) return yield { type: "skip", name, reason: `larger than ${bytesText(limits.entryBytes)} unpacked` };
        if (meter && size > limits.ratioAfter && size > meter.packed * limits.ratio) return yield { type: "skip", name, reason: bombText };
        parts.push(dec.decode(c, { stream: true }));
        if (since >= YIELD_EVERY) {
          since = 0;
          onProgress({ files: st.files, bytes: st.bytes + size, name });
          await breathe();
        }
      }
      parts.push(dec.decode());
      st.bytes += size;
      st.files++;
      yield { type: "file", name, text: parts.join(""), bytes: size };
      progress(name);
    } catch (e) {
      yield { type: "skip", name, reason: `could not be read: ${String(e?.message ?? e)}` };
    } finally {
      await r.close();
    }
  }

  /**
   * An archive's entries, from a reader positioned at its first byte.
   * `meter` is the enclosing entry's, when that was compressed: a tar
   * inside a zip or gzip entry is held to its ratio.
   */
  async function* container(name, kind, r, depth, meter = null) {
    if (kind === "gzip") {
      const gz = { packed: 0 };
      // A .tar.gz is a tar inside; anything else is one file.
      const inner = new ByteReader(gzipMembers(metered(r.rest(), gz)));
      try {
        const head = await inner.peek(512);
        if (sniff(head) === "tar") yield* tar(name, inner, depth, gz);
        else yield* entry(gunzippedName(name), inner.rest(), depth, gz);
      } finally {
        await inner.close();
      }
    } else if (kind === "tar") {
      yield* tar(name, r, depth, meter);
    } else if (kind === "zip") {
      // A zip is read from its end; a nested one is held in memory first,
      // which the entry size limit bounds. What is held counts toward the
      // set's limit and, when the enclosing entry was compressed, its ratio.
      const parts = [];
      let n = 0;
      for await (const c of r.rest()) {
        n += c.length;
        st.drained += c.length;
        if (st.bytes + st.drained > limits.totalBytes) {
          st.stop = `The set unpacks to more than ${bytesText(limits.totalBytes)}; the page stopped at ${name} and read nothing after it.`;
          return;
        }
        if (n > limits.entryBytes) return yield { type: "skip", name, reason: `a zip larger than ${bytesText(limits.entryBytes)} inside an archive` };
        if (meter && n > limits.ratioAfter && n > meter.packed * limits.ratio) return yield { type: "skip", name, reason: bombText };
        parts.push(c);
      }
      yield* zip(name, new Blob(parts), depth);
    }
  }

  /**
   * A tar's entries. `meter` counts the packed bytes behind it when it was
   * compressed; what the tar unpacks to, entries read and passed over
   * alike, is held to the ratio against it.
   */
  async function* tar(name, r, depth, meter) {
    let longName = null;
    let out = 0; // bytes of the tar stream taken so far
    const bomb = () => meter && out > limits.ratioAfter && out > meter.packed * limits.ratio;
    const bombRest = `${bombText}; the rest of this archive was not read`;
    /**
     * Count `n` bytes taken but not read as text (a header, a name record,
     * an entry passed over). Null while within the limits; else why the
     * rest of this tar is not read (the set's limit, or the ratio), with
     * st.stop set for the former.
     */
    const charge = (n) => {
      out += n;
      st.drained += n;
      if (st.bytes + st.drained > limits.totalBytes) {
        st.stop = `The set unpacks to more than ${bytesText(limits.totalBytes)}, counting entries passed over; the page stopped in ${name} and read nothing after it.`;
        return st.stop;
      }
      return bomb() ? bombRest : null;
    };
    /** Pass over `n` bytes unread, with turns for the page; null when done, else why the rest is not read. */
    const drain = async (n) => {
      let since = 0;
      for await (const c of r.take(n)) {
        const why = charge(c.length);
        if (why) return why;
        since += c.length;
        if (since >= YIELD_EVERY) {
          since = 0;
          await breathe();
        }
      }
      return null;
    };
    const stopTar = function* (why) {
      if (!st.stop) yield { type: "skip", name, reason: why };
    };
    const early = { type: "skip", name, reason: "the archive ends early; the rest was not read" };
    for (;;) {
      if (st.stop) return;
      const block = await r.exact(512);
      if (!block) return yield early;
      const h = tarHeader(block);
      if (h === null) return;
      // Every header counts, so a run of headers with no data (directories,
      // name records) is held to the limits like data.
      let why = charge(512);
      if (why) return yield* stopTar(why);
      if (h.bad || !Number.isFinite(h.size) || h.size < 0) return yield { type: "skip", name, reason: "a damaged tar header; the rest of this archive was not read" };
      const pad = (512 - (h.size % 512)) % 512;
      if (h.type === "L" || h.type === "x" || h.type === "K") {
        // A GNU long name or a pax header names the entry that follows (a
        // GNU long link name is read and left).
        if (h.size > 64 * 1024) return yield { type: "skip", name, reason: "an oversized tar name record" };
        const data = await r.exact(h.size + pad);
        if (!data) return yield early;
        why = charge(data.length);
        if (why) return yield* stopTar(why);
        const body = data.subarray(0, h.size);
        if (h.type === "L") longName = utf8.decode(tarField(body, 0, body.length));
        else if (h.type === "x") longName = paxPath(body) ?? longName;
        continue;
      }
      const entryName = longName ?? h.name;
      longName = null;
      const label = `${name}/${cleanName(entryName)}`;
      const regular = h.type === "0" || h.type === "7" || h.type === "\0";
      if (!regular || entryName.endsWith("/")) {
        // Directories and global pax headers are left out silently, the
        // rest said; each counts as an entry.
        if (!counted()) return;
        if (h.type !== "5" && h.type !== "g" && !entryName.endsWith("/")) {
          yield { type: "skip", name: label, reason: `not a regular file (${TAR_SKIP[h.type] ?? `tar type ${cleanName(h.type)}`})` };
        }
        why = await drain(h.size + pad);
        if (why) return yield* stopTar(why);
        continue;
      }
      if (macJunk(entryName)) {
        why = await drain(h.size + pad);
        if (why) return yield* stopTar(why);
        continue;
      }
      // What the entry left unread is skipped, so the next header lines up.
      const track = { left: h.size };
      yield* entry(label, r.take(h.size, track), depth, meter);
      out += h.size - track.left;
      if (st.stop) return;
      if (bomb()) return yield* stopTar(bombRest);
      why = await drain(track.left + pad);
      if (why) return yield* stopTar(why);
      await breathe();
    }
  }

  async function* zip(name, blob, depth) {
    const dir = await zipDirectory(blob);
    if (dir.error) yield { type: "skip", name, reason: dir.error };
    for (const ent of dir.entries ?? []) {
      if (st.stop) return;
      if (ent.name.endsWith("/") || macJunk(ent.name)) continue;
      const label = `${name}/${cleanName(ent.name)}`;
      const skip = (reason) => {
        st.entries++;
        return { type: "skip", name: label, reason };
      };
      if (ent.flags & 1) {
        yield skip("encrypted; the page does not take passwords");
        continue;
      }
      if (ent.method !== 0 && ent.method !== 8) {
        yield skip(`compressed with method ${ent.method}, which the page does not read (only stored and deflate)`);
        continue;
      }
      if (ent.size > limits.entryBytes) {
        yield skip(`larger than ${bytesText(limits.entryBytes)} unpacked`);
        continue;
      }
      const start = await zipDataStart(blob, ent);
      if (start < 0 || start + ent.packed > blob.size) {
        yield skip("its local header is damaged");
        continue;
      }
      const raw = chunksOf(blob.slice(start, start + ent.packed).stream());
      const meter = { packed: ent.packed };
      yield* entry(label, ent.method === 8 ? inflate(raw, "deflate-raw") : raw, depth, ent.method === 8 ? meter : null);
      await breathe();
    }
  }

  for (const src of sources) {
    if (st.stop) break;
    const name = cleanName(src.name);
    if (typeof src.text === "string") {
      const bytes = new TextEncoder().encode(src.text);
      yield* entry(name, (async function* () { yield bytes; })(), 0);
    } else if (sniff(new Uint8Array(await src.blob.slice(0, 4).arrayBuffer())) === "zip") {
      // A zip is read from its end, by slices of the file.
      st.entries++;
      try {
        yield* zip(name, src.blob, 1);
      } catch (e) {
        yield { type: "skip", name, reason: `could not be read: ${String(e?.message ?? e)}` };
      }
    } else {
      yield* entry(name, chunksOf(src.blob.stream()), 0);
    }
    if (st.stop) yield { type: "stop", reason: st.stop };
    await breathe();
  }
}

/**
 * Whether a picked set needs the set reader rather than the text box:
 * more than one file, or one whose first bytes are an archive.
 */
export async function needsSet(files) {
  if (files.length !== 1) return files.length > 1;
  const head = new Uint8Array(await files[0].slice(0, 512).arrayBuffer());
  const kind = sniff(head);
  return kind === "gzip" || kind === "zip" || kind === "tar";
}
