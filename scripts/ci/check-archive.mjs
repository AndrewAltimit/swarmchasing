#!/usr/bin/env node
// Tests for the site's archive reader (site/js/lib/archive.js), run in
// Node, which has the same DecompressionStream, Blob and TextDecoder the
// browser does. Every fixture is synthetic and built here at run time
// (scripts/ci/archive-fixtures.mjs): logs on .example hosts in gzip, zip,
// tar and tar.gz, hostile entry names, links, encrypted and binary
// entries, ZIP64 records, nested archives, gzips of several members, runs
// of header-only tar entries, truncated tars, and sets past each limit.
// Node's DecompressionStream reads past a gzip's first member and Chrome's
// does not; the reader finds member ends itself in both, and the gzip
// tests here check that path against zlib.
//
// Usage: node scripts/ci/check-archive.mjs
// Exit 0 is a pass, 1 a failure.

import { strict as assert } from "node:assert";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { gzipSync } from "node:zlib";
import { accessLog, crc32, gzip, logSet, tar, zip } from "./archive-fixtures.mjs";

const ROOT = resolve(import.meta.dirname, "..", "..");
const A = await import(pathToFileURL(resolve(ROOT, "site/js/lib/archive.js")).href);
const { LIMITS, MiB, sniff, looksBinary, cleanName, tarHeader, paxPath, bytesText, unpack, needsSet, zipDirectory, gunzippedName, gzipMembers, concat } = A;

const enc = new TextEncoder();
const blob = (b, name = "x") => ({ name, blob: new Blob([b]) });
async function read(sources, limits = LIMITS) {
  const out = { files: [], skips: [], stop: null, progress: 0 };
  for await (const ev of unpack(sources, { limits, onProgress: () => out.progress++ })) {
    if (ev.type === "file") out.files.push([ev.name, ev.text]);
    else if (ev.type === "skip") out.skips.push([ev.name, ev.reason]);
    else out.stop = ev.reason;
  }
  return out;
}

const tests = [];
const test = (name, fn) => tests.push([name, fn]);
const logs = logSet();
const names = Object.keys(logs);

test("sniff reads the bytes, not the name", () => {
  assert.equal(sniff(gzip("a")), "gzip");
  assert.equal(sniff(zip([{ name: "a", data: "b" }])), "zip");
  assert.equal(sniff(zip([])), "zip");
  assert.equal(sniff(tar([{ name: "a.log", data: "x" }])), "tar");
  assert.equal(sniff(enc.encode("203.0.113.7 - - [04/Oct/2026...")), "text");
  assert.equal(sniff(new Uint8Array([0x7f, 0x45, 0x4c, 0x46, 0, 1])), "binary");
  assert.equal(sniff(new Uint8Array(0)), "empty");
  assert.ok(looksBinary(new Uint8Array([1, 2, 3, 4, 5, 65])));
  assert.ok(!looksBinary(enc.encode("a\tb\r\nc\x1b[0m")));
});

test("names are labels: control characters shown, leading slashes dropped, cut", () => {
  assert.equal(cleanName("/etc/../x\u0000\u001b.log"), "etc/../x??.log");
  assert.equal(cleanName("./a.log"), "a.log");
  assert.equal(cleanName(""), "(no name)");
  assert.equal(cleanName("a".repeat(400)).length, 300);
  assert.equal(gunzippedName("access.log.2.gz"), "access.log.2");
  assert.equal(bytesText(3 * MiB), "3.0 MB");
});

test("tar headers: ustar fields, the zero block, a bad checksum, pax paths", () => {
  const t = tar([{ name: "logs/a.log", data: "hello" }]);
  assert.deepEqual(tarHeader(t.subarray(0, 512)), { name: "logs/a.log", size: 5, type: "0" });
  assert.equal(tarHeader(new Uint8Array(512)), null);
  const bad = t.slice(0, 512);
  bad[0] ^= 1;
  assert.deepEqual(tarHeader(bad), { bad: true });
  assert.equal(paxPath(enc.encode("20 path=dir/a-b.log\n12 uid=1234\n")), "dir/a-b.log");
  // Record lengths count bytes: a non-ASCII path is cut where its bytes end.
  assert.equal(paxPath(enc.encode("12 uid=1234\n29 path=var/\u65e5\u5fd7/\u00e9t\u00e9.log\n")), "var/\u65e5\u5fd7/\u00e9t\u00e9.log");
});

test("a pax path with non-ASCII characters names its entry whole", async () => {
  const name = "var/log/\u65e5\u5fd7-\u00e9t\u00e9-\u0436\u0443\u0440\u043d\u0430\u043b.log";
  const r = await read([blob(gzip(tar([{ name, pax: true, data: logs["access.log"] }, { name: "after.log", data: logs["access.log.1"] }])), "intl.tgz")]);
  assert.deepEqual(r.files.map((f) => f[0]), [`intl.tgz/${name}`, "intl.tgz/after.log"]);
});

test("a plain log and a gzipped one read as text", async () => {
  const r = await read([blob(enc.encode(logs["access.log"]), "access.log"), blob(gzip(logs["access.log.1"]), "access.log.1.gz")]);
  assert.deepEqual(r.files.map((f) => f[0]), ["access.log", "access.log.1"]);
  assert.equal(r.files[1][1], logs["access.log.1"]);
  assert.equal(r.skips.length, 0);
  assert.ok(r.progress >= 2);
});

test("a zip of logs: stored and deflated read; directories, Mac metadata, encrypted and binary entries skipped or left out", async () => {
  const z = zip([
    { name: "logs/", data: "" },
    { name: "logs/access.log", data: logs["access.log"] },
    { name: "logs/access.log.1", data: logs["access.log.1"], method: 0 },
    { name: "__MACOSX/logs/._access.log", data: "\0\0junk" },
    { name: "logs/secret.log", data: "x", encrypted: true },
    { name: "logs/core.bin", data: new Uint8Array([0x7f, 0x45, 0x4c, 0x46, 0, 0, 0]) },
    { name: "../../../etc/<img src=x onerror=alert(1)>.log", data: logs["access.log.2"] },
  ]);
  const r = await read([blob(z, "site-logs.zip")]);
  assert.deepEqual(r.files.map((f) => f[0]), ["site-logs.zip/logs/access.log", "site-logs.zip/logs/access.log.1", "site-logs.zip/../../../etc/<img src=x onerror=alert(1)>.log"]);
  assert.equal(r.files[2][1], logs["access.log.2"]);
  assert.deepEqual(r.skips.map((s) => s[0]), ["site-logs.zip/logs/secret.log", "site-logs.zip/logs/core.bin"]);
  assert.match(r.skips[0][1], /encrypted/);
  assert.match(r.skips[1][1], /binary/);
});

test("ZIP64 sizes and offsets are read", async () => {
  const z = zip(names.map((n) => ({ name: n, data: logs[n] })), { zip64: true });
  const dir = await zipDirectory(new Blob([z]));
  assert.equal(dir.entries.length, names.length);
  assert.equal(dir.entries[1].size, enc.encode(logs[names[1]]).length);
  const r = await read([blob(z, "big.zip")]);
  assert.deepEqual(r.files.map((f) => f[1]), names.map((n) => logs[n]));
});

test("a .tgz: GNU long names, pax paths, links and devices skipped", async () => {
  const long = `var/log/${"nginx-".repeat(30)}/access.log`;
  const t = tar([
    { name: "var/log/", type: "5" },
    { name: long, data: logs["access.log"] },
    { name: "x", pax: true, data: logs["access.log.1"] },
    { name: "var/log/current", type: "2", link: "/etc/shadow" },
    { name: "var/log/access.log.2", data: logs["access.log.2"] },
  ]);
  const r = await read([blob(gzip(t), "logs.tgz")]);
  assert.deepEqual(r.files.map((f) => f[0]), [`logs.tgz/${long}`, "logs.tgz/x", "logs.tgz/var/log/access.log.2"]);
  assert.equal(r.files[2][1], logs["access.log.2"]);
  assert.deepEqual(r.skips, [["logs.tgz/var/log/current", "not a regular file (a symbolic link)"]]);
});

test("an entry skipped part-way leaves the tar aligned for the next", async () => {
  const t = tar([
    { name: "a.bin", data: new Uint8Array(40000).fill(0) },
    { name: "b.log", data: logs["access.log"] },
  ]);
  const r = await read([blob(t, "plain.tar")]);
  assert.deepEqual(r.files.map((f) => f[0]), ["plain.tar/b.log"]);
  assert.equal(r.files[0][1], logs["access.log"]);
});

test("nested archives: one level read, a deeper one skipped", async () => {
  const inner = zip([{ name: "deep.log", data: logs["access.log"] }]);
  const deeper = gzip(tar([{ name: "deeper.zip", data: inner }]));
  const t = tar([
    { name: "inner.zip", data: inner },
    { name: "app.json.gz", data: gzip(logs["app.json"]) },
    { name: "deeper.tgz", data: deeper },
  ]);
  const r = await read([blob(gzip(t), "outer.tar.gz")]);
  assert.deepEqual(r.files.map((f) => f[0]), ["outer.tar.gz/inner.zip/deep.log", "outer.tar.gz/app.json"]);
  assert.equal(r.skips.length, 1);
  assert.match(r.skips[0][1], /nested deeper than one level/);
});

test("the set stops at its unpacked limit, its entry limit, and skips a bomb or a huge entry", async () => {
  const big = accessLog({ n: 4000 });
  const z = zip([{ name: "a.log", data: big }, { name: "b.log", data: big }, { name: "c.log", data: big }]);
  let r = await read([blob(z, "a.zip")], { ...LIMITS, totalBytes: 2.5 * enc.encode(big).length });
  assert.equal(r.files.length, 2);
  assert.match(r.stop, /stopped/);

  r = await read([blob(z, "a.zip"), blob(enc.encode(big), "more.log")], { ...LIMITS, entries: 3 });
  assert.equal(r.files.length, 2);
  assert.match(r.stop, /more than 3 files/);

  const bomb = gzip("a\n".repeat(600000));
  r = await read([blob(bomb, "bomb.log.gz")], { ...LIMITS, ratio: 50, ratioAfter: 64 * 1024 });
  assert.equal(r.files.length, 0);
  assert.match(r.skips[0][1], /archive bomb/);

  r = await read([blob(enc.encode(big), "huge.log")], { ...LIMITS, entryBytes: 1000 });
  assert.match(r.skips[0][1], /larger than/);
});

test("entries passed over count: a link with a huge body in a .tgz, a set past its limit, a tar in a zip", async () => {
  // A symbolic link that carries 64 MB of zeros packs to a few dozen kB:
  // passing over it is held to the ratio, so the archive stops, quickly.
  const zeros = new Uint8Array(64 * MiB);
  const t0 = Date.now();
  let r = await read([blob(gzip(tar([{ name: "link", type: "2", link: "x", body: true, data: zeros }, { name: "after.log", data: logs["access.log"] }])), "bomb.tgz")]);
  assert.deepEqual(r.files, []);
  assert.match(r.skips.at(-1)[1], /archive bomb/);
  assert.ok(Date.now() - t0 < 20000, "the bomb was drained, not stopped");

  // Uncompressed, what is passed over counts against the set's limit.
  r = await read([blob(tar([{ name: "link", type: "2", link: "x", body: true, data: new Uint8Array(4 * MiB) }, { name: "after.log", data: logs["access.log"] }]), "big.tar")], { ...LIMITS, totalBytes: 1 * MiB });
  assert.deepEqual(r.files, []);
  assert.match(r.stop, /passed over/);

  // A tar inside a deflated zip entry is held to that entry's ratio.
  const inner = tar([{ name: "a.log", data: "a\n".repeat(1_000_000) }]);
  r = await read([blob(zip([{ name: "logs.tar", data: inner }]), "tar-in.zip")], { ...LIMITS, ratio: 50, ratioAfter: 64 * 1024 });
  assert.deepEqual(r.files, []);
  assert.match(r.skips[0][1], /archive bomb/);
});

test("damaged archives are skipped with a reason, not thrown", async () => {
  const z = zip([{ name: "a.log", data: logs["access.log"] }]);
  let r = await read([blob(z.subarray(0, z.length - 30), "cut.zip")]);
  assert.equal(r.files.length, 0);
  assert.match(r.skips[0][1], /zip directory/);
  const g = gzip(logs["access.log"]);
  r = await read([blob(g.subarray(0, 20), "cut.log.gz")]);
  assert.equal(r.files.length, 0);
  assert.match(r.skips[0][1], /could not be read/);
});

test("a set needs the set reader when it is several files or an archive", async () => {
  assert.ok(await needsSet([new Blob(["a"]), new Blob(["b"])]));
  assert.ok(await needsSet([new Blob([gzip("a")])]));
  assert.ok(!(await needsSet([new Blob(["just a log"])])));
});

test("text handed over as text reads as itself", async () => {
  const r = await read([{ name: "carried.log", text: logs["access.log"] }]);
  assert.deepEqual(r.files, [["carried.log", logs["access.log"]]]);
});

/** `n` copies of one tar header block, then the end blocks. */
function headers(entry, n) {
  const one = tar([entry]).subarray(0, 512);
  const t = new Uint8Array(512 * n + 1024);
  for (let i = 0; i < n; i++) t.set(one, i * 512);
  return t;
}
let manyDirs = null; // 400,000 directory headers, gzipped once: about 1 MB packed, 205 MB unpacked

test("header-only tar entries count: directories against the entry limit, the unpacked limit and the ratio", async () => {
  manyDirs ??= gzipSync(headers({ name: "d/", type: "5" }, 400000), { level: 9 });
  const t0 = Date.now();
  let r = await read([blob(manyDirs, "dirs.tgz")], { ...LIMITS, totalBytes: 1 * MiB, entries: 10 });
  assert.match(r.stop ?? "", /more than 10 files/);
  assert.ok(Date.now() - t0 < 5000, "the directories were read to the end");

  const dirs = headers({ name: "d/", type: "5" }, 20000);
  r = await read([blob(dirs, "dirs.tar")], { ...LIMITS, totalBytes: 1 * MiB });
  assert.match(r.stop ?? "", /passed over/);
  r = await read([blob(gzipSync(dirs, { level: 9 }), "dirs.tgz")], { ...LIMITS, ratio: 10, ratioAfter: 64 * 1024 });
  assert.equal(r.stop, null);
  assert.match(r.skips.at(-1)?.[1] ?? "", /archive bomb/);

  // Global pax headers and GNU long link names are passed over the same way.
  r = await read([blob(gzipSync(headers({ name: "g", type: "g" }, 20000), { level: 9 }), "g.tgz")], { ...LIMITS, ratio: 10, ratioAfter: 64 * 1024 });
  assert.match(r.skips.at(-1)?.[1] ?? "", /archive bomb/);
});

test("pax and long-name records count toward the unpacked limit and the ratio", async () => {
  const body = `60011 comment=${"x".repeat(60000)}\n`.slice(0, 60000);
  const ents = [];
  for (let i = 0; i < 200; i++) ents.push({ name: "p", type: "x", data: body, body: true });
  ents.push({ name: "a.log", data: "hello\n" });
  const t = tar(ents);
  let r = await read([blob(t, "pax.tar")], { ...LIMITS, totalBytes: 1 * MiB });
  assert.deepEqual(r.files, []);
  assert.match(r.stop ?? "", /passed over/);
  r = await read([blob(gzipSync(t, { level: 9 }), "pax.tgz")], { ...LIMITS, ratio: 10, ratioAfter: 64 * 1024 });
  assert.deepEqual(r.files, []);
  assert.match(r.skips.at(-1)?.[1] ?? "", /archive bomb/);
});

test("a zip inside a compressed entry is held to its ratio and the set's limit while it is buffered", async () => {
  // 20 deflated inner zips, each 16 MB stored: a few hundred kB packed.
  const inner = zip([{ name: "bin", data: new Uint8Array(16 * MiB), method: 0 }]);
  const outer = zip(Array.from({ length: 20 }, (_, i) => ({ name: `n${i}.zip`, data: inner })));
  const t0 = Date.now();
  let r = await read([blob(outer, "outer.zip")], { ...LIMITS, totalBytes: 1 * MiB, ratio: 10, ratioAfter: 64 * 1024 });
  assert.match(r.skips[0]?.[1] ?? "", /archive bomb/);
  assert.match(r.stop ?? "", /stopped/);
  assert.ok(Date.now() - t0 < 5000, "the nested zips were buffered whole");

  // A zip inside a gzip, the same.
  const z = zip([{ name: "a.log", data: "A".repeat(4 * MiB), method: 0 }]);
  r = await read([blob(gzipSync(z, { level: 9 }), "z.zip.gz")], { ...LIMITS, ratio: 10, ratioAfter: 64 * 1024 });
  assert.deepEqual(r.files, []);
  assert.match(r.skips[0]?.[1] ?? "", /archive bomb/);

  // Buffered bytes count toward the set's limit.
  r = await read([blob(gzipSync(z), "z.zip.gz")], { ...LIMITS, totalBytes: 1 * MiB });
  assert.deepEqual(r.files, []);
  assert.match(r.stop ?? "", /stopped/);

  // Under the limits, a zip inside a gzip still reads.
  r = await read([blob(gzipSync(zip([{ name: "a.log", data: logs["access.log"] }])), "small.zip.gz")]);
  assert.deepEqual(r.files, [["small.zip/a.log", logs["access.log"]]]);
});

test("a gzip inside a deflated zip entry is held to its own ratio", async () => {
  const inner = gzipSync("B".repeat(4 * MiB) + "\n", { level: 9 });
  const r = await read([blob(zip([{ name: "a.log.gz", data: inner }]), "x.zip")], { ...LIMITS, ratio: 10, ratioAfter: 64 * 1024 });
  assert.deepEqual(r.files, []);
  assert.match(r.skips[0]?.[1] ?? "", /archive bomb/);
});

/** A gzip member with every optional header field: extra, name, comment and header CRC. */
function fullHeader(data) {
  const g = gzipSync(data);
  const extra = [0x41, 0x42, 3, 0, 1, 2, 3];
  const head = [...g.subarray(0, 10), 6, 0, ...extra, ...enc.encode("rotated.log\0"), ...enc.encode("a comment\0")];
  head[3] = 0x1e;
  const crc = crc32(Uint8Array.from(head)) & 0xffff;
  return concat([Uint8Array.from([...head, crc & 0xff, crc >> 8]), g.subarray(10)]);
}

test("a gzip of several members reads every member", async () => {
  let r = await read([blob(concat([gzipSync("one\n"), gzipSync("two\n")]), "cat.gz")]);
  assert.deepEqual(r.files, [["cat", "one\ntwo\n"]]);

  // Rotated logs joined with cat, at every level, one with every header field,
  // an empty member among them, and zeros after the last (as some tools pad).
  const parts = [gzipSync(logs["access.log"], { level: 0 }), gzipSync(""), fullHeader(logs["access.log.1"]), gzipSync(logs["access.log.2"], { level: 9 })];
  r = await read([blob(concat([...parts, new Uint8Array(512)]), "access.log.gz")]);
  assert.deepEqual(r.files, [["access.log", logs["access.log"] + logs["access.log.1"] + logs["access.log.2"]]]);
  assert.deepEqual(r.skips, []);

  // A .tgz whose tar spans members (bgzip and pigz cut where they like).
  const t = tar([{ name: "a.log", data: logs["access.log"] }, { name: "b.log", data: logs["access.log.1"] }]);
  r = await read([blob(concat([gzipSync(t.subarray(0, 700)), gzipSync(t.subarray(700, 1601)), gzipSync(t.subarray(1601))]), "split.tgz")]);
  assert.deepEqual(r.files, [["split.tgz/a.log", logs["access.log"]], ["split.tgz/b.log", logs["access.log.1"]]]);

  // The ratio holds across members: many small bombs are one bomb.
  const bomb = gzipSync("a\n".repeat(50000), { level: 9 });
  r = await read([blob(concat(Array.from({ length: 100 }, () => bomb)), "bombs.log.gz")], { ...LIMITS, ratio: 50, ratioAfter: 64 * 1024 });
  assert.deepEqual(r.files, []);
  assert.match(r.skips[0]?.[1] ?? "", /archive bomb/);
});

test("member by member, every deflate block kind and any chunking reads as zlib does", async () => {
  const { constants: Z } = await import("node:zlib");
  let seed = 7;
  const rand = () => (seed = (seed * 1103515245 + 12345) >>> 0) / 2 ** 32;
  const noise = (n) => Uint8Array.from({ length: n }, () => Math.floor(rand() * 256));
  // Text, random bytes, and a stored member whose data holds a gzip header.
  const datas = [enc.encode(accessLog({ n: 3000 })), noise(70000), enc.encode("x".repeat(300000)), concat([gzipSync("fake"), noise(100)]), new Uint8Array(0)];
  const opts = [{ level: 0 }, { level: 1 }, { level: 6 }, { level: 9 }, { strategy: Z.Z_FIXED }, { strategy: Z.Z_HUFFMAN_ONLY }, { strategy: Z.Z_RLE }];
  const members = [], want = [];
  datas.forEach((d, i) => opts.forEach((o, j) => {
    if ((i + j) % 2 === 0) {
      members.push(gzipSync(d, o));
      want.push(d);
    }
  }));
  const unpacked = async (whole, size) => {
    const chunks = (async function* () {
      for (let at = 0; at < whole.length; at += size) yield whole.subarray(at, at + size);
    })();
    const out = [];
    for await (const c of gzipMembers(chunks)) out.push(c);
    return concat(out);
  };
  const same = (got, want, what) => {
    assert.equal(got.length, want.length, what);
    assert.ok(got.every((x, i) => x === want[i]), what);
  };
  const whole = concat(members);
  for (const size of [61, 4096, whole.length]) same(await unpacked(whole, size), concat(want), `chunks of ${size}`);
  // Byte by byte, over a stored, a fixed and a dynamic member.
  const small = [enc.encode("stored\n"), enc.encode("fixed\n"), enc.encode(accessLog({ n: 20 }))];
  const smallGz = concat([gzipSync(small[0], { level: 0 }), gzipSync(small[1], { strategy: Z.Z_FIXED }), gzipSync(small[2])]);
  same(await unpacked(smallGz, 1), concat(small), "chunks of 1");
  // A damaged member is an error, not text.
  const bad = gzipSync(enc.encode(accessLog({ n: 50 })));
  bad[20] ^= 0xff;
  await assert.rejects(async () => {
    for await (const _ of gzipMembers((async function* () { yield concat([gzipSync("ok\n"), bad]); })()));
  });
});

test("a tar that ends early says so", async () => {
  const t = tar([{ name: "a.log", data: "hello\n" }, { name: "b".repeat(150), data: "x\n" }]);
  let r = await read([blob(t.subarray(0, 512 * 2 + 300), "cut.tar")]);
  assert.deepEqual(r.files, [["cut.tar/a.log", "hello\n"]]);
  assert.match(r.skips.at(-1)?.[1] ?? "", /ends early/);
  r = await read([blob(t.subarray(0, 512 * 2 + 100), "cut2.tar")]);
  assert.match(r.skips.at(-1)?.[1] ?? "", /ends early/);
  const t2 = tar([{ name: "a.log", data: "hello\n" }, { name: "b.log", data: "x\n" }]);
  r = await read([blob(gzipSync(t2.subarray(0, 512 * 2 + 200)), "cut.tgz")]);
  assert.deepEqual(r.files.map((f) => f[0]), ["cut.tgz/a.log"]);
  assert.match(r.skips.at(-1)?.[1] ?? "", /ends early/);
  // A whole tar says nothing.
  r = await read([blob(t2, "whole.tar")]);
  assert.deepEqual(r.skips, []);
});

let failed = 0;
for (const [name, fn] of tests) {
  try {
    await fn();
    console.log(`ok   ${name}`);
  } catch (e) {
    failed++;
    console.error(`FAIL ${name}\n     ${String(e?.stack ?? e).split("\n").slice(0, 6).join("\n     ")}`);
  }
}
console.log(failed ? `check-archive: ${failed} of ${tests.length} failed` : `check-archive: all ${tests.length} passed`);
process.exit(failed ? 1 : 0);
