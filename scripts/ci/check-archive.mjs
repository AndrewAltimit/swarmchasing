#!/usr/bin/env node
// Tests for the site's archive reader (site/js/lib/archive.js), run in
// Node, which has the same DecompressionStream, Blob and TextDecoder the
// browser does. Every fixture is synthetic and built here at run time
// (scripts/ci/archive-fixtures.mjs): logs on .example hosts in gzip, zip,
// tar and tar.gz, hostile entry names, links, encrypted and binary
// entries, ZIP64 records, nested archives, and sets past each limit.
//
// Usage: node scripts/ci/check-archive.mjs
// Exit 0 is a pass, 1 a failure.

import { strict as assert } from "node:assert";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { accessLog, gzip, logSet, tar, zip } from "./archive-fixtures.mjs";

const ROOT = resolve(import.meta.dirname, "..", "..");
const A = await import(pathToFileURL(resolve(ROOT, "site/js/lib/archive.js")).href);
const { LIMITS, MiB, sniff, looksBinary, cleanName, tarHeader, paxPath, bytesText, unpack, needsSet, zipDirectory, gunzippedName } = A;

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
