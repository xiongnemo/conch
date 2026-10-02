import assert from "node:assert/strict";
import { test } from "node:test";

import { countsAsFailure, describe, hostOf, newestFirst, record, rejects } from "../src/failures.ts";

test("network errors count, cancelled requests do not", () => {
  assert.equal(countsAsFailure("net::ERR_CONNECTION_RESET", "https://cdn.example.com/a.js"), true);
  assert.equal(countsAsFailure("NS_ERROR_NET_TIMEOUT", "https://cdn.example.com/a.js"), true);
  assert.equal(countsAsFailure("net::ERR_ABORTED", "https://cdn.example.com/a.js"), false);
  assert.equal(countsAsFailure("net::ERR_BLOCKED_BY_CLIENT", "https://ads.example.com/"), false);
  assert.equal(countsAsFailure("NS_BINDING_ABORTED", "https://cdn.example.com/a.js"), false);
  assert.equal(countsAsFailure("net::ERR_FAILED", "chrome-extension://abc/x.js"), false);
  assert.equal(countsAsFailure("net::ERR_FAILED", "not a url"), false);
});

test("failures are counted per host, newest first", () => {
  let t = record({}, "https://a.example.com/1", "net::ERR_TIMED_OUT", 1);
  t = record(t, "https://b.example.com/", "net::ERR_CONNECTION_RESET", 2);
  t = record(t, "https://a.example.com/2", "net::ERR_TIMED_OUT", 3);
  assert.deepEqual(newestFirst(t).map((f) => [f.host, f.count, f.url]), [
    ["a.example.com", 2, "https://a.example.com/2"],
    ["b.example.com", 1, "https://b.example.com/"],
  ]);
});

test("hosts are written the way conch writes them", () => {
  assert.equal(hostOf("https://[2001:db8::1]:8443/x"), "2001:db8::1");
  assert.equal(hostOf("https://Example.COM/"), "example.com");
});

test("errors are described in a few words", () => {
  assert.equal(describe("net::ERR_CONNECTION_TIMED_OUT"), "连接超时");
  assert.equal(describe("NS_ERROR_UNKNOWN_HOST"), "域名解析失败");
  assert.equal(describe("net::ERR_SOMETHING_NEW"), "net::ERR_SOMETHING_NEW");
});

test("hosts the rules block are told apart from failures", () => {
  const outbounds = [
    { name: "🛑 拦截", kind: "group", selected: "REJECT" },
    { name: "广告", kind: "group", selected: "🛑 拦截" },
    { name: "自动", kind: "group", now: "HK" },
    { name: "HK", kind: "node" },
    { name: "环", kind: "group", selected: "环" },
  ];
  assert.equal(rejects("REJECT", outbounds), true);
  assert.equal(rejects("广告", outbounds), true);
  assert.equal(rejects("自动", outbounds), false);
  assert.equal(rejects("DIRECT", outbounds), false);
  assert.equal(rejects("环", outbounds), false);
});
