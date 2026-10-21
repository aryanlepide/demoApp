import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import handler, { config } from "../api/[...path].ts";

test("exports a Vercel Node handler with raw multipart body access", () => {
  assert.equal(typeof handler, "function");
  assert.deepEqual(config, { api: { bodyParser: false } });
});

test("rewrites app pages to the static shell and includes synthetic scan fixtures", () => {
  const configFile = JSON.parse(readFileSync(new URL("../vercel.json", import.meta.url), "utf8"));
  const sources = configFile.rewrites.map((rewrite: { source: string }) => rewrite.source);

  for (const route of ["/", "/login", "/signup", "/dashboard", "/upload", "/findings"]) {
    assert.ok(sources.includes(route), `missing Vercel rewrite for ${route}`);
  }
  assert.equal(configFile.functions["api/[...path].ts"].includeFiles, "tests/fixtures/additional/**");
});