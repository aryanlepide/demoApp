import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import { after, before, test } from "node:test";
import { createServer } from "../src/server.ts";

const server = createServer();
let origin = "";
let ownerEmail = "";
let ownerPassword = "";
let ownerCookie = "";

async function createAccount(email: string, name: string, password: string) {
  const response = await fetch(`${origin}/api/auth/signup`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, name, password }),
  });
  const cookie = response.headers.get("set-cookie")?.split(";")[0] ?? "";
  return { response, cookie };
}

function apiFetch(path: string, init: RequestInit = {}, cookie = ownerCookie) {
  const headers = new Headers(init.headers);
  if (cookie) headers.set("Cookie", cookie);
  return fetch(`${origin}${path}`, { ...init, headers });
}

before(async () => {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Test server did not bind to a port.");
  origin = `http://127.0.0.1:${address.port}`;
  ownerEmail = `test-owner-${randomUUID()}@example.test`;
  ownerPassword = randomBytes(24).toString("base64url");
  const created = await createAccount(ownerEmail, "Synthetic Test Owner", ownerPassword);
  assert.equal(created.response.status, 201);
  ownerCookie = created.cookie;
});

after(async () => {
  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
});

test("serves public auth pages and protects dashboard APIs and pages", async () => {
  const loginPage = await fetch(`${origin}/login`);
  const signupPage = await fetch(`${origin}/signup`);
  assert.equal(loginPage.status, 200);
  assert.equal(signupPage.status, 200);
  assert.match(await loginPage.text(), /prototype.js/);

  const root = await fetch(origin, { redirect: "manual" });
  const dashboard = await fetch(`${origin}/dashboard`, { redirect: "manual" });
  assert.equal(root.status, 302);
  assert.equal(root.headers.get("location"), "/login");
  assert.equal(dashboard.status, 302);
  assert.match(dashboard.headers.get("location") ?? "", /^\/login\?next=/);
  assert.equal((await fetch(`${origin}/api/dashboard`)).status, 401);
  assert.deepEqual(await (await fetch(`${origin}/api/auth/me`)).json(), {
    authenticated: false,
    user: null,
    authMode: "local-demo",
  });

  const authenticatedDashboard = await (await apiFetch("/api/dashboard")).json();
  assert.equal(authenticatedDashboard.metrics.filesScanned, 0);
  assert.deepEqual(authenticatedDashboard.recentScans, []);
  const samples = await (await apiFetch("/api/samples")).json();
  assert.equal(samples.samples.length, 3);
  assert.equal(JSON.stringify(samples).includes("alex@example.test"), false);
});

test("logs in, rejects invalid credentials, logs out, and isolates accounts", async () => {
  const login = await fetch(`${origin}/api/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: ownerEmail, password: ownerPassword }),
  });
  const loginBody = await login.json();
  const loginCookie = login.headers.get("set-cookie")?.split(";")[0] ?? "";
  assert.equal(login.status, 200);
  assert.equal(loginBody.user.email, ownerEmail);
  assert.equal(JSON.stringify(loginBody).includes(ownerPassword), false);
  assert.match(login.headers.get("set-cookie") ?? "", /HttpOnly/);

  const wrongPassword = await fetch(`${origin}/api/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: ownerEmail, password: randomBytes(24).toString("base64url") }),
  });
  assert.equal(wrongPassword.status, 401);

  const duplicate = await createAccount(ownerEmail, "Duplicate Owner", randomBytes(24).toString("base64url"));
  assert.equal(duplicate.response.status, 409);

  const second = await createAccount(`other-${randomUUID()}@example.test`, "Other User", randomBytes(24).toString("base64url"));
  assert.equal(second.response.status, 201);
  const secondDashboard = await (await apiFetch("/api/dashboard", {}, second.cookie)).json();
  const secondFindings = await (await apiFetch("/api/findings", {}, second.cookie)).json();
  assert.equal(secondDashboard.metrics.filesScanned, 0);
  assert.deepEqual(secondFindings.findings, []);

  const logout = await apiFetch("/api/auth/logout", { method: "POST" }, loginCookie);
  assert.equal(logout.status, 200);
  assert.deepEqual(await (await apiFetch("/api/auth/me", {}, loginCookie)).json(), {
    authenticated: false,
    user: null,
    authMode: "local-demo",
  });
});

test("scans a known synthetic sample and aligns Dashboard, risk, and Findings totals", async () => {
  const response = await apiFetch("/api/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ sampleId: "mixed" }),
  });
  const result = await response.json();
  const serialized = JSON.stringify(result);

  assert.equal(response.status, 200);
  assert.equal(result.risk, "Critical");
  assert.deepEqual(result.findings.map((finding: { risk: string }) => finding.risk), ["Critical", "High", "Medium", "Low"]);
  const dashboard = await (await apiFetch("/api/dashboard")).json();
  const findingsView = await (await apiFetch("/api/findings")).json();
  assert.equal(dashboard.metrics.filesScanned, 1);
  assert.equal(dashboard.metrics.criticalRiskFiles, 1);
  assert.equal(dashboard.recentScans[0].fileName, "22_all_four.csv");
  const findingsOccurrences = findingsView.findings.reduce(
    (total: number, finding: { count: number }) => total + finding.count,
    0,
  );
  assert.equal(findingsOccurrences, dashboard.metrics.totalFindings);
  assert.equal(
    dashboard.riskDistribution.reduce((total: number, item: { occurrences: number }) => total + item.occurrences, 0),
    dashboard.metrics.totalFindings,
  );
  assert.deepEqual(dashboard.riskDistribution, [
    { risk: "Critical", files: 1, occurrences: 1, share: 25 },
    { risk: "High", files: 0, occurrences: 1, share: 25 },
    { risk: "Medium", files: 0, occurrences: 1, share: 25 },
    { risk: "Low", files: 0, occurrences: 1, share: 25 },
    { risk: "None", files: 0, occurrences: 0, share: 0 },
  ]);
  for (const value of ["alex@example.test", "07700 900123", "AB 12 34 56 C", "4111 1111 1111 1111"]) {
    assert.equal(serialized.includes(value), false);
  }
});

test("rejects arbitrary sample paths without echoing request data", async () => {
  const response = await apiFetch("/api/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ sampleId: "../../WORK_LOG.md" }),
  });
  const body = await response.text();
  assert.equal(response.status, 400);
  assert.equal(body.includes("WORK_LOG.md"), false);
});

test("accepts synthetic multipart uploads and exposes only masked scan metadata", async () => {
  const rawText = "Synthetic contact: qa-upload@example.test\nUK mobile: 07700 900123";
  const form = new FormData();
  form.append("file", new Blob([rawText], { type: "text/plain" }), "training.txt");

  const response = await apiFetch("/api/upload", { method: "POST", body: form });
  const result = await response.json();
  const dashboard = await (await apiFetch("/api/dashboard")).json();
  const findings = await (await apiFetch("/api/findings")).text();
  const criticalCards = await (await apiFetch("/api/findings?type=payment_card&risk=Critical")).json();

  assert.equal(response.status, 201);
  assert.equal(result.risk, "Medium");
  assert.equal(result.findingCount, 2);
  assert.equal(result.findings.some((finding: { maskedExample: string }) => finding.maskedExample.includes("qa-upload")), false);
  assert.equal(dashboard.metrics.filesScanned, 2);
  assert.deepEqual(dashboard.riskDistribution, [
    { risk: "Critical", files: 1, occurrences: 1, share: 17 },
    { risk: "High", files: 0, occurrences: 1, share: 17 },
    { risk: "Medium", files: 1, occurrences: 2, share: 33 },
    { risk: "Low", files: 0, occurrences: 2, share: 33 },
    { risk: "None", files: 0, occurrences: 0, share: 0 },
  ]);
  assert.equal(JSON.stringify(dashboard).includes("qa-upload@example.test"), false);
  assert.equal(findings.includes("qa-upload@example.test"), false);
  assert.equal(findings.includes("07700 900123"), false);
  assert.equal(criticalCards.findings.length, 1);
  assert.equal(criticalCards.findings[0].fileName, "22_all_four.csv");
});

test("reset clears only the signed-in user's scan history", async () => {
  const response = await apiFetch("/api/session/reset", { method: "POST" });
  const dashboard = await response.json();
  const findings = await (await apiFetch("/api/findings")).json();

  assert.equal(response.status, 200);
  assert.equal(dashboard.metrics.filesScanned, 0);
  assert.equal(dashboard.metrics.totalFindings, 0);
  assert.deepEqual(dashboard.recentScans, []);
  assert.deepEqual(findings.findings, []);
});

test("rejects unsupported, empty, binary, invalid UTF-8, and oversized uploads", async () => {
  const cases: Array<{ name: string; bytes: BlobPart; status: number }> = [
    { name: "unsupported.json", bytes: "qa@example.test", status: 400 },
    { name: "CSV SENSITIVE.xlsx", bytes: "synthetic workbook placeholder", status: 400 },
    { name: "empty.txt", bytes: "", status: 400 },
    { name: "binary.csv", bytes: new Uint8Array([65, 0, 66]), status: 400 },
    { name: "invalid-utf8.txt", bytes: new Uint8Array([0xc3, 0x28]), status: 400 },
    { name: "too-large.txt", bytes: new Uint8Array(1_048_577), status: 413 },
  ];

  for (const sample of cases) {
    const form = new FormData();
    form.append("file", new Blob([sample.bytes]), sample.name);
    const response = await apiFetch("/api/upload", { method: "POST", body: form });
    const body = await response.text();
    assert.equal(response.status, sample.status, sample.name);
    assert.equal(body.includes("qa@example.test"), false, sample.name);
    if (sample.name.endsWith(".xlsx")) {
      assert.match(body, /Excel workbooks \(\.xlsx\) are not supported/);
      assert.match(body, /export the workbook as CSV/);
    }
  }
});
