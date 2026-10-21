import { createServer as createHttpServer, type IncomingMessage, type ServerResponse } from "node:http";
import { readFile } from "node:fs/promises";
import { basename, extname, resolve } from "node:path";
import { randomBytes, randomUUID, scryptSync, timingSafeEqual } from "node:crypto";
import { pathToFileURL } from "node:url";
import { analyzeText } from "./detector.ts";
import type { Finding, RiskLevel, ScanResult } from "./detector.ts";

const root = resolve(import.meta.dirname, "..");
const fixtureRoot = resolve(root, "tests/fixtures/additional");
const publicRoot = resolve(root, "public");
const maxFileBytes = 1_048_576;
const maxRequestBytes = maxFileBytes + 16_384;
const sessionCookieName = "minidsp_session";
const sessionLifetimeMs = 8 * 60 * 60 * 1000;

const samples = {
  mixed: {
    fileName: "22_all_four.csv",
    label: "Mixed identifiers",
    description: "One synthetic example for each detector",
  },
  clean: {
    fileName: "01_clean_notes.txt",
    label: "Clean control",
    description: "A text sample with no sensitive patterns",
  },
  repeated: {
    fileName: "23_repeated_cards.txt",
    label: "Repeated matches",
    description: "Two valid test-card occurrences to verify counts",
  },
} as const;

const publicFiles = new Map([
  ["/login", "prototype.html"],
  ["/signup", "prototype.html"],
  ["/dashboard", "prototype.html"],
  ["/upload", "prototype.html"],
  ["/findings", "prototype.html"],
  ["/csv.js", "csv.js"],
  ["/prototype.js", "prototype.js"],
  ["/prototype.css", "prototype.css"],
]);

const contentTypes: Record<string, string> = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
};

interface ScanRecord {
  id: string;
  fileName: string;
  scannedAt: string;
  risk: RiskLevel;
  findings: Finding[];
}

interface Account {
  id: string;
  name: string;
  email: string;
  passwordSalt: Buffer;
  passwordHash: Buffer;
}

interface Session {
  userId: string;
  expiresAt: number;
}

const accountsByEmail = new Map<string, Account>();
const accountsById = new Map<string, Account>();
const sessions = new Map<string, Session>();
const scanHistory = new Map<string, ScanRecord[]>();
const riskOrder: RiskLevel[] = ["Critical", "High", "Medium", "Low", "None"];

function createRecord(fileName: string, result: ScanResult): ScanRecord {
  return {
    id: randomUUID(),
    fileName,
    scannedAt: new Date().toISOString(),
    risk: result.risk,
    findings: result.findings,
  };
}

function historyFor(userId: string): ScanRecord[] {
  let records = scanHistory.get(userId);
  if (!records) {
    records = [];
    scanHistory.set(userId, records);
  }
  return records;
}

function addRecord(userId: string, record: ScanRecord): void {
  const records = historyFor(userId);
  records.unshift(record);
  if (records.length > 100) records.length = 100;
}

function recordSummary(record: ScanRecord) {
  return {
    id: record.id,
    fileName: record.fileName,
    scannedAt: record.scannedAt,
    risk: record.risk,
    findingCount: record.findings.reduce((total, finding) => total + finding.count, 0),
  };
}

function authenticatedUser(request: IncomingMessage): Account | undefined {
  const cookie = request.headers.cookie?.split(";")
    .map((part) => part.trim())
    .find((part) => part.startsWith(`${sessionCookieName}=`));
  if (!cookie) return undefined;

  let sessionId: string;
  try {
    sessionId = decodeURIComponent(cookie.slice(sessionCookieName.length + 1));
  } catch {
    return undefined;
  }
  const session = sessions.get(sessionId);
  if (!session) return undefined;
  if (session.expiresAt <= Date.now()) {
    sessions.delete(sessionId);
    return undefined;
  }
  return accountsById.get(session.userId);
}

function setSessionCookie(response: ServerResponse, sessionId?: string): void {
  const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
  const value = sessionId
    ? `${sessionCookieName}=${encodeURIComponent(sessionId)}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${sessionLifetimeMs / 1000}${secure}`
    : `${sessionCookieName}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${secure}`;
  response.setHeader("Set-Cookie", value);
}

function startSession(response: ServerResponse, account: Account): void {
  const sessionId = randomBytes(32).toString("hex");
  sessions.set(sessionId, { userId: account.id, expiresAt: Date.now() + sessionLifetimeMs });
  setSessionCookie(response, sessionId);
}

function publicAccount(account: Account) {
  return { id: account.id, name: account.name, email: account.email };
}

function setHeaders(response: ServerResponse, contentType: string): void {
  response.setHeader("Content-Type", contentType);
  response.setHeader("Cache-Control", "no-store");
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("Referrer-Policy", "no-referrer");
  response.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self' https://lepide-design-system.vercel.app; "
      + "style-src 'self' https://lepide-design-system.vercel.app; "
      + "font-src 'self' https://lepide-design-system.vercel.app data:; "
      + "connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'",
  );
}

function sendJson(response: ServerResponse, status: number, value: unknown): void {
  setHeaders(response, "application/json; charset=utf-8");
  response.statusCode = status;
  response.end(JSON.stringify(value));
}

async function readJsonBody(request: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let totalBytes = 0;
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    totalBytes += buffer.byteLength;
    if (totalBytes > maxRequestBytes) throw new RangeError("Request body too large.");
    chunks.push(buffer);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

async function readUploadBody(request: IncomingMessage): Promise<Buffer> {
  const contentLength = Number(request.headers["content-length"] ?? 0);
  if (contentLength > maxRequestBytes) throw new RangeError("Request body too large.");

  const chunks: Buffer[] = [];
  let totalBytes = 0;
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    totalBytes += buffer.byteLength;
    if (totalBytes > maxRequestBytes) throw new RangeError("Request body too large.");
    chunks.push(buffer);
  }
  return Buffer.concat(chunks);
}

async function parseUpload(request: IncomingMessage): Promise<{ fileName: string; text: string }> {
  const contentType = request.headers["content-type"];
  if (!contentType?.toLowerCase().startsWith("multipart/form-data;")) {
    throw new TypeError("Choose a CSV or TXT file to scan.");
  }

  const body = await readUploadBody(request);
  const form = await new Request("http://localhost/upload", {
    method: "POST",
    headers: { "Content-Type": contentType },
    body,
  }).formData();
  const file = form.get("file");
  if (!(file instanceof File)) throw new TypeError("Choose a CSV or TXT file to scan.");
  if (file.size === 0) throw new TypeError("The selected file is empty.");
  if (file.size > maxFileBytes) throw new RangeError("Files must be 1 MiB or smaller.");

  const fileName = basename(file.name.replace(/\\/g, "/"));
  const extension = extname(fileName).toLowerCase();
  if (extension === ".xlsx") {
    throw new TypeError("Excel workbooks (.xlsx) are not supported. Save or export the workbook as CSV (.csv), then upload that file.");
  }
  if (extension !== ".csv" && extension !== ".txt") {
    throw new TypeError(`Unsupported file type (${extension || "unknown"}). Choose a CSV (.csv) or text (.txt) file.`);
  }

  const bytes = Buffer.from(await file.arrayBuffer());
  if (bytes.includes(0)) throw new TypeError("Binary files are not supported.");
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new TypeError("The file must contain valid UTF-8 text.");
  }
  return { fileName, text };
}

function dashboardData(userId: string) {
  const records = scanHistory.get(userId) ?? [];
  const fileCount = records.length;
  const findingCount = records.reduce(
    (total, record) => total + record.findings.reduce((count, finding) => count + finding.count, 0),
    0,
  );
  const riskDistribution = riskOrder.map((risk) => {
    const files = records.filter((record) => record.risk === risk).length;
    const occurrences = records.reduce((total, record) => total + record.findings
      .filter((finding) => finding.risk === risk)
      .reduce((count, finding) => count + finding.count, 0), 0);
    return { risk, files, occurrences, share: findingCount === 0 ? 0 : Math.round((occurrences / findingCount) * 100) };
  });

  return {
    metrics: {
      filesScanned: fileCount,
      totalFindings: findingCount,
      highRiskFiles: records.filter((record) => record.risk === "High" || record.risk === "Critical").length,
      criticalRiskFiles: records.filter((record) => record.risk === "Critical").length,
    },
    riskDistribution,
    recentScans: records.slice(0, 6).map(recordSummary),
  };
}

function findingRows(userId: string, searchParams: URLSearchParams) {
  const selectedType = searchParams.get("type");
  const selectedRisk = searchParams.get("risk");
  return (scanHistory.get(userId) ?? []).flatMap((record) => record.findings
    .filter((finding) => (!selectedType || selectedType === "all" || finding.type === selectedType)
      && (!selectedRisk || selectedRisk === "all" || finding.risk === selectedRisk))
    .map((finding) => ({ ...finding, scanId: record.id, fileName: record.fileName, scannedAt: record.scannedAt })));
}

async function handleAuthRequest(request: IncomingMessage, response: ServerResponse, pathname: string): Promise<boolean> {
  if (request.method === "GET" && pathname === "/api/auth/me") {
    const account = authenticatedUser(request);
    sendJson(response, 200, { authenticated: Boolean(account), user: account ? publicAccount(account) : null });
    return true;
  }

  if (request.method === "POST" && pathname === "/api/auth/logout") {
    const cookie = request.headers.cookie?.split(";")
      .map((part) => part.trim())
      .find((part) => part.startsWith(`${sessionCookieName}=`));
    if (cookie) sessions.delete(decodeURIComponent(cookie.slice(sessionCookieName.length + 1)));
    setSessionCookie(response);
    sendJson(response, 200, { authenticated: false });
    return true;
  }

  if (request.method !== "POST" || !["/api/auth/signup", "/api/auth/login"].includes(pathname)) return false;

  let body: unknown;
  try {
    body = await readJsonBody(request);
  } catch {
    sendJson(response, 400, { error: "Enter valid account details." });
    return true;
  }

  const data = typeof body === "object" && body !== null ? body as Record<string, unknown> : {};
  const email = typeof data.email === "string" ? data.email.trim().toLowerCase() : "";
  const password = typeof data.password === "string" ? data.password : "";

  if (pathname === "/api/auth/signup") {
    const name = typeof data.name === "string" ? data.name.trim() : "";
    if (!name || name.length > 80 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length < 8 || password.length > 128) {
      sendJson(response, 400, { error: "Enter a name, valid email, and password between 8 and 128 characters." });
      return true;
    }
    if (accountsByEmail.has(email)) {
      sendJson(response, 409, { error: "An account with that email already exists." });
      return true;
    }

    const salt = randomBytes(16);
    const account: Account = { id: randomUUID(), name, email, passwordSalt: salt, passwordHash: scryptSync(password, salt, 64) };
    accountsByEmail.set(email, account);
    accountsById.set(account.id, account);
    startSession(response, account);
    sendJson(response, 201, { authenticated: true, user: publicAccount(account) });
    return true;
  }

  const account = accountsByEmail.get(email);
  const salt = account?.passwordSalt ?? Buffer.alloc(16);
  const suppliedHash = scryptSync(password, salt, 64);
  if (!account || password.length < 8 || password.length > 128 || !timingSafeEqual(suppliedHash, account.passwordHash)) {
    sendJson(response, 401, { error: "Email or password is incorrect." });
    return true;
  }
  startSession(response, account);
  sendJson(response, 200, { authenticated: true, user: publicAccount(account) });
  return true;
}

async function handleRequest(request: IncomingMessage, response: ServerResponse): Promise<void> {
  const url = new URL(request.url ?? "/", "http://127.0.0.1");
  const pathname = url.pathname;

  if (pathname.startsWith("/api/auth/") && await handleAuthRequest(request, response, pathname)) return;

  const account = authenticatedUser(request);
  if (pathname === "/") {
    response.statusCode = 302;
    response.setHeader("Location", account ? "/dashboard" : "/login");
    response.end();
    return;
  }
  if (["/dashboard", "/upload", "/findings"].includes(pathname) && !account) {
    response.statusCode = 302;
    response.setHeader("Location", `/login?next=${encodeURIComponent(pathname)}`);
    response.end();
    return;
  }
  if (pathname.startsWith("/api/") && !account) {
    sendJson(response, 401, { error: "Sign in to access this workspace." });
    return;
  }
  if (["/login", "/signup"].includes(pathname) && account) {
    response.statusCode = 302;
    response.setHeader("Location", "/dashboard");
    response.end();
    return;
  }

  if (request.method === "GET" && pathname === "/favicon.ico") {
    response.statusCode = 204;
    response.end();
    return;
  }
  if (request.method === "GET" && pathname === "/api/samples") {
    sendJson(response, 200, { samples: Object.entries(samples).map(([id, sample]) => ({ id, ...sample })) });
    return;
  }
  if (request.method === "GET" && pathname === "/api/dashboard") {
    sendJson(response, 200, dashboardData(account!.id));
    return;
  }
  if (request.method === "GET" && pathname === "/api/findings") {
    sendJson(response, 200, { findings: findingRows(account!.id, url.searchParams) });
    return;
  }
  if (request.method === "POST" && pathname === "/api/upload") {
    try {
      const upload = await parseUpload(request);
      const result = analyzeText(upload.text);
      const record = createRecord(upload.fileName, result);
      addRecord(account!.id, record);
      sendJson(response, 201, { ...recordSummary(record), findings: record.findings });
    } catch (error) {
      const tooLarge = error instanceof RangeError;
      const message = error instanceof Error ? error.message : "The file could not be scanned.";
      sendJson(response, tooLarge ? 413 : error instanceof TypeError ? 400 : 500, { error: message });
    }
    return;
  }
  if (request.method === "POST" && pathname === "/api/session/reset") {
    scanHistory.delete(account!.id);
    sendJson(response, 200, dashboardData(account!.id));
    return;
  }
  if (request.method === "POST" && pathname === "/api/scan") {
    if (!request.headers["content-type"]?.startsWith("application/json")) {
      sendJson(response, 415, { error: "Send a sample selection as JSON." });
      return;
    }
    let body: unknown;
    try {
      body = await readJsonBody(request);
    } catch (error) {
      sendJson(response, error instanceof RangeError ? 413 : 400, { error: error instanceof RangeError ? "Request is too large." : "Invalid request." });
      return;
    }
    const sampleId = typeof body === "object" && body !== null && "sampleId" in body ? body.sampleId : undefined;
    if (typeof sampleId !== "string" || !Object.hasOwn(samples, sampleId)) {
      sendJson(response, 400, { error: "Choose a supported synthetic sample." });
      return;
    }
    try {
      const selected = samples[sampleId as keyof typeof samples];
      const content = await readFile(resolve(fixtureRoot, selected.fileName), "utf8");
      const result = analyzeText(content);
      const record = createRecord(selected.fileName, result);
      addRecord(account!.id, record);
      sendJson(response, 200, { fileName: selected.fileName, label: selected.label, purpose: selected.description, ...recordSummary(record), findings: result.findings });
    } catch {
      sendJson(response, 500, { error: "The sample could not be scanned." });
    }
    return;
  }

  const assetName = request.method === "GET" ? publicFiles.get(pathname) : undefined;
  if (assetName) {
    try {
      const assetPath = resolve(publicRoot, assetName);
      const content = await readFile(assetPath);
      setHeaders(response, contentTypes[extname(assetPath)] ?? "application/octet-stream");
      response.statusCode = 200;
      response.end(content);
    } catch {
      response.statusCode = 404;
      response.end();
    }
    return;
  }
  sendJson(response, 404, { error: "Not found." });
}

export function createServer() {
  return createHttpServer((request, response) => {
    void handleRequest(request, response).catch(() => {
      if (!response.headersSent) sendJson(response, 500, { error: "The request could not be completed." });
      else response.destroy();
    });
  });
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  const port = Number(process.env.PORT ?? 4173);
  createServer().listen(port, "127.0.0.1", () => {
    console.log(`MiniDSP prototype: http://127.0.0.1:${port}`);
  });
}
