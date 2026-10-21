import { createSafeCsv } from "/csv.js";

const view = document.querySelector("#view");
const toastRegion = document.querySelector("#toast-region");
const route = window.location.pathname.replace(/\/$/, "") || "/dashboard";
const isAuthRoute = route === "/login" || route === "/signup";
const currentRoute = ["/upload", "/findings"].includes(route) ? route.slice(1) : "dashboard";

const typeLabels = {
  email: "Email address",
  uk_phone: "UK phone",
  uk_nino: "UK NINO",
  payment_card: "Payment card",
};

const riskBadgeClass = {
  Critical: "error",
  High: "error",
  Medium: "warning",
  Low: "default",
  None: "success",
};

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  })[character]);
}

function badge(risk) {
  const variant = riskBadgeClass[risk] ?? "neutral";
  return `<span class="lp-badge lp-badge--${variant}">${escapeHtml(risk)}</span>`;
}

function formatDate(value) {
  return new Intl.DateTimeFormat("en-GB", {
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date(value));
}

async function getJson(url, options) {
  const response = await fetch(url, options);
  const body = await response.json();
  if (!response.ok) throw new Error(body.error || "The request could not be completed.");
  return body;
}

function setPage(title, eyebrow, description, content) {
  document.title = `MiniDSP | ${title}`;
  view.innerHTML = `
    <nav class="lp-breadcrumb" aria-label="Breadcrumb">
      <ol class="lp-breadcrumb__list">
        <li class="lp-breadcrumb__item"><span class="lp-breadcrumb__current">Lepide MiniDSP</span></li>
        <li class="lp-breadcrumb__item" aria-current="page"><span class="lp-breadcrumb__separator" aria-hidden="true">/</span><span class="lp-breadcrumb__current">${escapeHtml(title)}</span></li>
      </ol>
    </nav>
    <header class="page-heading">
      <p class="eyebrow">${escapeHtml(eyebrow)}</p>
      <h1>${escapeHtml(title)}</h1>
      <p class="page-description">${escapeHtml(description)}</p>
    </header>
    ${content}`;

  for (const link of document.querySelectorAll(".sidebar-link")) {
    const active = link.dataset.route === currentRoute;
    link.classList.toggle("sidebar-link--active", active);
    if (active) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  }
}

function emptyTable(message, columns) {
  return `<tr><td class="lp-table__empty-cell" colspan="${columns}">${escapeHtml(message)}</td></tr>`;
}

function renderRecentScans(records) {
  const rows = records.length ? records.map((record) => `
    <tr>
      <td class="lp-table__td"><div class="lp-table__cell-inner"><span class="lp-table__cell-text">${escapeHtml(record.fileName)}</span></div></td>
      <td class="lp-table__td"><div class="lp-table__cell-inner"><span class="lp-table__cell-text">${escapeHtml(formatDate(record.scannedAt))}</span></div></td>
      <td class="lp-table__td">${badge(record.risk)}</td>
      <td class="lp-table__td">${record.findingCount}</td>
    </tr>`).join("") : emptyTable("No scans yet. Upload a synthetic file to get started.", 4);

  return `
    <section class="lp-card dashboard-section" aria-labelledby="recent-title">
      <div class="lp-card__header"><h2 class="lp-card__title" id="recent-title">Recent scans</h2><a class="lp-link lp-link--standalone" href="/findings">View findings</a></div>
      <div class="lp-table table-wrap">
        <table class="lp-table__table">
          <caption class="visually-hidden">Recent synthetic file scans</caption>
          <thead><tr>
            <th class="lp-table__th" scope="col"><div class="lp-table__header-inner"><span class="lp-table__header-label">File</span></div></th>
            <th class="lp-table__th" scope="col"><div class="lp-table__header-inner"><span class="lp-table__header-label">Scanned</span></div></th>
            <th class="lp-table__th" scope="col"><div class="lp-table__header-inner"><span class="lp-table__header-label">Risk</span></div></th>
            <th class="lp-table__th" scope="col"><div class="lp-table__header-inner"><span class="lp-table__header-label">Findings</span></div></th>
          </tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
    </section>`;
}

function renderRiskDistribution(distribution) {
  const rows = distribution.map(({ risk, files, occurrences, share }) => `
    <tr>
      <td class="lp-table__td">${badge(risk)}</td>
      <td class="lp-table__td">${files}</td>
      <td class="lp-table__td">${occurrences}</td>
      <td class="lp-table__td">
        <div class="risk-share" aria-label="${share}% of finding occurrences">
          <div class="risk-share__track"><svg viewBox="0 0 100 8" preserveAspectRatio="none" aria-hidden="true"><rect class="risk-share__track-fill" x="0" y="0" width="100" height="8" rx="4"/><rect class="risk-share__fill" data-risk="${escapeHtml(risk)}" x="0" y="0" width="${share}" height="8" rx="4"/></svg></div>
          <span class="risk-share__value">${share}%</span>
        </div>
      </td>
    </tr>`).join("");

  return `
    <section class="lp-card dashboard-section" aria-labelledby="distribution-title">
      <div class="lp-card__header"><h2 class="lp-card__title" id="distribution-title">Risk distribution</h2></div>
      <div class="lp-table table-wrap">
        <table class="lp-table__table">
          <caption class="visually-hidden">Highest risk per file and finding occurrence distribution by risk</caption>
          <thead><tr>
            <th class="lp-table__th" scope="col"><div class="lp-table__header-inner"><span class="lp-table__header-label">Risk level</span></div></th>
            <th class="lp-table__th" scope="col"><div class="lp-table__header-inner"><span class="lp-table__header-label">Files</span></div></th>
            <th class="lp-table__th" scope="col"><div class="lp-table__header-inner"><span class="lp-table__header-label">Occurrences</span></div></th>
            <th class="lp-table__th" scope="col"><div class="lp-table__header-inner"><span class="lp-table__header-label">Share of occurrences</span></div></th>
          </tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
    </section>`;
}

async function renderDashboard() {
  setPage("Dashboard", "OVERVIEW", "Your scanned files and masked findings. Synthetic training data only.", '<p class="loading-line" role="status">Loading dashboard…</p>');
  try {
    const dashboard = await getJson("/api/dashboard");
    const { metrics } = dashboard;
    view.querySelector(".loading-line")?.remove();
    const metricCards = [
      ["Files scanned", metrics.filesScanned],
      ["Total findings", metrics.totalFindings],
      ["High-risk files", metrics.highRiskFiles],
      ["Critical-risk files", metrics.criticalRiskFiles],
    ].map(([label, value]) => `
      <article class="lp-card metric-card">
        <h2 class="metric-card__label">${escapeHtml(label)}</h2>
        <p class="metric-card__value">${value}</p>
      </article>`).join("");

    view.querySelector(".page-heading").insertAdjacentHTML("afterend", `
      <div class="metric-grid">${metricCards}</div>
      <div class="dashboard-stack">
        ${renderRiskDistribution(dashboard.riskDistribution)}
        ${renderRecentScans(dashboard.recentScans)}
      </div>`);
  } catch (error) {
    showError(error.message);
  }
}

function showError(message, target = view) {
  const error = document.createElement("p");
  error.className = "error-message";
  error.setAttribute("role", "alert");
  error.textContent = message;
  target.append(error);
}

function renderAuth(mode, authMode = "local-demo") {
  document.body.classList.add("auth-route");
  const isSignup = mode === "signup";
  const title = isSignup ? "Create your account" : "Welcome back";
  const action = isSignup ? "Create account" : "Sign in";
  const otherHref = isSignup ? "/login" : "/signup";
  const otherLabel = isSignup ? "Sign in" : "Create an account";
  document.title = `MiniDSP | ${action}`;
  view.innerHTML = `
    <section class="auth-shell" aria-labelledby="auth-title">
      <a class="auth-brand" href="/login" aria-label="MiniDSP sign in"><span aria-hidden="true">///</span><strong>MiniDSP</strong></a>
      <section class="lp-card auth-card" aria-labelledby="auth-title">
        <p class="eyebrow">SENSITIVE DATA DISCOVERY</p>
        <h1 id="auth-title">${title}</h1>
        <p class="auth-description">Sign in to your local training workspace.</p>
        <form id="auth-form" novalidate>
          ${isSignup ? `<div class="lp-input lp-input--full-width auth-field"><div class="lp-input__row lp-input__row--label-top"><label class="lp-input__label" for="auth-name">Name</label><div class="lp-input__field"><input class="lp-input__input" id="auth-name" name="name" type="text" autocomplete="name" maxlength="80" required /></div></div></div>` : ""}
          <div class="lp-input lp-input--full-width auth-field">
            <div class="lp-input__row lp-input__row--label-top"><label class="lp-input__label" for="auth-email">Email</label><div class="lp-input__field"><input class="lp-input__input" id="auth-email" name="email" type="email" autocomplete="email" maxlength="254" required /></div></div>
          </div>
          <div class="lp-input lp-input--full-width auth-field">
            <div class="lp-input__row lp-input__row--label-top"><label class="lp-input__label" for="auth-password">Password</label><div class="lp-input__field"><input class="lp-input__input" id="auth-password" name="password" type="password" autocomplete="${isSignup ? "new-password" : "current-password"}" minlength="8" maxlength="128" required /></div></div>
          </div>
          ${isSignup ? `<p class="auth-hint">Use at least 8 characters. Do not reuse a real account password.</p>` : ""}
          <div id="auth-message" aria-live="polite"></div>
          <button class="lp-button lp-button--primary lp-button--md auth-submit" id="auth-submit" type="submit">${action}</button>
        </form>
        <p class="auth-switch">${isSignup ? "Already have an account?" : "New to MiniDSP?"} <a class="lp-link lp-link--standalone" href="${otherHref}">${otherLabel}</a></p>
        <p class="auth-demo-note">${authMode === "supabase"
          ? "Training prototype. Sign-in uses the configured Supabase project; never use production personal data here."
          : "Local training mode. Accounts and scans stay in memory and clear when the server stops. This is not production authentication."}</p>
      </section>
    </section>`;

  const form = document.querySelector("#auth-form");
  const submit = document.querySelector("#auth-submit");
  const message = document.querySelector("#auth-message");
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    message.replaceChildren();
    const formData = new FormData(form);
    const values = Object.fromEntries(formData.entries());
    submit.disabled = true;
    submit.setAttribute("aria-busy", "true");
    submit.textContent = isSignup ? "Creating account…" : "Signing in…";
    try {
      const result = await getJson(isSignup ? "/api/auth/signup" : "/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(values),
      });
      if (result.requiresEmailConfirmation) {
        const notice = document.createElement("p");
        notice.className = "auth-confirmation";
        notice.setAttribute("role", "status");
        notice.textContent = result.message;
        message.replaceChildren(notice);
        return;
      }
      const requestedPath = new URLSearchParams(window.location.search).get("next");
      const nextPath = ["/dashboard", "/upload", "/findings"].includes(requestedPath) ? requestedPath : "/dashboard";
      window.location.replace(nextPath);
    } catch (error) {
      showError(error.message, message);
    } finally {
      submit.removeAttribute("aria-busy");
      submit.disabled = false;
      submit.textContent = action;
    }
  });
}

function renderUpload() {
  setPage("Upload and scan", "NEW SCAN", "Scan a synthetic CSV or TXT file. It is checked on the server and discarded; only masked, grouped findings are kept for this demo session.", `
    <section class="lp-card upload-card" aria-labelledby="upload-title">
      <h2 class="lp-card__title" id="upload-title">Choose a file</h2>
      <form id="upload-form" novalidate>
        <div class="upload-dropzone" id="upload-dropzone">
          <span class="upload-icon" aria-hidden="true"><svg viewBox="0 0 32 32" fill="none"><path d="M16 21V7m0 0-5 5m5-5 5 5M7 20v7h18v-7" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg></span>
          <span class="upload-dropzone__title">Choose a file or drop it here</span>
          <input class="upload-input" id="file-input" name="file" type="file" accept=".csv,.txt,text/csv,text/plain" aria-label="Choose a CSV or TXT file" required />
          <span class="upload-dropzone__hint">CSV or TXT · 1 byte to 1 MiB</span>
        </div>
        <div class="selected-file" id="selected-file" hidden></div>
        <div class="upload-actions">
          <p class="helper-copy">Original file contents are never saved or logged.</p>
          <button class="lp-button lp-button--primary lp-button--md" id="upload-button" type="submit">Upload and scan</button>
        </div>
        <div id="upload-message" aria-live="polite"></div>
      </form>
    </section>
    <section class="lp-card detector-note" aria-labelledby="detector-note-title">
      <h2 class="lp-card__title" id="detector-note-title">Detection coverage</h2>
      <div class="coverage-list">
        <span>Email <b>Low</b></span><span>UK phone <b>Medium</b></span><span>UK NINO <b>High</b></span><span>Payment card <b>Critical</b></span>
      </div>
      <p class="helper-copy">Cards must pass the Luhn check. NINOs are format-checked only and are not verified against an issuing authority.</p>
    </section>`);

  const form = document.querySelector("#upload-form");
  const fileInput = document.querySelector("#file-input");
  const uploadButton = document.querySelector("#upload-button");
  const selectedFile = document.querySelector("#selected-file");
  const uploadMessage = document.querySelector("#upload-message");

  fileInput.addEventListener("change", () => {
    uploadMessage.replaceChildren();
    const file = fileInput.files?.[0];
    uploadButton.disabled = false;
    if (!file) {
      selectedFile.hidden = true;
      selectedFile.textContent = "";
      return;
    }
    selectedFile.hidden = false;
    selectedFile.textContent = `${file.name} · ${formatBytes(file.size)}`;
  });

  const dropzone = document.querySelector("#upload-dropzone");
  dropzone.addEventListener("dragover", (event) => {
    event.preventDefault();
    dropzone.classList.add("upload-dropzone--dragging");
  });
  dropzone.addEventListener("dragleave", () => dropzone.classList.remove("upload-dropzone--dragging"));
  dropzone.addEventListener("drop", (event) => {
    event.preventDefault();
    dropzone.classList.remove("upload-dropzone--dragging");
    if (event.dataTransfer?.files?.length) {
      fileInput.files = event.dataTransfer.files;
      fileInput.dispatchEvent(new Event("change", { bubbles: true }));
    }
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    uploadMessage.replaceChildren();
    const file = fileInput.files?.[0];
    if (!file) {
      fileInput.click();
      return;
    }
    const extension = file.name.split(".").pop()?.toLowerCase();
    if (extension === "xlsx") {
      showError("Excel workbooks (.xlsx) are not supported. Save or export the workbook as CSV (.csv), then upload that file.", uploadMessage);
      return;
    }
    if (!extension || !["csv", "txt"].includes(extension)) {
      showError(`Unsupported file type${extension ? ` (.${extension})` : ""}. Choose a CSV (.csv) or text (.txt) file.`, uploadMessage);
      return;
    }
    if (file.size === 0) {
      showError("The selected file is empty.", uploadMessage);
      return;
    }
    if (file.size > 1_048_576) {
      showError("Choose a file that is 1 MiB or smaller.", uploadMessage);
      return;
    }

    uploadButton.disabled = true;
    uploadButton.setAttribute("aria-busy", "true");
    uploadButton.textContent = "Scanning…";
    uploadMessage.replaceChildren();
    try {
      const body = new FormData();
      body.append("file", file);
      const result = await getJson("/api/upload", { method: "POST", body });
      uploadMessage.innerHTML = `
        <section class="upload-result" aria-labelledby="upload-result-title">
          <div class="upload-result__heading"><h3 id="upload-result-title">Scan complete</h3>${badge(result.risk)}</div>
          <p>${escapeHtml(result.fileName)} · ${result.findingCount} ${result.findingCount === 1 ? "occurrence" : "occurrences"}</p>
          <p class="helper-copy">Only masked findings were kept. The original file was discarded after scanning.</p>
          <a class="lp-button lp-button--secondary lp-button--md" href="/findings">Review findings</a>
        </section>`;
      form.reset();
      selectedFile.hidden = true;
      selectedFile.textContent = "";
      showToast(`${result.fileName} scanned successfully.`);
    } catch (error) {
      showError(error.message, uploadMessage);
    } finally {
      uploadButton.removeAttribute("aria-busy");
      uploadButton.textContent = "Upload and scan";
      uploadButton.disabled = false;
    }
  });
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} bytes`;
  return `${(bytes / 1024).toFixed(bytes >= 1024 * 100 ? 0 : 1)} KiB`;
}

function showToast(message) {
  toastRegion.textContent = message;
  toastRegion.classList.add("toast-region--visible");
  window.setTimeout(() => toastRegion.classList.remove("toast-region--visible"), 3500);
}

function renderFindingTable(rows) {
  if (!rows.length) return emptyTable("No findings match these filters.", 6);
  return rows.map((finding) => `
    <tr>
      <td class="lp-table__td"><div class="lp-table__cell-inner"><span class="lp-table__cell-text">${escapeHtml(typeLabels[finding.type] ?? finding.type)}</span></div></td>
      <td class="lp-table__td">${badge(finding.risk)}</td>
      <td class="lp-table__td"><div class="lp-table__cell-inner"><span class="lp-table__cell-text">${escapeHtml(finding.fileName)}</span></div></td>
      <td class="lp-table__td">${finding.count}</td>
      <td class="lp-table__td masked-value">${escapeHtml(finding.maskedExample)}</td>
      <td class="lp-table__td"><div class="lp-table__cell-inner"><span class="lp-table__cell-text">${escapeHtml(formatDate(finding.scannedAt))}</span></div></td>
    </tr>`).join("");
}

async function loadFindings() {
  const type = document.querySelector("#type-filter").value;
  const risk = document.querySelector("#risk-filter").value;
  const query = new URLSearchParams({ type, risk });
  const body = document.querySelector("#findings-body");
  body.innerHTML = emptyTable("Loading findings…", 6);
  try {
    const { findings } = await getJson(`/api/findings?${query}`);
    body.innerHTML = renderFindingTable(findings);
    const occurrenceCount = findings.reduce((total, finding) => total + finding.count, 0);
    const groupLabel = `${findings.length} ${findings.length === 1 ? "pattern group" : "pattern groups"}`;
    document.querySelector("#finding-total").textContent = `${occurrenceCount} ${occurrenceCount === 1 ? "occurrence" : "occurrences"} across ${groupLabel}`;
    document.querySelector("#export-findings").disabled = findings.length === 0;
    document.querySelector("#export-findings").onclick = () => exportFindings(findings);
  } catch (error) {
    body.innerHTML = emptyTable(error.message, 6);
  }
}

function exportFindings(findings) {
  const columns = ["Pattern", "Risk", "File", "Occurrences", "Masked example", "Scanned"];
  const rows = findings.map((finding) => [
    typeLabels[finding.type] ?? finding.type,
    finding.risk,
    finding.fileName,
    finding.count,
    finding.maskedExample,
    formatDate(finding.scannedAt),
  ]);
  const csv = createSafeCsv(columns, rows);
  const url = URL.createObjectURL(new Blob([csv], { type: "text/csv;charset=utf-8" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = "minidsp-masked-findings.csv";
  link.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function renderFindings() {
  setPage("Findings", "CLASSIFICATION RESULTS", "Review grouped detections across this local demo session. Values are masked; original file contents are not retained.", `
    <section class="lp-card findings-card" aria-labelledby="findings-title">
      <div class="findings-toolbar">
        <div><h2 class="lp-card__title" id="findings-title">Masked findings</h2><p class="helper-copy" id="finding-total">Loading findings…</p></div>
        <div class="filter-actions">
          <label class="filter-control" for="type-filter"><span>Pattern</span><select id="type-filter"><option value="all">All patterns</option><option value="email">Email</option><option value="uk_phone">UK phone</option><option value="uk_nino">UK NINO</option><option value="payment_card">Payment card</option></select></label>
          <label class="filter-control" for="risk-filter"><span>Risk</span><select id="risk-filter"><option value="all">All risks</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option></select></label>
          <button class="lp-button lp-button--secondary lp-button--sm" id="export-findings" type="button" disabled>Export CSV</button>
        </div>
      </div>
      <div class="lp-table table-wrap">
        <table class="lp-table__table">
          <caption class="visually-hidden">Masked sensitive data findings by file</caption>
          <thead><tr>
            <th class="lp-table__th" scope="col"><div class="lp-table__header-inner"><span class="lp-table__header-label">Pattern</span></div></th>
            <th class="lp-table__th" scope="col"><div class="lp-table__header-inner"><span class="lp-table__header-label">Risk</span></div></th>
            <th class="lp-table__th" scope="col"><div class="lp-table__header-inner"><span class="lp-table__header-label">File</span></div></th>
            <th class="lp-table__th" scope="col"><div class="lp-table__header-inner"><span class="lp-table__header-label">Occurrences</span></div></th>
            <th class="lp-table__th" scope="col"><div class="lp-table__header-inner"><span class="lp-table__header-label">Masked example</span></div></th>
            <th class="lp-table__th" scope="col"><div class="lp-table__header-inner"><span class="lp-table__header-label">Scanned</span></div></th>
          </tr></thead>
          <tbody id="findings-body"></tbody>
        </table>
      </div>
      <p class="table-footnote">Risk labels are textual and do not rely on color alone.</p>
    </section>`);
  document.querySelector("#type-filter").addEventListener("change", loadFindings);
  document.querySelector("#risk-filter").addEventListener("change", loadFindings);
  void loadFindings();
}

async function resetDemo() {
  const button = document.querySelector("#reset-demo");
  button.disabled = true;
  try {
    await getJson("/api/session/reset", { method: "POST" });
    showToast("Scan history cleared.");
    if (currentRoute === "dashboard") void renderDashboard();
    if (currentRoute === "findings") void loadFindings();
  } catch (error) {
    showToast(error.message);
  } finally {
    button.disabled = false;
  }
}

document.querySelector("#reset-demo").addEventListener("click", resetDemo);
document.querySelector("#sign-out").addEventListener("click", async () => {
  try {
    await getJson("/api/auth/logout", { method: "POST" });
  } finally {
    window.location.replace("/login");
  }
});

async function initializeApp() {
  if (isAuthRoute) {
    const session = await getJson("/api/auth/me");
    if (session.authenticated) {
      window.location.replace("/dashboard");
      return;
    }
    renderAuth(route.slice(1), session.authMode);
    return;
  }

  try {
    const session = await getJson("/api/auth/me");
    if (!session.authenticated) {
      window.location.replace(`/login?next=${encodeURIComponent(route)}`);
      return;
    }
    const initials = session.user.name.split(/\s+/).slice(0, 2).map((part) => part[0]).join("").toUpperCase();
    document.querySelector(".user-avatar").textContent = initials;
    document.querySelector(".workspace-label").textContent = session.user.name;
    if (currentRoute === "upload") renderUpload();
    else if (currentRoute === "findings") renderFindings();
    else void renderDashboard();
  } catch {
    window.location.replace(`/login?next=${encodeURIComponent(route)}`);
  }
}

void initializeApp();