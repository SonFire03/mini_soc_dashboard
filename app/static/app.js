const ingestForm = document.getElementById("ingestForm");
const logFileInput = document.getElementById("logFile");
const ingestResult = document.getElementById("ingestResult");
const alertsBody = document.getElementById("alertsBody");
const logsBody = document.getElementById("logsBody");
const metrics = document.getElementById("metrics");
const timeline = document.getElementById("timeline");
const timelineStartInput = document.getElementById("timelineStart");
const timelineEndInput = document.getElementById("timelineEnd");
const timelineRangeLabel = document.getElementById("timelineRangeLabel");
const riskPanel = document.getElementById("riskPanel");

const qInput = document.getElementById("q");
const dslQueryInput = document.getElementById("dslQuery");
const ipInput = document.getElementById("ip");
const methodInput = document.getElementById("method");
const statusCodeInput = document.getElementById("statusCode");
const severityInput = document.getElementById("severity");
const alertStatusInput = document.getElementById("alertStatus");
const applyFilters = document.getElementById("applyFilters");
const resetDataButton = document.getElementById("resetData");
const savedViewNameInput = document.getElementById("savedViewName");
const savedViewTargetInput = document.getElementById("savedViewTarget");
const saveViewButton = document.getElementById("saveView");
const savedViewsList = document.getElementById("savedViewsList");

const tailPathInput = document.getElementById("tailPath");
const tailFromStartInput = document.getElementById("tailFromStart");
const tailStartButton = document.getElementById("tailStart");
const tailStopButton = document.getElementById("tailStop");
const tailStatus = document.getElementById("tailStatus");

const incidentTimelineBody = document.getElementById("incidentTimelineBody");
const alertContextPanel = document.getElementById("alertContextPanel");
const quickOpenAlerts = document.getElementById("quickOpenAlerts");
const quickHighAlerts = document.getElementById("quickHighAlerts");
const quickCompromise = document.getElementById("quickCompromise");
const quickCriticalAssets = document.getElementById("quickCriticalAssets");

const assetNameInput = document.getElementById("assetName");
const assetCriticalityInput = document.getElementById("assetCriticality");
const assetIpCidrInput = document.getElementById("assetIpCidr");
const assetPathPrefixInput = document.getElementById("assetPathPrefix");
const assetOwnerInput = document.getElementById("assetOwner");
const addAssetButton = document.getElementById("addAsset");
const assetsList = document.getElementById("assetsList");

const supIpInput = document.getElementById("supIp");
const supTypeInput = document.getElementById("supType");
const supPathInput = document.getElementById("supPath");
const supReasonInput = document.getElementById("supReason");
const supTtlInput = document.getElementById("supTtl");
const addSuppressionButton = document.getElementById("addSuppression");
const suppressionsList = document.getElementById("suppressionsList");
const iocTypeInput = document.getElementById("iocType");
const iocValueInput = document.getElementById("iocValue");
const iocSeverityInput = document.getElementById("iocSeverity");
const addIocButton = document.getElementById("addIoc");
const iocsList = document.getElementById("iocsList");
const policyNameInput = document.getElementById("policyName");
const policyConditionInput = document.getElementById("policyCondition");
const policyActionInput = document.getElementById("policyAction");
const policyPayloadInput = document.getElementById("policyPayload");
const addPolicyButton = document.getElementById("addPolicy");
const policiesList = document.getElementById("policiesList");
const createBackupButton = document.getElementById("createBackup");
const restoreLatestButton = document.getElementById("restoreLatest");
const backupsList = document.getElementById("backupsList");
const refreshDeltaReportButton = document.getElementById("refreshDeltaReport");
const deltaSinceHoursInput = document.getElementById("deltaSinceHours");
const deltaReportPanel = document.getElementById("deltaReportPanel");

const autoRefreshToggle = document.getElementById("autoRefreshToggle");
const refreshIntervalSelect = document.getElementById("refreshInterval");
const refreshNowButton = document.getElementById("refreshNow");
const lastRefreshAt = document.getElementById("lastRefreshAt");
const lastRefreshAtRight = document.getElementById("lastRefreshAtRight");
const toastStack = document.getElementById("toastStack");
const wsStatus = document.getElementById("wsStatus");
const wsStatusRight = document.getElementById("wsStatusRight");
const slaPanel = document.getElementById("slaPanel");
const casesBody = document.getElementById("casesBody");
const caseTitleInput = document.getElementById("caseTitle");
const casePriorityInput = document.getElementById("casePriority");
const caseOwnerInput = document.getElementById("caseOwner");
const addCaseButton = document.getElementById("addCase");
const schedulesBody = document.getElementById("schedulesBody");
const schedNameInput = document.getElementById("schedName");
const schedHourInput = document.getElementById("schedHour");
const schedMinuteInput = document.getElementById("schedMinute");
const addScheduleButton = document.getElementById("addSchedule");
const navLinks = Array.from(document.querySelectorAll(".section-nav-link"));
const scrollTopButton = document.getElementById("scrollTopButton");
const toggleLeftSidebarButton = document.getElementById("toggleLeftSidebar");
const toggleRightSidebarButton = document.getElementById("toggleRightSidebar");
const openPaletteButton = document.getElementById("openPalette");
const denseModeToggle = document.getElementById("denseModeToggle");
const commandPalette = document.getElementById("commandPalette");
const closePaletteButton = document.getElementById("closePalette");
const paletteSearchInput = document.getElementById("paletteSearch");
const paletteCommands = document.getElementById("paletteCommands");
const filterPresets = document.getElementById("filterPresets");
const commentCaseIdInput = document.getElementById("commentCaseId");
const commentAuthorInput = document.getElementById("commentAuthor");
const commentMessageInput = document.getElementById("commentMessage");
const addCommentButton = document.getElementById("addComment");
const loadCommentsButton = document.getElementById("loadComments");
const caseCommentsList = document.getElementById("caseCommentsList");
const workspaceGrid = document.getElementById("workspaceGrid");
const resizerA = document.getElementById("resizerA");
const resizerB = document.getElementById("resizerB");
const t = window.SOC_I18N?.t || ((key, vars = {}) => key);

let tickTimer = null;
let wsConn = null;
let activeCaseCommentsId = null;
let activeInvestigationAlertId = null;
let activeInvestigationCaseId = null;
let timelineData = [];
let timelineWindow = { start: 0, end: 100 };
let currentWsState = "status.connecting";
const PALETTE_COMMANDS = [
  { labelKey: "palette.refreshDashboard", run: async () => { await safeRefresh(); await refreshTailStatus(); } },
  { labelKey: "palette.focusSearch", run: async () => { qInput?.focus(); } },
  { labelKey: "palette.openDailyReport", run: async () => { window.open(`/reports/daily?lang=${encodeURIComponent(window.SOC_I18N?.getLanguage?.() || "en")}`, "_blank", "noopener,noreferrer"); } },
  { labelKey: "palette.toggleDenseTables", run: async () => { document.body.classList.toggle("dense-tables"); if (denseModeToggle) denseModeToggle.checked = document.body.classList.contains("dense-tables"); } },
  { labelKey: "palette.toggleLeftPanel", run: async () => { document.body.classList.toggle("left-collapsed"); } },
  { labelKey: "palette.toggleRightPanel", run: async () => { document.body.classList.toggle("right-collapsed"); } },
  { labelKey: "palette.gotoAlerts", run: async () => { document.getElementById("sec-alerts")?.scrollIntoView({ behavior: "smooth" }); } },
  { labelKey: "palette.gotoTimeline", run: async () => { document.getElementById("sec-timeline")?.scrollIntoView({ behavior: "smooth" }); } },
  { labelKey: "palette.gotoRiskRadar", run: async () => { document.getElementById("sec-risk")?.scrollIntoView({ behavior: "smooth" }); } },
];

function showToast(message, variant = "info") {
  if (!toastStack) return;
  const toast = document.createElement("div");
  toast.className = `toast ${variant === "error" ? "error" : ""}`;
  toast.textContent = message;
  toastStack.appendChild(toast);
  setTimeout(() => toast.remove(), 3200);
}

function updateLastSync() {
  if (!lastRefreshAt) return;
  const now = new Date();
  const label = t("status.lastSync", { time: now.toLocaleTimeString() });
  lastRefreshAt.textContent = label;
  if (lastRefreshAtRight) lastRefreshAtRight.textContent = label;
}

function setWsState(stateKey) {
  currentWsState = stateKey;
  const label = t(stateKey);
  if (wsStatus) wsStatus.textContent = label;
  if (wsStatusRight) wsStatusRight.textContent = label;
}

async function parseResponse(res) {
  const contentType = res.headers.get("content-type") || "";
  if (contentType.includes("application/json")) {
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
    return data;
  }
  const text = await res.text();
  if (!res.ok) throw new Error(text || `HTTP ${res.status}`);
  return text;
}

async function fetchJSON(url) {
  const res = await fetch(url);
  return parseResponse(res);
}

async function postJSON(url, payload) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  return parseResponse(res);
}

async function patchJSON(url, payload) {
  const res = await fetch(url, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  return parseResponse(res);
}

function severityBadge(level) {
  return `<span class="badge ${level}">${level}</span>`;
}

function stateBadge(level) {
  return `<span class="badge state ${level}">${level}</span>`;
}

function renderAlerts(items) {
  if (!items.length) {
    alertsBody.innerHTML = `<tr><td colspan="11">${t("status.noAlertsForFilters")}</td></tr>`;
    return;
  }
  alertsBody.innerHTML = items.map((a) => `
    <tr>
      <td class="mono">${a.ts}</td>
      <td>${severityBadge(a.severity)}</td>
      <td>${a.alert_type}</td>
      <td>${a.mitre_tactic || "-"} ${a.mitre_technique ? `(${a.mitre_technique})` : ""}</td>
      <td>${a.asset_name || "-"}${a.asset_criticality ? ` [${a.asset_criticality}]` : ""}</td>
      <td class="mono">${a.ip || "-"}</td>
      <td>${a.occurrences || 1}</td>
      <td>${stateBadge(a.status || "new")}</td>
      <td>${a.assignee || "-"}</td>
      <td>
        <div class="table-actions">
          <input class="mini-input assignee-input" data-id="${a.id}" placeholder="assignee" value="${a.assignee || ""}" />
          <button class="mini-btn set-status" data-id="${a.id}" data-status="investigating">${t("action.investigate")}</button>
          <button class="mini-btn set-status secondary" data-id="${a.id}" data-status="resolved">${t("action.resolve")}</button>
          <button class="mini-btn set-status secondary" data-id="${a.id}" data-status="false-positive">FP</button>
          <button class="mini-btn show-playbook secondary" data-id="${a.id}" data-type="${a.alert_type}">${t("action.playbook")}</button>
          <button class="mini-btn show-context secondary" data-id="${a.id}">${t("action.drill")}</button>
          <button class="mini-btn link-case secondary" data-id="${a.id}">${t("action.linkCase")}</button>
        </div>
      </td>
      <td>${a.details}${a.explain_text ? `<br/><small>why: ${a.explain_text}</small>` : ""}${a.resolution_note ? `<br/><small>note: ${a.resolution_note}</small>` : ""}</td>
    </tr>`).join("");
}

function renderLogs(items) {
  if (!items.length) {
    logsBody.innerHTML = `<tr><td colspan="6">${t("status.noLogsForFilters")}</td></tr>`;
    return;
  }
  logsBody.innerHTML = items.map((l) => `
    <tr>
      <td class="mono">${l.ts}</td>
      <td class="mono">${l.ip || "-"}</td>
      <td class="mono">${l.method || "-"}</td>
      <td>${l.path || l.message || "-"}</td>
      <td class="mono">${l.status_code || "-"}</td>
      <td>${l.user_agent || "-"}</td>
    </tr>`).join("");
}

function renderChips(items) {
  if (!items.length) return `<span class="chip">${t("status.noData")}</span>`;
  return items.map(([label, count]) => `<span class="chip">${label} (${count})</span>`).join("");
}

function renderMetrics(data) {
  if (quickOpenAlerts) quickOpenAlerts.textContent = String(data.open_alerts ?? 0);
  if (quickHighAlerts) quickHighAlerts.textContent = String(data.high_alerts ?? 0);
  if (quickCompromise) quickCompromise.textContent = String(data.compromise_count ?? 0);
  if (quickCriticalAssets) quickCriticalAssets.textContent = String(data.critical_open_assets ?? 0);

  const timelineValues = (data.timeline || []).slice(-18).map(([, n]) => Number(n || 0));
  const spark = buildSparkline(timelineValues);
  metrics.innerHTML = `
    <h2>${t("context.stats")}</h2>
    <div class="metrics-grid">
      <div class="metric"><h3>${t("context.totalLogs")}</h3><p>${data.total_logs}</p></div>
      <div class="metric"><h3>${t("context.totalAlerts")}</h3><p>${data.total_alerts}</p></div>
      <div class="metric"><h3>${t("context.highAlerts")}</h3><p>${data.high_alerts}</p></div>
      <div class="metric"><h3>${t("context.failedLogins")}</h3><p>${data.failed_logins}</p></div>
      <div class="metric"><h3>${t("context.bruteforce")}</h3><p>${data.bruteforce_count}</p></div>
      <div class="metric"><h3>${t("context.compromise")}</h3><p>${data.compromise_count}</p></div>
      <div class="metric"><h3>${t("context.uniqueIps")}</h3><p>${data.unique_ips}</p></div>
      <div class="metric"><h3>${t("context.http5xx")}</h3><p>${data.http_5xx}</p></div>
      <div class="metric"><h3>${t("context.openAlerts")}</h3><p>${data.open_alerts}</p></div>
      <div class="metric"><h3>${t("context.resolvedAlerts")}</h3><p>${data.resolved_alerts}</p></div>
      <div class="metric"><h3>${t("context.criticalOpenAssets")}</h3><p>${data.critical_open_assets || 0}</p></div>
    </div>
    <h3>${t("context.topIps")}</h3>
    <div class="chips">${renderChips(data.top_ips)}</div>
    <h3>${t("context.topUserAgents")}</h3>
    <div class="chips">${renderChips(data.top_user_agents)}</div>
    <h3>${t("context.topRiskyIps")}</h3>
    <div class="chips">${renderChips(data.top_risky_ips)}</div>
    <h3>${t("context.trafficTrend")}</h3>
    <div class="sparkline">${spark}</div>
  `;
}

function buildSparkline(values) {
  if (!values.length) return `<span class='chip'>${t("status.noTrendData")}</span>`;
  const width = 240;
  const height = 24;
  const max = Math.max(...values, 1);
  const step = values.length > 1 ? width / (values.length - 1) : width;
  const points = values
    .map((v, i) => {
      const x = i * step;
      const y = height - (v / max) * (height - 2) - 1;
      return `${x.toFixed(2)},${y.toFixed(2)}`;
    })
    .join(" ");
  return `<svg viewBox="0 0 ${width} ${height}" preserveAspectRatio="none"><polyline fill="none" stroke="#69d5ff" stroke-width="2" points="${points}" /></svg>`;
}

function updateTimelineRangeLabel(total, startIndex, endIndex) {
  if (!timelineRangeLabel) return;
  timelineRangeLabel.textContent = t("status.windowRange", { start: startIndex + 1, end: endIndex + 1, total });
  timelineRangeLabel.dataset.pristine = "false";
}

function renderTimeline(items) {
  timelineData = Array.isArray(items) ? items : [];
  timeline.innerHTML = "";
  if (!timelineData.length) {
    updateTimelineRangeLabel(0, 0, 0);
    return;
  }
  const total = timelineData.length;
  const startPct = Math.max(0, Math.min(100, timelineWindow.start));
  const endPct = Math.max(0, Math.min(100, timelineWindow.end));
  const safeStartPct = Math.min(startPct, endPct - 1);
  const startIndex = Math.max(0, Math.floor((safeStartPct / 100) * (total - 1)));
  const endIndex = Math.max(startIndex + 1, Math.ceil((endPct / 100) * (total - 1)));
  const windowed = timelineData.slice(startIndex, Math.min(total, endIndex + 1));
  const max = Math.max(...windowed.map(([, n]) => n), 1);
  windowed.forEach(([label, n]) => {
    const bar = document.createElement("div");
    bar.className = "bar";
    bar.style.height = `${Math.max(10, (n / max) * 120)}px`;
    bar.title = `${label}: ${n}`;
    timeline.appendChild(bar);
  });
  updateTimelineRangeLabel(total, startIndex, Math.min(total - 1, endIndex));
}

function renderIncidentTimeline(items) {
  if (!items.length) {
    incidentTimelineBody.innerHTML = `<tr><td colspan="7">${t("status.noIncidentEvents")}</td></tr>`;
    return;
  }
  incidentTimelineBody.innerHTML = items.map((e) => `
    <tr>
      <td class="mono">${e.ts}</td>
      <td>${e.event_type}</td>
      <td>${e.severity || "-"}</td>
      <td class="mono">${e.ip || "-"}</td>
      <td>${e.title}</td>
      <td>${e.actor || "-"}</td>
      <td>${e.details || "-"}</td>
    </tr>`).join("");
}

function renderAssets(items) {
  if (!items.length) {
    assetsList.innerHTML = `<li>${t("status.noAssets")}</li>`;
    return;
  }
  assetsList.innerHTML = items.map((a) => `
    <li>
      <strong>${a.name}</strong> [${a.criticality}] ${a.ip_cidr || ""} ${a.path_prefix || ""}
      ${a.owner ? `owner=${a.owner}` : ""}
      <button class="mini-btn secondary delete-asset" data-id="${a.id}">${t("action.delete")}</button>
    </li>`).join("");
}

function renderSuppressions(items) {
  if (!items.length) {
    suppressionsList.innerHTML = `<li>${t("status.noSuppressions")}</li>`;
    return;
  }
  suppressionsList.innerHTML = items.map((s) => `
    <li>
      ip=${s.ip || "*"} type=${s.alert_type || "*"} path=${s.path_pattern || "*"} until=${s.expires_at}
      <button class="mini-btn secondary delete-suppression" data-id="${s.id}">${t("action.delete")}</button>
    </li>`).join("");
}

function renderIocs(items) {
  if (!items.length) {
    iocsList.innerHTML = `<li>${t("status.noIocs")}</li>`;
    return;
  }
  iocsList.innerHTML = items.map((i) => `
    <li>
      <strong>${i.ioc_type}</strong> = <code>${i.ioc_value}</code> [${i.severity_override}] ${i.enabled ? "" : "(disabled)"}
      <button class="mini-btn secondary toggle-ioc" data-id="${i.id}" data-enabled="${i.enabled ? 0 : 1}">${i.enabled ? t("action.disable") : t("action.enable")}</button>
      <button class="mini-btn secondary delete-ioc" data-id="${i.id}">${t("action.delete")}</button>
    </li>`).join("");
}

function renderPolicies(items) {
  if (!items.length) {
    policiesList.innerHTML = `<li>${t("status.noPolicies")}</li>`;
    return;
  }
  policiesList.innerHTML = items.map((p) => `
    <li>
      <strong>${p.name}</strong> ${p.enabled ? "" : "(disabled)"}<br/>
      <code>${p.condition_expr}</code> => <code>${p.action_type}</code>
      <button class="mini-btn secondary toggle-policy" data-id="${p.id}" data-enabled="${p.enabled ? 0 : 1}">${p.enabled ? t("action.disable") : t("action.enable")}</button>
      <button class="mini-btn secondary delete-policy" data-id="${p.id}">${t("action.delete")}</button>
    </li>`).join("");
}

function renderBackups(items) {
  if (!items.length) {
    backupsList.innerHTML = `<li>${t("status.noBackups")}</li>`;
    return;
  }
  backupsList.innerHTML = items.map((b) => `
    <li>
      <code>${b.ts}</code> ${b.action} ${b.status} <span>${b.backup_path}</span>
      ${b.action === "backup" && b.status === "ok" ? `<button class="mini-btn secondary restore-backup" data-file="${b.backup_path.split("/").pop()}">${t("action.restore")}</button>` : ""}
    </li>`).join("");
}

function renderDeltaReport(data) {
  if (!data) {
    deltaReportPanel.innerHTML = `<p class='status-line'>${t("status.noDelta")}</p>`;
    return;
  }
  const sev = (data.by_severity || []).map(([k, v]) => `<span class="chip">${k} (${v})</span>`).join("") || `<span class='chip'>${t("status.noSeverityData")}</span>`;
  const types = (data.by_type || []).map(([k, v]) => `<span class="chip">${k} (${v})</span>`).join("") || `<span class='chip'>${t("status.noTypeData")}</span>`;
  const ips = (data.top_ips || []).map(([k, v]) => `<span class="chip">${k} (${v})</span>`).join("") || `<span class='chip'>${t("status.noIpData")}</span>`;
  deltaReportPanel.innerHTML = `
    <div class="context-grid">
      <div class="context-box"><h4>${t("context.window")}</h4><p>${t("context.lastHoursFrom", { hours: data.since_hours, ts: data.since_ts })}</p></div>
      <div class="context-box"><h4>${t("context.volume")}</h4><p>${t("context.logsAlertsVolume", { logs: data.logs_ingested, alerts: data.alerts_created })}</p></div>
      <div class="context-box"><h4>${t("context.openCritical")}</h4><p>${t("context.openCriticalHigh", { open: data.open_alerts, critical: data.critical_alerts, high: data.high_alerts })}</p></div>
      <div class="context-box"><h4>${t("context.generated")}</h4><p>${data.generated_at}</p></div>
    </div>
    <h3>${t("context.bySeverity")}</h3><div class="chips">${sev}</div>
    <h3>${t("context.byType")}</h3><div class="chips">${types}</div>
    <h3>${t("context.topIps")}</h3><div class="chips">${ips}</div>
  `;
}

function renderSavedViews(items) {
  if (!items.length) {
    savedViewsList.innerHTML = `<li>${t("status.noSavedViews")}</li>`;
    return;
  }
  savedViewsList.innerHTML = items.map((v) => `
    <li>
      <strong>${v.name}</strong> [${v.target}] <code>${v.query_dsl}</code>
      <button class="mini-btn load-view" data-dsl="${v.query_dsl}" data-target="${v.target}">${t("action.load")}</button>
      <button class="mini-btn secondary delete-view" data-id="${v.id}">${t("action.delete")}</button>
    </li>`).join("");
}

function renderSla(data) {
  slaPanel.innerHTML = `
    <div class="context-grid">
      <div class="context-box"><h4>${t("context.casesTotal")}</h4><p>${data.cases_total}</p></div>
      <div class="context-box"><h4>${t("context.alertsTotal")}</h4><p>${data.alerts_total}</p></div>
      <div class="context-box"><h4>${t("context.mtta")}</h4><p>${data.mtta_minutes_avg ?? "-"}</p></div>
      <div class="context-box"><h4>${t("context.mttr")}</h4><p>${data.mttr_minutes_avg ?? "-"}</p></div>
      <div class="context-box"><h4>${t("context.openHighAlerts")}</h4><p>${data.open_high_alerts}</p></div>
    </div>
  `;
}

function renderRisk(data) {
  if (!riskPanel) return;
  const row = (items) => {
    if (!items || !items.length) return `<span class='chip'>${t("status.noData")}</span>`;
    return items
      .slice(0, 8)
      .map((r) => `<span class=\"chip\">${r.entity}: ${r.score} (delta ${r.delta >= 0 ? "+" : ""}${r.delta})</span>`)
      .join("");
  };
  riskPanel.innerHTML = `
    <div class="context-grid">
      <div class="context-box"><h4>${t("context.window")}</h4><p>${t("context.lastHours", { hours: data.since_hours })}</p></div>
      <div class="context-box"><h4>${t("context.generated")}</h4><p>${data.generated_at}</p></div>
    </div>
    <h3>${t("context.topRiskyIps")}</h3>
    <div class="chips">${row(data.top_ips)}</div>
    <h3>${t("context.topRiskyUsers")}</h3>
    <div class="chips">${row(data.top_users)}</div>
    <h3>${t("context.topRiskyAssets")}</h3>
    <div class="chips">${row(data.top_assets)}</div>
  `;
}

function renderCases(items) {
  if (!items.length) {
    casesBody.innerHTML = `<tr><td colspan="7">${t("status.noCases")}</td></tr>`;
    return;
  }
  casesBody.innerHTML = items.map((c) => `
    <tr>
      <td class="mono">${c.id}</td>
      <td>${c.title}</td>
      <td>${c.priority}</td>
      <td>${c.status}</td>
      <td>${c.owner || "-"}</td>
      <td>${c.alert_count || 0}</td>
      <td>
        <div class="table-actions">
          <button class="mini-btn case-status" data-id="${c.id}" data-status="investigating">${t("action.investigate")}</button>
          <button class="mini-btn secondary case-status" data-id="${c.id}" data-status="closed">${t("action.close")}</button>
          <button class="mini-btn secondary case-comments" data-id="${c.id}">${t("section.caseComments")}</button>
        </div>
      </td>
    </tr>
  `).join("");
}

function renderCaseComments(items) {
  if (!caseCommentsList) return;
  if (!items || !items.length) {
    caseCommentsList.innerHTML = `<li>${t("status.noComments")}</li>`;
    return;
  }
  caseCommentsList.innerHTML = items.map((c) => `
    <li>
      <code>${c.ts}</code> <strong>${c.author || "analyst"}</strong>: ${c.message}
      <button class="mini-btn secondary delete-comment" data-id="${c.id}">${t("action.delete")}</button>
    </li>
  `).join("");
}

function renderSchedules(items) {
  if (!items.length) {
    schedulesBody.innerHTML = `<tr><td colspan="6">${t("status.noSchedules")}</td></tr>`;
    return;
  }
  schedulesBody.innerHTML = items.map((s) => `
    <tr>
      <td class="mono">${s.id}</td>
      <td>${s.name}</td>
      <td class="mono">${String(s.hour_utc).padStart(2, "0")}:${String(s.minute_utc).padStart(2, "0")}</td>
      <td>${s.enabled ? t("context.yes") : t("context.no")}</td>
      <td class="mono">${s.last_run_date || "-"}</td>
      <td>
        <div class="table-actions">
          <button class="mini-btn run-schedule" data-id="${s.id}">${t("action.runNow")}</button>
          <button class="mini-btn secondary toggle-schedule" data-id="${s.id}" data-enabled="${s.enabled ? 0 : 1}">${s.enabled ? t("action.disable") : t("action.enable")}</button>
          <button class="mini-btn secondary delete-schedule" data-id="${s.id}">${t("action.delete")}</button>
        </div>
      </td>
    </tr>
  `).join("");
}

function renderAlertContext(data) {
  if (!data || !data.alert) {
    alertContextPanel.innerHTML = `<p class='status-line'>${t("status.noAlertSelected")}</p>`;
    return;
  }
  const a = data.alert;
  const logs = (data.related_logs || []).slice(0, 8);
  const events = (data.related_events || []).slice(0, 8);
  const playbook = (data.playbook || []).slice(0, 8);
  const cases = (data.linked_cases || []).slice(0, 6);
  const iocs = (data.ioc_matches || []).slice(0, 6);
  const asset = data.asset || null;
  const caseDetail = data.case_detail || null;
  const summary = data.summary || {};
  const selectedCaseId = caseDetail?.case?.id || "";

  alertContextPanel.innerHTML = `
    <div class="investigation-head">
      <div>
        <div class="investigation-title">Alert #${a.id} <span class="badge ${a.severity}">${a.severity}</span></div>
        <p class="status-line">${t("table.type")}: ${a.alert_type} | ${t("table.status")}: ${a.status} | ${t("table.assignee")}: ${a.assignee || "-"}</p>
      </div>
      <div class="investigation-stats">
        <span class="chip">logs ${summary.related_logs_count ?? logs.length}</span>
        <span class="chip">events ${summary.related_events_count ?? events.length}</span>
        <span class="chip">cases ${summary.linked_cases_count ?? cases.length}</span>
        <span class="chip">iocs ${summary.ioc_matches_count ?? iocs.length}</span>
      </div>
    </div>
    <div class="investigation-actions">
      <input class="mini-input investigation-assignee" data-id="${a.id}" placeholder="${t("table.assignee")}" value="${a.assignee || ""}" />
      <button class="mini-btn investigation-status" data-id="${a.id}" data-status="investigating">${t("action.investigate")}</button>
      <button class="mini-btn secondary investigation-status" data-id="${a.id}" data-status="resolved">${t("action.resolve")}</button>
      <button class="mini-btn secondary investigation-status" data-id="${a.id}" data-status="false-positive">FP</button>
      <button class="mini-btn secondary investigation-link-case" data-id="${a.id}">${t("action.linkCase")}</button>
    </div>
    <div class="context-grid investigation-grid">
      <div class="context-box">
        <h4>${t("context.alertSummary")}</h4>
        <p><strong>${t("context.time")}:</strong> <code>${a.ts}</code></p>
        <p><strong>${t("table.mitre")}:</strong> ${a.mitre_tactic || "-"} ${a.mitre_technique ? `(${a.mitre_technique})` : ""}</p>
        <p><strong>${t("table.ip")}:</strong> ${a.ip || "-"} | <strong>${t("context.user")}:</strong> ${a.username || "-"}</p>
        <p><strong>${t("context.occurrences")}:</strong> ${a.occurrences || 1}</p>
        <p><strong>${t("context.why")}:</strong> ${a.explain_text || "-"}</p>
        <p><strong>${t("table.details")}:</strong> ${a.details || "-"}</p>
      </div>
      <div class="context-box">
        <h4>${t("context.assetBox")}</h4>
        <p><strong>${t("context.name")}:</strong> ${asset?.name || a.asset_name || "-"}</p>
        <p><strong>${t("context.criticality")}:</strong> ${asset?.criticality || a.asset_criticality || "-"}</p>
        <p><strong>${t("table.owner")}:</strong> ${asset?.owner || a.asset_owner || "-"}</p>
        <p><strong>${t("context.pathScope")}:</strong> ${asset?.path_prefix || "-"}</p>
        <p><strong>${t("context.ipScope")}:</strong> ${asset?.ip_cidr || "-"}</p>
      </div>
      <div class="context-box">
        <h4>${t("context.linkedCases")}</h4>
        <ul>${cases.map((c) => `<li><button class="linkish linked-case-open ${String(c.id) === String(selectedCaseId) ? "active" : ""}" data-case-id="${c.id}">#${c.id} ${c.title}</button> <span class="mono">(${c.status}/${c.priority})</span></li>`).join("") || `<li>${t("status.noLinkedCases")}</li>`}</ul>
      </div>
      <div class="context-box">
        <h4>${t("context.iocMatches")}</h4>
        <ul>${iocs.map((ioc) => `<li>${ioc.ioc_type}: <code>${ioc.ioc_value}</code> (${ioc.severity_override})</li>`).join("") || `<li>${t("status.noIocMatch")}</li>`}</ul>
      </div>
      <div class="context-box context-box-span">
        <h4>${t("context.playbook")}</h4>
        <ul>${playbook.map((x) => `<li>${x}</li>`).join("") || `<li>${t("status.noPlaybook")}</li>`}</ul>
      </div>
      <div class="context-box context-box-span">
        <h4>${t("context.caseDetail")}</h4>
        ${caseDetail?.case ? `
          <div class="case-detail-block">
            <p><strong>#${caseDetail.case.id}</strong> ${caseDetail.case.title}</p>
            <p><strong>${t("table.status")}:</strong> ${caseDetail.case.status} | <strong>${t("table.priority")}:</strong> ${caseDetail.case.priority} | <strong>${t("table.owner")}:</strong> ${caseDetail.case.owner || "-"}</p>
            <p><strong>${t("context.description")}:</strong> ${caseDetail.case.description || "-"}</p>
            <p><strong>${t("context.comments")}:</strong> ${(caseDetail.comments || []).slice(0, 3).map((c) => `${c.author}: ${c.message}`).join(" | ") || t("status.none")}</p>
            <p><strong>${t("context.caseActions")}:</strong> ${(caseDetail.actions || []).slice(0, 3).map((c) => `${c.action} @ ${c.ts}`).join(" | ") || t("status.none")}</p>
          </div>
        ` : `<p class='status-line'>${t("status.selectLinkedCase")}</p>`}
      </div>
      <div class="context-box context-box-span">
        <h4>${t("context.relatedLogs")}</h4>
        <ul>${logs.map((l) => `<li><code>${l.ts}</code> ${l.method || "-"} ${l.path || l.message || "-"} (${l.status_code || "-"})</li>`).join("") || `<li>${t("status.noRelatedLogs")}</li>`}</ul>
      </div>
      <div class="context-box context-box-span">
        <h4>${t("context.relatedEvents")}</h4>
        <ul>${events.map((e) => `<li><code>${e.ts}</code> ${e.event_type} ${e.title}</li>`).join("") || `<li>${t("status.noRelatedEvents")}</li>`}</ul>
      </div>
    </div>
  `;
}

async function loadAlertInvestigation(alertId, { announce = true } = {}) {
  const data = await fetchJSON(`/api/alerts/${alertId}/investigation`);
  const linkedCases = data.linked_cases || [];
  const selectedCase = linkedCases.find((item) => String(item.id) === String(activeInvestigationCaseId)) || linkedCases[0] || null;
  activeInvestigationCaseId = selectedCase ? String(selectedCase.id) : null;
  if (selectedCase) {
    try {
      data.case_detail = await fetchJSON(`/api/cases/${selectedCase.id}`);
    } catch {
      data.case_detail = null;
    }
  } else {
    data.case_detail = null;
  }
  activeInvestigationAlertId = String(alertId);
  renderAlertContext(data);
  if (announce) showToast(t("toast.investigationLoaded", { alertId }));
  return data;
}

async function updateAlertWorkflow(alertId, nextStatus, assignee = "") {
  let resolutionNote = null;
  if (nextStatus === "resolved" || nextStatus === "false-positive") {
    const note = window.prompt(t("prompt.resolutionNote"), "");
    resolutionNote = note === null ? "" : note;
  }
  await patchJSON(`/api/alerts/${alertId}`, { status: nextStatus, assignee, resolution_note: resolutionNote });
}

async function linkCaseWorkflow(alertId) {
  const caseId = window.prompt(t("prompt.caseIdToLink"), "");
  if (!caseId) return null;
  await postJSON(`/api/cases/${caseId}/alerts/${alertId}`, {});
  activeInvestigationCaseId = String(caseId);
  return caseId;
}

function buildQuery() {
  const params = new URLSearchParams();
  if (dslQueryInput.value.trim()) params.set("dsl", dslQueryInput.value.trim());
  if (qInput.value.trim()) params.set("q", qInput.value.trim());
  if (ipInput.value.trim()) params.set("ip", ipInput.value.trim());
  if (methodInput.value.trim()) params.set("method", methodInput.value.trim());
  if (statusCodeInput.value.trim()) params.set("status_code", statusCodeInput.value.trim());
  return params.toString() ? `?${params.toString()}` : "";
}

async function refresh() {
  const query = buildQuery();
  const deltaHours = Number(deltaSinceHoursInput?.value || "24");
  const [alerts, logs, stats, risk, incidents, assets, suppressions, iocs, policies, backups, savedViews, sla, cases, schedules, deltaReport] = await Promise.all([
    fetchJSON(`/api/alerts${query}${query ? "&" : "?"}severity=${severityInput.value}&status=${alertStatusInput.value}`),
    fetchJSON(`/api/logs${query}`),
    fetchJSON("/api/stats"),
    fetchJSON("/api/risk/entities?since_hours=24"),
    fetchJSON("/api/incidents/timeline?limit=100"),
    fetchJSON("/api/assets"),
    fetchJSON("/api/suppressions"),
    fetchJSON("/api/iocs"),
    fetchJSON("/api/policies"),
    fetchJSON("/api/admin/backups"),
    fetchJSON("/api/saved-views"),
    fetchJSON("/api/sla"),
    fetchJSON("/api/cases"),
    fetchJSON("/api/reports/schedules"),
    fetchJSON(`/api/reports/delta?since_hours=${deltaHours}`),
  ]);

  renderAlerts(alerts.items);
  renderLogs(logs.items);
  renderMetrics({ ...stats, timeline: stats.timeline || [] });
  renderRisk(risk);
  renderTimeline(stats.timeline);
  renderIncidentTimeline(incidents.items);
  renderAssets(assets.items);
  renderSuppressions(suppressions.items);
  renderIocs(iocs.items);
  renderPolicies(policies.items);
  renderBackups(backups.items);
  renderSavedViews(savedViews.items);
  renderSla(sla);
  renderCases(cases.items);
  renderSchedules(schedules.items);
  renderDeltaReport(deltaReport);
  if (activeCaseCommentsId) {
    const comments = await fetchJSON(`/api/cases/${activeCaseCommentsId}/comments`);
    renderCaseComments(comments.items);
  }
  if (activeInvestigationAlertId) {
    try {
      await loadAlertInvestigation(activeInvestigationAlertId, { announce: false });
    } catch {
      activeInvestigationAlertId = null;
      activeInvestigationCaseId = null;
      renderAlertContext(null);
    }
  }
  updateLastSync();
}

async function safeRefresh(silent = false) {
  try {
    await refresh();
  } catch (err) {
    if (!silent) showToast(t("toast.refreshFailed", { error: err.message }), "error");
  }
}

function restartTicker() {
  if (tickTimer) clearInterval(tickTimer);
  if (!autoRefreshToggle?.checked) return;
  const intervalMs = Number(refreshIntervalSelect?.value || "5000");
  tickTimer = setInterval(() => {
    safeRefresh(true);
    refreshTailStatus();
  }, intervalMs);
}

function setupWorkspaceResizer(resizer, onDrag) {
  if (!resizer) return;
  let active = false;
  let lastX = 0;
  const onMove = (event) => {
    if (!active) return;
    const dx = event.clientX - lastX;
    lastX = event.clientX;
    onDrag(dx);
  };
  const stop = () => {
    active = false;
    document.removeEventListener("mousemove", onMove);
    document.removeEventListener("mouseup", stop);
  };
  resizer.addEventListener("mousedown", (event) => {
    active = true;
    lastX = event.clientX;
    document.addEventListener("mousemove", onMove);
    document.addEventListener("mouseup", stop);
  });
}

function parseFr(value, fallback) {
  const n = Number(String(value).replace("fr", "").trim());
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

ingestForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    const file = logFileInput.files[0];
    if (!file) return;

    const formData = new FormData();
    formData.append("file", file);

    const res = await fetch("/api/logs/ingest", { method: "POST", body: formData });
    const data = await parseResponse(res);
    ingestResult.textContent = t("status.ingestResult", { ingested: data.ingested, batch: data.batch_alerts, inserted: data.inserted_alerts });
    showToast(t("toast.ingestionCompleted"));
    await safeRefresh(true);
  } catch (err) {
    showToast(t("toast.ingestionFailed", { error: err.message }), "error");
  }
});

applyFilters.addEventListener("click", async () => {
  await safeRefresh();
});

refreshNowButton?.addEventListener("click", async () => {
  await safeRefresh();
  await refreshTailStatus();
  showToast(t("toast.dashboardRefreshed"));
});

autoRefreshToggle?.addEventListener("change", () => {
  restartTicker();
  showToast(autoRefreshToggle.checked ? t("toast.autoRefreshEnabled") : t("toast.autoRefreshPaused"));
});

refreshIntervalSelect?.addEventListener("change", () => {
  restartTicker();
  showToast(t("toast.refreshInterval", { seconds: Number(refreshIntervalSelect.value) / 1000 }));
});

denseModeToggle?.addEventListener("change", () => {
  document.body.classList.toggle("dense-tables", denseModeToggle.checked);
});

timelineStartInput?.addEventListener("input", () => {
  const start = Number(timelineStartInput.value || "0");
  const end = Number(timelineEndInput?.value || "100");
  timelineWindow.start = Math.min(start, end - 1);
  if (timelineStartInput) timelineStartInput.value = String(timelineWindow.start);
  renderTimeline(timelineData);
});

timelineEndInput?.addEventListener("input", () => {
  const start = Number(timelineStartInput?.value || "0");
  const end = Number(timelineEndInput.value || "100");
  timelineWindow.end = Math.max(end, start + 1);
  if (timelineEndInput) timelineEndInput.value = String(timelineWindow.end);
  renderTimeline(timelineData);
});

resetDataButton.addEventListener("click", async () => {
  const ok = window.confirm(t("confirm.resetData"));
  if (!ok) return;
  try {
    await postJSON("/api/admin/reset", {});
    ingestResult.textContent = t("status.dataResetDone");
    await safeRefresh(true);
    await refreshTailStatus();
    showToast(t("toast.resetDone"));
  } catch (err) {
    showToast(t("toast.resetFailed", { error: err.message }), "error");
  }
});

addAssetButton.addEventListener("click", async () => {
  try {
    const res = await fetch("/api/assets", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        name: assetNameInput.value.trim(),
        criticality: assetCriticalityInput.value,
        ip_cidr: assetIpCidrInput.value.trim(),
        path_prefix: assetPathPrefixInput.value.trim(),
        owner: assetOwnerInput.value.trim(),
      }),
    });
    await parseResponse(res);
    assetNameInput.value = "";
    assetIpCidrInput.value = "";
    assetPathPrefixInput.value = "";
    assetOwnerInput.value = "";
    await safeRefresh(true);
    showToast(t("toast.assetAdded"));
  } catch (err) {
    showToast(t("toast.assetAddFailed", { error: err.message }), "error");
  }
});

addSuppressionButton.addEventListener("click", async () => {
  try {
    const res = await fetch("/api/suppressions", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ip: supIpInput.value.trim(),
        alert_type: supTypeInput.value.trim(),
        path_pattern: supPathInput.value.trim(),
        reason: supReasonInput.value.trim(),
        ttl_minutes: Number(supTtlInput.value || "60"),
      }),
    });
    await parseResponse(res);
    supIpInput.value = "";
    supTypeInput.value = "";
    supPathInput.value = "";
    supReasonInput.value = "";
    await safeRefresh(true);
    showToast(t("toast.suppressionAdded"));
  } catch (err) {
    showToast(t("toast.suppressionAddFailed", { error: err.message }), "error");
  }
});

addIocButton?.addEventListener("click", async () => {
  try {
    await postJSON("/api/iocs", {
      ioc_type: iocTypeInput.value,
      ioc_value: iocValueInput.value.trim(),
      severity_override: iocSeverityInput.value,
      enabled: true,
    });
    iocValueInput.value = "";
    await safeRefresh(true);
    showToast(t("toast.iocAdded"));
  } catch (err) {
    showToast(t("toast.iocAddFailed", { error: err.message }), "error");
  }
});

addPolicyButton?.addEventListener("click", async () => {
  try {
    let parsedPayload = {};
    const raw = policyPayloadInput.value.trim();
    if (raw) parsedPayload = JSON.parse(raw);
    await postJSON("/api/policies", {
      name: policyNameInput.value.trim(),
      condition_expr: policyConditionInput.value.trim(),
      action_type: policyActionInput.value,
      action_payload: parsedPayload,
      enabled: true,
    });
    policyNameInput.value = "";
    policyConditionInput.value = "";
    policyPayloadInput.value = "";
    await safeRefresh(true);
    showToast(t("toast.policyAdded"));
  } catch (err) {
    showToast(t("toast.policyAddFailed", { error: err.message }), "error");
  }
});

createBackupButton?.addEventListener("click", async () => {
  try {
    await postJSON("/api/admin/backup", {});
    await safeRefresh(true);
    showToast(t("toast.backupCreated"));
  } catch (err) {
    showToast(t("toast.backupFailed", { error: err.message }), "error");
  }
});

restoreLatestButton?.addEventListener("click", async () => {
  const ok = window.confirm(t("confirm.restoreLatest"));
  if (!ok) return;
  try {
    await postJSON("/api/admin/restore", {});
    await safeRefresh(true);
    showToast(t("toast.backupRestored"));
  } catch (err) {
    showToast(t("toast.restoreFailed", { error: err.message }), "error");
  }
});

refreshDeltaReportButton?.addEventListener("click", async () => {
  try {
    const data = await fetchJSON(`/api/reports/delta?since_hours=${Number(deltaSinceHoursInput.value || "24")}`);
    renderDeltaReport(data);
    showToast(t("toast.deltaRefreshed"));
  } catch (err) {
    showToast(t("toast.deltaFailed", { error: err.message }), "error");
  }
});

addCaseButton?.addEventListener("click", async () => {
  try {
    await postJSON("/api/cases", {
      title: caseTitleInput.value.trim(),
      priority: casePriorityInput.value,
      owner: caseOwnerInput.value.trim(),
    });
    caseTitleInput.value = "";
    caseOwnerInput.value = "";
    await safeRefresh(true);
    showToast(t("toast.caseCreated"));
  } catch (err) {
    showToast(t("toast.caseCreateFailed", { error: err.message }), "error");
  }
});

addScheduleButton?.addEventListener("click", async () => {
  try {
    await postJSON("/api/reports/schedules", {
      name: schedNameInput.value.trim(),
      hour_utc: Number(schedHourInput.value || "0"),
      minute_utc: Number(schedMinuteInput.value || "0"),
      enabled: true,
    });
    schedNameInput.value = "";
    await safeRefresh(true);
    showToast(t("toast.scheduleCreated"));
  } catch (err) {
    showToast(t("toast.scheduleCreateFailed", { error: err.message }), "error");
  }
});

saveViewButton?.addEventListener("click", async () => {
  try {
    const dsl = dslQueryInput.value.trim();
    if (!dsl) {
      showToast(t("toast.enterDslFirst"), "error");
      return;
    }
    await postJSON("/api/saved-views", {
      name: savedViewNameInput.value.trim() || `view-${Date.now()}`,
      target: savedViewTargetInput.value,
      query_dsl: dsl,
    });
    savedViewNameInput.value = "";
    await safeRefresh(true);
    showToast(t("toast.savedViewCreated"));
  } catch (err) {
    showToast(t("toast.saveViewFailed", { error: err.message }), "error");
  }
});

alertsBody.addEventListener("click", async (event) => {
  const target = event.target;
  if (!(target instanceof HTMLElement)) return;

  if (target.classList.contains("set-status")) {
    const alertId = target.dataset.id;
    const nextStatus = target.dataset.status;
    if (!alertId || !nextStatus) return;

    const assigneeInput = alertsBody.querySelector(`.assignee-input[data-id="${alertId}"]`);
    const assignee = assigneeInput instanceof HTMLInputElement ? assigneeInput.value.trim() : "";
    try {
      await updateAlertWorkflow(alertId, nextStatus, assignee);
      await safeRefresh(true);
      showToast(t("toast.alertUpdated", { id: alertId, status: nextStatus }));
    } catch (err) {
      showToast(t("toast.alertUpdateFailed", { error: err.message }), "error");
    }
  }

  if (target.classList.contains("show-playbook")) {
    const alertId = target.dataset.id;
    if (alertId) {
      try {
        await loadAlertInvestigation(alertId);
        document.getElementById("sec-drilldown")?.scrollIntoView({ behavior: "smooth", block: "start" });
      } catch (err) {
        showToast(t("toast.playbookLoadFailed", { error: err.message }), "error");
      }
      return;
    }
  }

  if (target.classList.contains("show-context")) {
    const alertId = target.dataset.id;
    if (!alertId) return;
    try {
      await loadAlertInvestigation(alertId);
    } catch (err) {
      showToast(t("toast.investigationLoadFailed", { error: err.message }), "error");
    }
  }

  if (target.classList.contains("link-case")) {
    const alertId = target.dataset.id;
    if (!alertId) return;
    try {
      const caseId = await linkCaseWorkflow(alertId);
      if (!caseId) return;
      await safeRefresh(true);
      showToast(t("toast.alertLinkedCase", { alertId, caseId }));
    } catch (err) {
      showToast(t("toast.linkCaseFailed", { error: err.message }), "error");
    }
  }
});

alertContextPanel?.addEventListener("click", async (event) => {
  const target = event.target;
  if (!(target instanceof HTMLElement)) return;

  if (target.classList.contains("investigation-status")) {
    const alertId = target.dataset.id;
    const nextStatus = target.dataset.status;
    if (!alertId || !nextStatus) return;
    const assigneeInput = alertContextPanel.querySelector(`.investigation-assignee[data-id="${alertId}"]`);
    const assignee = assigneeInput instanceof HTMLInputElement ? assigneeInput.value.trim() : "";
    try {
      await updateAlertWorkflow(alertId, nextStatus, assignee);
      await safeRefresh(true);
      showToast(t("toast.alertUpdated", { id: alertId, status: nextStatus }));
    } catch (err) {
      showToast(t("toast.alertUpdateFailed", { error: err.message }), "error");
    }
  }

  if (target.classList.contains("investigation-link-case")) {
    const alertId = target.dataset.id;
    if (!alertId) return;
    try {
      const caseId = await linkCaseWorkflow(alertId);
      if (!caseId) return;
      await safeRefresh(true);
      showToast(t("toast.alertLinkedCase", { alertId, caseId }));
    } catch (err) {
      showToast(t("toast.linkCaseFailed", { error: err.message }), "error");
    }
  }

  if (target.classList.contains("linked-case-open")) {
    const caseId = target.dataset.caseId;
    if (!caseId || !activeInvestigationAlertId) return;
    activeInvestigationCaseId = String(caseId);
    try {
      await loadAlertInvestigation(activeInvestigationAlertId, { announce: false });
      showToast(t("toast.caseLoaded", { caseId }));
    } catch (err) {
      showToast(t("toast.caseDetailLoadFailed", { error: err.message }), "error");
    }
  }
});

assetsList.addEventListener("click", async (event) => {
  const target = event.target;
  if (!(target instanceof HTMLElement)) return;
  if (!target.classList.contains("delete-asset")) return;
  const id = target.dataset.id;
  if (!id) return;
  try {
    const res = await fetch(`/api/assets/${id}`, { method: "DELETE" });
    await parseResponse(res);
    await safeRefresh(true);
    showToast(t("toast.assetDeleted", { id }));
  } catch (err) {
    showToast(t("toast.assetDeleteFailed", { error: err.message }), "error");
  }
});

suppressionsList.addEventListener("click", async (event) => {
  const target = event.target;
  if (!(target instanceof HTMLElement)) return;
  if (!target.classList.contains("delete-suppression")) return;
  const id = target.dataset.id;
  if (!id) return;
  try {
    const res = await fetch(`/api/suppressions/${id}`, { method: "DELETE" });
    await parseResponse(res);
    await safeRefresh(true);
    showToast(t("toast.suppressionDeleted", { id }));
  } catch (err) {
    showToast(t("toast.suppressionDeleteFailed", { error: err.message }), "error");
  }
});

iocsList?.addEventListener("click", async (event) => {
  const target = event.target;
  if (!(target instanceof HTMLElement)) return;
  const id = target.dataset.id;
  if (!id) return;
  try {
    if (target.classList.contains("delete-ioc")) {
      const res = await fetch(`/api/iocs/${id}`, { method: "DELETE" });
      await parseResponse(res);
      showToast(t("toast.iocDeleted", { id }));
    } else if (target.classList.contains("toggle-ioc")) {
      await patchJSON(`/api/iocs/${id}`, { enabled: Boolean(Number(target.dataset.enabled || "0")) });
      showToast(t("toast.iocUpdated", { id }));
    } else {
      return;
    }
    await safeRefresh(true);
  } catch (err) {
    showToast(t("toast.iocActionFailed", { error: err.message }), "error");
  }
});

policiesList?.addEventListener("click", async (event) => {
  const target = event.target;
  if (!(target instanceof HTMLElement)) return;
  const id = target.dataset.id;
  if (!id) return;
  try {
    if (target.classList.contains("delete-policy")) {
      const res = await fetch(`/api/policies/${id}`, { method: "DELETE" });
      await parseResponse(res);
      showToast(t("toast.policyDeleted", { id }));
    } else if (target.classList.contains("toggle-policy")) {
      await patchJSON(`/api/policies/${id}`, { enabled: Boolean(Number(target.dataset.enabled || "0")) });
      showToast(t("toast.policyUpdated", { id }));
    } else {
      return;
    }
    await safeRefresh(true);
  } catch (err) {
    showToast(t("toast.policyActionFailed", { error: err.message }), "error");
  }
});

backupsList?.addEventListener("click", async (event) => {
  const target = event.target;
  if (!(target instanceof HTMLElement)) return;
  if (!target.classList.contains("restore-backup")) return;
  const file = target.dataset.file;
  if (!file) return;
  const ok = window.confirm(t("confirm.restoreBackup", { file }));
  if (!ok) return;
  try {
    await postJSON("/api/admin/restore", { backup_name: file });
    await safeRefresh(true);
    showToast(t("toast.backupFileRestored", { file }));
  } catch (err) {
    showToast(t("toast.restoreFailed", { error: err.message }), "error");
  }
});

savedViewsList?.addEventListener("click", async (event) => {
  const target = event.target;
  if (!(target instanceof HTMLElement)) return;
  if (target.classList.contains("load-view")) {
    const dsl = target.dataset.dsl || "";
    dslQueryInput.value = dsl;
    await safeRefresh();
    showToast(t("toast.savedViewLoaded"));
    return;
  }
  if (target.classList.contains("delete-view")) {
    const id = target.dataset.id;
    if (!id) return;
    try {
      const res = await fetch(`/api/saved-views/${id}`, { method: "DELETE" });
      await parseResponse(res);
      await safeRefresh(true);
      showToast(t("toast.savedViewDeleted", { id }));
    } catch (err) {
      showToast(t("toast.deleteViewFailed", { error: err.message }), "error");
    }
  }
});

casesBody?.addEventListener("click", async (event) => {
  const target = event.target;
  if (!(target instanceof HTMLElement)) return;
  if (target.classList.contains("case-comments")) {
    const caseId = Number(target.dataset.id || "0");
    if (!caseId) return;
    try {
      activeCaseCommentsId = caseId;
      if (commentCaseIdInput) commentCaseIdInput.value = String(caseId);
      const data = await fetchJSON(`/api/cases/${caseId}/comments`);
      renderCaseComments(data.items);
      showToast(t("toast.commentsLoaded", { caseId }));
    } catch (err) {
      showToast(t("toast.loadCommentsFailed", { error: err.message }), "error");
    }
    return;
  }
  if (!target.classList.contains("case-status")) return;
  const caseId = target.dataset.id;
  const status = target.dataset.status;
  if (!caseId || !status) return;
  try {
    await patchJSON(`/api/cases/${caseId}`, { status });
    await safeRefresh(true);
    showToast(t("toast.caseUpdated", { caseId, status }));
  } catch (err) {
    showToast(t("toast.caseUpdateFailed", { error: err.message }), "error");
  }
});

addCommentButton?.addEventListener("click", async () => {
  const caseId = Number(commentCaseIdInput?.value || "0");
  if (!caseId) {
    showToast(t("toast.caseIdRequired"), "error");
    return;
  }
  const message = commentMessageInput?.value?.trim() || "";
  if (!message) {
    showToast(t("toast.commentMessageRequired"), "error");
    return;
  }
  try {
    await postJSON(`/api/cases/${caseId}/comments`, {
      author: commentAuthorInput?.value?.trim() || "analyst",
      message,
    });
    activeCaseCommentsId = caseId;
    commentMessageInput.value = "";
    const data = await fetchJSON(`/api/cases/${caseId}/comments`);
    renderCaseComments(data.items);
    showToast(t("toast.commentAdded", { caseId }));
  } catch (err) {
    showToast(t("toast.commentAddFailed", { error: err.message }), "error");
  }
});

loadCommentsButton?.addEventListener("click", async () => {
  const caseId = Number(commentCaseIdInput?.value || "0");
  if (!caseId) {
    showToast(t("toast.caseIdRequired"), "error");
    return;
  }
  try {
    activeCaseCommentsId = caseId;
    const data = await fetchJSON(`/api/cases/${caseId}/comments`);
    renderCaseComments(data.items);
    showToast(t("toast.commentsLoaded", { caseId }));
  } catch (err) {
    showToast(t("toast.loadCommentsFailed", { error: err.message }), "error");
  }
});

caseCommentsList?.addEventListener("click", async (event) => {
  const target = event.target;
  if (!(target instanceof HTMLElement)) return;
  if (!target.classList.contains("delete-comment")) return;
  const commentId = Number(target.dataset.id || "0");
  const caseId = Number(commentCaseIdInput?.value || activeCaseCommentsId || "0");
  if (!caseId || !commentId) return;
  try {
    const res = await fetch(`/api/cases/${caseId}/comments/${commentId}`, { method: "DELETE" });
    await parseResponse(res);
    const data = await fetchJSON(`/api/cases/${caseId}/comments`);
    renderCaseComments(data.items);
    showToast(t("toast.commentDeleted", { commentId }));
  } catch (err) {
    showToast(t("toast.commentDeleteFailed", { error: err.message }), "error");
  }
});

schedulesBody?.addEventListener("click", async (event) => {
  const target = event.target;
  if (!(target instanceof HTMLElement)) return;
  const id = target.dataset.id;
  if (!id) return;

  try {
    if (target.classList.contains("run-schedule")) {
      await postJSON(`/api/reports/schedules/${id}/run`, {});
      showToast(t("toast.scheduleExecuted", { id }));
    } else if (target.classList.contains("toggle-schedule")) {
      await patchJSON(`/api/reports/schedules/${id}`, { enabled: Boolean(Number(target.dataset.enabled || "0")) });
      showToast(t("toast.scheduleUpdated", { id }));
    } else if (target.classList.contains("delete-schedule")) {
      const res = await fetch(`/api/reports/schedules/${id}`, { method: "DELETE" });
      await parseResponse(res);
      showToast(t("toast.scheduleDeleted", { id }));
    }
    await safeRefresh(true);
  } catch (err) {
    showToast(t("toast.scheduleActionFailed", { error: err.message }), "error");
  }
});

async function refreshTailStatus() {
  try {
    const status = await fetchJSON("/api/live-tail/status");
    if (status.running) {
      tailStatus.textContent = t("status.liveTailRunning", { file: status.file_path, count: status.ingested_total });
    } else {
      const errorSuffix = status.last_error ? t("status.liveTailErrorSuffix", { error: status.last_error }) : "";
      tailStatus.textContent = t("status.liveTailStopped", { suffix: errorSuffix });
    }
  } catch (err) {
    tailStatus.textContent = t("status.liveTailStatusError", { error: err.message });
  }
}

tailStartButton.addEventListener("click", async () => {
  try {
    await postJSON("/api/live-tail/start", {
      file_path: tailPathInput.value.trim(),
      from_start: tailFromStartInput.checked,
      interval_sec: 1.0,
    });
    await refreshTailStatus();
    showToast(t("toast.liveTailStarted"));
  } catch (err) {
    tailStatus.textContent = t("status.startFailed", { error: err.message });
    showToast(t("toast.liveTailStartFailed", { error: err.message }), "error");
  }
});

tailStopButton.addEventListener("click", async () => {
  try {
    await postJSON("/api/live-tail/stop", {});
    await refreshTailStatus();
    showToast(t("toast.liveTailStopped"));
  } catch (err) {
    tailStatus.textContent = t("status.stopFailed", { error: err.message });
    showToast(t("toast.liveTailStopFailed", { error: err.message }), "error");
  }
});

document.addEventListener("keydown", async (event) => {
  if (event.key === "Escape" && commandPalette && !commandPalette.classList.contains("hidden")) {
    closePalette();
    return;
  }

  const targetTag = (event.target && event.target.tagName) ? event.target.tagName.toLowerCase() : "";
  const typing = ["input", "textarea", "select"].includes(targetTag);
  if (typing) return;

  if (event.key === "/") {
    event.preventDefault();
    qInput.focus();
    return;
  }

  if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
    event.preventDefault();
    openPalette();
    return;
  }

  if (event.key.toLowerCase() === "r") {
    event.preventDefault();
    await safeRefresh();
    await refreshTailStatus();
    showToast(t("toast.manualRefresh"));
    return;
  }

  if (event.key.toLowerCase() === "t") {
    event.preventDefault();
    const status = await fetchJSON("/api/live-tail/status");
    if (status.running) {
      await postJSON("/api/live-tail/stop", {});
      showToast(t("toast.liveTailStopped"));
    } else {
      await postJSON("/api/live-tail/start", {
        file_path: tailPathInput.value.trim(),
        from_start: tailFromStartInput.checked,
        interval_sec: 1.0,
      });
      showToast(t("toast.liveTailStarted"));
    }
    await refreshTailStatus();
  }
});

function renderPaletteCommands(filterText = "") {
  if (!paletteCommands) return;
  const q = filterText.trim().toLowerCase();
  const items = PALETTE_COMMANDS
    .map((c) => ({ ...c, label: t(c.labelKey) }))
    .filter((c) => !q || c.label.toLowerCase().includes(q));
  paletteCommands.innerHTML = items
    .map((c, idx) => `<button type="button" class="palette-item" data-cmd-index="${idx}">${idx + 1}. ${c.label}</button>`)
    .join("") || `<p class='status-line'>${t("status.noCommand")}</p>`;
}

function openPalette() {
  if (!commandPalette) return;
  commandPalette.classList.remove("hidden");
  commandPalette.setAttribute("aria-hidden", "false");
  renderPaletteCommands("");
  if (paletteSearchInput) {
    paletteSearchInput.value = "";
    paletteSearchInput.focus();
  }
}

function closePalette() {
  if (!commandPalette) return;
  commandPalette.classList.add("hidden");
  commandPalette.setAttribute("aria-hidden", "true");
}

openPaletteButton?.addEventListener("click", openPalette);
closePaletteButton?.addEventListener("click", closePalette);
toggleLeftSidebarButton?.addEventListener("click", () => document.body.classList.toggle("left-collapsed"));
toggleRightSidebarButton?.addEventListener("click", () => document.body.classList.toggle("right-collapsed"));
paletteSearchInput?.addEventListener("input", () => renderPaletteCommands(paletteSearchInput.value));
commandPalette?.addEventListener("click", async (event) => {
  const target = event.target;
  if (!(target instanceof HTMLElement)) return;
  if (target.dataset.closePalette) {
    closePalette();
    return;
  }
  if (target.classList.contains("palette-item")) {
    const index = Number(target.dataset.cmdIndex || "-1");
    const q = (paletteSearchInput?.value || "").trim().toLowerCase();
    const filtered = PALETTE_COMMANDS
      .map((c) => ({ ...c, label: t(c.labelKey) }))
      .filter((c) => !q || c.label.toLowerCase().includes(q));
    if (index >= 0 && filtered[index]) {
      await filtered[index].run();
      closePalette();
    }
  }
});

filterPresets?.addEventListener("click", async (event) => {
  const target = event.target;
  if (!(target instanceof HTMLElement)) return;
  if (!target.classList.contains("chip-action")) return;
  const preset = target.dataset.preset || "";
  if (preset === "clear") {
    dslQueryInput.value = "";
    qInput.value = "";
    ipInput.value = "";
    severityInput.value = "";
    alertStatusInput.value = "";
  } else if (preset === "bruteforce") {
    dslQueryInput.value = "type:possible-bruteforce severity:high";
  } else if (preset === "compromise") {
    dslQueryInput.value = "type:possible-account-compromise severity:high";
  } else if (preset === "injection") {
    dslQueryInput.value = "type:injection-or-traversal";
  } else if (preset === "ioc") {
    dslQueryInput.value = "type:ioc-match";
  }
  await safeRefresh();
});

scrollTopButton?.addEventListener("click", () => {
  window.scrollTo({ top: 0, behavior: "smooth" });
});

window.addEventListener("soc:languagechange", async () => {
  setWsState(currentWsState);
  renderPaletteCommands(paletteSearchInput?.value || "");
  updateLastSync();
  await safeRefresh(true);
  await refreshTailStatus();
});

function connectWebSocket() {
  try {
    if (wsConn) wsConn.close();
    const proto = window.location.protocol === "https:" ? "wss" : "ws";
    wsConn = new WebSocket(`${proto}://${window.location.host}/ws/live`);
    wsConn.onopen = () => {
      setWsState("status.connected");
    };
    wsConn.onclose = () => {
      setWsState("status.disconnected");
      setTimeout(connectWebSocket, 3000);
    };
    wsConn.onerror = () => {
      setWsState("status.error");
    };
    wsConn.onmessage = async (ev) => {
      try {
        const data = JSON.parse(ev.data);
        if (data.event_type && data.event_type !== "heartbeat") {
          await safeRefresh(true);
        }
      } catch (_) {
        // ignore malformed frames
      }
    };
  } catch (_) {
    setWsState("status.unavailable");
  }
}

function setupSectionNavHighlight() {
  if (!navLinks.length) return;
  const sectionIds = Array.from(new Set(navLinks.map((link) => (link.getAttribute("href") || "").replace("#", ""))));
  const sections = sectionIds.map((id) => document.getElementById(id)).filter(Boolean);
  if (!sections.length) return;

  const setActive = (id) => {
    navLinks.forEach((link) => {
      const targetId = (link.getAttribute("href") || "").replace("#", "");
      link.classList.toggle("active", targetId === id);
    });
  };

  const observer = new IntersectionObserver(
    (entries) => {
      const visible = entries
        .filter((entry) => entry.isIntersecting)
        .sort((a, b) => b.intersectionRatio - a.intersectionRatio);
      if (!visible.length) return;
      const id = visible[0].target.id;
      if (id) setActive(id);
    },
    { rootMargin: "-22% 0px -58% 0px", threshold: [0.1, 0.25, 0.5] },
  );

  sections.forEach((section) => observer.observe(section));
}

function setupWorkspace() {
  if (!workspaceGrid) return;
  setupWorkspaceResizer(resizerA, (dx) => {
    const rect = workspaceGrid.getBoundingClientRect();
    const deltaFr = (dx / Math.max(rect.width, 1)) * 4;
    const left = parseFr(getComputedStyle(workspaceGrid).getPropertyValue("--ws-left"), 1.2);
    const mid = parseFr(getComputedStyle(workspaceGrid).getPropertyValue("--ws-mid"), 1);
    const nextLeft = Math.max(0.7, left + deltaFr);
    const nextMid = Math.max(0.7, mid - deltaFr);
    workspaceGrid.style.setProperty("--ws-left", `${nextLeft.toFixed(3)}fr`);
    workspaceGrid.style.setProperty("--ws-mid", `${nextMid.toFixed(3)}fr`);
  });
  setupWorkspaceResizer(resizerB, (dx) => {
    const rect = workspaceGrid.getBoundingClientRect();
    const deltaFr = (dx / Math.max(rect.width, 1)) * 4;
    const mid = parseFr(getComputedStyle(workspaceGrid).getPropertyValue("--ws-mid"), 1);
    const right = parseFr(getComputedStyle(workspaceGrid).getPropertyValue("--ws-right"), 1.1);
    const nextMid = Math.max(0.7, mid + deltaFr);
    const nextRight = Math.max(0.7, right - deltaFr);
    workspaceGrid.style.setProperty("--ws-mid", `${nextMid.toFixed(3)}fr`);
    workspaceGrid.style.setProperty("--ws-right", `${nextRight.toFixed(3)}fr`);
  });
}

(async function bootstrap() {
  if (document.body.classList.contains("wallboard")) {
    if (autoRefreshToggle) autoRefreshToggle.checked = true;
    if (refreshIntervalSelect) refreshIntervalSelect.value = "3000";
  }
  if (timelineRangeLabel) timelineRangeLabel.dataset.pristine = "true";
  setWsState(currentWsState);
  await safeRefresh();
  await refreshTailStatus();
  restartTicker();
  connectWebSocket();
  setupSectionNavHighlight();
  setupWorkspace();
})();
