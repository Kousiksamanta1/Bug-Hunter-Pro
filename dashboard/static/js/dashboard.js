(function () {
  "use strict";

  const severityColors = {
    CRITICAL: "#D92D20",
    HIGH: "#E35D12",
    MEDIUM: "#B7791F",
    LOW: "#0077B6",
    INFO: "#6956C7"
  };
  const state = { stats: {}, scans: [] };

  function escapeHTML(value) {
    return String(value == null ? "" : value).replace(/[&<>"']/g, character => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;"
    })[character]);
  }

  async function fetchJSON(url, options = {}) {
    const response = await fetch(url, options);
    let data;
    try { data = await response.json(); } catch (error) { data = {}; }
    if (!response.ok) throw new Error(data.error || `Request failed with status ${response.status}`);
    return data;
  }

  function renderSeverityBadge(severity) {
    const normalized = String(severity || "INFO").toUpperCase();
    return `<span class="severity-badge severity-${normalized.toLowerCase()}">${escapeHTML(normalized)}</span>`;
  }

  function renderRiskScore(score) {
    const value = Number(score || 0);
    const color = value >= 9 ? severityColors.CRITICAL : value >= 7 ? severityColors.HIGH : value >= 4 ? severityColors.MEDIUM : severityColors.LOW;
    return `<span class="risk-score" style="color:${color}">${value.toFixed(1)}</span>`;
  }

  function formatDate(value) {
    if (!value) return "Never";
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? escapeHTML(value) : date.toLocaleString();
  }

  function toast(message, type = "success") {
    const region = document.getElementById("toast-region");
    const item = document.createElement("div");
    item.className = `toast ${type}`;
    item.textContent = message;
    region.appendChild(item);
    setTimeout(() => item.remove(), 4200);
  }

  function statusLabel(status) {
    const normalized = String(status || "unknown").toLowerCase();
    return `<span class="status-label ${escapeHTML(normalized)}">${escapeHTML(normalized)}</span>`;
  }

  function switchTab(name) {
    document.querySelectorAll(".tab-link").forEach(button => button.classList.toggle("active", button.dataset.tab === name));
    document.querySelectorAll(".tab-panel").forEach(panel => panel.classList.toggle("active", panel.id === `tab-${name}`));
    document.getElementById("main-tabs").classList.remove("open");
    history.replaceState(null, "", `#${name}`);
    if (name === "findings" && window.BugHunterFindings) window.BugHunterFindings.load();
    if (name === "monitoring" && window.BugHunterMonitor) window.BugHunterMonitor.load();
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  function renderRecentScans(scans) {
    const body = document.getElementById("recent-scans-body");
    if (!scans.length) {
      body.innerHTML = '<tr><td colspan="9" class="empty-state">No scans recorded.</td></tr>';
      return;
    }
    body.innerHTML = scans.slice(0, 10).map(scan => `
      <tr>
        <td class="target-cell">${escapeHTML(scan.target)}</td>
        <td>${escapeHTML(scan.scan_type)}</td>
        <td>${formatDate(scan.started_at)}</td>
        <td>${scan.critical_count || 0}</td>
        <td>${scan.high_count || 0}</td>
        <td>${scan.medium_count || 0}</td>
        <td>${renderRiskScore(scan.risk_score)}</td>
        <td>${statusLabel(scan.status)}</td>
        <td><div class="table-actions">
          <button class="btn btn-small view-scan-findings" data-scan-id="${escapeHTML(scan.id)}">FINDINGS</button>
          <a class="btn btn-small" href="/api/report/${encodeURIComponent(scan.id)}/pdf">REPORT</a>
        </div></td>
      </tr>`).join("");
  }

  function renderReports(scans) {
    const body = document.getElementById("reports-body");
    const completed = scans.filter(scan => scan.status === "completed");
    body.innerHTML = completed.length ? completed.map(scan => `
      <tr>
        <td class="target-cell">${escapeHTML(scan.target)}</td>
        <td>${formatDate(scan.completed_at || scan.started_at)}</td>
        <td>${renderSeverityBadge("CRITICAL")} ${scan.critical_count || 0} &nbsp; ${renderSeverityBadge("HIGH")} ${scan.high_count || 0}</td>
        <td>${renderRiskScore(scan.risk_score)}</td>
        <td><a class="btn btn-small" href="/api/report/${encodeURIComponent(scan.id)}/pdf">DOWNLOAD PDF</a></td>
        <td><a class="btn btn-small" href="/api/report/${encodeURIComponent(scan.id)}/html">DOWNLOAD HTML</a></td>
        <td><button class="btn btn-small preview-report" data-scan-id="${escapeHTML(scan.id)}">VIEW</button></td>
      </tr>`).join("") : '<tr><td colspan="7" class="empty-state">No completed scans available.</td></tr>';
  }

  function renderHistory(scans) {
    const timeline = document.getElementById("scan-timeline");
    timeline.innerHTML = scans.length ? scans.map(scan => `
      <div class="timeline-item">
        <strong>${escapeHTML(scan.target)}</strong>
        <p>${scan.total_findings || 0} findings · risk ${Number(scan.risk_score || 0).toFixed(1)} · ${escapeHTML(scan.scan_type)}</p>
        <small>${formatDate(scan.started_at)} · ${escapeHTML(scan.status)}</small>
      </div>`).join("") : '<div class="empty-state">No scan history yet.</div>';
    const options = scans.map(scan => `<option value="${escapeHTML(scan.id)}">${escapeHTML(scan.target)} · ${formatDate(scan.started_at)}</option>`).join("");
    document.getElementById("compare-first").innerHTML = options;
    document.getElementById("compare-second").innerHTML = options;
    if (scans.length > 1) document.getElementById("compare-first").selectedIndex = 1;
  }

  async function loadDashboard() {
    try {
      const [stats, scans] = await Promise.all([fetchJSON("/api/stats"), fetchJSON("/api/scans")]);
      state.stats = stats;
      state.scans = scans;
      document.getElementById("stat-total-scans").textContent = stats.total_scans || 0;
      document.getElementById("stat-critical").textContent = stats.critical_count || 0;
      document.getElementById("stat-high").textContent = stats.high_count || 0;
      document.getElementById("stat-medium").textContent = stats.medium_count || 0;
      document.getElementById("stat-low").textContent = stats.low_count || 0;
      document.getElementById("last-updated").textContent = new Date().toLocaleTimeString();
      renderRecentScans(scans);
      renderReports(scans);
      renderHistory(scans);
      if (window.BugHunterCharts) window.BugHunterCharts.updateCharts(stats);
    } catch (error) {
      toast(error.message, "error");
    }
  }

  async function openFindingModal(findingId) {
    const modal = document.getElementById("finding-modal");
    const content = document.getElementById("finding-modal-content");
    modal.hidden = false;
    content.innerHTML = '<div class="loading-spinner"></div>';
    try {
      const finding = await fetchJSON(`/api/findings/${encodeURIComponent(findingId)}`);
      const steps = String(finding.remediation || "").split(/\n+|(?<=\.)\s+/).filter(Boolean);
      const score = Math.min(10, Number(finding.cvss_score || 0));
      content.innerHTML = `
        <div class="modal-title-row">${renderSeverityBadge(finding.severity)}<h2 id="modal-title">${escapeHTML(finding.title)}</h2></div>
        <div class="modal-section"><strong>CVSS ${score.toFixed(1)}</strong><div class="cvss-gauge" style="--score:${score * 10}%;--score-color:${severityColors[finding.severity] || severityColors.INFO}"><i></i></div></div>
        <div class="modal-section"><h3>Description</h3><p>${escapeHTML(finding.description)}</p></div>
        <div class="modal-section"><h3>Evidence</h3><div class="evidence-block"><button class="btn btn-small copy-button" id="copy-evidence">COPY</button><pre id="modal-evidence">${escapeHTML(finding.evidence)}</pre></div></div>
        <div class="modal-section"><h3>Remediation</h3><ol class="remediation-steps">${steps.map(step => `<li>${escapeHTML(step)}</li>`).join("")}</ol></div>
        <div class="modal-section"><span class="tag">${escapeHTML(finding.owasp || "OWASP unmapped")}</span> <span class="tag">${escapeHTML(finding.mitre || "MITRE unmapped")}</span></div>
        <div class="modal-section"><button class="btn ${finding.false_positive ? "btn-danger" : ""}" id="modal-false-positive" data-finding-id="${escapeHTML(finding.id)}">${finding.false_positive ? "RESTORE FINDING" : "MARK FALSE POSITIVE"}</button></div>`;
      document.getElementById("copy-evidence").addEventListener("click", async event => {
        const text = document.getElementById("modal-evidence").textContent;
        try { await navigator.clipboard.writeText(text); } catch (error) {
          const area = document.createElement("textarea");
          area.value = text; document.body.appendChild(area); area.select(); document.execCommand("copy"); area.remove();
        }
        event.currentTarget.textContent = "COPIED";
      });
      document.getElementById("modal-false-positive").addEventListener("click", () => toggleFalsePositive(finding.id));
    } catch (error) {
      content.innerHTML = `<p class="form-error">${escapeHTML(error.message)}</p>`;
    }
  }

  function closeFindingModal() {
    document.getElementById("finding-modal").hidden = true;
    document.getElementById("finding-modal-content").innerHTML = "";
  }

  async function toggleFalsePositive(findingId) {
    try {
      await fetchJSON(`/api/findings/${encodeURIComponent(findingId)}/false-positive`, { method: "POST" });
      toast("Finding status updated");
      closeFindingModal();
      if (window.BugHunterFindings) window.BugHunterFindings.load();
      loadDashboard();
    } catch (error) {
      toast(error.message, "error");
    }
  }

  async function previewReport(scanId) {
    const scan = state.scans.find(item => item.id === scanId);
    const container = document.getElementById("report-preview-content");
    container.innerHTML = '<div class="loading-spinner"></div>';
    document.getElementById("preview-label").textContent = scan ? scan.target : "LOADING";
    try {
      const findings = await fetchJSON(`/api/findings?scan_id=${encodeURIComponent(scanId)}&limit=500`);
      container.innerHTML = `
        <div class="preview-summary">
          <div class="preview-risk"><strong style="color:${Number(scan.risk_score) >= 7 ? severityColors.HIGH : severityColors.LOW}">${Number(scan.risk_score || 0).toFixed(1)}</strong><span>RISK / 10</span></div>
          <div><h3>${escapeHTML(scan.target)}</h3><p>${findings.length} findings recorded during the ${escapeHTML(scan.scan_type)} assessment.</p>
          ${findings.slice(0, 6).map(item => `<div class="preview-finding">${renderSeverityBadge(item.severity)} <strong>${escapeHTML(item.title)}</strong></div>`).join("") || '<p>No findings recorded.</p>'}</div>
        </div>`;
    } catch (error) {
      container.textContent = error.message;
    }
  }

  async function compareScans() {
    const first = document.getElementById("compare-first").value;
    const second = document.getElementById("compare-second").value;
    const container = document.getElementById("comparison-results");
    if (!first || !second || first === second) {
      toast("Choose two different scans", "error");
      return;
    }
    container.innerHTML = '<div class="loading-spinner"></div>';
    try {
      const result = await fetchJSON(`/api/scans/compare?first=${encodeURIComponent(first)}&second=${encodeURIComponent(second)}`);
      const sections = [
        ["new", "New findings", result.new],
        ["fixed", "Fixed findings", result.fixed],
        ["unchanged", "Unchanged findings", result.unchanged]
      ];
      container.innerHTML = sections.map(([kind, label, items]) => `
        <div class="comparison-result ${kind}"><h4>${label}: ${items.length}</h4>
        ${items.slice(0, 10).map(item => `<p>${escapeHTML(item.title)} · ${escapeHTML(item.url)}</p>`).join("") || "<p>None</p>"}</div>`).join("");
    } catch (error) {
      container.innerHTML = `<p class="form-error">${escapeHTML(error.message)}</p>`;
    }
  }

  async function loadSettings() {
    try {
      const settings = await fetchJSON("/api/settings");
      document.getElementById("setting-email").value = settings.ALERT_EMAIL || "";
      document.getElementById("setting-smtp-host").value = settings.SMTP_HOST || "";
      document.getElementById("setting-smtp-port").value = settings.SMTP_PORT || 587;
      document.getElementById("setting-smtp-user").value = settings.SMTP_USER || "";
      document.getElementById("setting-timeout").value = settings.SCAN_TIMEOUT || 10;
      document.getElementById("setting-threads").value = settings.MAX_THREADS || 10;
      document.getElementById("timeout-value").textContent = `${settings.SCAN_TIMEOUT || 10}s`;
      document.getElementById("setting-bounty-mode").checked = Boolean(settings.BUG_BOUNTY_MODE);
      document.getElementById("setting-bounty-program").value = settings.BUG_BOUNTY_PROGRAM || "";
      document.getElementById("setting-hackerone-handle").value = settings.HACKERONE_HANDLE || "";
      document.getElementById("setting-rps").value = settings.REQUESTS_PER_SECOND || 2;
      applyBountySafety(settings);
    } catch (error) {
      toast(error.message, "error");
    }
  }

  async function saveSettings(event) {
    event.preventDefault();
    const value = id => document.getElementById(id).value;
    const payload = {
      ALERT_EMAIL: value("setting-email"),
      SMTP_HOST: value("setting-smtp-host"),
      SMTP_PORT: Number(value("setting-smtp-port")),
      SMTP_USER: value("setting-smtp-user"),
      SCAN_TIMEOUT: Number(value("setting-timeout")),
      MAX_THREADS: Number(value("setting-threads")),
      BUG_BOUNTY_MODE: document.getElementById("setting-bounty-mode").checked,
      BUG_BOUNTY_PROGRAM: value("setting-bounty-program"),
      HACKERONE_HANDLE: value("setting-hackerone-handle").trim(),
      REQUESTS_PER_SECOND: Number(value("setting-rps")),
      RESEARCHER_USER_AGENT: "",
      RESEARCHER_HEADER_NAME: "",
      RESEARCHER_HEADER_VALUE: ""
    };
    if (value("setting-nvd")) payload.NVD_API_KEY = value("setting-nvd");
    if (value("setting-virustotal")) payload.VIRUSTOTAL_API_KEY = value("setting-virustotal");
    if (value("setting-smtp-pass")) payload.SMTP_PASS = value("setting-smtp-pass");
    if (value("setting-slack")) payload.SLACK_WEBHOOK_URL = value("setting-slack");
    try {
      await fetchJSON("/api/settings", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
      document.getElementById("settings-message").textContent = "Configuration saved for this application session.";
      toast("Settings saved");
      loadSettings();
    } catch (error) {
      document.getElementById("settings-message").textContent = error.message;
    }
  }

  function applyBountySafety(settings) {
    const active = Boolean(settings.BUG_BOUNTY_MODE);
    const program = settings.BUG_BOUNTY_PROGRAM || "";
    const scopeName = program === "ring" ? "ring" : "";
    document.getElementById("scan-safety-notice").hidden = !active;
    document.getElementById("recon-safety-notice").hidden = !active;
    ["scan-scope-program", "recon-scope-program", "scope-program", "exploit-program", "nuclei-program"].forEach(id => {
      const input = document.getElementById(id);
      if (input && active && !input.value) input.value = scopeName;
    });
    const network = document.querySelector('input[name="scan_type"][value="network"]');
    if (network) {
      network.checked = active ? false : network.checked;
      network.disabled = active;
      network.closest(".choice").classList.toggle("choice-disabled", active);
    }
    const subdomain = document.querySelector('input[name="recon_type"][value="subdomain"]');
    if (subdomain) {
      subdomain.checked = active ? false : subdomain.checked;
      subdomain.disabled = active;
      subdomain.closest(".choice").classList.toggle("choice-disabled", active);
    }
    const monitorButton = document.querySelector("#monitor-form button[type='submit']");
    if (monitorButton) monitorButton.disabled = active;
    document.getElementById("monitor-safety-message").textContent = active
      ? "Recurring monitoring is disabled while the production bug-bounty safety profile is active."
      : "";
    const nucleiButton = document.querySelector("#nuclei-form button[type='submit']");
    if (nucleiButton) nucleiButton.disabled = active;
  }

  function bindEvents() {
    document.querySelectorAll(".tab-link").forEach(button => button.addEventListener("click", () => switchTab(button.dataset.tab)));
    document.querySelectorAll("[data-tab-jump]").forEach(button => button.addEventListener("click", () => switchTab(button.dataset.tabJump)));
    document.getElementById("mobile-menu").addEventListener("click", () => document.getElementById("main-tabs").classList.toggle("open"));
    document.getElementById("modal-close").addEventListener("click", closeFindingModal);
    document.getElementById("finding-modal").addEventListener("click", event => { if (event.target.id === "finding-modal") closeFindingModal(); });
    document.addEventListener("keydown", event => { if (event.key === "Escape") closeFindingModal(); });
    document.getElementById("recent-scans-body").addEventListener("click", event => {
      const button = event.target.closest(".view-scan-findings");
      if (!button) return;
      switchTab("findings");
      if (window.BugHunterFindings) window.BugHunterFindings.load(button.dataset.scanId);
    });
    document.getElementById("reports-body").addEventListener("click", event => {
      const button = event.target.closest(".preview-report");
      if (button) previewReport(button.dataset.scanId);
    });
    document.getElementById("compare-scans").addEventListener("click", compareScans);
    document.getElementById("settings-form").addEventListener("submit", saveSettings);
    document.getElementById("setting-bounty-mode").addEventListener("change", event => {
      if (event.target.checked && !document.getElementById("setting-bounty-program").value) {
        document.getElementById("setting-bounty-program").value = "ring";
      }
    });
    document.getElementById("setting-timeout").addEventListener("input", event => { document.getElementById("timeout-value").textContent = `${event.target.value}s`; });
    document.querySelectorAll(".test-alert").forEach(button => button.addEventListener("click", async () => {
      try {
        const result = await fetchJSON(`/api/alerts/test/${button.dataset.alertType}`, { method: "POST" });
        toast(`Alert test ${result.status}`);
      } catch (error) { toast(error.message, "error"); }
    }));
  }

  document.addEventListener("DOMContentLoaded", () => {
    bindEvents();
    loadDashboard();
    loadSettings();
    const initial = location.hash.replace("#", "");
    if (["dashboard", "new-scan", "findings", "reports", "history", "monitoring", "settings"].includes(initial)) switchTab(initial);
    setInterval(loadDashboard, 15000);
  });

  window.BugHunter = {
    state,
    escapeHTML,
    fetchJSON,
    renderSeverityBadge,
    renderRiskScore,
    formatDate,
    toast,
    switchTab,
    loadDashboard,
    openFindingModal,
    closeFindingModal,
    toggleFalsePositive
  };
  window.renderSeverityBadge = renderSeverityBadge;
  window.renderRiskScore = renderRiskScore;
  window.openFindingModal = openFindingModal;
  window.closeFindingModal = closeFindingModal;
  window.toggleFalsePositive = toggleFalsePositive;
})();
