(function () {
  "use strict";

  const state = {
    reconId: "",
    pollTimer: null,
    subdomains: [],
    jsFindings: [],
    dorks: {},
    wayback: {},
    waybackCategory: "all"
  };

  const escapeHTML = value => window.BugHunter.escapeHTML(value);

  function selectedModules() {
    return [...document.querySelectorAll('input[name="recon_type"]:checked')]
      .map(input => input.value);
  }

  async function startRecon(event) {
    event.preventDefault();
    const target = document.getElementById("recon-target").value.trim();
    const scanTypes = selectedModules();
    const consent = document.getElementById("recon-consent").checked;
    const error = document.getElementById("recon-error");
    error.textContent = "";
    if (!target || !scanTypes.length || !consent) {
      error.textContent = "Enter a target, select at least one module, and confirm authorization.";
      return;
    }
    document.getElementById("recon-status").textContent = "STARTING";
    document.getElementById("recon-progress").style.width = "0%";
    try {
      const data = await window.BugHunter.fetchJSON("/api/recon/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target,
          scan_types: scanTypes,
          consent: true,
          program_name: document.getElementById("recon-scope-program").value.trim()
        })
      });
      state.reconId = data.recon_id;
      clearInterval(state.pollTimer);
      state.pollTimer = setInterval(pollReconStatus, 3000);
      pollReconStatus();
    } catch (requestError) {
      error.textContent = requestError.message;
      document.getElementById("recon-status").textContent = "FAILED";
    }
  }

  async function pollReconStatus() {
    if (!state.reconId) return;
    try {
      const data = await window.BugHunter.fetchJSON(`/api/recon/results/${encodeURIComponent(state.reconId)}`);
      document.getElementById("recon-status").textContent = String(data.status || "running").toUpperCase();
      document.getElementById("recon-progress").style.width = `${Number(data.progress_percent || 0)}%`;
      renderSubdomains(data.subdomains || []);
      renderJSFindings(data.js_findings || []);
      renderTechStack(data.tech_stack || {});
      renderDorks(data.dorks || {});
      renderWayback(data.wayback_urls || {});
      if (data.status === "completed") {
        clearInterval(state.pollTimer);
        state.pollTimer = null;
        window.BugHunter.toast("Recon completed");
      }
    } catch (error) {
      clearInterval(state.pollTimer);
      state.pollTimer = null;
      document.getElementById("recon-error").textContent = error.message;
    }
  }

  function renderSubdomains(items) {
    state.subdomains = items;
    const alive = items.filter(item => Number(item.status_code || 0) > 0).length;
    document.getElementById("recon-subdomain-summary").textContent = `${items.length} found / ${alive} alive`;
    document.getElementById("recon-subdomains-body").innerHTML = items.length ? items.map(item => `
      <tr>
        <td><strong>${escapeHTML(item.subdomain)}</strong></td>
        <td>${escapeHTML(item.ip || "-")}</td>
        <td>${item.status_code || "-"}</td>
        <td>${escapeHTML(item.server_header || "-")}</td>
        <td>${item.response_time == null ? "-" : `${Number(item.response_time).toFixed(3)}s`}</td>
        <td>${escapeHTML(item.discovered_by || "-")}</td>
        <td><button class="btn btn-small recon-queue" data-subdomain="${escapeHTML(item.subdomain)}" type="button">ADD TO QUEUE</button></td>
      </tr>`).join("") : '<tr><td colspan="7" class="empty-state">No subdomains found.</td></tr>';
  }

  function maskValue(value) {
    const text = String(value || "");
    if (text.length <= 10) return "••••••••";
    return `${text.slice(0, 4)}••••••••${text.slice(-4)}`;
  }

  function renderJSFindings(items) {
    state.jsFindings = items;
    const files = new Set(items.map(item => item.js_file)).size;
    const secrets = items.filter(item => !["API endpoint", "Hidden endpoint comment"].includes(item.finding_type)).length;
    document.getElementById("recon-js-summary").textContent = `${files} files / ${secrets} secrets / ${items.length} findings`;
    document.getElementById("recon-js-body").innerHTML = items.length ? items.map((item, index) => `
      <tr>
        <td class="url-cell" title="${escapeHTML(item.js_file)}">${escapeHTML(item.js_file)}</td>
        <td>${escapeHTML(item.finding_type)}</td>
        <td>${window.BugHunter.renderSeverityBadge(item.severity)}</td>
        <td><code>${escapeHTML(maskValue(item.value))}</code></td>
        <td>${item.line_approximate || "-"}</td>
        <td><button class="btn btn-small recon-view-value" data-index="${index}" type="button">VIEW</button></td>
      </tr>`).join("") : '<tr><td colspan="6" class="empty-state">No JavaScript findings.</td></tr>';
  }

  function renderTechStack(data) {
    const fields = ["server", "language", "framework", "cms", "cdn", "waf"];
    document.getElementById("recon-tech-stack").innerHTML = fields.map(field => `
      <div class="fingerprint-item"><span>${escapeHTML(field)}</span><strong>${escapeHTML(data[field] || "Not detected")}</strong></div>`).join("");
    const paths = Array.isArray(data.interesting_paths) ? data.interesting_paths : [];
    document.getElementById("recon-interesting-paths").innerHTML = paths.length
      ? paths.map(path => `<span class="result-chip ${/\/(?:\\.env|\\.git|actuator\/env)/i.test(path) ? "critical" : ""}">${escapeHTML(path)}</span>`).join("")
      : '<span class="muted-copy">No paths found.</span>';
    const findings = Array.isArray(data.findings) ? data.findings : [];
    document.getElementById("recon-tech-findings").innerHTML = findings.map(item => `
      <div class="comparison-result new"><h4>${window.BugHunter.renderSeverityBadge(item.severity)} ${escapeHTML(item.title)}</h4><p>${escapeHTML(item.url)}</p></div>`).join("");
  }

  function renderDorks(data) {
    state.dorks = data;
    const groups = Object.entries(data);
    document.getElementById("recon-dorks").innerHTML = groups.length ? groups.map(([category, items]) => `
      <section class="dork-group"><h3>${escapeHTML(category)}</h3>${items.map(item => `
        <div class="dork-row"><code>${escapeHTML(item.query)}</code><a class="btn btn-small" href="${escapeHTML(item.url)}" target="_blank" rel="noopener noreferrer">OPEN</a></div>`).join("")}</section>`).join("")
      : '<div class="empty-state">No dorks generated.</div>';
  }

  function waybackRows(data, category) {
    const categories = data.categories || {};
    const aliveMap = new Map((data.alive_urls || []).map(item => [item.url, item]));
    const keys = category === "all" ? Object.keys(categories) : [category === "interesting_params" ? "interesting" : category];
    const rows = [];
    keys.forEach(key => (categories[key] || []).forEach(url => {
      const alive = aliveMap.get(url) || {};
      rows.push({ url, category: key, status: alive.status || "-", last_seen: alive.last_seen || "-" });
    }));
    return rows;
  }

  function renderWayback(data) {
    state.wayback = data;
    document.getElementById("recon-wayback-summary").textContent = `${data.total_found || 0} found / ${data.alive_count || 0} alive`;
    const rows = waybackRows(data, state.waybackCategory);
    document.getElementById("recon-wayback-body").innerHTML = rows.length ? rows.slice(0, 1000).map(item => `
      <tr><td class="url-cell" title="${escapeHTML(item.url)}">${escapeHTML(item.url)}</td><td>${escapeHTML(item.last_seen)}</td><td>${item.status}</td><td><span class="tag">${escapeHTML(item.category.replaceAll("_", " "))}</span></td></tr>`).join("")
      : '<tr><td colspan="4" class="empty-state">No URLs in this category.</td></tr>';
  }

  async function addToScanQueue(subdomain) {
    try {
      await window.BugHunter.fetchJSON("/api/targets", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: `https://${subdomain}`, monitor_enabled: false, interval: "24h", alerts: false })
      });
      window.BugHunter.toast(`${subdomain} added to the scan queue`);
    } catch (error) {
      window.BugHunter.toast(error.message, "error");
    }
  }

  function exportSubdomains() {
    if (!state.subdomains.length) return window.BugHunter.toast("No subdomains to export", "error");
    const columns = ["subdomain", "ip", "status_code", "server_header", "response_time", "discovered_by"];
    const quote = value => `"${String(value == null ? "" : value).replaceAll('"', '""')}"`;
    const csv = [columns.join(","), ...state.subdomains.map(item => columns.map(column => quote(item[column])).join(","))].join("\n");
    const link = document.createElement("a");
    link.href = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
    link.download = "bug-hunter-subdomains.csv";
    link.click();
    URL.revokeObjectURL(link.href);
  }

  function bind() {
    document.getElementById("recon-form").addEventListener("submit", startRecon);
    document.getElementById("recon-export-subdomains").addEventListener("click", exportSubdomains);
    document.getElementById("recon-subdomains-body").addEventListener("click", event => {
      const button = event.target.closest(".recon-queue");
      if (button) addToScanQueue(button.dataset.subdomain);
    });
    document.getElementById("recon-js-body").addEventListener("click", event => {
      const button = event.target.closest(".recon-view-value");
      if (!button) return;
      const finding = state.jsFindings[Number(button.dataset.index)];
      document.getElementById("recon-value-title").textContent = `${finding.finding_type} in ${finding.js_file}`;
      document.getElementById("recon-value-content").textContent = finding.value;
      document.getElementById("recon-value-modal").hidden = false;
    });
    document.getElementById("recon-value-close").addEventListener("click", () => {
      document.getElementById("recon-value-modal").hidden = true;
    });
    document.getElementById("recon-value-modal").addEventListener("click", event => {
      if (event.target.id === "recon-value-modal") event.currentTarget.hidden = true;
    });
    document.getElementById("recon-copy-dorks").addEventListener("click", async () => {
      const text = Object.values(state.dorks).flat().map(item => item.query).join("\n");
      if (!text) return window.BugHunter.toast("No dorks to copy", "error");
      await navigator.clipboard.writeText(text);
      window.BugHunter.toast("Dorks copied");
    });
    document.getElementById("recon-wayback-filters").addEventListener("click", event => {
      const button = event.target.closest("[data-wayback-category]");
      if (!button) return;
      state.waybackCategory = button.dataset.waybackCategory;
      document.querySelectorAll("[data-wayback-category]").forEach(item => item.classList.toggle("active", item === button));
      renderWayback(state.wayback);
    });
    if (location.hash === "#recon") window.BugHunter.switchTab("recon");
  }

  document.addEventListener("DOMContentLoaded", bind);
  window.BugHunterRecon = {
    startRecon,
    pollReconStatus,
    renderSubdomains,
    renderJSFindings,
    renderTechStack,
    renderDorks,
    renderWayback,
    addToScanQueue
  };
})();
