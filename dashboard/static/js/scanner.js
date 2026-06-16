(function () {
  "use strict";

  const state = { scanId: "", pollTimer: null, seenFindings: new Set(), output: "dashboard" };

  function selectedScanners() {
    return [...document.querySelectorAll('input[name="scan_type"]:checked')].map(item => item.value);
  }

  function resetProgress(target, scanners) {
    state.seenFindings.clear();
    document.getElementById("progress-target").textContent = target;
    document.getElementById("scan-live-status").textContent = "RUNNING";
    document.getElementById("live-findings").innerHTML = "";
    document.getElementById("live-finding-count").textContent = "0";
    updateProgressBar(0);
    document.querySelectorAll("[data-scanner-row]").forEach(row => {
      const enabled = scanners.includes(row.dataset.scannerRow);
      row.hidden = !enabled;
      row.querySelector(".status-badge").className = "status-badge";
      row.querySelector(".status-badge").textContent = "PENDING";
      row.querySelector(".mini-track i").style.width = "0%";
      row.querySelector("small").textContent = "0 findings";
    });
    document.getElementById("stop-scan-button").hidden = false;
  }

  function updateProgressBar(percent) {
    const value = Math.max(0, Math.min(100, Number(percent || 0)));
    document.getElementById("overall-progress").style.width = `${value}%`;
    document.getElementById("progress-percent").textContent = `${Math.round(value)}%`;
  }

  function updateScannerRows(scannerStatus) {
    Object.entries(scannerStatus || {}).forEach(([name, details]) => {
      const row = document.querySelector(`[data-scanner-row="${CSS.escape(name)}"]`);
      if (!row) return;
      const badge = row.querySelector(".status-badge");
      badge.textContent = String(details.status || "pending").toUpperCase();
      badge.className = `status-badge ${details.status || ""}`;
      row.querySelector(".mini-track i").style.width = `${details.progress || 0}%`;
      row.querySelector("small").textContent = `${details.findings || 0} findings`;
    });
  }

  function appendLiveFinding(finding) {
    if (!finding.id || state.seenFindings.has(finding.id)) return;
    state.seenFindings.add(finding.id);
    const feed = document.getElementById("live-findings");
    const row = document.createElement("div");
    row.className = "live-finding";
    row.innerHTML = `${window.BugHunter.renderSeverityBadge(finding.severity)}
      <div><strong>${window.BugHunter.escapeHTML(finding.title)}</strong><small>${window.BugHunter.escapeHTML(finding.url)}</small></div>
      <small>${window.BugHunter.formatDate(finding.timestamp)}</small>`;
    feed.prepend(row);
    document.getElementById("live-finding-count").textContent = String(state.seenFindings.size);
  }

  async function pollScan() {
    if (!state.scanId) return;
    try {
      const status = await window.BugHunter.fetchJSON(`/api/scan/status/${encodeURIComponent(state.scanId)}`);
      updateProgressBar(status.progress_percent);
      updateScannerRows(status.scanner_status);
      (status.findings_so_far || []).forEach(appendLiveFinding);
      document.getElementById("scan-live-status").textContent = String(status.status).toUpperCase();
      if (["completed", "failed", "stopped"].includes(status.status)) {
        clearInterval(state.pollTimer);
        state.pollTimer = null;
        onScanComplete(status);
      }
    } catch (error) {
      clearInterval(state.pollTimer);
      window.BugHunter.toast(error.message, "error");
    }
  }

  async function startScan(event) {
    event.preventDefault();
    const target = document.getElementById("scan-target").value.trim();
    const scanners = selectedScanners();
    const consent = document.getElementById("scan-consent").checked;
    const mode = document.getElementById("scan-mode").value;
    const error = document.getElementById("scan-form-error");
    error.textContent = "";
    if (!target || !scanners.length || !consent) {
      error.textContent = "A target, at least one scanner, and authorization confirmation are required.";
      return;
    }
    state.output = document.getElementById("scan-output").value;
    if (mode === "scheduled") {
      let interval = document.getElementById("scan-schedule").value;
      if (interval === "custom") interval = document.getElementById("scan-custom-interval").value.trim();
      try {
        await window.BugHunter.fetchJSON("/api/targets", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url: target, monitor_enabled: true, interval })
        });
        window.BugHunter.toast("Target added to scheduled monitoring");
        window.BugHunter.switchTab("monitoring");
      } catch (requestError) {
        error.textContent = requestError.message;
      }
      return;
    }
    resetProgress(target, scanners);
    try {
      const result = await window.BugHunter.fetchJSON("/api/scan/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target,
          scan_type: scanners,
          mode: "manual",
          consent: true,
          program_name: document.getElementById("scan-scope-program").value.trim()
        })
      });
      state.scanId = result.scan_id;
      state.pollTimer = setInterval(pollScan, 2000);
      pollScan();
    } catch (requestError) {
      error.textContent = requestError.message;
      document.getElementById("stop-scan-button").hidden = true;
    }
  }

  async function stopScan() {
    if (!state.scanId) return;
    try {
      await window.BugHunter.fetchJSON(`/api/scan/stop/${encodeURIComponent(state.scanId)}`, { method: "POST" });
      document.getElementById("scan-live-status").textContent = "STOPPING";
    } catch (error) {
      window.BugHunter.toast(error.message, "error");
    }
  }

  function onScanComplete(status) {
    document.getElementById("stop-scan-button").hidden = true;
    updateProgressBar(100);
    if (status.status === "completed") {
      window.BugHunter.toast(`Scan complete with ${(status.findings_so_far || []).length} findings`);
      if (["pdf", "all"].includes(state.output)) window.open(`/api/report/${encodeURIComponent(state.scanId)}/pdf`, "_blank");
      if (["html", "all"].includes(state.output)) window.open(`/api/report/${encodeURIComponent(state.scanId)}/html`, "_blank");
      window.BugHunter.loadDashboard();
    } else {
      window.BugHunter.toast(`Scan ${status.status}`, status.status === "failed" ? "error" : "success");
    }
  }

  function bind() {
    document.getElementById("scan-form").addEventListener("submit", startScan);
    document.getElementById("stop-scan-button").addEventListener("click", stopScan);
    document.getElementById("scan-mode").addEventListener("change", event => {
      document.getElementById("scan-schedule-field").hidden = event.target.value !== "scheduled";
    });
    document.getElementById("scan-schedule").addEventListener("change", event => {
      document.getElementById("scan-custom-field").hidden = event.target.value !== "custom";
    });
  }

  document.addEventListener("DOMContentLoaded", bind);
  window.BugHunterScanner = { startScan, stopScan, updateProgressBar, updateScannerRows, appendLiveFinding };
})();
