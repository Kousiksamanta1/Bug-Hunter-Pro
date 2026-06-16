(function () {
  "use strict";

  const state = { targets: [], countdownTimer: null };

  function duration(milliseconds) {
    if (milliseconds <= 0) return "due now";
    const seconds = Math.floor(milliseconds / 1000);
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    if (days) return `${days}d ${hours}h`;
    if (hours) return `${hours}h ${minutes}m`;
    return `${minutes}m ${seconds % 60}s`;
  }

  function updateCountdowns() {
    document.querySelectorAll("[data-next-run]").forEach(element => {
      element.textContent = duration(new Date(element.dataset.nextRun).getTime() - Date.now());
    });
  }

  function renderTargets(targets) {
    const app = window.BugHunter;
    const body = document.getElementById("monitor-targets-body");
    document.getElementById("monitor-count").textContent = `${targets.length} TARGET${targets.length === 1 ? "" : "S"}`;
    body.innerHTML = targets.length ? targets.map(target => `
      <tr data-target-id="${app.escapeHTML(target.id)}">
        <td class="target-cell">${app.escapeHTML(target.url)}</td>
        <td>${app.formatDate(target.added_at)}</td>
        <td>${app.formatDate(target.last_scanned)}</td>
        <td><span class="countdown" data-next-run="${app.escapeHTML(target.next_run)}">${duration(new Date(target.next_run).getTime() - Date.now())}</span></td>
        <td>${target.total_findings || 0}</td>
        <td><span class="status-label ${app.escapeHTML(target.status)}">${app.escapeHTML(target.status)}</span></td>
        <td><div class="table-actions"><button class="btn btn-small scan-now">SCAN NOW</button><button class="btn btn-small edit-target">EDIT</button><button class="btn btn-small btn-danger remove-target">REMOVE</button></div></td>
      </tr>`).join("") : '<tr><td colspan="7" class="empty-state">No monitored targets configured.</td></tr>';
  }

  function renderAlerts(alerts) {
    const app = window.BugHunter;
    const body = document.getElementById("alert-history-body");
    body.innerHTML = alerts.length ? alerts.map(alert => `
      <tr><td>${app.escapeHTML(alert.target || "")}</td><td>${app.escapeHTML(alert.title || "")}</td><td>${app.renderSeverityBadge(alert.severity || "INFO")}</td><td>${app.escapeHTML(alert.alert_type)}</td><td>${app.formatDate(alert.sent_at)}</td><td><span class="status-label ${app.escapeHTML(alert.status)}">${app.escapeHTML(alert.status)}</span></td></tr>`).join("") : '<tr><td colspan="6" class="empty-state">No alert deliveries recorded.</td></tr>';
  }

  async function load() {
    try {
      const [targets, alerts] = await Promise.all([
        window.BugHunter.fetchJSON("/api/monitor/status"),
        window.BugHunter.fetchJSON("/api/alerts")
      ]);
      state.targets = targets;
      renderTargets(targets);
      renderAlerts(alerts);
      clearInterval(state.countdownTimer);
      state.countdownTimer = setInterval(updateCountdowns, 1000);
    } catch (error) {
      window.BugHunter.toast(error.message, "error");
    }
  }

  async function addTarget(event) {
    event.preventDefault();
    const target = document.getElementById("monitor-target").value.trim();
    let interval = document.getElementById("monitor-interval").value;
    if (interval === "custom") interval = document.getElementById("monitor-custom").value.trim();
    try {
      await window.BugHunter.fetchJSON("/api/targets", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: target, interval, monitor_enabled: true, alerts: document.getElementById("monitor-alerts").checked })
      });
      event.currentTarget.reset();
      window.BugHunter.toast("Monitoring target added");
      load();
    } catch (error) {
      window.BugHunter.toast(error.message, "error");
    }
  }

  async function removeTarget(id) {
    try {
      await window.BugHunter.fetchJSON(`/api/targets/${encodeURIComponent(id)}`, { method: "DELETE" });
      window.BugHunter.toast("Monitoring target removed");
      load();
    } catch (error) {
      window.BugHunter.toast(error.message, "error");
    }
  }

  async function scanNow(id) {
    try {
      const result = await window.BugHunter.fetchJSON(`/api/targets/${encodeURIComponent(id)}/scan`, { method: "POST" });
      window.BugHunter.toast(`Scan ${result.scan_id.slice(0, 8)} started`);
    } catch (error) {
      window.BugHunter.toast(error.message, "error");
    }
  }

  async function editTarget(id) {
    const target = state.targets.find(item => item.id === id);
    if (!target) return;
    const interval = window.prompt("Monitoring interval (examples: 30m, 24h, 7d)", target.monitor_interval);
    if (!interval || interval === target.monitor_interval) return;
    try {
      await window.BugHunter.fetchJSON("/api/targets", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          url: target.url,
          interval,
          monitor_enabled: true,
          alerts: Boolean(target.alerts_enabled)
        })
      });
      window.BugHunter.toast("Monitoring interval updated");
      load();
    } catch (error) {
      window.BugHunter.toast(error.message, "error");
    }
  }

  function bind() {
    document.getElementById("monitor-form").addEventListener("submit", addTarget);
    document.getElementById("monitor-interval").addEventListener("change", event => {
      document.getElementById("monitor-custom-field").hidden = event.target.value !== "custom";
    });
    document.getElementById("monitor-targets-body").addEventListener("click", event => {
      const row = event.target.closest("[data-target-id]");
      if (!row) return;
      if (event.target.closest(".remove-target")) removeTarget(row.dataset.targetId);
      if (event.target.closest(".scan-now")) scanNow(row.dataset.targetId);
      if (event.target.closest(".edit-target")) editTarget(row.dataset.targetId);
    });
    setInterval(() => {
      if (document.getElementById("tab-monitoring").classList.contains("active")) load();
    }, 60000);
  }

  document.addEventListener("DOMContentLoaded", bind);
  window.BugHunterMonitor = { load, addTarget, removeTarget, scanNow, editTarget };
})();
