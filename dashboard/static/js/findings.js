(function () {
  "use strict";

  const state = { severity: "", scanner: "", search: "", includeFalse: true, scanId: "", findings: [] };
  let debounceTimer;

  function rowColor(severity) {
    return { CRITICAL: "#D92D20", HIGH: "#E35D12", MEDIUM: "#B7791F", LOW: "#0077B6", INFO: "#6956C7" }[severity] || "#6956C7";
  }

  function filteredFindings() {
    const term = state.search.trim().toLowerCase();
    return state.findings.filter(item => !term || item.title.toLowerCase().includes(term) || String(item.url || "").toLowerCase().includes(term));
  }

  function render() {
    const app = window.BugHunter;
    const body = document.getElementById("findings-body");
    const items = filteredFindings();
    document.getElementById("finding-result-count").textContent = `${items.length} finding${items.length === 1 ? "" : "s"}`;
    body.innerHTML = items.length ? items.map(item => `
      <tr data-finding-id="${app.escapeHTML(item.id)}" class="${item.false_positive ? "false-positive" : ""}" style="--row-color:${rowColor(item.severity)}">
        <td>${app.renderSeverityBadge(item.severity)}</td>
        <td class="finding-title"><strong>${app.escapeHTML(item.title)}</strong></td>
        <td>${app.escapeHTML(item.scanner)}</td>
        <td class="url-cell" title="${app.escapeHTML(item.url)}">${app.escapeHTML(item.url)}</td>
        <td>${Number(item.cvss_score || 0).toFixed(1)}</td>
        <td><span class="tag" title="${app.escapeHTML(item.owasp)}">${app.escapeHTML(item.owasp || "Unmapped")}</span></td>
        <td><span class="tag" title="${app.escapeHTML(item.mitre)}">${app.escapeHTML(item.mitre || "Unmapped")}</span></td>
        <td>${app.formatDate(item.timestamp)}</td>
        <td><button class="btn btn-small finding-fp">${item.false_positive ? "RESTORE" : "FALSE +"}</button></td>
      </tr>`).join("") : '<tr><td colspan="9" class="empty-state">No findings match these filters.</td></tr>';
  }

  async function load(scanId) {
    if (scanId !== undefined) state.scanId = scanId || "";
    const params = new URLSearchParams({ limit: "5000", include_false: String(state.includeFalse) });
    if (state.severity) params.set("severity", state.severity);
    if (state.scanner) params.set("scanner", state.scanner);
    if (state.scanId) params.set("scan_id", state.scanId);
    try {
      state.findings = await window.BugHunter.fetchJSON(`/api/findings?${params}`);
      render();
    } catch (error) {
      window.BugHunter.toast(error.message, "error");
    }
  }

  function exportCSV() {
    const items = filteredFindings();
    const columns = ["severity", "title", "scanner", "url", "cvss_score", "owasp", "mitre", "timestamp", "false_positive"];
    const encode = value => `"${String(value == null ? "" : value).replaceAll('"', '""')}"`;
    const csv = [columns.join(","), ...items.map(item => columns.map(column => encode(item[column])).join(","))].join("\n");
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = `BugHunterPro_findings_${new Date().toISOString().slice(0, 10)}.csv`;
    link.click();
    URL.revokeObjectURL(link.href);
  }

  function bind() {
    document.getElementById("severity-filters").addEventListener("click", event => {
      const button = event.target.closest("[data-severity]");
      if (!button) return;
      document.querySelectorAll("#severity-filters .filter-button").forEach(item => item.classList.remove("active"));
      button.classList.add("active");
      state.severity = button.dataset.severity;
      load();
    });
    document.getElementById("finding-scanner").addEventListener("change", event => { state.scanner = event.target.value; load(); });
    document.getElementById("finding-search").addEventListener("input", event => {
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(() => { state.search = event.target.value; render(); }, 300);
    });
    document.getElementById("show-false-positives").addEventListener("change", event => { state.includeFalse = event.target.checked; load(); });
    document.getElementById("export-findings").addEventListener("click", exportCSV);
    document.getElementById("findings-body").addEventListener("click", async event => {
      const row = event.target.closest("[data-finding-id]");
      if (!row) return;
      if (event.target.closest(".finding-fp")) {
        event.stopPropagation();
        await window.BugHunter.toggleFalsePositive(row.dataset.findingId);
      } else {
        window.BugHunter.openFindingModal(row.dataset.findingId);
      }
    });
  }

  document.addEventListener("DOMContentLoaded", bind);
  window.BugHunterFindings = { load, render, state };
})();
