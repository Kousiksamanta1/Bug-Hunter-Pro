(function () {
  "use strict";

  const escapeHTML = value => window.BugHunter.escapeHTML(value);

  function lines(value) {
    return value.split(/\r?\n/).map(item => item.trim()).filter(Boolean);
  }

  function renderScope(scope) {
    document.getElementById("scope-current").innerHTML = `
      <strong>${escapeHTML(scope.program_name)}</strong>
      <p class="muted-copy">In scope</p><ul class="scope-list">${scope.in_scope.map(item => `<li>${escapeHTML(item)}</li>`).join("")}</ul>
      <p class="muted-copy">Out of scope</p><ul class="scope-list">${scope.out_of_scope.length ? scope.out_of_scope.map(item => `<li>${escapeHTML(item)}</li>`).join("") : "<li>None specified</li>"}</ul>`;
  }

  async function saveScope(event) {
    event.preventDefault();
    const programName = document.getElementById("scope-program").value.trim();
    const message = document.getElementById("scope-message");
    message.textContent = "";
    try {
      const scope = await window.BugHunter.fetchJSON("/api/intelligence/scope", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          program_name: programName,
          in_scope: lines(document.getElementById("scope-in").value),
          out_of_scope: lines(document.getElementById("scope-out").value)
        })
      });
      renderScope(scope);
      document.getElementById("exploit-program").value = programName;
      document.getElementById("nuclei-program").value = programName;
      message.style.color = "var(--success)";
      message.textContent = "Scope saved.";
      window.BugHunter.toast("Scope saved");
    } catch (error) {
      message.style.color = "";
      message.textContent = error.message;
    }
  }

  async function loadScope(programName) {
    if (!programName) return;
    try {
      const scope = await window.BugHunter.fetchJSON(`/api/intelligence/scope/${encodeURIComponent(programName)}`);
      document.getElementById("scope-in").value = scope.in_scope.join("\n");
      document.getElementById("scope-out").value = scope.out_of_scope.join("\n");
      renderScope(scope);
    } catch (error) {
      document.getElementById("scope-current").innerHTML = `<span class="muted-copy">${escapeHTML(error.message)}</span>`;
    }
  }

  function renderNucleiFindings(data) {
    const findings = data.findings || [];
    document.getElementById("nuclei-results").innerHTML = findings.length ? `
      <div class="table-wrap"><table><thead><tr><th>Template</th><th>Severity</th><th>Finding</th><th>URL</th></tr></thead><tbody>${findings.map(item => `
        <tr><td>${escapeHTML(item.template_id || "-")}</td><td>${window.BugHunter.renderSeverityBadge(item.severity)}</td><td>${escapeHTML(item.title)}</td><td class="url-cell">${escapeHTML(item.url)}</td></tr>`).join("")}</tbody></table></div>`
      : `<div class="empty-state">${escapeHTML(data.status === "unavailable" ? "Nuclei is not installed. Installation instructions are shown below." : "No Nuclei findings.")}</div>${data.instructions ? `<pre class="result-json">${escapeHTML(JSON.stringify(data.instructions, null, 2))}</pre>` : ""}`;
  }

  async function runNuclei(event) {
    event.preventDefault();
    const button = event.submitter;
    const message = document.getElementById("nuclei-message");
    message.textContent = "Nuclei is running. Larger template sets can take several minutes.";
    if (button) button.disabled = true;
    try {
      const data = await window.BugHunter.fetchJSON("/api/intelligence/nuclei", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target: document.getElementById("nuclei-target").value.trim(),
          program_name: document.getElementById("nuclei-program").value.trim(),
          severity: document.getElementById("nuclei-severity").value,
          tags: [...document.getElementById("nuclei-tags").selectedOptions].map(option => option.value)
        })
      });
      message.textContent = `Nuclei status: ${data.status}`;
      renderNucleiFindings(data);
      window.BugHunter.loadDashboard();
    } catch (error) {
      message.textContent = error.message;
    } finally {
      if (button) button.disabled = false;
    }
  }

  async function updateNuclei() {
    const message = document.getElementById("nuclei-message");
    message.textContent = "Updating Nuclei templates...";
    try {
      const data = await window.BugHunter.fetchJSON("/api/intelligence/nuclei/update", { method: "POST" });
      message.textContent = data.success ? `Templates updated. ${data.template_count} available.` : JSON.stringify(data.instructions || data.error);
      loadNucleiStatus();
    } catch (error) {
      message.textContent = error.message;
    }
  }

  async function loadNucleiStatus() {
    try {
      const data = await window.BugHunter.fetchJSON("/api/intelligence/nuclei/status");
      document.getElementById("nuclei-template-count").textContent = data.installed ? `${data.template_count} TEMPLATES` : "NUCLEI NOT INSTALLED";
    } catch (error) {
      document.getElementById("nuclei-template-count").textContent = "STATUS UNAVAILABLE";
    }
  }

  async function checkDuplicate(findingId) {
    if (!findingId) return window.BugHunter.toast("Choose a finding first", "error");
    const container = document.getElementById("duplicate-results");
    container.innerHTML = '<div class="loading-spinner"></div>';
    try {
      const data = await window.BugHunter.fetchJSON("/api/intelligence/check-duplicate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ finding_id: findingId })
      });
      renderDuplicateResults(data);
    } catch (error) {
      container.innerHTML = `<p class="form-error">${escapeHTML(error.message)}</p>`;
    }
  }

  function renderDuplicateResults(data) {
    const uniqueness = data.uniqueness || { score: 0, breakdown: [] };
    const h1 = data.hackerone && data.hackerone.similar_reports ? data.hackerone.similar_reports : [];
    const github = data.github && data.github.github_issues ? data.github.github_issues : [];
    document.getElementById("duplicate-results").innerHTML = `
      <div class="uniqueness-score"><strong>${Number(uniqueness.score || 0)}/100 UNIQUE</strong><div class="score-track"><i style="width:${Number(uniqueness.score || 0)}%"></i></div></div>
      <p>${data.nvd && data.nvd.is_known_cve ? `Known CVE: ${escapeHTML(data.nvd.cve_id)}` : "No known CVE matched."}</p>
      <p>${h1.length} similar disclosed HackerOne reports; ${github.length} related GitHub issues.</p>
      <pre class="result-json">${escapeHTML(JSON.stringify(data, null, 2))}</pre>`;
  }

  async function loadSelectors() {
    try {
      const findings = await window.BugHunter.fetchJSON("/api/findings?limit=500&include_false=false");
      const findingOptions = '<option value="">Select a finding</option>' + findings.map(item => `<option value="${escapeHTML(item.id)}">${escapeHTML(item.severity)} · ${escapeHTML(item.title)}</option>`).join("");
      document.getElementById("duplicate-finding").innerHTML = findingOptions;
    } catch (error) {
      window.BugHunter.toast(`Intelligence data: ${error.message}`, "error");
    }
  }

  function bind() {
    document.getElementById("scope-form").addEventListener("submit", saveScope);
    document.getElementById("scope-program").addEventListener("change", event => loadScope(event.target.value.trim()));
    document.getElementById("nuclei-form").addEventListener("submit", runNuclei);
    document.getElementById("nuclei-update").addEventListener("click", updateNuclei);
    document.getElementById("duplicate-check").addEventListener("click", () => checkDuplicate(document.getElementById("duplicate-finding").value));
    loadSelectors();
    loadNucleiStatus();
    if (location.hash === "#intelligence") window.BugHunter.switchTab("intelligence");
  }

  document.addEventListener("DOMContentLoaded", bind);
  window.BugHunterIntelligence = {
    saveScope,
    runNuclei,
    checkDuplicate,
    renderDuplicateResults
  };
})();
