(function () {
  "use strict";

  const seen = new Set();
  const escapeHTML = value => window.BugHunter.escapeHTML(value);

  function parsedData(callback) {
    try {
      const data = JSON.parse(callback.data || "{}");
      return Object.keys(data).length ? JSON.stringify(data) : callback.path || callback.body || "-";
    } catch (error) {
      return callback.data || callback.path || callback.body || "-";
    }
  }

  function render(callbacks) {
    const feed = document.getElementById("oob-callback-feed");
    if (!callbacks.length) {
      feed.innerHTML = '<div class="empty-state">No callbacks received.</div>';
      return;
    }
    feed.innerHTML = callbacks.map(callback => {
      const isNew = !seen.has(callback.id);
      seen.add(callback.id);
      return `<div class="callback-entry ${isNew ? "new" : ""}" data-callback-id="${escapeHTML(callback.id)}">
        <span>${window.BugHunter.formatDate(callback.timestamp)}</span>
        <span>${escapeHTML(callback.source_ip || "-")}</span>
        <strong>${escapeHTML(callback.callback_type || "-")}</strong>
        <span>${escapeHTML(parsedData(callback))}</span>
      </div>`;
    }).join("");
  }

  function highlight(callback) {
    const row = document.querySelector(`[data-callback-id="${CSS.escape(callback.id)}"]`);
    if (row) row.classList.add("new");
  }

  async function refresh() {
    try {
      const [status, callbacks] = await Promise.all([
        window.BugHunter.fetchJSON("/api/oob/status"),
        window.BugHunter.fetchJSON("/api/oob/callbacks")
      ]);
      const badge = document.getElementById("exploit-oob-badge");
      badge.textContent = status.running ? "OOB ONLINE" : "OOB STANDBY";
      badge.className = `status-label ${status.running ? "completed" : ""}`;
      document.getElementById("exploit-callback-url").textContent = status.callback_url;
      if (window.BugHunterExploit) window.BugHunterExploit.setCallbackURL(status.callback_url);
      render(callbacks);
    } catch (error) {
      document.getElementById("exploit-oob-badge").textContent = "OOB ERROR";
    }
  }

  function bind() {
    document.getElementById("oob-refresh").addEventListener("click", refresh);
    refresh();
    setInterval(refresh, 5000);
  }

  document.addEventListener("DOMContentLoaded", bind);
  window.BugHunterOOB = { refresh, render, highlight };
})();
