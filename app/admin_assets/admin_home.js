const els = {
  logList: document.getElementById("logList"),
  logStatus: document.getElementById("logStatus"),
  refreshLogsBtn: document.getElementById("refreshLogsBtn"),
};

let refreshTimer = null;

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function setStatus(message, isError = false) {
  els.logStatus.textContent = message;
  els.logStatus.className = isError ? "status error" : "status";
}

async function fetchJson(url, options = {}) {
  const res = await fetch(url, options);
  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.detail || JSON.stringify(data));
  }
  return data;
}

function formatTimestamp(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return date.toLocaleString();
}

function renderLogs(entries) {
  if (!entries.length) {
    els.logList.innerHTML = `
      <div class="log-empty">
        No matching log activity yet. Errors and DefectDojo send events will appear here.
      </div>
    `;
    return;
  }

  els.logList.innerHTML = entries.map((entry) => `
    <article class="log-entry log-entry-${escapeHtml(entry.category)}">
      <div class="log-entry-head">
        <span class="log-badge">${escapeHtml(entry.category)}</span>
        <span class="log-level">${escapeHtml(entry.level)}</span>
        <time class="log-time">${escapeHtml(formatTimestamp(entry.timestamp))}</time>
      </div>
      <p class="log-message">${escapeHtml(entry.message)}</p>
    </article>
  `).join("");
}

async function loadLogs() {
  try {
    const data = await fetchJson("/admin/api/logs");
    renderLogs(data.entries || []);
    setStatus("Log stream connected.");
  } catch (error) {
    setStatus(`Failed to load logs: ${error}`, true);
  }
}

function startRefresh() {
  if (refreshTimer) {
    clearInterval(refreshTimer);
  }
  refreshTimer = setInterval(loadLogs, 5000);
}

els.refreshLogsBtn.addEventListener("click", loadLogs);

loadLogs();
startRefresh();
