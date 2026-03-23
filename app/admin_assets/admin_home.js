const els = {
  queueSummary: document.getElementById("queueSummary"),
  queueMeta: document.getElementById("queueMeta"),
  queueFailures: document.getElementById("queueFailures"),
  queueStatus: document.getElementById("queueStatus"),
  refreshQueueBtn: document.getElementById("refreshQueueBtn"),
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

function setQueueStatus(message, isError = false) {
  els.queueStatus.textContent = message;
  els.queueStatus.className = isError ? "status error" : "status";
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

function formatAge(seconds) {
  const total = Number(seconds || 0);
  if (!Number.isFinite(total) || total <= 0) {
    return "0s";
  }
  if (total < 60) {
    return `${total}s`;
  }
  const minutes = Math.floor(total / 60);
  const remainder = total % 60;
  if (minutes < 60) {
    return `${minutes}m ${remainder}s`;
  }
  const hours = Math.floor(minutes / 60);
  const leftoverMinutes = minutes % 60;
  return `${hours}h ${leftoverMinutes}m`;
}

function renderQueue(snapshot) {
  const cards = [
    { label: "Pending", value: snapshot.pending || 0 },
    { label: "Ready", value: snapshot.ready || 0 },
    { label: "Processing", value: snapshot.processing || 0 },
    { label: "Failed", value: snapshot.failed || 0 },
  ];

  els.queueSummary.innerHTML = cards.map((card) => `
    <article class="queue-card">
      <p class="queue-label">${escapeHtml(card.label)}</p>
      <p class="queue-value">${escapeHtml(card.value)}</p>
    </article>
  `).join("");

  els.queueMeta.innerHTML = `
    <span class="pill">Oldest live item: ${escapeHtml(formatAge(snapshot.oldest_age_seconds || 0))}</span>
    <span class="pill">${escapeHtml((snapshot.ready || 0) > 0 ? "Worker has ready alerts to process" : "No ready backlog right now")}</span>
  `;

  const failures = snapshot.failed_items || [];
  if (!failures.length) {
    els.queueFailures.innerHTML = `
      <div class="log-empty">
        No failed queue items. Alerts that cannot be processed after retries will appear here.
      </div>
    `;
    return;
  }

  els.queueFailures.innerHTML = failures.map((item) => `
    <article class="log-entry log-entry-error">
      <div class="log-entry-head">
        <span class="log-badge">queue failed</span>
        <span class="log-level">Attempt ${escapeHtml(item.attempts)}</span>
        <time class="log-time">${escapeHtml(formatTimestamp(item.updated_at * 1000))}</time>
      </div>
      <p class="log-message">Job #${escapeHtml(item.id)}: ${escapeHtml(item.last_error || "Unknown error")}</p>
    </article>
  `).join("");
}

function renderLogs(entries) {
  if (!entries.length) {
    els.logList.innerHTML = `
      <div class="log-empty">
        No application errors yet. New error entries will appear here automatically.
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

async function loadQueue() {
  try {
    const snapshot = await fetchJson("/admin/api/queue");
    renderQueue(snapshot);
    setQueueStatus("Queue connected.");
  } catch (error) {
    setQueueStatus(`Failed to load queue: ${error}`, true);
  }
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
  refreshTimer = setInterval(() => {
    loadQueue();
    loadLogs();
  }, 5000);
}

els.refreshQueueBtn.addEventListener("click", loadQueue);
els.refreshLogsBtn.addEventListener("click", loadLogs);

loadQueue();
loadLogs();
startRefresh();
