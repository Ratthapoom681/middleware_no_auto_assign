const state = { config: null };

const els = {
  status: document.getElementById("status"),
  saveBtn: document.getElementById("saveBtn"),
  reloadBtn: document.getElementById("reloadBtn"),
  dedupSettingsEditor: document.getElementById("dedupSettingsEditor"),
  findingDefaultsEditor: document.getElementById("findingDefaultsEditor"),
  findingStatusRulesEditor: document.getElementById("findingStatusRulesEditor"),
  addFindingStatusRuleBtn: document.getElementById("addFindingStatusRuleBtn"),
};

function escapeAttr(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/"/g, "&quot;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function setStatus(message, isError = false) {
  els.status.textContent = message;
  els.status.className = isError ? "status error" : "status";
}

function parseOptionalBool(value) {
  if (value === "true") return true;
  if (value === "false") return false;
  return null;
}

function parseOptionalInt(value) {
  const normalized = String(value || "").trim();
  if (!normalized) return null;
  const parsed = Number(normalized);
  return Number.isFinite(parsed) ? parsed : null;
}

function splitCommaList(value) {
  return String(value || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function joinCommaList(values) {
  return (values || []).join(", ");
}

function renderDedupSettingsEditor() {
  const settings = state.config?.dedup_settings || {
    enabled: true,
    use_unique_id: true,
    use_title_test_fallback: true,
    require_same_endpoint: true,
    require_same_cwe: true,
    require_network_match: true,
    ignore_mitigated: true,
    action_on_match: "skip",
  };

  const boolOptions = (value) => `
    <option value="true" ${value === true ? "selected" : ""}>True</option>
    <option value="false" ${value === false ? "selected" : ""}>False</option>
  `;

  els.dedupSettingsEditor.innerHTML = `
    <div class="editor-card">
      <div class="editor-card-header">
        <span class="editor-card-title">Dedup Matching</span>
      </div>
      <div class="editor-grid">
        <label class="field">
          <span>Dedup Enabled</span>
          <select class="dedup-enabled">${boolOptions(settings.enabled)}</select>
        </label>
        <label class="field">
          <span>Action On Match</span>
          <select class="dedup-action-on-match">
            <option value="skip" ${settings.action_on_match === "skip" ? "selected" : ""}>Skip create</option>
            <option value="create_new" ${settings.action_on_match === "create_new" ? "selected" : ""}>Create new anyway</option>
          </select>
        </label>
        <label class="field">
          <span>Match By Unique ID</span>
          <select class="dedup-use-unique-id">${boolOptions(settings.use_unique_id)}</select>
        </label>
        <label class="field">
          <span>Use Title/Test Fallback</span>
          <select class="dedup-use-title-test-fallback">${boolOptions(settings.use_title_test_fallback)}</select>
        </label>
        <label class="field">
          <span>Require Same Endpoint</span>
          <select class="dedup-require-same-endpoint">${boolOptions(settings.require_same_endpoint)}</select>
        </label>
        <label class="field">
          <span>Require Same CWE</span>
          <select class="dedup-require-same-cwe">${boolOptions(settings.require_same_cwe)}</select>
        </label>
        <label class="field">
          <span>Require Same Network Match</span>
          <select class="dedup-require-network-match">${boolOptions(settings.require_network_match)}</select>
        </label>
        <label class="field">
          <span>Ignore Mitigated Findings</span>
          <select class="dedup-ignore-mitigated">${boolOptions(settings.ignore_mitigated)}</select>
        </label>
      </div>
    </div>
  `;
}

function renderFindingDefaultsEditor() {
  const defaults = state.config?.finding_defaults || {
    active: true,
    verified: true,
    false_positive: false,
    out_of_scope: false,
    risk_accepted: false,
    under_review: null,
  };

  const selectOptions = (value) => `
    <option value="" ${value == null ? "selected" : ""}>Keep unset</option>
    <option value="true" ${value === true ? "selected" : ""}>True</option>
    <option value="false" ${value === false ? "selected" : ""}>False</option>
  `;

  els.findingDefaultsEditor.innerHTML = `
    <div class="editor-card">
      <div class="editor-card-header">
        <span class="editor-card-title">Default Finding Fields</span>
      </div>
      <div class="editor-grid">
        <label class="field">
          <span>Active</span>
          <select class="finding-default-active">
            <option value="true" ${defaults.active === true ? "selected" : ""}>True</option>
            <option value="false" ${defaults.active === false ? "selected" : ""}>False</option>
          </select>
        </label>
        <label class="field">
          <span>Verified</span>
          <select class="finding-default-verified">
            <option value="true" ${defaults.verified === true ? "selected" : ""}>True</option>
            <option value="false" ${defaults.verified === false ? "selected" : ""}>False</option>
          </select>
        </label>
        <label class="field">
          <span>False Positive</span>
          <select class="finding-default-false-positive">
            <option value="true" ${defaults.false_positive === true ? "selected" : ""}>True</option>
            <option value="false" ${defaults.false_positive === false ? "selected" : ""}>False</option>
          </select>
        </label>
        <label class="field">
          <span>Out Of Scope</span>
          <select class="finding-default-out-of-scope">
            <option value="true" ${defaults.out_of_scope === true ? "selected" : ""}>True</option>
            <option value="false" ${defaults.out_of_scope === false ? "selected" : ""}>False</option>
          </select>
        </label>
        <label class="field">
          <span>Risk Accepted</span>
          <select class="finding-default-risk-accepted">
            <option value="true" ${defaults.risk_accepted === true ? "selected" : ""}>True</option>
            <option value="false" ${defaults.risk_accepted === false ? "selected" : ""}>False</option>
          </select>
        </label>
        <label class="field">
          <span>Under Review</span>
          <select class="finding-default-under-review">${selectOptions(defaults.under_review)}</select>
        </label>
      </div>
    </div>
  `;
}

function renderFindingStatusRuleEditors() {
  const rules = state.config?.finding_status_rules || [];

  if (!rules.length) {
    els.findingStatusRulesEditor.innerHTML = '<div class="helper">No finding status rules yet. Add one to change active, verified, or other fields in real time.</div>';
    return;
  }

  const selectOptions = (value) => `
    <option value="" ${value == null ? "selected" : ""}>Keep</option>
    <option value="true" ${value === true ? "selected" : ""}>True</option>
    <option value="false" ${value === false ? "selected" : ""}>False</option>
  `;

  els.findingStatusRulesEditor.innerHTML = rules.map((rule, index) => `
    <div class="editor-card">
      <div class="editor-card-header">
        <span class="editor-card-title">Status Rule ${index + 1}</span>
        <button class="ghost remove-finding-status-rule-btn" type="button" data-index="${index}">Remove</button>
      </div>
      <div class="editor-grid">
        <label class="field">
          <span>Rule Name</span>
          <input class="finding-status-name" type="text" value="${escapeAttr(rule.name || "")}" placeholder="Low severity inactive" />
        </label>
        <label class="field">
          <span>Match Rule Groups</span>
          <input class="finding-status-match-groups" type="text" value="${escapeAttr(joinCommaList(rule.match_rule_groups || []))}" placeholder="fortigate, anomaly" />
        </label>
        <label class="field">
          <span>Severity Min</span>
          <input class="finding-status-severity-min" type="number" value="${escapeAttr(rule.severity_min ?? "")}" placeholder="1" />
        </label>
        <label class="field">
          <span>Severity Max</span>
          <input class="finding-status-severity-max" type="number" value="${escapeAttr(rule.severity_max ?? "")}" placeholder="4" />
        </label>
        <label class="field">
          <span>Set Active</span>
          <select class="finding-status-active">${selectOptions(rule.set_active)}</select>
        </label>
        <label class="field">
          <span>Set Verified</span>
          <select class="finding-status-verified">${selectOptions(rule.set_verified)}</select>
        </label>
        <label class="field">
          <span>Set False Positive</span>
          <select class="finding-status-false-positive">${selectOptions(rule.set_false_positive)}</select>
        </label>
        <label class="field">
          <span>Set Out Of Scope</span>
          <select class="finding-status-out-of-scope">${selectOptions(rule.set_out_of_scope)}</select>
        </label>
        <label class="field">
          <span>Set Risk Accepted</span>
          <select class="finding-status-risk-accepted">${selectOptions(rule.set_risk_accepted)}</select>
        </label>
        <label class="field">
          <span>Set Under Review</span>
          <select class="finding-status-under-review">${selectOptions(rule.set_under_review)}</select>
        </label>
      </div>
    </div>
  `).join("");
}

function collectDedupSettings() {
  return {
    enabled: parseOptionalBool(els.dedupSettingsEditor.querySelector(".dedup-enabled")?.value) ?? true,
    use_unique_id: parseOptionalBool(els.dedupSettingsEditor.querySelector(".dedup-use-unique-id")?.value) ?? true,
    use_title_test_fallback: parseOptionalBool(els.dedupSettingsEditor.querySelector(".dedup-use-title-test-fallback")?.value) ?? true,
    require_same_endpoint: parseOptionalBool(els.dedupSettingsEditor.querySelector(".dedup-require-same-endpoint")?.value) ?? true,
    require_same_cwe: parseOptionalBool(els.dedupSettingsEditor.querySelector(".dedup-require-same-cwe")?.value) ?? true,
    require_network_match: parseOptionalBool(els.dedupSettingsEditor.querySelector(".dedup-require-network-match")?.value) ?? true,
    ignore_mitigated: parseOptionalBool(els.dedupSettingsEditor.querySelector(".dedup-ignore-mitigated")?.value) ?? true,
    action_on_match: els.dedupSettingsEditor.querySelector(".dedup-action-on-match")?.value || "skip",
  };
}

function collectFindingDefaults() {
  return {
    active: parseOptionalBool(els.findingDefaultsEditor.querySelector(".finding-default-active")?.value) ?? true,
    verified: parseOptionalBool(els.findingDefaultsEditor.querySelector(".finding-default-verified")?.value) ?? true,
    false_positive: parseOptionalBool(els.findingDefaultsEditor.querySelector(".finding-default-false-positive")?.value) ?? false,
    out_of_scope: parseOptionalBool(els.findingDefaultsEditor.querySelector(".finding-default-out-of-scope")?.value) ?? false,
    risk_accepted: parseOptionalBool(els.findingDefaultsEditor.querySelector(".finding-default-risk-accepted")?.value) ?? false,
    under_review: parseOptionalBool(els.findingDefaultsEditor.querySelector(".finding-default-under-review")?.value),
  };
}

function collectFindingStatusRules() {
  return Array.from(els.findingStatusRulesEditor.querySelectorAll(".editor-card")).map((card) => ({
    name: card.querySelector(".finding-status-name")?.value.trim() || "",
    match_rule_groups: splitCommaList(card.querySelector(".finding-status-match-groups")?.value),
    severity_min: parseOptionalInt(card.querySelector(".finding-status-severity-min")?.value),
    severity_max: parseOptionalInt(card.querySelector(".finding-status-severity-max")?.value),
    set_active: parseOptionalBool(card.querySelector(".finding-status-active")?.value),
    set_verified: parseOptionalBool(card.querySelector(".finding-status-verified")?.value),
    set_false_positive: parseOptionalBool(card.querySelector(".finding-status-false-positive")?.value),
    set_out_of_scope: parseOptionalBool(card.querySelector(".finding-status-out-of-scope")?.value),
    set_risk_accepted: parseOptionalBool(card.querySelector(".finding-status-risk-accepted")?.value),
    set_under_review: parseOptionalBool(card.querySelector(".finding-status-under-review")?.value),
  })).filter((rule) => rule.name);
}

function addFindingStatusRule() {
  state.config.finding_status_rules = state.config.finding_status_rules || [];
  state.config.finding_status_rules.push({
    name: "",
    match_rule_groups: [],
    severity_min: null,
    severity_max: null,
    set_active: null,
    set_verified: null,
    set_false_positive: null,
    set_out_of_scope: null,
    set_risk_accepted: null,
    set_under_review: null,
  });
  renderFindingStatusRuleEditors();
}

function handleEditorClick(event) {
  const removeFindingStatusRule = event.target.closest(".remove-finding-status-rule-btn");
  if (removeFindingStatusRule) {
    state.config.finding_status_rules.splice(Number(removeFindingStatusRule.dataset.index), 1);
    renderFindingStatusRuleEditors();
  }
}

async function fetchJson(url, options = {}) {
  const res = await fetch(url, options);
  const data = await res.json();
  if (!res.ok) throw new Error(data.detail || JSON.stringify(data));
  return data;
}

async function loadAll() {
  setStatus("Loading...");
  try {
    state.config = await fetchJson("/admin/api/config");
    renderDedupSettingsEditor();
    renderFindingDefaultsEditor();
    renderFindingStatusRuleEditors();
    setStatus("Finding behavior config loaded.");
  } catch (error) {
    setStatus(`Failed to load finding behavior config: ${error}`, true);
  }
}

async function saveConfig() {
  setStatus("Saving...");
  try {
    const payload = {
      ...state.config,
      dedup_settings: collectDedupSettings(),
      finding_defaults: collectFindingDefaults(),
      finding_status_rules: collectFindingStatusRules(),
    };
    await fetchJson("/admin/api/config", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    setStatus("Finding behavior config saved.");
    await loadAll();
  } catch (error) {
    setStatus(`Save failed: ${error}`, true);
  }
}

els.reloadBtn.addEventListener("click", loadAll);
els.saveBtn.addEventListener("click", saveConfig);
els.addFindingStatusRuleBtn.addEventListener("click", addFindingStatusRule);
els.findingStatusRulesEditor.addEventListener("click", handleEditorClick);

loadAll();
