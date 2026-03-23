const state = { config: null, options: null };

const els = {
  status: document.getElementById("status"),
  saveBtn: document.getElementById("saveBtn"),
  reloadBtn: document.getElementById("reloadBtn"),
  defaultOwnerGroup: document.getElementById("defaultOwnerGroup"),
  teamsEditor: document.getElementById("teamsEditor"),
  routingRulesEditor: document.getElementById("routingRulesEditor"),
  tagRulesEditor: document.getElementById("tagRulesEditor"),
  addTeamBtn: document.getElementById("addTeamBtn"),
  addRoutingRuleBtn: document.getElementById("addRoutingRuleBtn"),
  addTagRuleBtn: document.getElementById("addTagRuleBtn"),
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

function populateSelect(select, items, currentValue) {
  select.innerHTML = "";
  for (const item of items) {
    const option = document.createElement("option");
    option.value = item;
    option.textContent = item;
    if (item === currentValue) option.selected = true;
    select.appendChild(option);
  }
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

function getUsernames() {
  return (state.options?.users || []).map((user) => user.username).filter(Boolean);
}

function getTeamEntries() {
  return Object.entries(state.config?.teams || {});
}

function getTeamNames() {
  return getTeamEntries().map(([teamName]) => teamName);
}

function renderDefaultOwnerSelect() {
  const teamNames = getTeamNames();
  populateSelect(els.defaultOwnerGroup, teamNames, state.config.default_owner_group || teamNames[0] || "");
}

function renderTeamEditors() {
  const usernames = getUsernames();
  const teamEntries = getTeamEntries();
  renderDefaultOwnerSelect();

  if (!teamEntries.length) {
    els.teamsEditor.innerHTML = '<div class="helper">No teams yet. Add one to start routing alerts.</div>';
    return;
  }

  els.teamsEditor.innerHTML = teamEntries.map(([teamName, teamConfig], index) => `
    <div class="editor-card">
      <div class="editor-card-header">
        <span class="editor-card-title">Team ${index + 1}</span>
        <button class="ghost remove-team-btn" type="button" data-team-name="${escapeAttr(teamName)}">Remove</button>
      </div>
      <div class="editor-grid">
        <label class="field">
          <span>Team Name</span>
          <input class="team-name" type="text" value="${escapeAttr(teamName)}" />
        </label>
        <label class="field">
          <span>Fallback User</span>
          <input class="team-fallback" type="text" value="${escapeAttr(teamConfig.fallback_user || "")}" placeholder="admin" />
        </label>
        <label class="field full">
          <span>Users</span>
          <input class="team-users" type="text" value="${escapeAttr(joinCommaList(teamConfig.users || []))}" placeholder="admin, Test1, WindowsTest1" />
        </label>
      </div>
      <div class="helper">Available users: ${escapeAttr(usernames.join(", ") || "None loaded")}</div>
    </div>
  `).join("");
}

function renderRoutingRuleEditors() {
  const rules = state.config?.routing_rules || [];
  const teamNames = getTeamNames();

  if (!rules.length) {
    els.routingRulesEditor.innerHTML = '<div class="helper">No routing rules yet. Add one to map Wazuh groups to a team.</div>';
    return;
  }

  els.routingRulesEditor.innerHTML = rules.map((rule, index) => `
    <div class="editor-card">
      <div class="editor-card-header">
        <span class="editor-card-title">Routing Rule ${index + 1}</span>
        <button class="ghost remove-routing-btn" type="button" data-index="${index}">Remove</button>
      </div>
      <div class="editor-grid">
        <label class="field full">
          <span>Match Rule Groups</span>
          <input class="routing-match-groups" type="text" value="${escapeAttr(joinCommaList(rule.match_rule_groups || []))}" placeholder="windows, wef, sysmon" />
        </label>
        <label class="field">
          <span>Owner Group</span>
          <select class="routing-owner-group">
            ${teamNames.map((teamName) => `
              <option value="${escapeAttr(teamName)}" ${teamName === rule.owner_group ? "selected" : ""}>${teamName}</option>
            `).join("")}
          </select>
        </label>
      </div>
    </div>
  `).join("");
}

function renderTagRuleEditors() {
  const rules = state.config?.tag_rules || [];

  if (!rules.length) {
    els.tagRulesEditor.innerHTML = '<div class="helper">No tag rules yet. Add one to attach tags automatically.</div>';
    return;
  }

  els.tagRulesEditor.innerHTML = rules.map((rule, index) => `
    <div class="editor-card">
      <div class="editor-card-header">
        <span class="editor-card-title">Tag Rule ${index + 1}</span>
        <button class="ghost remove-tag-btn" type="button" data-index="${index}">Remove</button>
      </div>
      <div class="editor-grid">
        <label class="field full">
          <span>Match Rule Groups</span>
          <input class="tag-match-groups" type="text" value="${escapeAttr(joinCommaList(rule.match_rule_groups || []))}" placeholder="authentication_failed, vulnerability, syscollector" />
        </label>
        <label class="field full">
          <span>Tags</span>
          <input class="tag-tags" type="text" value="${escapeAttr(joinCommaList(rule.tags || []))}" placeholder="threat-hunting, vulnerability-detector" />
        </label>
      </div>
    </div>
  `).join("");
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
    els.findingStatusRulesEditor.innerHTML = '<div class="helper">No finding status rules yet. Add one to change active or verified status in real time.</div>';
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

function collectTeams() {
  const teams = {};
  for (const card of Array.from(els.teamsEditor.querySelectorAll(".editor-card"))) {
    const teamName = card.querySelector(".team-name")?.value.trim();
    if (!teamName) continue;
    teams[teamName] = {
      users: splitCommaList(card.querySelector(".team-users")?.value),
      fallback_user: card.querySelector(".team-fallback")?.value.trim() || "",
    };
  }
  return teams;
}

function collectRoutingRules() {
  return Array.from(els.routingRulesEditor.querySelectorAll(".editor-card")).map((card) => ({
    match_rule_groups: splitCommaList(card.querySelector(".routing-match-groups")?.value),
    owner_group: card.querySelector(".routing-owner-group")?.value || "",
  })).filter((rule) => rule.match_rule_groups.length && rule.owner_group);
}

function collectTagRules() {
  return Array.from(els.tagRulesEditor.querySelectorAll(".editor-card")).map((card) => ({
    match_rule_groups: splitCommaList(card.querySelector(".tag-match-groups")?.value),
    tags: splitCommaList(card.querySelector(".tag-tags")?.value),
  })).filter((rule) => rule.match_rule_groups.length && rule.tags.length);
}

function parseOptionalInt(value) {
  const normalized = String(value || "").trim();
  if (!normalized) return null;
  const parsed = Number(normalized);
  return Number.isFinite(parsed) ? parsed : null;
}

function parseOptionalBool(value) {
  if (value === "true") return true;
  if (value === "false") return false;
  return null;
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

function addTeam() {
  const names = getTeamNames();
  let index = names.length + 1;
  let candidate = `Team ${index}`;
  while (names.includes(candidate)) {
    index += 1;
    candidate = `Team ${index}`;
  }
  state.config.teams[candidate] = { users: [], fallback_user: "" };
  renderTeamEditors();
  renderRoutingRuleEditors();
}

function addRoutingRule() {
  state.config.routing_rules = state.config.routing_rules || [];
  state.config.routing_rules.push({
    match_rule_groups: [],
    owner_group: getTeamNames()[0] || "",
  });
  renderRoutingRuleEditors();
}

function addTagRule() {
  state.config.tag_rules = state.config.tag_rules || [];
  state.config.tag_rules.push({
    match_rule_groups: [],
    tags: [],
  });
  renderTagRuleEditors();
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
  const removeTeam = event.target.closest(".remove-team-btn");
  if (removeTeam) {
    delete state.config.teams[removeTeam.dataset.teamName];
    renderTeamEditors();
    renderRoutingRuleEditors();
    return;
  }

  const removeRouting = event.target.closest(".remove-routing-btn");
  if (removeRouting) {
    state.config.routing_rules.splice(Number(removeRouting.dataset.index), 1);
    renderRoutingRuleEditors();
    return;
  }

  const removeTag = event.target.closest(".remove-tag-btn");
  if (removeTag) {
    state.config.tag_rules.splice(Number(removeTag.dataset.index), 1);
    renderTagRuleEditors();
    return;
  }

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
    const [config, options] = await Promise.all([
      fetchJson("/admin/api/config"),
      fetchJson("/admin/api/dojo-options"),
    ]);
    state.config = config;
    state.options = options;
    renderTeamEditors();
    renderRoutingRuleEditors();
    renderTagRuleEditors();
    renderDedupSettingsEditor();
    renderFindingDefaultsEditor();
    renderFindingStatusRuleEditors();
    setStatus("Routing and team config loaded.");
  } catch (error) {
    setStatus(`Failed to load admin data: ${error}`, true);
  }
}

async function saveConfig() {
  setStatus("Saving...");
  try {
    const currentTeams = collectTeams();
    const payload = {
      ...state.config,
      dedup_settings: collectDedupSettings(),
      finding_defaults: collectFindingDefaults(),
      teams: currentTeams,
      routing_rules: collectRoutingRules(),
      tag_rules: collectTagRules(),
      finding_status_rules: collectFindingStatusRules(),
      default_owner_group: els.defaultOwnerGroup.value || Object.keys(currentTeams)[0] || "SecOps",
    };
    await fetchJson("/admin/api/config", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    setStatus("Routing and team config saved.");
    await loadAll();
  } catch (error) {
    setStatus(`Save failed: ${error}`, true);
  }
}

els.reloadBtn.addEventListener("click", loadAll);
els.saveBtn.addEventListener("click", saveConfig);
els.addTeamBtn.addEventListener("click", addTeam);
els.addRoutingRuleBtn.addEventListener("click", addRoutingRule);
els.addTagRuleBtn.addEventListener("click", addTagRule);
els.addFindingStatusRuleBtn.addEventListener("click", addFindingStatusRule);
els.teamsEditor.addEventListener("click", handleEditorClick);
els.routingRulesEditor.addEventListener("click", handleEditorClick);
els.tagRulesEditor.addEventListener("click", handleEditorClick);
els.findingStatusRulesEditor.addEventListener("click", handleEditorClick);

loadAll();
