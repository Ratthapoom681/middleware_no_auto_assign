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
      teams: currentTeams,
      routing_rules: collectRoutingRules(),
      tag_rules: collectTagRules(),
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
els.teamsEditor.addEventListener("click", handleEditorClick);
els.routingRulesEditor.addEventListener("click", handleEditorClick);
els.tagRulesEditor.addEventListener("click", handleEditorClick);

loadAll();
