const state = { config: null };

const els = {
  status: document.getElementById("status"),
  saveBtn: document.getElementById("saveBtn"),
  reloadBtn: document.getElementById("reloadBtn"),
  defaultOwnerGroup: document.getElementById("defaultOwnerGroup"),
  routingRulesEditor: document.getElementById("routingRulesEditor"),
  tagRulesEditor: document.getElementById("tagRulesEditor"),
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

function getTeamEntries() {
  return Object.entries(state.config?.teams || {});
}

function getTeamNames() {
  return getTeamEntries().map(([teamName]) => teamName);
}

function renderDefaultOwnerSelect() {
  const teamNames = getTeamNames();
  if (!teamNames.length) {
    els.defaultOwnerGroup.innerHTML = '<option value="">No teams defined yet</option>';
    return;
  }
  populateSelect(els.defaultOwnerGroup, teamNames, state.config.default_owner_group || teamNames[0]);
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
    state.config = await fetchJson("/admin/api/config");
    renderDefaultOwnerSelect();
    renderRoutingRuleEditors();
    renderTagRuleEditors();
    setStatus("Routing config loaded.");
  } catch (error) {
    setStatus(`Failed to load routing config: ${error}`, true);
  }
}

async function saveConfig() {
  setStatus("Saving...");
  try {
    const payload = {
      ...state.config,
      routing_rules: collectRoutingRules(),
      tag_rules: collectTagRules(),
      default_owner_group: els.defaultOwnerGroup.value || getTeamNames()[0] || "SecOps",
    };
    await fetchJson("/admin/api/config", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    setStatus("Routing config saved.");
    await loadAll();
  } catch (error) {
    setStatus(`Save failed: ${error}`, true);
  }
}

els.reloadBtn.addEventListener("click", loadAll);
els.saveBtn.addEventListener("click", saveConfig);
els.addRoutingRuleBtn.addEventListener("click", addRoutingRule);
els.addTagRuleBtn.addEventListener("click", addTagRule);
els.routingRulesEditor.addEventListener("click", handleEditorClick);
els.tagRulesEditor.addEventListener("click", handleEditorClick);

loadAll();
