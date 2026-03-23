const state = { config: null, options: { users: [], dojo_groups: [] } };

const els = {
  status: document.getElementById("status"),
  saveBtn: document.getElementById("saveBtn"),
  reloadBtn: document.getElementById("reloadBtn"),
  teamsEditor: document.getElementById("teamsEditor"),
  dojoTeamsInventory: document.getElementById("dojoTeamsInventory"),
  addTeamBtn: document.getElementById("addTeamBtn"),
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

function renderDojoTeamsInventory() {
  const groups = state.options?.dojo_groups || [];

  if (!groups.length) {
    els.dojoTeamsInventory.innerHTML = '<div class="helper">No DefectDojo group data is available right now.</div>';
    return;
  }

  els.dojoTeamsInventory.innerHTML = groups.map((group) => `
    <section class="inventory-group">
      <div class="inventory-group-head">
        <div>
          <h3>${escapeAttr(group.name || "Unnamed Group")}</h3>
          <p class="helper">${escapeAttr(group.description || "No description")}</p>
        </div>
        <span class="pill">${escapeAttr(String(group.member_count || 0))} users</span>
      </div>
      ${(group.social_provider && String(group.social_provider).trim()) ? `
        <div class="helper">Source: ${escapeAttr(group.social_provider)}</div>
      ` : ""}
      ${(group.members || []).length ? `
        <div class="member-grid">
          ${(group.members || []).map((member) => `
            <article class="detail-item">
              <span class="detail-label">${escapeAttr(member.username || "Unknown user")}</span>
              <div class="detail-value">${escapeAttr(member.full_name || member.email || "No extra profile details")}</div>
              <div class="helper">${escapeAttr(member.role ? `Role: ${member.role}` : "Role unavailable")}</div>
            </article>
          `).join("")}
        </div>
      ` : `
        <div class="helper">No users are currently assigned to this DefectDojo team.</div>
      `}
    </section>
  `).join("");
}

function getTeamEntries() {
  return Object.entries(state.config?.teams || {});
}

function getTeamNames() {
  return getTeamEntries().map(([teamName]) => teamName);
}

function renderTeamEditors() {
  const usernames = getUsernames();
  const teamEntries = getTeamEntries();

  if (!teamEntries.length) {
    els.teamsEditor.innerHTML = '<div class="helper">No teams yet. Add one to define the ownership groups used by routing.</div>';
    return;
  }

  els.teamsEditor.innerHTML = teamEntries.map(([teamName, teamConfig], index) => `
    <div class="editor-card" data-original-team-name="${escapeAttr(teamName)}">
      <div class="editor-card-header">
        <span class="editor-card-title">Team ${index + 1}</span>
        <button class="ghost remove-team-btn" type="button" data-team-name="${escapeAttr(teamName)}">Remove</button>
      </div>
      <div class="editor-grid">
        <label class="field">
          <span>Team Name</span>
          <input class="team-name" type="text" value="${escapeAttr(teamName)}" placeholder="SOC-Network" />
        </label>
        <label class="field">
          <span>Fallback User</span>
          <input class="team-fallback" type="text" value="${escapeAttr(teamConfig.fallback_user || "")}" placeholder="admin" />
        </label>
        <label class="field full">
          <span>Users</span>
          <input class="team-users" type="text" value="${escapeAttr(joinCommaList(teamConfig.users || []))}" placeholder="alice, bob, charlie" />
        </label>
      </div>
      <div class="helper">Available users from DefectDojo: ${escapeAttr(usernames.join(", ") || "Unavailable right now")}</div>
    </div>
  `).join("");
}

function collectTeamState() {
  const teams = {};
  const renameMap = {};
  for (const card of Array.from(els.teamsEditor.querySelectorAll(".editor-card"))) {
    const originalTeamName = card.dataset.originalTeamName || "";
    const teamName = card.querySelector(".team-name")?.value.trim();
    if (!teamName) {
      continue;
    }
    if (originalTeamName && originalTeamName !== teamName) {
      renameMap[originalTeamName] = teamName;
    }
    teams[teamName] = {
      users: splitCommaList(card.querySelector(".team-users")?.value),
      fallback_user: card.querySelector(".team-fallback")?.value.trim() || "",
    };
  }
  return { teams, renameMap };
}

function addTeam() {
  const names = getTeamNames();
  let index = names.length + 1;
  let candidate = `Team ${index}`;
  while (names.includes(candidate)) {
    index += 1;
    candidate = `Team ${index}`;
  }
  state.config.teams = state.config.teams || {};
  state.config.teams[candidate] = { users: [], fallback_user: "" };
  renderTeamEditors();
}

function handleEditorClick(event) {
  const removeTeam = event.target.closest(".remove-team-btn");
  if (!removeTeam) {
    return;
  }
  delete state.config.teams[removeTeam.dataset.teamName];
  renderTeamEditors();
}

async function fetchJson(url, options = {}) {
  const res = await fetch(url, options);
  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.detail || JSON.stringify(data));
  }
  return data;
}

async function loadAll() {
  setStatus("Loading...");
  try {
    const config = await fetchJson("/admin/api/config");
    state.config = config;

    try {
      state.options = await fetchJson("/admin/api/dojo-options");
    } catch (error) {
      state.options = { users: [], dojo_groups: [] };
    }

    renderTeamEditors();
    renderDojoTeamsInventory();
    setStatus("Team config loaded.");
  } catch (error) {
    setStatus(`Failed to load team config: ${error}`, true);
  }
}

async function saveConfig() {
  setStatus("Saving...");
  try {
    const { teams, renameMap } = collectTeamState();
    const teamNames = Object.keys(teams);
    let defaultOwnerGroup = renameMap[state.config.default_owner_group] || state.config.default_owner_group || "";
    if (defaultOwnerGroup && !teams[defaultOwnerGroup]) {
      defaultOwnerGroup = teamNames[0] || "";
    }
    const payload = {
      ...state.config,
      teams,
      default_owner_group: defaultOwnerGroup,
      routing_rules: (state.config.routing_rules || []).map((rule) => ({
        ...rule,
        owner_group: renameMap[rule.owner_group] || rule.owner_group,
      })),
    };
    await fetchJson("/admin/api/config", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    setStatus("Team config saved.");
    await loadAll();
  } catch (error) {
    setStatus(`Save failed: ${error}`, true);
  }
}

els.reloadBtn.addEventListener("click", loadAll);
els.saveBtn.addEventListener("click", saveConfig);
els.addTeamBtn.addEventListener("click", addTeam);
els.teamsEditor.addEventListener("click", handleEditorClick);

loadAll();
