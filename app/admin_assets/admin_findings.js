const state = { config: null };

const els = {
  status: document.getElementById("status"),
  saveBtn: document.getElementById("saveBtn"),
  reloadBtn: document.getElementById("reloadBtn"),
  dedupSettingsEditor: document.getElementById("dedupSettingsEditor"),
  findingDefaultsEditor: document.getElementById("findingDefaultsEditor"),
  findingStatusRulesEditor: document.getElementById("findingStatusRulesEditor"),
  findingGroupRulesEditor: document.getElementById("findingGroupRulesEditor"),
  addFindingStatusRuleBtn: document.getElementById("addFindingStatusRuleBtn"),
  addFindingGroupRuleBtn: document.getElementById("addFindingGroupRuleBtn"),
};

const DEDUP_PRESETS = {
  pair: {
    enabled: true,
    use_unique_id: false,
    use_title_test_fallback: true,
    require_same_endpoint: false,
    require_same_cwe: false,
    require_network_match: true,
    network_match_mode: "all",
    network_match_fields: ["src_ip", "dst_ip"],
    ignore_mitigated: true,
    action_on_match: "skip",
  },
  balanced: {
    enabled: true,
    use_unique_id: true,
    use_title_test_fallback: true,
    require_same_endpoint: true,
    require_same_cwe: true,
    require_network_match: true,
    network_match_mode: "any",
    network_match_fields: ["src_ip", "observed_ip", "dst_ip"],
    ignore_mitigated: true,
    action_on_match: "skip",
  },
  strict: {
    enabled: true,
    use_unique_id: true,
    use_title_test_fallback: false,
    require_same_endpoint: false,
    require_same_cwe: false,
    require_network_match: false,
    network_match_mode: "all",
    network_match_fields: ["src_ip", "dst_ip"],
    ignore_mitigated: true,
    action_on_match: "skip",
  },
  loose: {
    enabled: true,
    use_unique_id: true,
    use_title_test_fallback: true,
    require_same_endpoint: false,
    require_same_cwe: false,
    require_network_match: false,
    network_match_mode: "any",
    network_match_fields: ["src_ip", "observed_ip", "dst_ip"],
    ignore_mitigated: true,
    action_on_match: "skip",
  },
  off: {
    enabled: false,
    use_unique_id: false,
    use_title_test_fallback: false,
    require_same_endpoint: false,
    require_same_cwe: false,
    require_network_match: false,
    network_match_mode: "any",
    network_match_fields: ["src_ip", "observed_ip", "dst_ip"],
    ignore_mitigated: true,
    action_on_match: "create_new",
  },
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

function getDedupSettings() {
  return state.config?.dedup_settings || DEDUP_PRESETS.balanced;
}

function isPresetMatch(settings, preset) {
  return Object.entries(preset).every(([key, value]) => settings[key] === value);
}

function getDedupPresetName(settings) {
  if (isPresetMatch(settings, DEDUP_PRESETS.pair)) return "pair";
  if (isPresetMatch(settings, DEDUP_PRESETS.off)) return "off";
  if (isPresetMatch(settings, DEDUP_PRESETS.loose)) return "loose";
  if (isPresetMatch(settings, DEDUP_PRESETS.strict)) return "strict";
  if (isPresetMatch(settings, DEDUP_PRESETS.balanced)) return "balanced";
  return "custom";
}

function describeDedupSettings(settings) {
  if (!settings.enabled) {
    return {
      headline: "Dedup is disabled",
      details: [
        "Every alert is allowed to create a new finding.",
        "Existing findings are not used to block creation.",
      ],
    };
  }

  const checks = [];
  if (settings.use_unique_id) checks.push("unique tool dedup key");
  if (settings.use_title_test_fallback) checks.push("same title inside the same test");
  if (settings.require_same_endpoint) checks.push("same endpoint");
  if (settings.require_same_cwe) checks.push("same CWE");
  if (settings.require_network_match) {
    const selectedFields = (settings.network_match_fields || []).join(" + ") || "selected network fields";
    checks.push(`network match uses ${settings.network_match_mode === "all" ? "all" : "any"} of ${selectedFields}`);
  }

  return {
    headline: settings.action_on_match === "skip"
      ? "Duplicates will be skipped"
      : "Duplicates can still create new findings",
    details: [
      checks.length
        ? `Matching looks at ${checks.join(", ")}.`
        : "No dedup matching checks are active right now.",
      settings.ignore_mitigated
        ? "Mitigated or closed findings are ignored during matching."
        : "Mitigated or closed findings still count as duplicates.",
    ],
  };
}

function formatNetworkFieldLabel(field) {
  const labels = {
    src_ip: "Source IP",
    dst_ip: "Destination IP",
    observed_ip: "Observed IP",
  };
  return labels[field] || field;
}

function buildDedupFlow(settings) {
  const selectedFields = (settings.network_match_fields || []).map(formatNetworkFieldLabel);
  const networkSummary = settings.require_network_match
    ? `${settings.network_match_mode === "all" ? "All" : "Any"} of ${selectedFields.join(", ") || "selected IP fields"}`
    : "Not required";

  return [
    {
      step: "1",
      title: "Start Match",
      detail: settings.use_unique_id
        ? "Check the generated unique dedup key first."
        : "Skip the unique key and move to fallback matching.",
      tone: settings.use_unique_id ? "active" : "muted",
    },
    {
      step: "2",
      title: "Fallback Scope",
      detail: settings.use_title_test_fallback
        ? "Then compare findings with the same title in the same DefectDojo test."
        : "No title/test fallback is used.",
      tone: settings.use_title_test_fallback ? "active" : "muted",
    },
    {
      step: "3",
      title: "Extra Guards",
      detail: settings.use_title_test_fallback
        ? `Endpoint: ${settings.require_same_endpoint ? "same required" : "not required"} • CWE: ${settings.require_same_cwe ? "same required" : "not required"} • Network: ${networkSummary}.`
        : "Extra guards are inactive because fallback matching is off.",
      tone: settings.use_title_test_fallback ? "active" : "muted",
    },
    {
      step: "4",
      title: "Result",
      detail: settings.action_on_match === "skip"
        ? "If a match is found, the middleware skips creating a new finding."
        : "If a match is found, the middleware still creates a new finding.",
      tone: settings.action_on_match === "skip" ? "active" : "warning",
    },
  ];
}

function buildDedupScenarios(settings) {
  const networkFields = new Set(settings.network_match_fields || []);
  const selectedNames = Array.from(networkFields).map(formatNetworkFieldLabel);
  const networkLabel = selectedNames.length ? selectedNames.join(" + ") : "selected IP fields";
  const requireAll = settings.network_match_mode === "all";

  if (!settings.enabled) {
    return [
      { label: "Any alert arrives", outcome: "Create new finding", emphasis: "new" },
      { label: "Same title and same IPs", outcome: "Still create new finding", emphasis: "new" },
      { label: "Old finding already exists", outcome: "Still create new finding", emphasis: "new" },
    ];
  }

  const scenarios = [];

  if (settings.use_unique_id) {
    scenarios.push({
      label: "Same unique dedup key repeats",
      outcome: settings.action_on_match === "skip" ? "Duplicate, skip create" : "Match found, still create",
      emphasis: settings.action_on_match === "skip" ? "duplicate" : "warning",
    });
  }

  if (settings.use_title_test_fallback) {
    scenarios.push({
      label: "Same title in same test",
      outcome: settings.require_same_endpoint || settings.require_same_cwe || settings.require_network_match
        ? "Check extra guards before treating as duplicate"
        : (settings.action_on_match === "skip" ? "Duplicate, skip create" : "Match found, still create"),
      emphasis: "guard",
    });

    if (settings.require_network_match) {
      scenarios.push({
        label: `${networkLabel} ${requireAll ? "all match" : "partly match"}`,
        outcome: settings.action_on_match === "skip"
          ? "Counts as duplicate if the title/test fallback also matches"
          : "Counts as match, but create behavior still follows your action setting",
        emphasis: "duplicate",
      });
      scenarios.push({
        label: `${networkLabel} do not match`,
        outcome: "Create new finding",
        emphasis: "new",
      });
    }
  } else {
    scenarios.push({
      label: "Different unique key",
      outcome: "Create new finding",
      emphasis: "new",
    });
  }

  return scenarios;
}

function renderDedupSettingsEditor() {
  const settings = getDedupSettings();
  const activePreset = getDedupPresetName(settings);
  const description = describeDedupSettings(settings);
  const fallbackEnabled = settings.enabled && settings.use_title_test_fallback;
  const networkEnabled = fallbackEnabled && settings.require_network_match;
  const selectedNetworkFields = new Set(settings.network_match_fields || []);
  const flow = buildDedupFlow(settings);
  const scenarios = buildDedupScenarios(settings);

  els.dedupSettingsEditor.innerHTML = `
    <div class="editor-card dedup-shell">
      <div class="dedup-topline">
        <div>
          <span class="editor-card-title">Dedup Matching</span>
          <p class="dedup-kicker">Choose how the middleware decides whether an alert should reuse an existing finding or create a new one.</p>
        </div>
        <span class="pill">${escapeAttr(activePreset === "custom" ? "Custom policy" : `${activePreset} preset`)}</span>
      </div>

      <div class="preset-bar dedup-preset-bar">
        <button class="ghost preset-btn ${activePreset === "pair" ? "active" : ""}" type="button" data-dedup-preset="pair">Title + IP Pair</button>
        <button class="ghost preset-btn ${activePreset === "balanced" ? "active" : ""}" type="button" data-dedup-preset="balanced">Balanced</button>
        <button class="ghost preset-btn ${activePreset === "strict" ? "active" : ""}" type="button" data-dedup-preset="strict">Strict</button>
        <button class="ghost preset-btn ${activePreset === "loose" ? "active" : ""}" type="button" data-dedup-preset="loose">Loose</button>
        <button class="ghost preset-btn ${activePreset === "off" ? "active" : ""}" type="button" data-dedup-preset="off">Off</button>
      </div>

      <div class="dedup-summary dedup-summary-hero">
        <p class="dedup-summary-title">${escapeAttr(description.headline)}</p>
        <div class="pills">
          <span class="pill">${escapeAttr(settings.action_on_match === "skip" ? "Skip duplicate create" : "Allow create on match")}</span>
          <span class="pill">${escapeAttr(settings.ignore_mitigated ? "Ignore mitigated findings" : "Include mitigated findings")}</span>
        </div>
        <div class="dedup-summary-list">
          ${description.details.map((detail) => `<p>${escapeAttr(detail)}</p>`).join("")}
        </div>
      </div>

      <section class="dedup-visual-block">
        <div class="dedup-section-head">
          <h5>How Matching Works</h5>
          <p>Read this left to right like the middleware decision path.</p>
        </div>
        <div class="dedup-flow-grid">
          ${flow.map((item) => `
            <article class="dedup-flow-card dedup-flow-card-${escapeAttr(item.tone)}">
              <div class="dedup-flow-step">${escapeAttr(item.step)}</div>
              <div class="dedup-flow-copy">
                <h6>${escapeAttr(item.title)}</h6>
                <p>${escapeAttr(item.detail)}</p>
              </div>
            </article>
          `).join("")}
        </div>
      </section>

      <section class="dedup-visual-block">
        <div class="dedup-section-head">
          <h5>Quick Examples</h5>
          <p>These examples update from the settings below so you can see what the current policy actually means.</p>
        </div>
        <div class="dedup-scenario-list">
          ${scenarios.map((scenario) => `
            <article class="dedup-scenario dedup-scenario-${escapeAttr(scenario.emphasis)}">
              <div>
                <p class="dedup-scenario-label">${escapeAttr(scenario.label)}</p>
                <p class="dedup-scenario-outcome">${escapeAttr(scenario.outcome)}</p>
              </div>
            </article>
          `).join("")}
        </div>
      </section>

      <div class="dedup-sections">
        <section class="choice-card dedup-section">
          <div class="dedup-section-head">
            <h5>Core Behavior</h5>
            <p>Decide whether dedup is on and what happens when a match is found.</p>
          </div>
          <label class="toggle-row">
            <input class="dedup-enabled" type="checkbox" ${settings.enabled ? "checked" : ""} />
            <span>
              <strong>Enable dedup</strong>
              <small>Turn duplicate detection on or off for new alerts.</small>
            </span>
          </label>
          <label class="field">
            <span>When a duplicate is found</span>
            <select class="dedup-action-on-match">
              <option value="skip" ${settings.action_on_match === "skip" ? "selected" : ""}>Skip creating a new finding</option>
              <option value="create_new" ${settings.action_on_match === "create_new" ? "selected" : ""}>Still create a new finding</option>
            </select>
          </label>
          <label class="toggle-row">
            <input class="dedup-ignore-mitigated" type="checkbox" ${settings.ignore_mitigated ? "checked" : ""} ${!settings.enabled ? "disabled" : ""} />
            <span>
              <strong>Ignore mitigated findings</strong>
              <small>Only open findings count as duplicates.</small>
            </span>
          </label>
        </section>

        <section class="choice-card dedup-section">
          <div class="dedup-section-head">
            <h5>Primary Match Sources</h5>
            <p>Pick the main signals used to start duplicate matching.</p>
          </div>
          <label class="toggle-row">
            <input class="dedup-use-unique-id" type="checkbox" ${settings.use_unique_id ? "checked" : ""} ${!settings.enabled ? "disabled" : ""} />
            <span>
              <strong>Unique tool dedup key</strong>
              <small>Use the generated Wazuh dedup key first. Best when the same alert keeps repeating.</small>
            </span>
          </label>
          <label class="toggle-row">
            <input class="dedup-use-title-test-fallback" type="checkbox" ${settings.use_title_test_fallback ? "checked" : ""} ${!settings.enabled ? "disabled" : ""} />
            <span>
              <strong>Title and test fallback</strong>
              <small>If the unique key does not match, also compare findings with the same title in the same DefectDojo test.</small>
            </span>
          </label>
        </section>

        <section class="choice-card dedup-section ${fallbackEnabled ? "" : "muted-card"}">
          <div class="dedup-section-head">
            <h5>Context Guards</h5>
            <p>These narrow title/test fallback so different assets or weaknesses stay separate.</p>
          </div>
          <label class="toggle-row">
            <input class="dedup-require-same-endpoint" type="checkbox" ${settings.require_same_endpoint ? "checked" : ""} ${!fallbackEnabled ? "disabled" : ""} />
            <span>
              <strong>Require same endpoint</strong>
              <small>Only match if the finding is attached to the same host or endpoint.</small>
            </span>
          </label>
          <label class="toggle-row">
            <input class="dedup-require-same-cwe" type="checkbox" ${settings.require_same_cwe ? "checked" : ""} ${!fallbackEnabled ? "disabled" : ""} />
            <span>
              <strong>Require same CWE</strong>
              <small>Only match if the weakness classification is the same.</small>
            </span>
          </label>
        </section>

        <section class="choice-card dedup-section ${fallbackEnabled ? "" : "muted-card"}">
          <div class="dedup-section-head">
            <h5>Network Matching</h5>
            <p>Use IP identity when you want alerts to dedup by network pair, not just by title.</p>
          </div>
          <label class="toggle-row">
            <input class="dedup-require-network-match" type="checkbox" ${settings.require_network_match ? "checked" : ""} ${!fallbackEnabled ? "disabled" : ""} />
            <span>
              <strong>Require network field match</strong>
              <small>Use selected IP fields like source and destination when deciding whether two findings are duplicates.</small>
            </span>
          </label>
          <div class="dedup-network-controls ${networkEnabled ? "" : "muted-card"}">
            <label class="field">
              <span>Network field match mode</span>
              <select class="dedup-network-match-mode" ${!networkEnabled ? "disabled" : ""}>
                <option value="any" ${settings.network_match_mode === "any" ? "selected" : ""}>Any selected field can match</option>
                <option value="all" ${settings.network_match_mode === "all" ? "selected" : ""}>All selected fields must match</option>
              </select>
            </label>
            <div class="network-pill-grid">
              <label class="network-pill ${selectedNetworkFields.has("src_ip") ? "active" : ""}">
                <input class="dedup-network-field" type="checkbox" value="src_ip" ${selectedNetworkFields.has("src_ip") ? "checked" : ""} ${!networkEnabled ? "disabled" : ""} />
                <span>Source IP</span>
              </label>
              <label class="network-pill ${selectedNetworkFields.has("dst_ip") ? "active" : ""}">
                <input class="dedup-network-field" type="checkbox" value="dst_ip" ${selectedNetworkFields.has("dst_ip") ? "checked" : ""} ${!networkEnabled ? "disabled" : ""} />
                <span>Destination IP</span>
              </label>
              <label class="network-pill ${selectedNetworkFields.has("observed_ip") ? "active" : ""}">
                <input class="dedup-network-field" type="checkbox" value="observed_ip" ${selectedNetworkFields.has("observed_ip") ? "checked" : ""} ${!networkEnabled ? "disabled" : ""} />
                <span>Observed IP</span>
              </label>
            </div>
            <div class="helper">Example: choose <code>All selected fields must match</code> with <code>Source IP</code> and <code>Destination IP</code> to create a new finding when only one IP changes.</div>
          </div>
        </section>
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

function renderFindingGroupRuleEditors() {
  const rules = state.config?.finding_group_rules || [];

  if (!rules.length) {
    els.findingGroupRulesEditor.innerHTML = '<div class="helper">No finding group rules yet. Add one when you want low-severity bursts with many unique source IPs to appear in a DefectDojo finding group.</div>';
    return;
  }

  els.findingGroupRulesEditor.innerHTML = rules.map((rule, index) => `
    <div class="editor-card">
      <div class="editor-card-header">
        <span class="editor-card-title">Group Rule ${index + 1}</span>
        <button class="ghost remove-finding-group-rule-btn" type="button" data-index="${index}">Remove</button>
      </div>
      <div class="editor-grid">
        <label class="field">
          <span>Rule Name</span>
          <input class="finding-group-name" type="text" value="${escapeAttr(rule.name || "")}" placeholder="Low severity DNS burst" />
        </label>
        <label class="field">
          <span>Enabled</span>
          <select class="finding-group-enabled">
            <option value="true" ${rule.enabled !== false ? "selected" : ""}>True</option>
            <option value="false" ${rule.enabled === false ? "selected" : ""}>False</option>
          </select>
        </label>
        <label class="field">
          <span>Match Rule Groups</span>
          <input class="finding-group-match-groups" type="text" value="${escapeAttr(joinCommaList(rule.match_rule_groups || []))}" placeholder="fortigate, anomaly" />
        </label>
        <label class="field">
          <span>Severity Values</span>
          <input class="finding-group-severity-values" type="text" value="${escapeAttr(joinCommaList(rule.severity_values || []))}" placeholder="Low, Informational" />
        </label>
        <label class="field">
          <span>Unique Source IP Threshold</span>
          <input class="finding-group-unique-src-threshold" type="number" min="1" value="${escapeAttr(rule.unique_src_ip_threshold ?? 10)}" placeholder="10" />
        </label>
        <label class="field">
          <span>Window Minutes</span>
          <input class="finding-group-window-minutes" type="number" min="1" value="${escapeAttr(rule.window_minutes ?? 60)}" placeholder="60" />
        </label>
        <label class="field">
          <span>Require Same Title</span>
          <select class="finding-group-require-same-title">
            <option value="true" ${rule.require_same_title !== false ? "selected" : ""}>True</option>
            <option value="false" ${rule.require_same_title === false ? "selected" : ""}>False</option>
          </select>
        </label>
        <label class="field">
          <span>Require Same Destination IP</span>
          <select class="finding-group-require-same-dst-ip">
            <option value="true" ${rule.require_same_dst_ip !== false ? "selected" : ""}>True</option>
            <option value="false" ${rule.require_same_dst_ip === false ? "selected" : ""}>False</option>
          </select>
        </label>
      </div>
    </div>
  `).join("");
}

function collectDedupSettings() {
  const currentSettings = getDedupSettings();
  const enabled = !!els.dedupSettingsEditor.querySelector(".dedup-enabled")?.checked;
  const useTitleFallback = enabled && !!els.dedupSettingsEditor.querySelector(".dedup-use-title-test-fallback")?.checked;
  const selectedNetworkFields = Array.from(
    els.dedupSettingsEditor.querySelectorAll(".dedup-network-field:checked"),
  ).map((field) => field.value);
  const networkMatchRequested = useTitleFallback
    && !!els.dedupSettingsEditor.querySelector(".dedup-require-network-match")?.checked;
  const networkMatchFields = networkMatchRequested
    ? (selectedNetworkFields.length
        ? selectedNetworkFields
        : (currentSettings.network_match_fields?.length
            ? currentSettings.network_match_fields
            : ["src_ip", "dst_ip"]))
    : [];

  return {
    enabled,
    use_unique_id: enabled && !!els.dedupSettingsEditor.querySelector(".dedup-use-unique-id")?.checked,
    use_title_test_fallback: useTitleFallback,
    require_same_endpoint: useTitleFallback && !!els.dedupSettingsEditor.querySelector(".dedup-require-same-endpoint")?.checked,
    require_same_cwe: useTitleFallback && !!els.dedupSettingsEditor.querySelector(".dedup-require-same-cwe")?.checked,
    require_network_match: networkMatchRequested,
    network_match_mode: networkMatchRequested
      ? (els.dedupSettingsEditor.querySelector(".dedup-network-match-mode")?.value || "any")
      : "any",
    network_match_fields: networkMatchFields,
    ignore_mitigated: enabled && !!els.dedupSettingsEditor.querySelector(".dedup-ignore-mitigated")?.checked,
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

function collectFindingGroupRules() {
  return Array.from(els.findingGroupRulesEditor.querySelectorAll(".editor-card")).map((card) => ({
    name: card.querySelector(".finding-group-name")?.value.trim() || "",
    enabled: parseOptionalBool(card.querySelector(".finding-group-enabled")?.value) !== false,
    match_rule_groups: splitCommaList(card.querySelector(".finding-group-match-groups")?.value),
    severity_values: splitCommaList(card.querySelector(".finding-group-severity-values")?.value),
    unique_src_ip_threshold: parseOptionalInt(card.querySelector(".finding-group-unique-src-threshold")?.value) ?? 10,
    window_minutes: parseOptionalInt(card.querySelector(".finding-group-window-minutes")?.value) ?? 60,
    require_same_title: parseOptionalBool(card.querySelector(".finding-group-require-same-title")?.value) !== false,
    require_same_dst_ip: parseOptionalBool(card.querySelector(".finding-group-require-same-dst-ip")?.value) !== false,
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

function addFindingGroupRule() {
  state.config.finding_group_rules = state.config.finding_group_rules || [];
  state.config.finding_group_rules.push({
    name: "",
    enabled: true,
    match_rule_groups: [],
    severity_values: ["Low"],
    unique_src_ip_threshold: 10,
    window_minutes: 60,
    require_same_title: true,
    require_same_dst_ip: true,
  });
  renderFindingGroupRuleEditors();
}

function applyDedupPreset(presetName) {
  const preset = DEDUP_PRESETS[presetName];
  if (!preset) return;
  state.config.dedup_settings = { ...preset };
  renderDedupSettingsEditor();
}

function handleEditorClick(event) {
  const presetButton = event.target.closest("[data-dedup-preset]");
  if (presetButton) {
    applyDedupPreset(presetButton.dataset.dedupPreset);
    return;
  }

  const removeFindingStatusRule = event.target.closest(".remove-finding-status-rule-btn");
  if (removeFindingStatusRule) {
    state.config.finding_status_rules.splice(Number(removeFindingStatusRule.dataset.index), 1);
    renderFindingStatusRuleEditors();
    return;
  }

  const removeFindingGroupRule = event.target.closest(".remove-finding-group-rule-btn");
  if (removeFindingGroupRule) {
    state.config.finding_group_rules.splice(Number(removeFindingGroupRule.dataset.index), 1);
    renderFindingGroupRuleEditors();
  }
}

function handleDedupChange(event) {
  if (!event.target.closest(".dedup-shell")) {
    return;
  }
  state.config.dedup_settings = collectDedupSettings();
  renderDedupSettingsEditor();
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
    renderFindingGroupRuleEditors();
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
      finding_group_rules: collectFindingGroupRules(),
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
els.addFindingGroupRuleBtn.addEventListener("click", addFindingGroupRule);
els.dedupSettingsEditor.addEventListener("click", handleEditorClick);
els.dedupSettingsEditor.addEventListener("change", handleDedupChange);
els.findingStatusRulesEditor.addEventListener("click", handleEditorClick);
els.findingGroupRulesEditor.addEventListener("click", handleEditorClick);

loadAll();
