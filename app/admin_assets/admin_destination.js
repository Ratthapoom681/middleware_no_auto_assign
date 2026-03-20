const state = { config: null, options: null, selectedTestId: null };

const els = {
  status: document.getElementById("status"),
  saveBtn: document.getElementById("saveBtn"),
  reloadBtn: document.getElementById("reloadBtn"),
  productTypeSelect: document.getElementById("productTypeSelect"),
  productTypeDescription: document.getElementById("productTypeDescription"),
  productSelect: document.getElementById("productSelect"),
  productDescription: document.getElementById("productDescription"),
  engagementSelect: document.getElementById("engagementSelect"),
  engagementStatus: document.getElementById("engagementStatus"),
  engagementStart: document.getElementById("engagementStart"),
  engagementEnd: document.getElementById("engagementEnd"),
  testTitlePrefix: document.getElementById("testTitlePrefix"),
  testTypeId: document.getElementById("testTypeId"),
  threatHuntingTest: document.getElementById("threatHuntingTest"),
  vulnerabilityTest: document.getElementById("vulnerabilityTest"),
  defaultTest: document.getElementById("defaultTest"),
  inventory: document.getElementById("inventory"),
  testDetailCard: document.getElementById("testDetailCard"),
  testDetailTitle: document.getElementById("testDetailTitle"),
  testDetailSubtitle: document.getElementById("testDetailSubtitle"),
  testDetailGrid: document.getElementById("testDetailGrid"),
};

function setStatus(message, isError = false) {
  els.status.textContent = message;
  els.status.className = isError ? "status error" : "status";
}

function populateSelect(select, items, currentValue, labelKey = "name") {
  select.innerHTML = "";
  const values = new Set();
  for (const item of items) {
    const value = item[labelKey] || item.name || item.username || item.id;
    if (value == null || values.has(String(value))) continue;
    values.add(String(value));
    const option = document.createElement("option");
    option.value = String(value);
    option.textContent = String(value);
    if (String(value) === String(currentValue)) option.selected = true;
    select.appendChild(option);
  }
}

function renderPills(items, labelKey = "name") {
  if (!items?.length) return '<span class="pill">None</span>';
  return items.map((item) => {
    const label = item[labelKey] || item.name || item.username || item.id;
    return `<span class="pill">${label}</span>`;
  }).join("");
}

function escapeAttr(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/"/g, "&quot;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function findTestById(testId) {
  return (state.options?.tests || []).find((test) => String(test.id) === String(testId)) || null;
}

function getTestLabel(test) {
  return test?.title || test?.name || `Test ${test?.id ?? ""}`.trim();
}

function getEngagementName(engagementId) {
  const engagement = (state.options?.engagements || []).find((item) => String(item.id) === String(engagementId));
  return engagement?.name || String(engagementId || "Unknown");
}

function renderTestDetail() {
  const tests = state.options?.tests || [];
  if (!tests.length) {
    els.testDetailCard.hidden = true;
    return;
  }

  const selected = findTestById(state.selectedTestId) || tests[0];
  state.selectedTestId = selected.id;

  const fields = [
    ["Test ID", selected.id],
    ["Title", getTestLabel(selected)],
    ["Engagement", getEngagementName(selected.engagement)],
    ["Test Type", selected.test_type],
    ["Target Start", selected.target_start || "Not set"],
    ["Target End", selected.target_end || "Not set"],
    ["Environment", selected.environment || "Not set"],
    ["Branch Tag", selected.branch_tag || "Not set"],
  ].filter(([, value]) => value !== undefined && value !== null && value !== "");

  els.testDetailTitle.textContent = getTestLabel(selected);
  els.testDetailSubtitle.textContent = `Inspecting test ID ${selected.id} linked to engagement ${getEngagementName(selected.engagement)}.`;
  els.testDetailGrid.innerHTML = fields.map(([label, value]) => `
    <div class="detail-item">
      <span class="detail-label">${label}</span>
      <span class="detail-value">${escapeAttr(value)}</span>
    </div>
  `).join("");
  els.testDetailCard.hidden = false;
}

function renderTestInventory(tests) {
  if (!tests?.length) {
    return `
      <section class="inventory-group">
        <h3>Tests</h3>
        <div class="pills"><span class="pill">None</span></div>
      </section>
    `;
  }

  const selectedId = String(state.selectedTestId ?? tests[0].id);
  return `
    <section class="inventory-group inventory-group-tests">
      <div class="inventory-group-head">
        <h3>Tests</h3>
        <p class="helper">Click a test name to view its details.</p>
      </div>
      <div class="test-list">
        ${tests.map((test) => `
          <button
            class="test-chip ${String(test.id) === selectedId ? "active" : ""}"
            type="button"
            data-test-id="${escapeAttr(test.id)}"
          >
            ${escapeAttr(getTestLabel(test))}
          </button>
        `).join("")}
      </div>
    </section>
  `;
}

function renderInventory(options) {
  els.inventory.innerHTML = [
    ["Product Types", options.product_types],
    ["Products", options.products],
    ["Engagements", options.engagements],
    ["Users", options.users, "username"],
  ].map(([title, items, labelKey]) => `
    <section class="inventory-group">
      <h3>${title}</h3>
      <div class="pills">${renderPills(items, labelKey)}</div>
    </section>
  `).join("") + renderTestInventory(options.tests || []);

  renderTestDetail();
}

function syncSelectedObjectDetails() {
  const productType = state.options.product_types?.find((item) => item.name === els.productTypeSelect.value);
  const product = state.options.products?.find((item) => item.name === els.productSelect.value);
  const engagement = state.options.engagements?.find((item) => item.name === els.engagementSelect.value);

  if (productType) els.productTypeDescription.value = productType.description || "";
  if (product) els.productDescription.value = product.description || "";
  if (engagement) {
    els.engagementStatus.value = engagement.status || "";
    els.engagementStart.value = engagement.target_start || "";
    els.engagementEnd.value = engagement.target_end || "";
  }
}

function applyConfig() {
  const cfg = state.config;
  populateSelect(els.productTypeSelect, state.options.product_types || [], cfg.defectdojo.product_type.name);
  populateSelect(els.productSelect, state.options.products || [], cfg.defectdojo.product.name);
  populateSelect(els.engagementSelect, state.options.engagements || [], cfg.defectdojo.engagement.name);

  els.productTypeDescription.value = cfg.defectdojo.product_type.description || "";
  els.productDescription.value = cfg.defectdojo.product.description || "";
  els.engagementStatus.value = cfg.defectdojo.engagement.status || "";
  els.engagementStart.value = cfg.defectdojo.engagement.target_start || "";
  els.engagementEnd.value = cfg.defectdojo.engagement.target_end || "";
  els.testTitlePrefix.value = cfg.defectdojo.test.title_prefix || "";
  els.testTypeId.value = cfg.defectdojo.test.test_type_id || 1;
  els.threatHuntingTest.value = cfg.categories.tag_to_test?.["threat-hunting"] || "Threat Hunting";
  els.vulnerabilityTest.value = cfg.categories.tag_to_test?.["vulnerability-detector"] || "Vulnerability Detector";
  els.defaultTest.value = cfg.categories.default_test || "General Monitoring";
  renderInventory(state.options);
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
    if (!findTestById(state.selectedTestId) && options.tests?.length) {
      state.selectedTestId = options.tests[0].id;
    }
    applyConfig();
    syncSelectedObjectDetails();
    setStatus("Destination config loaded.");
  } catch (error) {
    setStatus(`Failed to load admin data: ${error}`, true);
  }
}

async function saveConfig() {
  setStatus("Saving...");
  try {
    const payload = {
      ...state.config,
      defectdojo: {
        product_type: {
          name: els.productTypeSelect.value,
          description: els.productTypeDescription.value,
        },
        product: {
          name: els.productSelect.value,
          description: els.productDescription.value,
        },
        engagement: {
          name: els.engagementSelect.value,
          status: els.engagementStatus.value,
          target_start: els.engagementStart.value,
          target_end: els.engagementEnd.value,
        },
        test: {
          title_prefix: els.testTitlePrefix.value,
          test_type_id: Number(els.testTypeId.value),
          target_start: els.engagementStart.value,
          target_end: els.engagementEnd.value,
        },
      },
      categories: {
        tag_to_test: {
          "threat-hunting": els.threatHuntingTest.value,
          "vulnerability-detector": els.vulnerabilityTest.value,
        },
        default_test: els.defaultTest.value,
      },
    };
    await fetchJson("/admin/api/config", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    setStatus("Destination config saved.");
    await loadAll();
  } catch (error) {
    setStatus(`Save failed: ${error}`, true);
  }
}

els.reloadBtn.addEventListener("click", loadAll);
els.saveBtn.addEventListener("click", saveConfig);
els.productTypeSelect.addEventListener("change", syncSelectedObjectDetails);
els.productSelect.addEventListener("change", syncSelectedObjectDetails);
els.engagementSelect.addEventListener("change", syncSelectedObjectDetails);
els.inventory.addEventListener("click", (event) => {
  const button = event.target.closest(".test-chip");
  if (!button) return;
  state.selectedTestId = button.dataset.testId;
  renderInventory(state.options);
});

loadAll();
