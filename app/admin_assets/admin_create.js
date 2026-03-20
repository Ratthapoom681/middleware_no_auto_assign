const state = {
  config: null,
  wizard: {
    step: 0,
    data: {},
  },
};

const els = {
  status: document.getElementById("status"),
  reloadBtn: document.getElementById("reloadBtn"),
  wizardForm: document.getElementById("wizardForm"),
  wizardTitle: document.getElementById("wizardTitle"),
  wizardFields: document.getElementById("wizardFields"),
  wizardBack: document.getElementById("wizardBack"),
  wizardNext: document.getElementById("wizardNext"),
  wizardFinish: document.getElementById("wizardFinish"),
  wizardSteps: Array.from(document.querySelectorAll(".wizard-step")),
};

const wizardSchemas = [
  {
    key: "product-type",
    title: "Step 1: Product Type",
    nextLabel: "Next: Product",
    fields: [
      { name: "name", label: "Product Type Name", placeholder: "Wazuh", required: true },
      { name: "description", label: "Product Type Description", placeholder: "Security Operations" },
    ],
  },
  {
    key: "product",
    title: "Step 2: Product",
    nextLabel: "Next: Engagement",
    fields: [
      { name: "name", label: "Product Name", placeholder: "Wazuh Endpoint Security", required: true },
      { name: "description", label: "Product Description", placeholder: "Continuous endpoint monitoring", required: true },
    ],
  },
  {
    key: "engagement",
    title: "Step 3: Engagement",
    nextLabel: "Next: Test",
    fields: [
      { name: "name", label: "Engagement Name", placeholder: "Continuous Monitoring", required: true },
      { name: "status", label: "Engagement Status", placeholder: "In Progress", required: true },
      { name: "target_start", label: "Target Start", placeholder: "2026-03-19", required: true },
      { name: "target_end", label: "Target End", placeholder: "2027-03-19", required: true },
    ],
  },
  {
    key: "test",
    title: "Step 4: Test",
    finishLabel: "Create Path",
    fields: [
      { name: "title", label: "Test Title", placeholder: "Wazuh Alerts - Threat Hunting", required: true },
      { name: "test_type", label: "Test Type ID", type: "number", placeholder: "1", required: true },
      { name: "target_start", label: "Test Start", placeholder: "2026-03-19T00:00:00Z", required: true },
      { name: "target_end", label: "Test End", placeholder: "2027-03-19T00:00:00Z", required: true },
    ],
  },
];

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

async function fetchJson(url, options = {}) {
  const res = await fetch(url, options);
  const data = await res.json();
  if (!res.ok) throw new Error(data.detail || JSON.stringify(data));
  return data;
}

function wizardDefaults() {
  return {
    "product-type": {
      name: state.config?.defectdojo?.product_type?.name || "",
      description: state.config?.defectdojo?.product_type?.description || "",
    },
    product: {
      name: state.config?.defectdojo?.product?.name || "",
      description: state.config?.defectdojo?.product?.description || "",
    },
    engagement: {
      name: state.config?.defectdojo?.engagement?.name || "",
      status: state.config?.defectdojo?.engagement?.status || "In Progress",
      target_start: state.config?.defectdojo?.engagement?.target_start || "",
      target_end: state.config?.defectdojo?.engagement?.target_end || "",
    },
    test: {
      title: `${state.config?.defectdojo?.test?.title_prefix || "Wazuh Alerts"} - ${state.config?.categories?.tag_to_test?.["threat-hunting"] || "Threat Hunting"}`,
      test_type: String(state.config?.defectdojo?.test?.test_type_id || 1),
      target_start: state.config?.defectdojo?.test?.target_start || "",
      target_end: state.config?.defectdojo?.test?.target_end || "",
    },
  };
}

function resetWizard() {
  state.wizard.step = 0;
  state.wizard.data = wizardDefaults();
  renderWizard();
}

function renderWizard() {
  const schema = wizardSchemas[state.wizard.step];
  const stepData = state.wizard.data[schema.key] || {};

  els.wizardTitle.textContent = schema.title;
  els.wizardFields.innerHTML = schema.fields.map((field) => {
    const type = field.type || "text";
    const required = field.required ? "required" : "";
    const value = stepData[field.name] ?? "";
    return `
      <label class="field">
        <span>${field.label}</span>
        <input name="${field.name}" type="${type}" placeholder="${escapeAttr(field.placeholder || "")}" value="${escapeAttr(value)}" ${required} />
      </label>
    `;
  }).join("");

  els.wizardSteps.forEach((stepEl, index) => {
    stepEl.classList.toggle("active", index === state.wizard.step);
    stepEl.classList.toggle("complete", index < state.wizard.step);
  });

  els.wizardBack.hidden = state.wizard.step === 0;
  els.wizardNext.hidden = state.wizard.step === wizardSchemas.length - 1;
  els.wizardFinish.hidden = state.wizard.step !== wizardSchemas.length - 1;
  els.wizardNext.textContent = schema.nextLabel || "Next";
  els.wizardFinish.textContent = schema.finishLabel || "Create Path";
}

function persistWizardStep() {
  const inputs = Array.from(els.wizardFields.querySelectorAll("input"));
  const invalid = inputs.find((input) => !input.checkValidity());
  if (invalid) {
    invalid.reportValidity();
    return false;
  }
  const schema = wizardSchemas[state.wizard.step];
  state.wizard.data[schema.key] = Object.fromEntries(new FormData(els.wizardForm).entries());
  return true;
}

function normalizeObjectPayload(objectType, payload) {
  const normalized = {};
  for (const [key, value] of Object.entries(payload)) {
    if (value === "") continue;
    if (["prod_type", "product", "engagement", "test_type"].includes(key)) {
      normalized[key] = Number(value);
    } else {
      normalized[key] = value;
    }
  }
  if (objectType === "product-type") delete normalized.prod_type;
  return normalized;
}

function moveWizard(direction) {
  if (!persistWizardStep()) return;
  const nextStep = state.wizard.step + direction;
  if (nextStep < 0 || nextStep >= wizardSchemas.length) return;
  state.wizard.step = nextStep;
  renderWizard();
}

async function loadConfig() {
  setStatus("Loading...");
  try {
    state.config = await fetchJson("/admin/api/config");
    resetWizard();
    setStatus("Create path wizard ready.");
  } catch (error) {
    setStatus(`Failed to load config: ${error}`, true);
  }
}

async function createWizardPath(event) {
  event.preventDefault();
  if (!persistWizardStep()) return;

  const wizardData = state.wizard.data;
  const productTypePayload = normalizeObjectPayload("product-type", wizardData["product-type"] || {});
  const productPayload = normalizeObjectPayload("product", wizardData.product || {});
  const engagementPayload = normalizeObjectPayload("engagement", wizardData.engagement || {});
  const testPayload = normalizeObjectPayload("test", wizardData.test || {});

  try {
    setStatus("Creating Product Type -> Product -> Engagement -> Test...");
    const productType = await fetchJson("/admin/api/dojo/product-type", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(productTypePayload),
    });
    const product = await fetchJson("/admin/api/dojo/product", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ...productPayload, prod_type: productType.id }),
    });
    const engagement = await fetchJson("/admin/api/dojo/engagement", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ...engagementPayload, product: product.id }),
    });
    await fetchJson("/admin/api/dojo/test", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ...testPayload, engagement: engagement.id }),
    });

    setStatus("Path created. Open Destination Path if you want to route alerts to it.");
    await loadConfig();
  } catch (error) {
    setStatus(`Create path failed: ${error}`, true);
  }
}

els.wizardForm.addEventListener("submit", createWizardPath);
els.wizardBack.addEventListener("click", () => moveWizard(-1));
els.wizardNext.addEventListener("click", () => moveWizard(1));
els.reloadBtn.addEventListener("click", loadConfig);

loadConfig();
