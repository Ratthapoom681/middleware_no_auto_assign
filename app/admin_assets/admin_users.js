const state = { options: null };

const els = {
  status: document.getElementById("status"),
  reloadBtn: document.getElementById("reloadBtn"),
  userForm: document.getElementById("userForm"),
  inventory: document.getElementById("inventory"),
};

function setStatus(message, isError = false) {
  els.status.textContent = message;
  els.status.className = isError ? "status error" : "status";
}

function renderPills(items, labelKey = "username") {
  if (!items?.length) return '<span class="pill">None</span>';
  return items.map((item) => {
    const label = item[labelKey] || item.name || item.id;
    return `<span class="pill">${label}</span>`;
  }).join("");
}

function renderInventory(options) {
  els.inventory.innerHTML = `
    <section class="inventory-group">
      <h3>Users</h3>
      <div class="pills">${renderPills(options.users || [])}</div>
    </section>
  `;
}

async function fetchJson(url, options = {}) {
  const res = await fetch(url, options);
  const data = await res.json();
  if (!res.ok) throw new Error(data.detail || JSON.stringify(data));
  return data;
}

async function loadUsers() {
  setStatus("Loading...");
  try {
    state.options = await fetchJson("/admin/api/dojo-options");
    renderInventory(state.options);
    setStatus("Users loaded.");
  } catch (error) {
    setStatus(`Failed to load users: ${error}`, true);
  }
}

async function createUser(event) {
  event.preventDefault();
  const formData = Object.fromEntries(new FormData(els.userForm).entries());
  if (formData.password !== formData.confirm_password) {
    setStatus("Create user failed: passwords do not match.", true);
    return;
  }
  delete formData.confirm_password;
  try {
    setStatus("Creating user...");
    await fetchJson("/admin/api/dojo/user", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(formData),
    });
    els.userForm.reset();
    setStatus("User created.");
    await loadUsers();
  } catch (error) {
    setStatus(`Create user failed: ${error}`, true);
  }
}

els.reloadBtn.addEventListener("click", loadUsers);
els.userForm.addEventListener("submit", createUser);

loadUsers();
