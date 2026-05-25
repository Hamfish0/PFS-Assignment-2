/* nu-tracker frontend logic. */

const API = "";
const state = {
  token: localStorage.getItem("nutracker_token") || null,
  user: JSON.parse(localStorage.getItem("nutracker_user") || "null"),
  suppliers: [],
  locations: [],
};

// ---------- helpers ----------
const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

function escapeHtml(value) {
  if (value === null || value === undefined) return "";
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
const h = escapeHtml;

async function api(path, opts = {}) {
  const headers = { "Content-Type": "application/json", ...(opts.headers || {}) };
  if (state.token) headers["Authorization"] = "Bearer " + state.token;
  const res = await fetch(API + path, { ...opts, headers });
  const text = await res.text();
  let data; try { data = JSON.parse(text); } catch { data = { error: text }; }
  if (!res.ok) throw Object.assign(new Error(data.error || res.statusText), { data, status: res.status });
  return data;
}

function setView(viewId) {
  ["login-view", "app-view"].forEach((id) => $("#" + id).classList.add("hidden"));
  $("#" + viewId).classList.remove("hidden");
}

function showTab(tab) {
  $$(".nav-btn").forEach((b) => b.classList.toggle("active", b.dataset.tab === tab));
  $$(".tab").forEach((t) => t.classList.add("hidden"));
  $("#tab-" + tab).classList.remove("hidden");
  if (tab === "inventory") loadInventory();
  if (tab === "locations") loadLocations();
  if (tab === "suppliers") loadSuppliers();
  if (tab === "users") loadUsers();
  if (tab === "audit") loadAudit();
}

function qtyBadge(q) {
  const cls = q === 0 ? "zero" : q < 5 ? "low" : "";
  // q is numeric here, but escape defensively in case the server ever sends a string.
  return `<span class="qty-badge ${cls}">${h(q)}</span>`;
}

// ---------- auth ----------
async function login(ev) {
  ev.preventDefault();
  $("#login-error").textContent = "";
  try {
    const data = await api("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({
        username: $("#login-username").value,
        password: $("#login-password").value,
      }),
    });
    state.token = data.token;
    state.user = data.user;
    localStorage.setItem("nutracker_token", data.token);
    localStorage.setItem("nutracker_user", JSON.stringify(data.user));
    enterApp();
  } catch (e) {
    $("#login-error").textContent = e.message || "Login failed";
  }
}

function logout() {
  state.token = null;
  state.user = null;
  localStorage.removeItem("nutracker_token");
  localStorage.removeItem("nutracker_user");
  setView("login-view");
}

async function enterApp() {
  setView("app-view");
  $("#current-user").textContent = state.user ? `${state.user.username} (${state.user.role})` : "-";
  try {
    [state.suppliers, state.locations] = await Promise.all([
      api("/api/suppliers"),
      api("/api/locations"),
    ]);
  } catch (e) { console.warn("Reference data load failed", e); }
  showTab("inventory");
}

// ---------- inventory ----------
async function loadInventory() {
  const items = await api("/api/inventory");
  renderInventory(items);
}

function renderInventory(items) {
  const body = $("#inventory-body");
  body.innerHTML = items.map((i) => `
    <tr>
      <td>${h(i.id)}</td>
      <td>${h(i.name)}</td>
      <td>${h(i.description || "")}</td>
      <td>${qtyBadge(i.quantity)}</td>
      <td>${h(i.location || "")}</td>
      <td><code>${h(i.rfid_tag || "")}</code></td>
      <td>${h((i.last_updated || "").slice(0, 19).replace("T", " "))}</td>
      <td>
        <button class="row-action" data-view="${h(i.id)}">view</button>
        <button class="row-action" data-edit="${h(i.id)}">edit</button>
        <button class="row-action danger" data-delete="${h(i.id)}">delete</button>
      </td>
    </tr>
  `).join("");

  body.querySelectorAll("[data-view]").forEach((b) =>
    b.addEventListener("click", () => openDetail(b.dataset.view)));
  body.querySelectorAll("[data-edit]").forEach((b) =>
    b.addEventListener("click", () => openItemForm(b.dataset.edit)));
  body.querySelectorAll("[data-delete]").forEach((b) =>
    b.addEventListener("click", () => deleteItem(b.dataset.delete)));
}

async function doSearch() {
  const q = $("#search-input").value;
  const items = await api("/api/inventory/search?q=" + encodeURIComponent(q));
  renderInventory(items);
}

async function deleteItem(id) {
  if (!confirm("Delete item #" + id + "?")) return;
  await api("/api/inventory/" + id, { method: "DELETE" });
  loadInventory();
}

async function openDetail(id) {
  const { item, history } = await api("/api/inventory/" + id);
  $("#detail-title").textContent = item.name || "";
  $("#detail-body").innerHTML = `
    <dl>
      <dt>ID</dt><dd><code>${h(item.id)}</code></dd>
      <dt>RFID</dt><dd><code>${h(item.rfid_tag || "")}</code></dd>
      <dt>Description</dt><dd>${h(item.description || "")}</dd>
      <dt>Quantity</dt><dd>${qtyBadge(item.quantity)}</dd>
      <dt>Location</dt><dd>${h(item.location || "")}</dd>
      <dt>Supplier</dt><dd>${h(item.supplier_name || "-")}</dd>
      <dt>Updated</dt><dd>${h((item.last_updated || "").slice(0, 19).replace("T", " "))} by ${h(item.updated_by || "-")}</dd>
    </dl>
  `;
  $("#detail-history").innerHTML = history.map((hh) =>
    `<li>[${h((hh.timestamp || "").slice(0,19).replace("T"," "))}] ${h(hh.action)} - ${h(hh.details || "")}</li>`
  ).join("") || "<li>(no history)</li>";
  $("#detail-modal").classList.remove("hidden");
}

function openItemForm(id) {
  const supSelect = $("#item-supplier");
  supSelect.innerHTML = '<option value="">(none)</option>' +
    state.suppliers.map((s) => `<option value="${h(s.id)}">${h(s.name)}</option>`).join("");
  const locSelect = $("#item-location");
  locSelect.innerHTML = '<option value="">(none)</option>' +
    state.locations.map((l) => `<option value="${h(l.name)}">${h(l.name)}</option>`).join("");

  if (id) {
    $("#form-title").textContent = "Edit Item #" + id;
    api("/api/inventory/" + id).then(({ item }) => {
      $("#item-id").value = item.id;
      $("#item-name").value = item.name || "";
      $("#item-description").value = item.description || "";
      $("#item-quantity").value = item.quantity || 0;
      $("#item-location").value = item.location || "";
      $("#item-supplier").value = item.supplier_id || "";
      $("#item-rfid").value = item.rfid_tag || "";
    });
  } else {
    $("#form-title").textContent = "Add Item";
    $("#item-form").reset();
    $("#item-id").value = "";
  }
  $("#form-modal").classList.remove("hidden");
}

async function submitItem(ev) {
  ev.preventDefault();
  const id = $("#item-id").value;
  const body = {
    name: $("#item-name").value,
    description: $("#item-description").value,
    quantity: parseInt($("#item-quantity").value, 10) || 0,
    location: $("#item-location").value,
    supplier_id: $("#item-supplier").value ? parseInt($("#item-supplier").value, 10) : null,
    rfid_tag: $("#item-rfid").value,
  };
  if (id) {
    await api("/api/inventory/" + id, { method: "PUT", body: JSON.stringify(body) });
  } else {
    await api("/api/inventory", { method: "POST", body: JSON.stringify(body) });
  }
  $("#form-modal").classList.add("hidden");
  loadInventory();
}

// ---------- locations ----------
async function loadLocations() {
  const locs = await api("/api/locations");
  state.locations = locs;
  $("#locations-map").innerHTML = locs.map((l) => `
    <div class="loc-card">
      <h3>${h(l.name)}</h3>
      <div class="loc-meta">${h(l.building || "")} &middot; floor ${h(l.floor || "-")} &middot; ${h(l.description || "")}</div>
      <ul>
        ${(l.items || []).map((i) =>
          `<li>${h(i.name)} ${qtyBadge(i.quantity)} <code>${h(i.rfid_tag || "")}</code></li>`
        ).join("") || "<li>(empty)</li>"}
      </ul>
    </div>
  `).join("");
}

// ---------- suppliers ----------
async function loadSuppliers() {
  const sups = await api("/api/suppliers");
  state.suppliers = sups;
  $("#suppliers-body").innerHTML = sups.map((s) => `
    <tr>
      <td>${h(s.id)}</td><td>${h(s.name)}</td><td>${h(s.contact_email || "")}</td>
      <td>${h(s.contact_phone || "")}</td><td>${h(s.address || "")}</td>
    </tr>
  `).join("");
}

// ---------- users ----------
async function loadUsers() {
  const isAdmin = state.user && state.user.role === "admin";
  $("#new-user-btn").classList.toggle("hidden", !isAdmin);

  let users;
  try {
    users = await api("/api/auth/users");
  } catch (e) {
    $("#users-body").innerHTML = `<tr><td colspan="4">${h(e.message || "Forbidden")}</td></tr>`;
    return;
  }
  $("#users-body").innerHTML = users.map((u) => `
    <tr>
      <td>${h(u.id)}</td><td>${h(u.username)}</td>
      <td>${h(u.role)}</td>
      <td>${h((u.created_at || "").slice(0,19).replace("T"," "))}</td>
    </tr>
  `).join("");
}

function openCreateAccount() {
  $("#user-form").reset();
  $("#user-form-error").textContent = "";
  $("#user-modal").classList.remove("hidden");
}

async function submitCreateAccount(ev) {
  ev.preventDefault();
  $("#user-form-error").textContent = "";
  try {
    await api("/api/auth/register", {
      method: "POST",
      body: JSON.stringify({
        username: $("#new-username").value,
        password: $("#new-password").value,
        role: $("#new-role").value,
      }),
    });
    $("#user-modal").classList.add("hidden");
    loadUsers();
  } catch (e) {
    $("#user-form-error").textContent = e.message || "Could not create account";
  }
}

// ---------- audit ----------
async function loadAudit() {
  let rows;
  try {
    rows = await api("/api/audit");
  } catch (e) {
    $("#audit-body").innerHTML = `<tr><td colspan="6">${h(e.message || "Forbidden")}</td></tr>`;
    return;
  }
  $("#audit-body").innerHTML = rows.map((r) => `
    <tr>
      <td>${h(r.id)}</td><td>${h(r.action)}</td><td>${h(r.item_id ?? "")}</td>
      <td>${h(r.user_id ?? "")}</td>
      <td>${h((r.timestamp || "").slice(0,19).replace("T"," "))}</td>
      <td>${h(r.details || "")}</td>
    </tr>
  `).join("");
}

// ---------- wiring ----------
document.addEventListener("DOMContentLoaded", () => {
  $("#login-form").addEventListener("submit", login);
  $("#logout-btn").addEventListener("click", logout);
  $("#new-user-btn").addEventListener("click", openCreateAccount);
  $("#user-form").addEventListener("submit", submitCreateAccount);

  $$(".nav-btn").forEach((b) =>
    b.addEventListener("click", () => showTab(b.dataset.tab)));

  $("#search-btn").addEventListener("click", doSearch);
  $("#search-input").addEventListener("keydown", (e) => { if (e.key === "Enter") doSearch(); });
  $("#refresh-btn").addEventListener("click", loadInventory);
  $("#new-item-btn").addEventListener("click", () => openItemForm(null));
  $("#item-form").addEventListener("submit", submitItem);

  document.addEventListener("click", (e) => {
    if (e.target.matches("[data-close]") || e.target.classList.contains("modal")) {
      $$(".modal").forEach((m) => m.classList.add("hidden"));
    }
  });

  if (state.token) enterApp(); else setView("login-view");
});
