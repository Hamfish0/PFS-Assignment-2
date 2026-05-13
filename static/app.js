/*
 * nu-tracker frontend logic.
 *
 * NOTE: This frontend contains deliberate vulnerabilities to pair with the
 * backend's documented flaws. In particular:
 *   - VULN-V6: stored fields are rendered via .innerHTML so XSS payloads in
 *     item names/descriptions/locations execute on display.
 *   - VULN-V7: the JWT is rendered into the navbar in plaintext and stored
 *     in localStorage where it is readable by any same-origin script.
 */

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
  ["login-view", "register-view", "app-view"].forEach((id) => $("#" + id).classList.add("hidden"));
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
  return `<span class="qty-badge ${cls}">${q}</span>`;
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

async function register(ev) {
  ev.preventDefault();
  $("#register-error").textContent = "";
  try {
    const data = await api("/api/auth/register", {
      method: "POST",
      body: JSON.stringify({
        username: $("#reg-username").value,
        password: $("#reg-password").value,
        role: $("#reg-role").value,
      }),
    });
    state.token = data.token;
    state.user = data.user;
    localStorage.setItem("nutracker_token", data.token);
    localStorage.setItem("nutracker_user", JSON.stringify(data.user));
    enterApp();
  } catch (e) {
    $("#register-error").textContent = e.message || "Registration failed";
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
  // VULN-V7: render the raw JWT into the DOM so any onlooker / screenshot leaks it.
  $("#current-token").textContent = state.token || "-";
  // Preload reference data used by the item form.
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
  // VULN-V6: No Input Validation / XSS - using innerHTML on stored fields
  // means any <script>, <img onerror=...>, etc. in name/description/location
  // executes here.
  body.innerHTML = items.map((i) => `
    <tr>
      <td>${i.id}</td>
      <td>${i.name}</td>
      <td>${i.description || ""}</td>
      <td>${qtyBadge(i.quantity)}</td>
      <td>${i.location || ""}</td>
      <td><code>${i.rfid_tag || ""}</code></td>
      <td>${(i.last_updated || "").slice(0, 19).replace("T", " ")}</td>
      <td>
        <button class="row-action" data-view="${i.id}">view</button>
        <button class="row-action" data-edit="${i.id}">edit</button>
        <button class="row-action danger" data-delete="${i.id}">delete</button>
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
  $("#detail-title").innerHTML = item.name; // VULN-V6: innerHTML
  $("#detail-body").innerHTML = `
    <dl>
      <dt>ID</dt><dd><code>${item.id}</code></dd>
      <dt>RFID</dt><dd><code>${item.rfid_tag || ""}</code></dd>
      <dt>Description</dt><dd>${item.description || ""}</dd>
      <dt>Quantity</dt><dd>${qtyBadge(item.quantity)}</dd>
      <dt>Location</dt><dd>${item.location || ""}</dd>
      <dt>Supplier</dt><dd>${item.supplier_name || "-"}</dd>
      <dt>Updated</dt><dd>${(item.last_updated || "").slice(0, 19).replace("T", " ")} by ${item.updated_by || "-"}</dd>
    </dl>
  `;
  $("#detail-history").innerHTML = history.map((h) =>
    `<li>[${(h.timestamp || "").slice(0,19).replace("T"," ")}] ${h.action} - ${h.details || ""}</li>`
  ).join("") || "<li>(no history)</li>";
  $("#detail-modal").classList.remove("hidden");
}

function openItemForm(id) {
  const supSelect = $("#item-supplier");
  supSelect.innerHTML = '<option value="">(none)</option>' +
    state.suppliers.map((s) => `<option value="${s.id}">${s.name}</option>`).join("");
  const locSelect = $("#item-location");
  locSelect.innerHTML = '<option value="">(none)</option>' +
    state.locations.map((l) => `<option value="${l.name}">${l.name}</option>`).join("");

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
      <h3>${l.name}</h3>
      <div class="loc-meta">${l.building || ""} &middot; floor ${l.floor || "-"} &middot; ${l.description || ""}</div>
      <ul>
        ${(l.items || []).map((i) =>
          `<li>${i.name} ${qtyBadge(i.quantity)} <code>${i.rfid_tag || ""}</code></li>`
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
      <td>${s.id}</td><td>${s.name}</td><td>${s.contact_email || ""}</td>
      <td>${s.contact_phone || ""}</td><td>${s.address || ""}</td>
    </tr>
  `).join("");
}

// ---------- users ----------
async function loadUsers() {
  const users = await api("/api/auth/users");
  $("#users-body").innerHTML = users.map((u) => `
    <tr>
      <td>${u.id}</td><td>${u.username}</td>
      <td><code>${u.password}</code></td>
      <td>${u.role}</td>
      <td>${(u.created_at || "").slice(0,19).replace("T"," ")}</td>
    </tr>
  `).join("");
}

// ---------- audit ----------
async function loadAudit() {
  const rows = await api("/api/audit");
  $("#audit-body").innerHTML = rows.map((r) => `
    <tr>
      <td>${r.id}</td><td>${r.action}</td><td>${r.item_id ?? ""}</td>
      <td>${r.user_id ?? ""}</td>
      <td>${(r.timestamp || "").slice(0,19).replace("T"," ")}</td>
      <td>${r.details || ""}</td>
    </tr>
  `).join("");
}

// ---------- wiring ----------
document.addEventListener("DOMContentLoaded", () => {
  $("#login-form").addEventListener("submit", login);
  $("#register-form").addEventListener("submit", register);
  $("#show-register").addEventListener("click", () => setView("register-view"));
  $("#show-login").addEventListener("click", () => setView("login-view"));
  $("#logout-btn").addEventListener("click", logout);

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
