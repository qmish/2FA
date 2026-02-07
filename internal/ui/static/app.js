/* global window, document, fetch */
function setResult(id, data) {
  const el = document.getElementById(id);
  if (!el) return;
  if (typeof data === "string") {
    el.textContent = data;
    return;
  }
  el.textContent = JSON.stringify(data, null, 2);
}

function errorLabel(err) {
  if (!err) return "Ошибка";
  if (typeof err === "string") return "Ошибка";
  if (err.status) return `Ошибка ${err.status}`;
  return "Ошибка";
}

function setStatus(id, ok, err) {
  const badge = document.getElementById(id);
  if (!badge) return;
  if (ok) {
    badge.textContent = "Ошибка";
    badge.classList.add("hidden");
    return;
  }
  badge.textContent = errorLabel(err);
  badge.classList.remove("hidden");
  badge.classList.add("error");
}

function getAccessToken() {
  return window.localStorage.getItem("access_token") || "";
}

function setAccessToken(token) {
  if (token) {
    window.localStorage.setItem("access_token", token);
  }
}

function getRefreshToken() {
  return window.localStorage.getItem("refresh_token") || "";
}

function setRefreshToken(token) {
  if (token) {
    window.localStorage.setItem("refresh_token", token);
  }
}

function syncTokenFields() {
  const accessEl = document.getElementById("access-token");
  const refreshEl = document.getElementById("refresh-token");
  if (accessEl) accessEl.value = getAccessToken();
  if (refreshEl) refreshEl.value = getRefreshToken();
}

function formatTime(value) {
  if (!value) return "-";
  if (typeof value === "number") {
    const date = new Date(value * 1000);
    return Number.isNaN(date.getTime()) ? String(value) : date.toISOString();
  }
  if (typeof value === "string" && /^\d+$/.test(value)) {
    const date = new Date(Number(value) * 1000);
    return Number.isNaN(date.getTime()) ? value : date.toISOString();
  }
  return value;
}

function getAdminToken() {
  return window.localStorage.getItem("admin_token") || "";
}

function setAdminToken(token) {
  if (token) {
    window.localStorage.setItem("admin_token", token);
  }
}

function clearAdminToken() {
  window.localStorage.removeItem("admin_token");
}

function isAdminAuthorized() {
  return Boolean(getAdminToken());
}

function updateAdminVisibility() {
  const adminSections = document.getElementById("admin-sections");
  const adminLocked = document.getElementById("admin-locked");
  const isAuthorized = isAdminAuthorized();
  if (adminSections) {
    adminSections.classList.toggle("hidden", !isAuthorized);
  }
  if (adminLocked) {
    adminLocked.classList.toggle("hidden", isAuthorized);
  }
}

async function api(path, options) {
  const opts = options || {};
  const headers = opts.headers || {};
  if (!headers["Content-Type"] && opts.body) {
    headers["Content-Type"] = "application/json";
  }
  const token = getAccessToken();
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }
  const res = await fetch(path, { ...opts, headers });
  const text = await res.text();
  let payload = text;
  try {
    payload = JSON.parse(text);
  } catch (_) {
    // keep raw text
  }
  if (!res.ok) {
    throw { status: res.status, payload };
  }
  return payload;
}

async function handleLogin() {
  setStatus("login-status", true);
  try {
    const body = {
      username: document.getElementById("login-username").value.trim(),
      password: document.getElementById("login-password").value,
      channel: document.getElementById("login-channel").value,
      method: document.getElementById("login-method").value,
    };
    const resp = await api("/api/v1/auth/login", {
      method: "POST",
      body: JSON.stringify(body),
    });
    setResult("login-result", resp);
    document.getElementById("verify-user").value = resp.user_id || "";
    document.getElementById("verify-challenge").value = resp.challenge_id || "";
    document.getElementById("verify-method").value = resp.method || "otp";
  } catch (err) {
    setResult("login-result", err);
    setStatus("login-status", false, err);
  }
}

async function handleRegister() {
  setStatus("register-status", true);
  try {
    const body = {
      token: document.getElementById("register-token").value.trim(),
      username: document.getElementById("register-username").value.trim(),
      password: document.getElementById("register-password").value,
      email: document.getElementById("register-email").value.trim(),
      phone: document.getElementById("register-phone").value.trim(),
    };
    const resp = await api("/api/v1/auth/register", {
      method: "POST",
      body: JSON.stringify(body),
    });
    setResult("register-result", resp);
  } catch (err) {
    setResult("register-result", err);
    setStatus("register-status", false, err);
  }
}

async function handleVerify() {
  setStatus("verify-status", true);
  try {
    const body = {
      user_id: document.getElementById("verify-user").value.trim(),
      challenge_id: document.getElementById("verify-challenge").value.trim(),
      method: document.getElementById("verify-method").value,
      code: document.getElementById("verify-code").value.trim(),
    };
    const resp = await api("/api/v1/auth/verify", {
      method: "POST",
      body: JSON.stringify(body),
    });
    setResult("verify-result", resp);
    setAccessToken(resp.access_token || "");
    setRefreshToken(resp.refresh_token || "");
    syncTokenFields();
  } catch (err) {
    setResult("verify-result", err);
    setStatus("verify-status", false, err);
  }
}

async function handleSessions() {
  setStatus("sessions-status", true);
  try {
    const resp = await api("/api/v1/sessions?active_only=true", { method: "GET" });
    setResult("sessions-result", resp);
    renderSessions(resp);
  } catch (err) {
    setResult("sessions-result", err);
    setStatus("sessions-status", false, err);
  }
}

async function handleCurrentSession() {
  try {
    const resp = await api("/api/v1/sessions/current", { method: "GET" });
    renderCurrentSession(resp);
  } catch (err) {
    renderCurrentSession(err && err.payload ? err.payload : err);
  }
}

function renderCurrentSession(data) {
  const box = document.getElementById("current-session");
  if (!box) return;
  if (!data || data.error) {
    box.innerHTML = "<div>Нет данных</div>";
    return;
  }
  box.innerHTML = `
    <div><span class="label">ID</span><span class="value">${data.id || "-"}</span></div>
    <div><span class="label">IP</span><span class="value">${data.ip || "-"}</span></div>
    <div><span class="label">User-Agent</span><span class="value">${data.user_agent || "-"}</span></div>
    <div><span class="label">Created</span><span class="value">${formatTime(data.created_at)}</span></div>
    <div><span class="label">Last Seen</span><span class="value">${formatTime(data.last_seen_at)}</span></div>
    <div><span class="label">Expires</span><span class="value">${formatTime(data.expires_at)}</span></div>
    <div><span class="label">Revoked</span><span class="value">${formatTime(data.revoked_at)}</span></div>
  `;
}

async function handleLogout() {
  setStatus("sessions-status", true);
  try {
    await api("/api/v1/auth/logout", { method: "POST" });
    window.localStorage.removeItem("access_token");
    window.localStorage.removeItem("refresh_token");
    setResult("sessions-result", { ok: true, message: "logged out" });
  } catch (err) {
    setResult("sessions-result", err);
    setStatus("sessions-status", false, err);
  }
}

async function handleRevoke() {
  setStatus("sessions-status", true);
  try {
    const revokeAll = document.getElementById("revoke-all").value === "true";
    if (revokeAll) {
      await api("/api/v1/sessions/revoke_all", {
        method: "POST",
        body: JSON.stringify({ except_current: true }),
      });
      setResult("sessions-result", { ok: true, revoked: "all_except_current" });
      return;
    }
    const sessionID = document.getElementById("session-id").value.trim();
    const resp = await api("/api/v1/sessions/revoke", {
      method: "POST",
      body: JSON.stringify({ session_id: sessionID }),
    });
    setResult("sessions-result", resp || { ok: true });
  } catch (err) {
    setResult("sessions-result", err);
    setStatus("sessions-status", false, err);
  }
}

function renderSessions(resp) {
  const list = document.getElementById("sessions-list");
  if (!list) return;
  if (!resp || !resp.items || !Array.isArray(resp.items)) {
    list.innerHTML = "";
    return;
  }
  const rows = resp.items
    .map((item) => {
      return `
        <tr>
          <td>${item.id}</td>
          <td>${item.ip || "-"}</td>
          <td>${item.user_agent || "-"}</td>
          <td>${formatTime(item.created_at)}</td>
          <td>${formatTime(item.last_seen_at)}</td>
          <td>${formatTime(item.expires_at)}</td>
          <td><button class="btn-link" data-session-id="${item.id}">revoke</button></td>
        </tr>
      `;
    })
    .join("");
  list.innerHTML = `
    <table>
      <thead>
        <tr>
          <th>ID</th>
          <th>IP</th>
          <th>User-Agent</th>
          <th>Created</th>
          <th>Last Seen</th>
          <th>Expires</th>
          <th></th>
        </tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>
  `;
  list.querySelectorAll("button[data-session-id]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const id = btn.getAttribute("data-session-id");
      if (!id) return;
      document.getElementById("session-id").value = id;
      await handleRevoke();
    });
  });
}

async function handleRefresh() {
  setStatus("tokens-status", true);
  try {
    const token = document.getElementById("refresh-token").value.trim();
    const resp = await api("/api/v1/auth/refresh", {
      method: "POST",
      body: JSON.stringify({ refresh_token: token }),
    });
    setResult("tokens-result", resp);
    setAccessToken(resp.access_token || "");
    setRefreshToken(resp.refresh_token || token);
    syncTokenFields();
  } catch (err) {
    setResult("tokens-result", err);
    setStatus("tokens-status", false, err);
  }
}

async function handleLockoutStatus() {
  setStatus("tokens-status", true);
  try {
    const resp = await api("/api/v1/lockouts/current", { method: "GET" });
    setResult("tokens-result", resp);
  } catch (err) {
    setResult("tokens-result", err);
    setStatus("tokens-status", false, err);
  }
}

async function handleTotpSetup() {
  setStatus("totp-setup-status", true);
  try {
    const resp = await api("/api/v1/auth/totp/setup", { method: "POST" });
    setResult("totp-setup-result", resp);
  } catch (err) {
    setResult("totp-setup-result", err);
    setStatus("totp-setup-status", false, err);
  }
}

async function handleTotpDisable() {
  setStatus("totp-setup-status", true);
  try {
    await api("/api/v1/auth/totp/disable", { method: "POST" });
    setResult("totp-setup-result", { ok: true });
  } catch (err) {
    setResult("totp-setup-result", err);
    setStatus("totp-setup-status", false, err);
  }
}

async function handleAuditList() {
  setStatus("audit-status", true);
  try {
    const token = document.getElementById("admin-token").value.trim();
    setAdminToken(token);
    const params = buildAuditParams();
    const res = await fetch(`/api/v1/admin/audit/events?${params.toString()}`, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });
    const text = await res.text();
    let payload = text;
    try {
      payload = JSON.parse(text);
    } catch (_) {
      // keep raw
    }
    if (!res.ok) {
      throw { status: res.status, payload };
    }
    setResult("audit-result", payload);
    renderAudit(payload);
  } catch (err) {
    setResult("audit-result", err);
    setStatus("audit-status", false, err);
  }
}

function buildAuditParams() {
  const params = new URLSearchParams();
  const action = document.getElementById("audit-action").value.trim();
  const entity = document.getElementById("audit-entity").value.trim();
  const actor = document.getElementById("audit-actor").value.trim();
  if (action) params.set("action", action);
  if (entity) params.set("entity_type", entity);
  if (actor) params.set("actor_user_id", actor);
  return params;
}

async function handleAuditExport() {
  setStatus("audit-status", true);
  try {
    const token = document.getElementById("admin-token").value.trim();
    setAdminToken(token);
    const params = buildAuditParams();
    params.set("format", "csv");
    const res = await fetch(`/api/v1/admin/audit/export?${params.toString()}`, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });
    if (!res.ok) {
      const text = await res.text();
      throw { status: res.status, payload: text };
    }
    const blob = await res.blob();
    const url = window.URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "audit.csv";
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.URL.revokeObjectURL(url);
  } catch (err) {
    setResult("audit-result", err);
    setStatus("audit-status", false, err);
  }
}

function renderAudit(resp) {
  const list = document.getElementById("audit-list");
  if (!list) return;
  if (!resp || !resp.items || !Array.isArray(resp.items)) {
    list.innerHTML = "";
    return;
  }
  const rows = resp.items
    .map((item) => {
      return `
        <tr>
          <td>${item.id}</td>
          <td>${item.action}</td>
          <td>${item.entity_type}</td>
          <td>${item.entity_id || "-"}</td>
          <td>${item.actor_user_id || "-"}</td>
          <td>${item.ip || "-"}</td>
          <td>${item.payload || "-"}</td>
          <td>${formatTime(item.created_at)}</td>
        </tr>
      `;
    })
    .join("");
  list.innerHTML = `
    <table>
      <thead>
        <tr>
          <th>ID</th>
          <th>Action</th>
          <th>Entity</th>
          <th>Entity ID</th>
          <th>Actor</th>
          <th>IP</th>
          <th>Payload</th>
          <th>Created</th>
        </tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>
  `;
}

async function handleAdminSessions() {
  setStatus("admin-sessions-status", true);
  try {
    const token = document.getElementById("admin-sessions-token").value.trim();
    setAdminToken(token);
    const params = new URLSearchParams();
    const userID = document.getElementById("admin-sessions-user").value.trim();
    const activeOnly = document.getElementById("admin-sessions-active").value;
    const ip = document.getElementById("admin-sessions-ip").value.trim();
    const ua = document.getElementById("admin-sessions-ua").value.trim();
    if (userID) params.set("user_id", userID);
    if (activeOnly) params.set("active_only", activeOnly);
    if (ip) params.set("ip", ip);
    if (ua) params.set("user_agent", ua);
    const res = await fetch(`/api/v1/admin/sessions?${params.toString()}`, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });
    const text = await res.text();
    let payload = text;
    try {
      payload = JSON.parse(text);
    } catch (_) {
      // keep raw
    }
    if (!res.ok) {
      throw { status: res.status, payload };
    }
    setResult("admin-sessions-result", payload);
    renderAdminSessions(payload, token);
  } catch (err) {
    setResult("admin-sessions-result", err);
    setStatus("admin-sessions-status", false, err);
  }
}

function renderAdminSessions(resp, token) {
  const list = document.getElementById("admin-sessions-list");
  if (!list) return;
  if (!resp || !resp.items || !Array.isArray(resp.items)) {
    list.innerHTML = "";
    return;
  }
  const rows = resp.items
    .map((item) => {
      return `
        <tr>
          <td>${item.id}</td>
          <td>${item.user_id}</td>
          <td>${item.ip || "-"}</td>
          <td>${item.user_agent || "-"}</td>
          <td>${formatTime(item.created_at)}</td>
          <td>${formatTime(item.last_seen_at)}</td>
          <td>${formatTime(item.expires_at)}</td>
          <td><button class="btn-link" data-admin-session-id="${item.id}">revoke</button></td>
        </tr>
      `;
    })
    .join("");
  list.innerHTML = `
    <table>
      <thead>
        <tr>
          <th>ID</th>
          <th>User</th>
          <th>IP</th>
          <th>User-Agent</th>
          <th>Created</th>
          <th>Last Seen</th>
          <th>Expires</th>
          <th></th>
        </tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>
  `;
  list.querySelectorAll("button[data-admin-session-id]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const id = btn.getAttribute("data-admin-session-id");
      if (!id) return;
      try {
        const res = await fetch("/api/v1/admin/sessions/revoke", {
          method: "POST",
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ session_id: id }),
        });
        if (!res.ok) {
          const text = await res.text();
          throw { status: res.status, payload: text };
        }
        await handleAdminSessions();
      } catch (err) {
        setResult("admin-sessions-result", err);
      }
    });
  });
}

async function handleAdminLockouts() {
  setStatus("admin-lockouts-status", true);
  try {
    const token = document.getElementById("admin-lockouts-token").value.trim();
    setAdminToken(token);
    const params = new URLSearchParams();
    const userID = document.getElementById("admin-lockouts-user").value.trim();
    const ip = document.getElementById("admin-lockouts-ip").value.trim();
    const reason = document.getElementById("admin-lockouts-reason").value.trim();
    const activeOnly = document.getElementById("admin-lockouts-active").value;
    if (userID) params.set("user_id", userID);
    if (ip) params.set("ip", ip);
    if (reason) params.set("reason", reason);
    if (activeOnly) params.set("active_only", activeOnly);
    const res = await fetch(`/api/v1/admin/lockouts?${params.toString()}`, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });
    const text = await res.text();
    let payload = text;
    try {
      payload = JSON.parse(text);
    } catch (_) {
      // keep raw
    }
    if (!res.ok) {
      throw { status: res.status, payload };
    }
    setResult("admin-lockouts-result", payload);
    renderAdminLockouts(payload);
  } catch (err) {
    setResult("admin-lockouts-result", err);
    setStatus("admin-lockouts-status", false, err);
  }
}

async function handleAdminLockoutsClear() {
  setStatus("admin-lockouts-status", true);
  try {
    const token = document.getElementById("admin-lockouts-token").value.trim();
    setAdminToken(token);
    const userID = document.getElementById("admin-lockouts-user").value.trim();
    const ip = document.getElementById("admin-lockouts-ip").value.trim();
    const reason = document.getElementById("admin-lockouts-reason").value.trim();
    const body = {};
    if (userID) body.user_id = userID;
    if (ip) body.ip = ip;
    if (reason) body.reason = reason;
    const res = await fetch("/api/v1/admin/lockouts/clear", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const text = await res.text();
      throw { status: res.status, payload: text };
    }
    await handleAdminLockouts();
  } catch (err) {
    setResult("admin-lockouts-result", err);
    setStatus("admin-lockouts-status", false, err);
  }
}

function renderAdminLockouts(resp) {
  const list = document.getElementById("admin-lockouts-list");
  if (!list) return;
  if (!resp || !resp.items || !Array.isArray(resp.items)) {
    list.innerHTML = "";
    return;
  }
  const rows = resp.items
    .map((item) => {
      return `
        <tr>
          <td>${item.id}</td>
          <td>${item.user_id}</td>
          <td>${item.ip || "-"}</td>
          <td>${item.reason || "-"}</td>
          <td>${formatTime(item.expires_at)}</td>
          <td>${formatTime(item.created_at)}</td>
        </tr>
      `;
    })
    .join("");
  list.innerHTML = `
    <table>
      <thead>
        <tr>
          <th>ID</th>
          <th>User</th>
          <th>IP</th>
          <th>Reason</th>
          <th>Expires</th>
          <th>Created</th>
        </tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>
  `;
}

async function handleAdminLogin() {
  setStatus("admin-login-status", true);
  try {
    const body = {
      username: document.getElementById("admin-login-username").value.trim(),
      password: document.getElementById("admin-login-password").value,
    };
    const res = await fetch("/api/v1/admin/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const text = await res.text();
    let payload = text;
    try {
      payload = JSON.parse(text);
    } catch (_) {
      // keep raw
    }
    if (!res.ok) {
      throw { status: res.status, payload };
    }
    const token = payload && payload.access_token ? payload.access_token : "";
    if (token) {
      setAdminToken(token);
    }
    document.getElementById("admin-token").value = getAdminToken();
  document.getElementById("admin-invites-token").value = getAdminToken();
    document.getElementById("admin-sessions-token").value = getAdminToken();
    document.getElementById("admin-lockouts-token").value = getAdminToken();
    updateAdminVisibility();
    setResult("admin-login-result", payload);
  } catch (err) {
    setResult("admin-login-result", err);
    setStatus("admin-login-status", false, err);
  }
}

function handleAdminTokenClear() {
  clearAdminToken();
  document.getElementById("admin-token").value = "";
  document.getElementById("admin-invites-token").value = "";
  document.getElementById("admin-sessions-token").value = "";
  document.getElementById("admin-lockouts-token").value = "";
  updateAdminVisibility();
  setResult("admin-login-result", { ok: true });
  setStatus("admin-login-status", true);
}

async function handleAdminInviteCreate() {
  setStatus("admin-invites-status", true);
  try {
    const token = document.getElementById("admin-invites-token").value.trim();
    setAdminToken(token);
    const body = {
      email: document.getElementById("admin-invites-email").value.trim(),
      phone: document.getElementById("admin-invites-phone").value.trim(),
      role: document.getElementById("admin-invites-role").value,
      ttl_minutes: Number(document.getElementById("admin-invites-ttl").value),
    };
    if (!body.ttl_minutes) {
      delete body.ttl_minutes;
    }
    const res = await fetch("/api/v1/admin/invites/create", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
    });
    const text = await res.text();
    let payload = text;
    try {
      payload = JSON.parse(text);
    } catch (_) {
      // keep raw
    }
    if (!res.ok) {
      throw { status: res.status, payload };
    }
    setResult("admin-invites-result", payload);
    if (payload && payload.token) {
      document.getElementById("register-token").value = payload.token;
    }
  } catch (err) {
    setResult("admin-invites-result", err);
    setStatus("admin-invites-status", false, err);
  }
}

async function handleHealth() {
  setStatus("health-status", true);
  try {
    const res = await fetch("/healthz");
    const text = await res.text();
    let payload = text;
    try {
      payload = JSON.parse(text);
    } catch (_) {
      // keep raw
    }
    setResult("health-result", payload);
    const badge = document.getElementById("health-badge");
    if (badge) {
      badge.textContent = res.ok ? "ok" : "fail";
      badge.classList.remove("ok", "fail");
      badge.classList.add(res.ok ? "ok" : "fail");
    }
  } catch (err) {
    setResult("health-result", err);
    setStatus("health-status", false, err);
    const badge = document.getElementById("health-badge");
    if (badge) {
      badge.textContent = "fail";
      badge.classList.remove("ok");
      badge.classList.add("fail");
    }
  }
}

async function handleMetrics() {
  setStatus("metrics-status", true);
  try {
    const res = await fetch("/metrics");
    const text = await res.text();
    if (!res.ok) {
      throw { status: res.status, payload: text };
    }
    setResult("metrics-result", text);
  } catch (err) {
    setResult("metrics-result", err);
    setStatus("metrics-status", false, err);
  }
}

function initUI() {
  document.getElementById("login-btn").addEventListener("click", handleLogin);
  document.getElementById("register-btn").addEventListener("click", handleRegister);
  document.getElementById("verify-btn").addEventListener("click", handleVerify);
  document.getElementById("sessions-btn").addEventListener("click", handleSessions);
  document.getElementById("logout-btn").addEventListener("click", handleLogout);
  document.getElementById("current-session-btn").addEventListener("click", handleCurrentSession);
  document.getElementById("revoke-btn").addEventListener("click", handleRevoke);
  document.getElementById("refresh-btn").addEventListener("click", handleRefresh);
  document.getElementById("lockout-btn").addEventListener("click", handleLockoutStatus);
  const totpSetupBtn = document.getElementById("totp-setup-btn");
  const totpDisableBtn = document.getElementById("totp-disable-btn");
  if (totpSetupBtn) totpSetupBtn.addEventListener("click", handleTotpSetup);
  if (totpDisableBtn) totpDisableBtn.addEventListener("click", handleTotpDisable);
  document.getElementById("audit-btn").addEventListener("click", handleAuditList);
  document.getElementById("audit-export-btn").addEventListener("click", handleAuditExport);
  document.getElementById("admin-token").value = getAdminToken();
  document.getElementById("admin-invites-token").value = getAdminToken();
  document.getElementById("admin-sessions-token").value = getAdminToken();
  document.getElementById("admin-sessions-btn").addEventListener("click", handleAdminSessions);
  document.getElementById("admin-lockouts-token").value = getAdminToken();
  document.getElementById("admin-lockouts-btn").addEventListener("click", handleAdminLockouts);
  document.getElementById("admin-lockouts-clear").addEventListener("click", handleAdminLockoutsClear);
  document.getElementById("admin-login-btn").addEventListener("click", handleAdminLogin);
  document.getElementById("admin-token-clear").addEventListener("click", handleAdminTokenClear);
  document.getElementById("admin-invites-btn").addEventListener("click", handleAdminInviteCreate);
  document.getElementById("health-btn").addEventListener("click", handleHealth);
  document.getElementById("metrics-btn").addEventListener("click", handleMetrics);
  syncTokenFields();
  updateAdminVisibility();
}

window.addEventListener("DOMContentLoaded", initUI);
