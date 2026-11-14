
// auth.js: cloud API helper and login screens. Load it BEFORE script.js.
async function api(path, method = "GET", body) {
  let res;
  try {
    res = await fetch("/api/" + path, { method, credentials: "same-origin",
      headers: body ? { "Content-Type": "application/json" } : {},
      body: body ? JSON.stringify(body) : undefined });
  } catch (e) { throw new Error("Could not reach the server. Check your connection."); }
  const data = await res.json().catch(() => ({}));
  if (res.status === 401 && !["login", "signup", "me"].includes(path)) Auth.expire();
  if (!res.ok) throw new Error(data.error || "Something went wrong.");
  return data;
}

const Auth = (() => {
  const safe = s => String(s).replace(/[&<>"']/g, c => "&#" + c.charCodeAt(0) + ";");
  const $a = id => document.getElementById(id);
  let session = null, users = [], mode = "login";
  document.body.classList.add("loading", "locked");

  const isAdmin = () => !!session && session.role === "admin";
  const msg = t => { $a("auth-msg").textContent = t; };

  async function refreshUsers() { users = isAdmin() ? await api("users") : []; renderChrome(); }
  async function start(u) {
    session = u; apply();
    try { await Promise.all([manager.load(), refreshUsers()]); } catch (e) { notice(e.message, false); }
    render();
  }
  async function logout() {
    try { await api("logout", "POST"); } catch (e) {}
    session = null; users = []; apply(); notice("", true); formMessage("", true); render();
  }
  function expire() { session = null; apply(); msg("Your session has expired. Please log in again."); }
  const visible = () => session ? manager.incidents : [];

  document.body.insertAdjacentHTML("afterbegin", `
    <div id="auth" class="auth-screen">
      <div class="panel auth-card">
        <h1>Cybersecurity Incident System</h1>
        <div class="auth-tabs" role="group" aria-label="Account">
          <button type="button" class="active" data-mode="login">Log in</button>
          <button type="button" data-mode="signup">Create account</button>
        </div>
        <form id="auth-form" novalidate>
          <label>Username <input id="au-name" autocomplete="username"></label>
          <label>Password <input id="au-pw" type="password" autocomplete="current-password"></label>
          <label id="au-pw2-wrap" hidden>Confirm password
            <input id="au-pw2" type="password" autocomplete="new-password"></label>
          <p id="auth-msg" role="alert"></p>
          <button type="submit" class="full" id="au-submit">Log in</button>
        </form>
      </div>
    </div>`);
  document.querySelector("header").insertAdjacentHTML("afterend", `
    <div id="userbar" class="userbar">
      <span id="who"></span>
      <button type="button" id="logout" class="secondary">Log out</button>
    </div>`);
  document.querySelector("main").insertAdjacentHTML("beforeend", `
    <section id="admin-users" class="panel" hidden aria-labelledby="users-h">
      <h2 id="users-h">User accounts</h2>
      <div class="table-wrap"><table class="users">
        <thead><tr><th>Username</th><th>Created</th><th>Incidents</th><th></th></tr></thead>
        <tbody id="users-body"></tbody>
      </table></div>
    </section>`);

  function setMode(m) {
    mode = m;
    document.querySelectorAll(".auth-tabs button").forEach(b => b.classList.toggle("active", b.dataset.mode === m));
    $a("au-pw2-wrap").hidden = m === "login";
    $a("au-pw").autocomplete = m === "login" ? "current-password" : "new-password";
    $a("au-submit").textContent = m === "login" ? "Log in" : "Create account";
    msg("");
  }

  function apply() {
    const b = document.body, admin = isAdmin();
    b.classList.remove("loading");
    b.classList.toggle("locked", !session);
    b.classList.toggle("role-admin", admin);
    b.classList.toggle("role-user", !!session && !admin);
    document.querySelector("header h1").textContent =
      admin ? "Admin Console · Cybersecurity Incident System" : "Cybersecurity Incident System";
    $a("reporter").closest("label").hidden = !admin;
    $a("who").innerHTML = session
      ? `Signed in as <strong>${safe(session.name)}</strong> <span class="badge ${admin ? "High" : "Low"}">${admin ? "Admin" : "User"}</span>`
      : "";
  }

  function renderChrome() {
    $a("admin-users").hidden = !isAdmin();
    if (!isAdmin()) return;
    const rows = users.map(u => `
      <tr><td>${safe(u.name)}</td><td>${new Date(u.created).toLocaleDateString()}</td><td>${u.incidents}</td>
        <td><button type="button" class="danger" data-rm="${u.id}">Remove</button></td></tr>`);
    $a("users-body").innerHTML = rows.length ? rows.join("")
      : `<tr><td colspan="4" class="empty">No user accounts have been created yet.</td></tr>`;
  }

  document.querySelectorAll(".auth-tabs button").forEach(b => b.addEventListener("click", () => setMode(b.dataset.mode)));
  $a("logout").addEventListener("click", logout);
  $a("users-body").addEventListener("click", async e => {
    const id = e.target.dataset.rm;
    const u = users.find(x => String(x.id) === id);
    if (!u || !confirm(`Remove the account "${u.name}"? Their incidents are kept.`)) return;
    try { await api(`users/${id}`, "DELETE"); await refreshUsers(); } catch (err) { notice(err.message, false); }
  });
  $a("auth-form").addEventListener("submit", async e => {
    e.preventDefault();
    const btn = $a("au-submit");
    btn.disabled = true;
    try {
      const username = $a("au-name").value.trim(), password = $a("au-pw").value;
      if (mode === "signup" && password !== $a("au-pw2").value) throw new Error("The two passwords do not match.");
      const r = await api(mode, "POST", { username, password });
      e.target.reset(); msg("");
      await start(r.user);
    } catch (err) { msg(err.message); }
    btn.disabled = false;
  });

  const ready = api("me").then(r => { session = r.user || null; }).catch(() => { session = null; })
    .then(() => apply());
  return { isAdmin, user: () => session, visible, renderChrome, refreshUsers, expire, ready };
})();
