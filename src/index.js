// Cloudflare Worker: handles every /api/* request and serves the static site from /public.
// Needs a D1 binding named DB and a secret named ADMIN_PASSWORD.
const TYPES = ["Malware", "Phishing", "Unauthorized Access"];
const SEVERITIES = ["Low", "Medium", "High", "Critical"];
const STATUSES = ["Open", "Under Investigation", "Resolved"];
const INC = "id, type, reporter, description, severity, status, queued_at AS queuedAt";

const J = (data, status = 200, headers = {}) => new Response(JSON.stringify(data), {
  status, headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...headers } });
const hex = b => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, "0")).join("");
const enc = new TextEncoder();
const sha = async s => hex(await crypto.subtle.digest("SHA-256", enc.encode(s)));
async function hashPw(pw, salt) {
  const key = await crypto.subtle.importKey("raw", enc.encode(pw), "PBKDF2", false, ["deriveBits"]);
  return hex(await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: enc.encode(salt), iterations: 100000, hash: "SHA-256" }, key, 256));
}

async function handle({ request, env, params }) {
  const db = env.DB;
  if (!db) return J({ error: "Database not connected. Add a D1 binding named DB." }, 500);
  const url = new URL(request.url), method = request.method, now = Date.now();
  const origin = request.headers.get("Origin");
  if (method !== "GET" && origin && origin !== url.origin) return J({ error: "Forbidden." }, 403);
  const [a, b, c] = params.path || [];
  const body = (method === "POST" || method === "PATCH") ? await request.json().catch(() => ({})) : {};

  const m = /(?:^|; )sid=([a-f0-9]{64})/.exec(request.headers.get("Cookie") || "");
  const me = m ? await db.prepare(
    "SELECT u.id, u.username, u.role FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ? AND s.expires > ?"
  ).bind(m[1], now).first() : null;
  const admin = !!me && me.role === "admin";

  const startSession = async u => {
    const token = hex(crypto.getRandomValues(new Uint8Array(32)));
    await db.prepare("INSERT INTO sessions (token, user_id, expires) VALUES (?, ?, ?)")
      .bind(token, u.id, now + 7 * 864e5).run();
    return J({ user: { name: u.username, role: u.role } }, 200,
      { "Set-Cookie": `sid=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=604800` });
  };

  // ----- Accounts -----
  if (a === "me") return J({ user: me && { name: me.username, role: me.role } });

  if (a === "signup" && method === "POST") {
    const name = String(body.username || "").trim(), pw = String(body.password || "");
    if (!/^[A-Za-z0-9_]{3,20}$/.test(name)) return J({ error: "Username must be 3 to 20 letters, numbers or underscores." }, 400);
    if (name.toLowerCase() === "admin") return J({ error: "That username is already taken." }, 409);
    if (pw.length < 8 || pw.length > 200) return J({ error: "Password must be at least 8 characters." }, 400);
    const salt = hex(crypto.getRandomValues(new Uint8Array(16)));
    try {
      const r = await db.prepare("INSERT INTO users (username, role, salt, hash, created) VALUES (?, 'user', ?, ?, ?)")
        .bind(name, salt, await hashPw(pw, salt), now).run();
      return startSession({ id: r.meta.last_row_id, username: name, role: "user" });
    } catch (e) {
      const dup = /UNIQUE/i.test(String(e));
      return J({ error: dup ? "That username is already taken." : "Database error: " + (e.message || e) }, dup ? 409 : 500);
    }
  }

  if (a === "login" && method === "POST") {
    const name = String(body.username || "").trim(), pw = String(body.password || ""), key = name.toLowerCase();
    const f = await db.prepare("SELECT n, until FROM attempts WHERE k = ?").bind(key).first();
    if (f && f.until > now) return J({ error: "Too many attempts. Wait 5 minutes and try again." }, 429);
    let u = null, ok = false;
    if (key === "admin") {
      if (!env.ADMIN_PASSWORD) return J({ error: "The ADMIN_PASSWORD secret is not set on this Worker." }, 500);
      ok = !!env.ADMIN_PASSWORD && (await sha(pw)) === (await sha(env.ADMIN_PASSWORD));
      if (ok) {
        await db.prepare("INSERT OR IGNORE INTO users (username, role, salt, hash, created) VALUES ('admin', 'admin', '', '', ?)").bind(now).run();
        u = await db.prepare("SELECT * FROM users WHERE username = 'admin'").first();
      }
    } else {
      u = await db.prepare("SELECT * FROM users WHERE username = ?").bind(name).first();
      ok = u ? (await hashPw(pw, u.salt)) === u.hash : (await hashPw(pw, "0"), false);
    }
    if (!ok) {
      let n = (f ? f.n : 0) + 1, until = 0;
      if (n >= 5) { until = now + 300000; n = 0; }
      await db.prepare("INSERT INTO attempts (k, n, until) VALUES (?1, ?2, ?3) ON CONFLICT(k) DO UPDATE SET n = ?2, until = ?3")
        .bind(key, n, until).run();
      return J({ error: "Incorrect username or password." }, 401);
    }
    await db.prepare("DELETE FROM attempts WHERE k = ?").bind(key).run();
    return startSession(u);
  }

  if (a === "logout") {
    if (m) await db.prepare("DELETE FROM sessions WHERE token = ?").bind(m[1]).run();
    return J({ ok: true }, 200, { "Set-Cookie": "sid=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0" });
  }

  if (!me) return J({ error: "Please log in." }, 401);

  // ----- Incidents -----
  if (a === "incidents" && !b && method === "GET") {
    const q = admin ? db.prepare(`SELECT ${INC} FROM incidents ORDER BY id`)
      : db.prepare(`SELECT ${INC} FROM incidents WHERE owner_id = ? ORDER BY id`).bind(me.id);
    return J((await q.all()).results);
  }

  if (a === "incidents" && !b && method === "POST") {
    const type = body.type, description = String(body.description || "").trim();
    const reporter = admin ? String(body.reporter || "").trim() : me.username;
    if (!TYPES.includes(type)) return J({ error: "Invalid incident type." }, 400);
    if (!reporter || reporter.length > 60) return J({ error: "Reporter name cannot be empty." }, 400);
    if (!description || description.length > 2000) return J({ error: "Incident description cannot be empty." }, 400);
    const r = await db.prepare("INSERT INTO incidents (type, reporter, owner_id, description, created) VALUES (?, ?, ?, ?, ?)")
      .bind(type, reporter, me.id, description, now).run();
    return J({ id: r.meta.last_row_id });
  }

  if (a === "incidents" && b) {
    if (!admin) return J({ error: "Admins only." }, 403);
    const r = await db.prepare("SELECT * FROM incidents WHERE id = ?").bind(b).first();
    if (!r) return J({ error: `Incident not found (ID: ${b}).` }, 404);

    if (method === "DELETE") {
      await db.prepare("DELETE FROM incidents WHERE id = ?").bind(r.id).run();
      return J({ ok: true });
    }
    if (r.status === "Closed") return J({ error: "This incident is closed and can no longer be changed." }, 409);

    if (c === "close" && method === "POST") {
      await db.prepare("UPDATE incidents SET status = 'Closed', queued_at = NULL WHERE id = ?").bind(r.id).run();
      return J({ ok: true });
    }
    if (method === "PATCH") {
      const { severity, status } = body;
      let queued = false, qa = r.queued_at;
      if (severity !== undefined) {
        if (!SEVERITIES.includes(severity)) return J({ error: "Invalid severity choice." }, 400);
        if ((severity === "High" || severity === "Critical") && qa == null) { qa = now; queued = true; }
      }
      if (status !== undefined && !STATUSES.includes(status)) return J({ error: "Invalid status choice." }, 400);
      await db.prepare("UPDATE incidents SET severity = ?, status = ?, queued_at = ? WHERE id = ?")
        .bind(severity ?? r.severity, status ?? r.status, qa, r.id).run();
      return J({ queued });
    }
  }

  if (a === "escalate" && method === "POST") {
    if (!admin) return J({ error: "Admins only." }, 403);
    for (;;) {
      const r = await db.prepare("SELECT * FROM incidents WHERE queued_at IS NOT NULL ORDER BY queued_at LIMIT 1").first();
      if (!r) return J({ report: null });
      await db.prepare("UPDATE incidents SET queued_at = NULL WHERE id = ?").bind(r.id).run();
      if (r.status !== "Closed" && (r.severity === "High" || r.severity === "Critical")) {
        const changed = r.status === "Open";
        if (changed) await db.prepare("UPDATE incidents SET status = 'Under Investigation' WHERE id = ?").bind(r.id).run();
        const left = await db.prepare("SELECT COUNT(*) AS n FROM incidents WHERE queued_at IS NOT NULL").first();
        return J({ report: `#${r.id} [${r.type}] Severity: ${r.severity} | Status: ${r.status} | Reporter: ${r.reporter}`,
          changed, remaining: left.n });
      }
    }
  }

  // ----- Users (admin) -----
  if (a === "users") {
    if (!admin) return J({ error: "Admins only." }, 403);
    if (!b && method === "GET") {
      return J((await db.prepare(
        "SELECT u.id, u.username AS name, u.created, (SELECT COUNT(*) FROM incidents i WHERE i.owner_id = u.id) AS incidents FROM users u WHERE u.role = 'user' ORDER BY u.id"
      ).all()).results);
    }
    if (b && method === "DELETE") {
      await db.prepare("DELETE FROM sessions WHERE user_id = ?").bind(b).run();
      await db.prepare("DELETE FROM users WHERE id = ? AND role = 'user'").bind(b).run();
      return J({ ok: true });
    }
  }
  return J({ error: "Not found." }, 404);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (!url.pathname.startsWith("/api/")) return env.ASSETS.fetch(request);
    const path = url.pathname.slice(5).split("/").filter(Boolean);
    try {
      return await handle({ request, env, params: { path } });
    } catch (e) {
      return new Response(JSON.stringify({ error: "Server error: " + (e.message || e) }),
        { status: 500, headers: { "Content-Type": "application/json" } });
    }
  },
};
