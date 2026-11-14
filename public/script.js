// ---------- Custom exceptions ----------
class InvalidInputException extends Error {}
class IncidentNotFoundException extends Error {
  constructor(id) { super(`Incident not found (ID: ${id}).`); }
}
class IncidentClosedException extends Error {}

// ---------- Incident classes ----------
// JavaScript has no "interface" keyword, so Reportable (generateReport) and
// Escalatable (requiresEscalation) are simply methods on the base class.
class SecurityIncident {
  constructor(id, reporter, description, severity = "Medium", status = "Open") {
    if (new.target === SecurityIncident) throw new Error("SecurityIncident is abstract");
    this.id = id;
    this.reporter = reporter;
    this.description = description;
    this.severity = severity;
    this.status = status;
  }
  get incidentType() { throw new Error("Not implemented"); }
  get baseRiskScore() { throw new Error("Not implemented"); }
  recommendResponse() { throw new Error("Not implemented"); }

  calculateRiskScore() {
    const weights = { Medium: 1, High: 2, Critical: 3 };
    return this.baseRiskScore + (weights[this.severity] || 0);
  }
  requiresEscalation() {
    return this.severity === "High" || this.severity === "Critical";
  }
  generateReport() {
    return `#${this.id} [${this.incidentType}] Severity: ${this.severity} | Status: ${this.status} | Reporter: ${this.reporter}`;
  }
}

class MalwareIncident extends SecurityIncident {
  get incidentType() { return "Malware"; }
  get baseRiskScore() { return 7; }
  recommendResponse() {
    return "Isolate the affected device and scan it using approved security software.";
  }
}
class PhishingIncident extends SecurityIncident {
  get incidentType() { return "Phishing"; }
  get baseRiskScore() { return 5; }
  recommendResponse() {
    return "Avoid clicking suspicious links and report the message to the security team.";
  }
}
class UnauthorizedAccessIncident extends SecurityIncident {
  get incidentType() { return "Unauthorized Access"; }
  get baseRiskScore() { return 8; }
  recommendResponse() {
    return "Review access logs, secure the affected account, and investigate suspicious activity.";
  }
}

const TYPES = {
  "Malware": MalwareIncident,
  "Phishing": PhishingIncident,
  "Unauthorized Access": UnauthorizedAccessIncident,
};
const SEVERITIES = ["Low", "Medium", "High", "Critical"];
const STATUSES = ["Open", "Under Investigation", "Resolved"];

// ---------- Manager (talks to the cloud API) ----------
const manager = {
  incidents: [], incidentMap: new Map(), escalationQueue: [],

  async load() {
    const rows = await api("incidents");
    this.incidents = rows.map(d => new TYPES[d.type](d.id, d.reporter, d.description, d.severity, d.status));
    this.incidentMap = new Map(this.incidents.map(i => [i.id, i]));
    this.escalationQueue = rows.filter(d => d.queuedAt).sort((x, y) => x.queuedAt - y.queuedAt).map(d => d.id);
  },
  find(id) {
    const incident = this.incidentMap.get(id);
    if (!incident) throw new IncidentNotFoundException(id);
    return incident;
  },
  async report(type, reporter, description) {
    const r = await api("incidents", "POST", { type, reporter, description });
    await this.load();
    return this.incidentMap.get(r.id);
  },
  async setSeverity(id, severity) {
    const r = await api(`incidents/${id}`, "PATCH", { severity });
    await this.load();
    return r.queued;
  },
  async setStatus(id, status) { await api(`incidents/${id}`, "PATCH", { status }); await this.load(); },
  async close(id) { await api(`incidents/${id}/close`, "POST"); await this.load(); },
  async remove(id) { await api(`incidents/${id}`, "DELETE"); await this.load(); },
  async processNextEscalation() {
    const r = await api("escalate", "POST");
    await this.load();
    return r.report ? r : null;
  },
  highSeverity() { return this.incidents.filter(i => i.requiresEscalation()); },
};

// ---------- UI ----------
let filter = "all";

const $ = id => document.getElementById(id);
const esc = s => s.replace(/[&<>"']/g, c =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

function options(list, selected) {
  return list.map(v => `<option${v === selected ? " selected" : ""}>${v}</option>`).join("");
}

function card(i) {
  const closed = i.status === "Closed";
  const controls = !Auth.isAdmin() ? "" : closed
    ? `<span class="meta">This incident is closed and can no longer be changed.</span>`
    : `<label>Severity
         <select data-action="severity" data-id="${i.id}">${options(SEVERITIES, i.severity)}</select>
       </label>
       <label>Status
         <select data-action="status" data-id="${i.id}">${options(STATUSES, i.status)}</select>
       </label>
       <button class="secondary" data-action="close" data-id="${i.id}">Close incident</button>`;
  return `
    <article class="incident ${i.severity}${closed ? " is-closed" : ""}">
      <h3>#${i.id} ${esc(i.incidentType)} <span class="badge ${i.severity}">${i.severity}</span></h3>
      <p class="meta">Reported by ${esc(i.reporter)} · Status: ${i.status} ·
        Risk score: <span class="risk">${i.calculateRiskScore()}</span></p>
      <p class="desc">${esc(i.description)}</p>
      <p class="response"><strong>Recommended response:</strong> ${i.recommendResponse()}</p>
      <div class="actions">
        ${controls}
        ${Auth.isAdmin() ? `<button class="danger" data-action="delete" data-id="${i.id}">Delete</button>` : ""}
      </div>
    </article>`;
}

function render() {
  const query = $("search").value.trim();
  const pool = Auth.visible();
  let items = filter === "high" ? pool.filter(i => i.requiresEscalation()) : pool;
  let empty = filter === "high" ? "No high-severity incidents found." : "No incidents have been reported.";

  if (query) {
    items = [];
    if (!/^\d+$/.test(query)) {
      empty = "Please enter a valid whole number.";
    } else {
      try {
        items = [manager.find(+query)].filter(i => pool.includes(i));
        if (!items.length) empty = `Incident not found (ID: ${query}).`;
      } catch (e) { empty = e.message; }
    }
  }

  $("list").innerHTML = items.length ? items.map(card).join("") : `<p class="empty">${empty}</p>`;
  $("queue-count").textContent = `${manager.escalationQueue.length} waiting in escalation queue`;

  const open = pool.filter(i => i.status !== "Closed").length;
  $("summary").textContent =
    `${pool.length} reported · ${open} still open · ${pool.filter(i => i.requiresEscalation()).length} high or critical`;
  Auth.renderChrome();
}

function notice(text, ok) {
  const el = $("notice");
  el.textContent = text;
  el.className = text ? (ok ? "ok" : "err") : "";
}

function formMessage(text, ok) {
  const el = $("form-msg");
  el.textContent = text;
  el.className = ok ? "ok" : "";
}

// Run an action, show any exception message, then redraw
async function attempt(action) {
  try { await action(); } catch (e) { notice(e.message, false); }
  render();
}

$("report-form").addEventListener("submit", async e => {
  e.preventDefault();
  try {
    const incident = await manager.report($("type").value, Auth.isAdmin() ? $("reporter").value : Auth.user().name, $("description").value);
    e.target.reset();
    formMessage(`Incident reported. Assigned ID: ${incident.id}`, true);
  } catch (err) {
    formMessage(err.message, false);
  }
  render();
});

$("list").addEventListener("change", e => {
  const { action, id } = e.target.dataset;
  const value = e.target.value;
  if (action === "severity") {
    attempt(async () => {
      const queued = await manager.setSeverity(+id, value);
      notice(`Severity updated to ${value}.` +
        (queued ? ` Incident #${id} added to the escalation queue.` : ""), true);
    });
  } else if (action === "status") {
    attempt(async () => {
      await manager.setStatus(+id, value);
      notice(`Incident status updated to ${value}.`, true);
    });
  }
});

$("list").addEventListener("click", e => {
  const btn = e.target.closest("button[data-action]");
  if (!btn) return;
  const id = +btn.dataset.id;

  if (btn.dataset.action === "close") {
    attempt(async () => { await manager.close(id); notice(`Incident #${id} has been closed.`, true); });
  } else if (btn.dataset.action === "delete") {
    attempt(async () => {
      const incident = manager.find(id);
      if (confirm(`Delete this incident permanently?\n\n${incident.generateReport()}`)) {
        await manager.remove(id);
        notice(`Incident #${id} has been deleted.`, true);
      } else {
        notice("Deletion cancelled.", true);
      }
    });
  }
});

$("escalate-btn").addEventListener("click", () => {
  attempt(async () => {
    const result = await manager.processNextEscalation();
    if (!result) return notice("No incidents are waiting for escalation.", true);
    notice(
      `Escalating next incident for review:\n${result.report}` +
      (result.changed ? "\nStatus changed to Under Investigation." : "") +
      `\nIncidents still waiting in queue: ${result.remaining}`, true);
  });
});

document.querySelectorAll(".tab").forEach(tab => {
  tab.addEventListener("click", () => {
    filter = tab.dataset.filter;
    document.querySelectorAll(".tab").forEach(t => t.classList.toggle("active", t === tab));
    render();
  });
});

$("search").addEventListener("input", render);

Auth.ready.then(async () => {
  if (Auth.user()) {
    try { await Promise.all([manager.load(), Auth.refreshUsers()]); } catch (e) { notice(e.message, false); }
  }
  render();
});
