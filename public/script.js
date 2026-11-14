class InvalidInputException extends Error {}
class IncidentNotFoundException extends Error {
  constructor(id) { super(`Incident not found (ID: ${id}).`); }
}
class IncidentClosedException extends Error {}

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

class IncidentManager {
  constructor() {
    this.incidents = [];             
    this.incidentMap = new Map();    
    this.escalationQueue = [];       
    this.nextId = 1;
    this.load();
  }

  report(type, reporter, description) {
    if (!TYPES[type]) throw new InvalidInputException("Invalid incident type.");
    reporter = reporter.trim();
    description = description.trim();
    if (!reporter) throw new InvalidInputException("Reporter name cannot be empty.");
    if (!description) throw new InvalidInputException("Incident description cannot be empty.");

    const incident = new TYPES[type](this.nextId++, reporter, description);
    this.incidents.push(incident);
    this.incidentMap.set(incident.id, incident);
    this.save();
    return incident;
  }

  find(id) {
    const incident = this.incidentMap.get(id);
    if (!incident) throw new IncidentNotFoundException(id);
    return incident;
  }

  setSeverity(id, severity) {
    const incident = this.find(id);
    if (incident.status === "Closed") {
      throw new IncidentClosedException("Cannot change the severity of a closed incident.");
    }
    if (!SEVERITIES.includes(severity)) throw new InvalidInputException("Invalid severity choice.");

    incident.severity = severity;
    let queued = false;
    if (incident.requiresEscalation() && !this.escalationQueue.includes(id)) {
      this.escalationQueue.push(id);
      queued = true;
    }
    this.save();
    return queued;
  }

  setStatus(id, status) {
    const incident = this.find(id);
    if (incident.status === "Closed") {
      throw new IncidentClosedException("This incident is already closed.");
    }
    if (!STATUSES.includes(status)) throw new InvalidInputException("Invalid status choice.");
    incident.status = status;
    this.save();
  }

  close(id) {
    const incident = this.find(id);
    if (incident.status === "Closed") {
      throw new IncidentClosedException("This incident is already closed.");
    }
    incident.status = "Closed";
    this.removeFromQueue(id);
    this.save();
  }

  remove(id) {
    this.find(id);
    this.incidents = this.incidents.filter(i => i.id !== id);
    this.incidentMap.delete(id);
    this.removeFromQueue(id);
    this.save();
  }

  removeFromQueue(id) {
    this.escalationQueue = this.escalationQueue.filter(q => q !== id);
  }

  processNextEscalation() {
    while (this.escalationQueue.length > 0) {
      const incident = this.incidentMap.get(this.escalationQueue.shift());
      if (incident && incident.status !== "Closed" && incident.requiresEscalation()) {
        const report = incident.generateReport();
        const changed = incident.status === "Open";
        if (changed) incident.status = "Under Investigation";
        this.save();
        return { report, changed, remaining: this.escalationQueue.length };
      }
    }
    this.save();
    return null;
  }

  highSeverity() {
    return this.incidents.filter(i => i.requiresEscalation());
  }

  save() {
    try {
      localStorage.setItem("incidents", JSON.stringify({
        nextId: this.nextId,
        queue: this.escalationQueue,
        items: this.incidents.map(i => ({
          type: i.incidentType, id: i.id, reporter: i.reporter,
          description: i.description, severity: i.severity, status: i.status,
        })),
      }));
    } catch (e) { }
  }

  load() {
    try {
      const data = JSON.parse(localStorage.getItem("incidents"));
      if (!data) return;
      this.nextId = data.nextId;
      this.escalationQueue = data.queue || [];
      this.incidents = data.items.map(d =>
        new TYPES[d.type](d.id, d.reporter, d.description, d.severity, d.status));
      this.incidents.forEach(i => this.incidentMap.set(i.id, i));
    } catch (e) { }
  }
}

const manager = new IncidentManager();
let filter = "all";

const $ = id => document.getElementById(id);
const esc = s => s.replace(/[&<>"']/g, c =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

function options(list, selected) {
  return list.map(v => `<option${v === selected ? " selected" : ""}>${v}</option>`).join("");
}

function card(i) {
  const closed = i.status === "Closed";
  const controls = closed
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
        <button class="danger" data-action="delete" data-id="${i.id}">Delete</button>
      </div>
    </article>`;
}

function render() {
  const query = $("search").value.trim();
  let items = filter === "high" ? manager.highSeverity() : manager.incidents;
  let empty = filter === "high" ? "No high-severity incidents found." : "No incidents have been reported.";

  if (query) {
    items = [];
    if (!/^\d+$/.test(query)) {
      empty = "Please enter a valid whole number.";
    } else {
      try { items = [manager.find(+query)]; } catch (e) { empty = e.message; }
    }
  }

  $("list").innerHTML = items.length ? items.map(card).join("") : `<p class="empty">${empty}</p>`;
  $("queue-count").textContent = `${manager.escalationQueue.length} waiting in escalation queue`;

  const open = manager.incidents.filter(i => i.status !== "Closed").length;
  $("summary").textContent =
    `${manager.incidents.length} reported · ${open} still open · ${manager.highSeverity().length} high or critical`;
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

function attempt(action) {
  try { action(); } catch (e) { notice(e.message, false); }
  render();
}

$("report-form").addEventListener("submit", e => {
  e.preventDefault();
  try {
    const incident = manager.report($("type").value, $("reporter").value, $("description").value);
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
    attempt(() => {
      const queued = manager.setSeverity(+id, value);
      notice(`Severity updated to ${value}.` +
        (queued ? ` Incident #${id} added to the escalation queue.` : ""), true);
    });
  } else if (action === "status") {
    attempt(() => {
      manager.setStatus(+id, value);
      notice(`Incident status updated to ${value}.`, true);
    });
  }
});

$("list").addEventListener("click", e => {
  const btn = e.target.closest("button[data-action]");
  if (!btn) return;
  const id = +btn.dataset.id;

  if (btn.dataset.action === "close") {
    attempt(() => { manager.close(id); notice(`Incident #${id} has been closed.`, true); });
  } else if (btn.dataset.action === "delete") {
    attempt(() => {
      const incident = manager.find(id);
      if (confirm(`Delete this incident permanently?\n\n${incident.generateReport()}`)) {
        manager.remove(id);
        notice(`Incident #${id} has been deleted.`, true);
      } else {
        notice("Deletion cancelled.", true);
      }
    });
  }
});

$("escalate-btn").addEventListener("click", () => {
  attempt(() => {
    const result = manager.processNextEscalation();
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

render();
