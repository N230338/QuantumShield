"use strict";

const API = "";
const state = {
  currentRun: null,
  lastRequest: null,
  encrypted: null,
  currentCircuit: "normal",
  qberChart: null,
  keyVerifiedSession: null,
  toastTimer: null,
  departments: [],
  quantumStates: [],
  quantumIndex: 0,
  quantumTimer: null,
};

const byId = (id) => document.getElementById(id);
const delay = (milliseconds) => new Promise((resolve) => window.setTimeout(resolve, milliseconds));

async function api(path, options = {}) {
  const response = await fetch(`${API}${path}`, {
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail = typeof data.detail === "string" ? data.detail : `Request failed (${response.status}).`;
    throw new Error(detail);
  }
  return data;
}

function toast(message) {
  const element = byId("toast");
  element.textContent = message;
  element.classList.add("show");
  window.clearTimeout(state.toastTimer);
  state.toastTimer = window.setTimeout(() => element.classList.remove("show"), 4300);
}

function setView(name) {
  const showingHistory = name === "history";
  byId("view-dashboard").classList.toggle("active", !showingHistory);
  byId("view-history").classList.toggle("active", showingHistory);
  document.querySelectorAll(".nav-item").forEach((button) => button.classList.toggle("active", button.dataset.view === (showingHistory ? "history" : "dashboard")));
  if (name === "circuit") loadCircuit();
  if (name === "monitoring") loadLastComparison();
  if (showingHistory) {
    refreshHistory();
    return;
  }
  const section = byId(`view-${name}`);
  if (name === "dashboard") window.scrollTo({ top: 0, behavior: "smooth" });
  else if (section) section.scrollIntoView({ behavior: "smooth", block: "start" });
}

document.querySelectorAll(".nav-item").forEach((button) => button.addEventListener("click", () => setView(button.dataset.view)));
document.querySelectorAll("[data-view-link]").forEach((button) => button.addEventListener("click", () => setView(button.dataset.viewLink)));

function showStatusValue(id, value, className = "") {
  const element = byId(id);
  element.textContent = value;
  element.className = `status-value ${className}`.trim();
}

function showDemoStage(id, value, stateName) {
  const element = byId(id);
  element.textContent = value;
  element.dataset.state = stateName;
}

function resetLiveSecurityStatus() {
  showStatusValue("status-qkd", "RUNNING");
  showStatusValue("status-qkd-inline", "RUNNING");
  showStatusValue("status-qber", "PENDING");
  showStatusValue("status-pqc", "WAITING", "pqc-status-value");
  showStatusValue("status-hybrid", "WAITING");
  showStatusValue("status-aes", "WAITING");
  showStatusValue("status-decryption", "WAITING");
  showDemoStage("demo-stage-bb84", "RUNNING", "running");
  showDemoStage("demo-stage-mlkem", "WAITING", "waiting");
  showDemoStage("demo-stage-hybrid", "WAITING", "waiting");
  showDemoStage("demo-stage-aes", "WAITING", "waiting");
  showDemoStage("demo-stage-receiver", "WAITING", "waiting");
}

function applyTheme(theme, persist = false) {
  const selected = theme === "light" ? "light" : "dark";
  document.documentElement.dataset.theme = selected;
  const toggle = byId("theme-toggle");
  if (toggle) {
    const light = selected === "light";
    toggle.textContent = light ? "Dark mode" : "Light mode";
    toggle.setAttribute("aria-label", `Switch to ${light ? "dark" : "light"} mode`);
    toggle.setAttribute("aria-pressed", String(light));
  }
  const themeColor = document.querySelector('meta[name="theme-color"]');
  if (themeColor) themeColor.content = selected === "light" ? "#eef4fb" : "#080d18";
  if (persist) {
    try { window.localStorage.setItem("quantumshield-theme", selected); } catch { /* Storage may be unavailable in private contexts. */ }
  }
}

let savedTheme = "dark";
try { savedTheme = window.localStorage.getItem("quantumshield-theme") || "dark"; } catch { /* Use the dark default when storage is unavailable. */ }
applyTheme(savedTheme);
byId("theme-toggle").addEventListener("click", () => {
  applyTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark", true);
});

function syncDepartmentWarning() {
  const sender = byId("sender-select");
  const receiver = byId("receiver-select");
  const composerButton = byId("composer-send-button");
  const sameDepartment = sender && receiver && sender.value && receiver.value && sender.value === receiver.value;
  document.querySelectorAll("#department-warning").forEach((warning) => warning.classList.toggle("hidden", !sameDepartment));
  if (composerButton) composerButton.disabled = sameDepartment;
}

function syncDepartmentSelects(changedSelect) {
  document.querySelectorAll(`#${changedSelect.id}`).forEach((select) => {
    if (select !== changedSelect) select.value = changedSelect.value;
  });
  syncDepartmentWarning();
}

function integrateDashboardSections() {
  const dashboard = byId("view-dashboard");
  const dashboardGrid = dashboard.querySelector(".dashboard-grid");
  const quantumVisualizer = document.querySelector("#view-bb84 .quantum-visualizer");
  if (quantumVisualizer && dashboardGrid) {
    quantumVisualizer.classList.add("dashboard-quantum");
    dashboard.insertBefore(quantumVisualizer, dashboardGrid.nextElementSibling);
  }

  ["view-bb84", "view-circuit", "view-attack", "view-monitoring"].forEach((id) => {
    const section = byId(id);
    const anchor = dashboard.querySelector(".status-grid");
    if (!section || !anchor) return;
    section.classList.remove("view", "active");
    section.classList.add("dashboard-feature-section");
    dashboard.insertBefore(section, anchor);
  });

  const historyBox = byId("message-history-list")?.closest(".history-box");
  const historyPanel = document.querySelector("#view-history .history-page-panel");
  if (historyBox && historyPanel) historyPanel.append(historyBox);
}

function updateMessageCounter() {
  const textarea = byId("message-textarea");
  const counter = byId("message-counter");
  if (!textarea || !counter) return;
  counter.textContent = `${Array.from(textarea.value).length} characters`;
}

function renderHistory(entries) {
  const list = byId("message-history-list");
  if (!list) return;
  if (!entries.length) {
    const empty = document.createElement("li");
    empty.textContent = "No recent messages yet.";
    list.replaceChildren(empty);
    return;
  }
  const items = entries.slice(0, 8).map((entry) => {
    const item = document.createElement("li");
    item.dataset.session = entry.session_id || "";
    const route = document.createElement("strong");
    route.textContent = `${entry.sender || "Sender"} → ${entry.receiver || "Receiver"}`;
    const summary = document.createElement("small");
    summary.textContent = `${entry.decision || "status"} · ${formatHistoryTime(entry.time)}`;
    const timings = document.createElement("small");
    timings.textContent = formatHistoryTimings(entry.timings_seconds, entry.blocked);
    const plaintext = document.createElement("p");
    plaintext.className = "history-plaintext";
    plaintext.textContent = typeof entry.decrypted_message === "string"
      ? entry.decrypted_message
      : entry.blocked
        ? "Message withheld; key establishment was rejected."
        : "Plaintext is shown after receiver authentication.";
    item.append(route, summary, timings, plaintext);
    return item;
  });
  list.replaceChildren(...items);
}
function formatHistoryTime(value) {
  if (!value) return "Time not returned";
  const timestamp = new Date(value);
  return Number.isNaN(timestamp.getTime())
    ? "Time not returned"
    : new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(timestamp);
}

function formatHistoryTimings(timings, blocked) {
  if (!timings) return "Transaction timings not returned";
  const duration = (seconds) => Number.isFinite(seconds) ? `${(seconds * 1000).toFixed(0)} ms` : "Not returned";
  const encryption = blocked ? "Not performed" : duration(timings.encryption);
  const decryption = blocked ? "Not performed" : duration(timings.decryption);
  const receiverDecryption = timings.receiver_decryption === undefined
    ? "Awaiting receiver"
    : duration(timings.receiver_decryption);
  return `Total ${duration(timings.total)} · validation ${duration(timings.validation)} · BB84 ${duration(timings.bb84_key_establishment)} · ML-KEM ${duration(timings.mlkem_key_establishment)} · encryption ${encryption} · decryption ${decryption} · receiver ${receiverDecryption}`;
}

const PIPELINE_STEP_TITLES = [
  "Message entered",
  "Random bits generated",
  "Random bases chosen",
  "Qubits prepared",
  "Quantum transmission",
  "Receiver measures",
  "Bases compared and key sifted",
  "QBER sample checked",
  "QBER security decision",
  "ML-KEM-768 key establishment",
  "Mode-separated key derivation",
  "AES-GCM encryption",
  "Ciphertext sent",
  "Receiver authenticates and decrypts",
  "Message tampering check",
  "Message delivered or withheld",
];

function renderPipelineStart() {
  const trace = PIPELINE_STEP_TITLES.map((title, index) => ({
    number: index + 1,
    title,
    what_happens: index === 0 ? "Submitting this message to the secure backend pipeline." : "Waiting for the preceding stage.",
    why_it_matters: "",
    status: index === 0 ? "running" : "pending",
    data: null,
  }));
  byId("pipeline-summary").textContent = "The backend is processing this message. No quantum values are shown until its response arrives.";
  byId("pipeline-session").textContent = "RUNNING";
  renderPipelineRows(trace, null, { completedThrough: 0, runningIndex: 0 });
}

function pipelineFinalStatus(step, response) {
  if (step.status === "done") return "completed";
  if (step.status === "blocked" && step.number === 9 && response?.key_status === "REJECTED") return "rejected";
  return step.status === "blocked" ? "blocked" : "pending";
}

function pipelineData(step, response) {
  if (!response) return [];
  const data = step.data || {};
  const arrays = response.bb84?.arrays || {};
  const sample = (name) => {
    const values = arrays[name]?.values;
    return Array.isArray(values) ? values.slice(0, 16).map(String).join("") : "Not returned";
  };
  const qber = response.sample_qber;
  const qberText = Number.isFinite(qber) ? `${(qber * 100).toFixed(1)}%` : "Not available";
  const accepted = !response.blocked;
  const senderFingerprint = response.key_fingerprints?.alice;
  const ciphertext = response.envelope?.ciphertext;

  switch (step.number) {
    case 1:
      return [["Route", `${response.sender} → ${response.receiver}`], ["Message length", `${data.characters ?? "—"} characters`]];
    case 2:
      return [["Qubits", String(data.qubits ?? response.bb84?.qubits_transmitted ?? "—")], ["Alice bit sample (not the final key)", sample("alice_bits")]];
    case 3:
      return [["Alice basis sample", data.alice || sample("alice_bases")], ["Bob basis sample", data.bob || sample("bob_bases")]];
    case 4:
      return [["Simulator", data.simulator || "Not returned"], ["Prepared qubits", String(data.circuit_positions ?? response.bb84?.qubits_transmitted ?? "Not returned")]];
    case 5: {
      const attack = typeof data.attack === "boolean" ? data.attack ? "Enabled" : "Disabled" : "Not returned";
      const intercept = Number.isFinite(data.intercept_fraction) ? String(data.intercept_fraction) : "Not returned";
      const noise = Number.isFinite(data.noise_probability) ? `${(data.noise_probability * 100).toFixed(1)}%` : "Not returned";
      return [["Eve interception", attack], ["Intercept fraction", intercept], ["Channel noise", noise]];
    }
    case 6:
      return [["Measured positions", String(data.measured_positions ?? "—")], ["Bob bit sample", sample("bob_bits")]];
    case 7:
      return [["Matching positions", `${response.matching_count ?? response.bb84?.matching_positions_count ?? data.matching ?? "—"}`], ["Sifted length", String(response.sifted_length ?? response.bb84?.sifted_length ?? data.sifted_length ?? "—")], ["Position sample", (response.bb84?.matching_positions || []).slice(0, 12).join(", ") || "None returned"]];
    case 8:
      return [["Public sample size", String(response.sample_size ?? response.bb84?.sample_size ?? data.sample_size ?? "—")], ["Sample QBER", qberText]];
    case 9:
      return [["BB84 decision", response.key_status || data.key_status || "Not returned"], ["QBER threshold", `${((response.security_status?.qber_threshold ?? 0.11) * 100).toFixed(1)}%`], ["Decision detail", response.security_mode === "ml-kem" ? "QBER is reported but rejected QKD material is not used in ML-KEM mode." : response.reason || data.reason || "No additional reason returned"]];
    case 10:
      return [["ML-KEM-768", data.status || "NOT_REQUIRED"], ["Encapsulation required", data.required ? "Yes" : "No"], ["Key establishment", "No private key or shared secret exposed"]];
    case 11:
      return [["Hybrid derivation", data.hybrid_derivation || "NOT_APPLICABLE"], ["KDF", "HKDF-SHA256 with mode and route domain separation"]];
    case 12:
      return [["AES-GCM encryption", response.security_status?.aes_gcm_encryption || "NOT_PERFORMED"], ["Cipher", data.cipher || "AES-256-GCM"], ["Authenticated route", data.aad || `${response.sender} -> ${response.receiver}`]];
    case 13:
      return accepted ? [["Ciphertext", ciphertext ? `${ciphertext.slice(0, 48)}${ciphertext.length > 48 ? "…" : ""}` : "Not returned"], ["Transmission", "Encrypted envelope stored for this session"]] : [["Ciphertext", "Not created"], ["Transmission", "Blocked by security decision"]];
    case 14:
      return accepted ? [["Decryption", "Authenticated and completed"], ["BB84 key match", typeof response.receiver?.fingerprints_match === "boolean" ? response.receiver.fingerprints_match ? "Yes" : "No" : "Not applicable"], ["Authentication", response.receiver?.authenticated ? "Valid" : "Not returned"]] : [["Decryption", "Not attempted"], ["Receiver status", "No ciphertext delivered"]];
    case 15:
      return [["Modified ciphertext", response.security_status?.tampering_detection || data.status || "NOT_TESTED"], ["AES-GCM action", "Rejected modified ciphertext"]];
    case 16:
      return accepted ? [["Delivery", "Authenticated message available in receiver inbox"], ["Plaintext", "Available after receiver authentication"]] : [["Delivery", "Withheld"], ["Reason", response.reason || "The required key establishment did not pass"]];
    default:
      return [];
  }
}

function renderPipelineRows(trace, response, progress = {}) {
  const list = byId("pipeline-list");
  list.replaceChildren();
  trace.forEach((step, index) => {
    const finalStatus = response ? pipelineFinalStatus(step, response) : step.status;
    let status = finalStatus;
    if (progress.finalFrom !== undefined && index >= progress.finalFrom) {
      status = finalStatus;
    } else if (index < (progress.completedThrough || 0)) {
      status = finalStatus;
    } else if (index === progress.runningIndex && finalStatus === "completed") {
      status = "running";
    } else if (response && index > (progress.runningIndex ?? -1)) {
      status = "pending";
    }

    const item = document.createElement("li");
    item.className = `pipeline-step status-${status}`;
    const number = document.createElement("span");
    number.className = "pipeline-number";
    number.textContent = String(step.number).padStart(2, "0");
    const content = document.createElement("div");
    content.className = "pipeline-step-content";
    const heading = document.createElement("div");
    heading.className = "pipeline-step-heading";
    const title = document.createElement("h4");
    title.textContent = step.title;
    const badge = document.createElement("span");
    badge.className = "pipeline-status";
    badge.textContent = status;
    heading.append(title, badge);
    const what = document.createElement("p");
    what.className = "pipeline-what";
    what.textContent = step.what_happens || "Waiting for this stage.";
    content.append(heading, what);
    if (step.why_it_matters) {
      const why = document.createElement("p");
      why.className = "pipeline-why";
      why.textContent = step.why_it_matters;
      content.append(why);
    }
    const entries = status === "pending" ? [] : pipelineData(step, response);
    if (entries.length) {
      const values = document.createElement("dl");
      values.className = "pipeline-values";
      entries.forEach(([label, value]) => {
        const row = document.createElement("div");
        const term = document.createElement("dt");
        term.textContent = label;
        const detail = document.createElement("dd");
        detail.textContent = value;
        row.append(term, detail);
        values.append(row);
      });
      content.append(values);
    }
    item.append(number, content);
    list.append(item);
  });
}

async function playPipeline(response) {
  const trace = response.step_trace;
  if (!Array.isArray(trace) || trace.length !== 16) {
    throw new Error("The message response did not contain the expected 16-step trace.");
  }
  const session = response.session_id || "session unavailable";
  byId("pipeline-session").textContent = `SESSION ${session.slice(0, 8).toUpperCase()}`;
  byId("pipeline-summary").textContent = "Backend returned its recorded trace; presenting the 16 stages in order.";

  for (let index = 0; index < trace.length; index += 1) {
    const status = pipelineFinalStatus(trace[index], response);
    if (status === "blocked" || status === "rejected") {
      renderPipelineRows(trace, response, { completedThrough: index, finalFrom: index });
      const attackEnabled = Boolean(trace[4]?.data?.attack);
      const failure = attackEnabled ? "Security check failed — possible interception detected." : "Security check failed.";
      byId("pipeline-summary").textContent = `${failure} QBER ${formatRate(response.sample_qber)} · decision ${response.key_status}. Key rejected; message blocked. No ciphertext was created or transmitted, and no delivery occurred. QBER does not prove Eve.`;
      return;
    }
    renderPipelineRows(trace, response, { completedThrough: index, runningIndex: index });
    await delay(90);
    renderPipelineRows(trace, response, { completedThrough: index + 1, runningIndex: index + 1 });
  }
  renderPipelineRows(trace, response, { completedThrough: trace.length });
  byId("pipeline-summary").textContent = "Key establishment completed, AES-GCM authenticated the message, and modified ciphertext was rejected.";
}

function renderPipelineRequestFailure(error) {
  const trace = PIPELINE_STEP_TITLES.map((title, index) => ({
    number: index + 1,
    title,
    what_happens: index === 0 ? error.message : "Not reached because the request did not complete.",
    why_it_matters: "",
    status: index === 0 ? "blocked" : "blocked",
    data: null,
  }));
  byId("pipeline-summary").textContent = "The backend did not return a message pipeline result; no cryptographic values are available to display.";
  byId("pipeline-session").textContent = "REQUEST FAILED";
  renderPipelineRows(trace, { blocked: true });
}

function formatQber(value) {
  return Number.isFinite(value) ? `${(value * 100).toFixed(1)}%` : "Not available";
}

function renderKeyUniqueness(records) {
  const list = byId("key-uniqueness-list");
  const status = byId("key-uniqueness-status");
  byId("key-uniqueness-count").textContent = `${records.length} / 5`;
  list.replaceChildren();
  if (!records.length) {
    status.textContent = "No message sessions recorded yet.";
    const empty = document.createElement("li");
    empty.className = "pipeline-placeholder";
    empty.textContent = "Successful fresh sessions will appear here.";
    list.append(empty);
    return;
  }

  const successful = records.filter(({ entry, detail }) => (detail?.key_status || entry.decision) === "ACCEPTED" && !entry.blocked);
  const fingerprintCounts = new Map();
  successful.forEach(({ entry, detail }) => {
    const fingerprint = entry.key_fingerprint || detail?.key_fingerprints?.alice;
    if (fingerprint) fingerprintCounts.set(fingerprint, (fingerprintCounts.get(fingerprint) || 0) + 1);
  });
  const allUnique = [...fingerprintCounts.values()].every((count) => count === 1);
  status.textContent = successful.length
    ? allUnique ? "Successful fresh sessions shown have distinct key fingerprints." : "A fingerprint repeats among the successful sessions shown."
    : "No successful fresh sessions in the recent history.";

  records.forEach(({ entry, detail }) => {
    const fingerprint = entry.key_fingerprint || detail?.key_fingerprints?.alice || "Not returned";
    const decision = detail?.key_status || entry.decision || "UNKNOWN";
    const isSuccessful = decision === "ACCEPTED" && !entry.blocked;
    const matching = detail?.matching_count ?? detail?.bb84?.matching_positions_count ?? entry.matching_count;
    const sifted = detail?.sifted_length ?? detail?.bb84?.sifted_length;
    const qber = detail?.sample_qber ?? entry.qber;
    const duplicate = isSuccessful && fingerprintCounts.get(fingerprint) > 1;
    const item = document.createElement("li");
    item.className = `key-uniqueness-item ${isSuccessful ? "accepted" : "blocked"}`;
    const route = document.createElement("strong");
    route.textContent = `${entry.sender} → ${entry.receiver}`;
    const decisionBadge = document.createElement("span");
    decisionBadge.className = "uniqueness-decision";
    decisionBadge.textContent = decision;
    const session = document.createElement("code");
    session.textContent = `Session ${entry.session_id || detail?.session_id || "Not returned"}`;
    const fingerprintLine = document.createElement("code");
    fingerprintLine.textContent = `Key fingerprint ${fingerprint}`;
    const metrics = document.createElement("small");
    metrics.textContent = `QBER ${formatQber(qber)} · matching ${matching ?? "not returned"} · sifted ${sifted ?? "not recorded"}`;
    const uniqueness = document.createElement("small");
    uniqueness.className = duplicate ? "fingerprint-repeat" : "fingerprint-unique";
    uniqueness.textContent = isSuccessful ? duplicate ? "Fingerprint repeats in these recent sessions" : "Unique among recent successful sessions" : entry.blocked ? "Message blocked; no ciphertext sent" : "No successful key established";
    item.append(route, decisionBadge, session, fingerprintLine, metrics, uniqueness);
    list.append(item);
  });
}

async function refreshKeyUniqueness(quiet = false) {
  try {
    const response = await api("/api/messages");
    const recent = (response.messages || []).slice(0, 5);
    const records = await Promise.all(recent.map(async (entry) => {
      try {
        const detail = await api(`/api/messages/${encodeURIComponent(entry.message_id)}`);
        return { entry, detail };
      } catch {
        return { entry, detail: null };
      }
    }));
    renderKeyUniqueness(records);
  } catch (error) {
    if (!quiet) toast(error.message);
  }
}

async function loadDepartments() {
  try {
    const departments = await api("/api/departments");
    state.departments = departments;
    const senders = document.querySelectorAll("#sender-select");
    const receivers = document.querySelectorAll("#receiver-select");
    if (!senders.length || !receivers.length) return;
    const options = departments.map((item) => `<option value="${item.name}">${item.name}</option>`).join("");
    senders.forEach((sender) => {
      sender.innerHTML = options;
      sender.value = "Defence";
    });
    receivers.forEach((receiver) => {
      receiver.innerHTML = options;
      receiver.value = "Home Affairs";
    });
    syncDepartmentWarning();
  } catch (error) {
    toast(error.message);
  }
}

async function refreshStatus() {
  try {
    const status = await api("/api/status");
    const keyStatus = status.latest_key_status || "NOT_RUN";
    showStatusValue("status-qkd", keyStatus);
    showStatusValue("status-qkd-inline", keyStatus);
    showStatusValue("status-pqc-inline", status.pqc?.status || "ML-KEM-768 unavailable", "pqc-status-value");
    showStatusValue("status-communication", status.communication_status.replaceAll("_", " "));
    showStatusValue("status-interception-inline", status.interception_status.replaceAll("_", " "));
    byId("dashboard-session").textContent = status.latest_session_id ? `SESSION ${status.latest_session_id.slice(0, 8).toUpperCase()}` : "NO ACTIVE SESSION";
  } catch (error) {
    toast(error.message);
  }
}

function updateSecurityStatus(response) {
  const status = response.security_status || {};
  const bb84Status = status.bb84 || response.key_status || "Not assessed";
  const accepted = bb84Status === "ACCEPTED";
  const qberStatus = Number.isFinite(status.qber)
    ? `${formatQber(status.qber)} / threshold ${formatQber(status.qber_threshold)} · key ${response.final_key_length ?? "not returned"} bits`
    : "Not assessed";
  const mlkemStatus = status.mlkem || "NOT_REPORTED";
  const hybridStatus = status.hybrid_derivation || "NOT_APPLICABLE";
  const encryptionStatus = status.aes_gcm_encryption || "NOT_PERFORMED";
  const receiverStatus = status.aes_gcm_decryption || "NOT_PERFORMED";
  showStatusValue("status-qkd", bb84Status);
  showStatusValue("status-qkd-inline", bb84Status);
  showStatusValue("status-qber", qberStatus);
  showStatusValue("status-pqc", mlkemStatus, "pqc-status-value");
  showStatusValue("status-hybrid", hybridStatus);
  showStatusValue("status-aes", encryptionStatus);
  showStatusValue("status-decryption", receiverStatus);
  showStatusValue("status-communication", response.blocked ? "MESSAGE BLOCKED" : "ENCRYPTED / SENT");
  showDemoStage(
    "demo-stage-bb84",
    Number.isFinite(status.qber) ? `${bb84Status} · QBER ${formatQber(status.qber)}` : bb84Status,
    accepted ? "done" : response.blocked ? "rejected" : "failed",
  );
  showDemoStage("demo-stage-mlkem", mlkemStatus, mlkemStatus === "ESTABLISHED" ? "done" : "waiting");
  showDemoStage("demo-stage-hybrid", hybridStatus, hybridStatus === "DERIVED" ? "done" : "waiting");
  showDemoStage("demo-stage-aes", encryptionStatus, encryptionStatus === "ENCRYPTED" ? "done" : "waiting");
  showDemoStage(
    "demo-stage-receiver",
    receiverStatus === "AUTHENTICATED" ? "AUTHENTICATED · READY TO DISPLAY" : receiverStatus,
    receiverStatus === "AUTHENTICATED" ? "done" : "waiting",
  );
}

function formatRate(value) {
  return value == null ? "INSUFFICIENT DATA" : `${(value * 100).toFixed(1)}%`;
}

function animationValue(values, index) {
  return Array.isArray(values) && index < values.length && values[index] != null
    ? String(values[index])
    : "Not returned";
}

function pauseQuantumTimer() {
  if (state.quantumTimer !== null) window.clearInterval(state.quantumTimer);
  state.quantumTimer = null;
}

function updateQuantumPosition() {
  document.querySelectorAll(".qubit-state").forEach((card, index) => {
    card.classList.toggle("is-current", index === state.quantumIndex);
    const revealed = index <= state.quantumIndex;
    card.classList.toggle("is-unrevealed", !revealed);
    card.setAttribute("aria-hidden", String(!revealed));
    const result = card.querySelector(".qubit-state-heading span");
    result.textContent = revealed ? result.dataset.returnedLabel : "Pending reveal";
    card.querySelectorAll(".qubit-value-row strong").forEach((value) => {
      value.textContent = revealed ? value.dataset.returnedValue : "Pending reveal";
    });
  });
  byId("quantum-progress").textContent = state.quantumStates.length
    ? `${state.quantumIndex + 1} / ${state.quantumStates.length}`
    : "0 / 0";
}

function pauseQuantumAnimation() {
  pauseQuantumTimer();
  if (state.quantumStates.length) byId("quantum-visualizer-status").textContent = "Paused. Use Step to inspect a returned state or Play to continue.";
}

function playQuantumAnimation() {
  if (!state.quantumStates.length || state.quantumTimer !== null) return;
  if (state.quantumIndex >= state.quantumStates.length - 1) state.quantumIndex = 0;
  updateQuantumPosition();
  byId("quantum-visualizer-status").textContent = "Playing returned BB84 states.";
  state.quantumTimer = window.setInterval(() => {
    if (state.quantumIndex >= state.quantumStates.length - 1) {
      pauseQuantumTimer();
      byId("quantum-visualizer-status").textContent = "Animation complete. Replay to view these returned states again.";
      return;
    }
    state.quantumIndex += 1;
    updateQuantumPosition();
  }, Number(byId("quantum-speed").value));
}

function renderQuantumAnimation(result) {
  pauseQuantumTimer();
  state.quantumIndex = 0;
  state.quantumStates = [];
  const grid = byId("qubit-grid");
  if (!grid) return;
  const arrays = result.arrays || {};
  const names = ["alice_bits", "alice_bases", "bob_bases", "bob_bits", "matching_mask"];
  const lengths = names.map((name) => Array.isArray(arrays[name]?.values) ? arrays[name].values.length : 0);
  const count = Math.min(32, Math.max(0, ...lengths));
  grid.replaceChildren();
  byId("quantum-run-label").textContent = result.attack_enabled ? "ATTACK RUN" : "BB84 RUN";
  byId("quantum-eve-arrow").classList.toggle("hidden", !result.attack_enabled);
  byId("quantum-eve-node").classList.toggle("hidden", !result.attack_enabled);

  const controls = ["quantum-play", "quantum-pause", "quantum-step", "quantum-replay", "quantum-speed"];
  controls.forEach((id) => { byId(id).disabled = count === 0; });
  if (count === 0) {
    const empty = document.createElement("p");
    empty.className = "qubit-empty";
    empty.textContent = "Not returned. The backend response contains no BB84 state arrays.";
    grid.append(empty);
    byId("quantum-progress").textContent = "0 / 0";
    byId("quantum-visualizer-status").textContent = "Insufficient data to visualize transmitted states.";
    return;
  }

  for (let index = 0; index < count; index += 1) {
    const aliceBit = arrays.alice_bits?.values?.[index];
    const bobBit = arrays.bob_bits?.values?.[index];
    const rawMatch = arrays.matching_mask?.values?.[index];
    const matchReturned = rawMatch != null;
    const matching = matchReturned && Boolean(rawMatch);
    const error = matching && aliceBit != null && bobBit != null && aliceBit !== bobBit;
    const card = document.createElement("article");
    const stateClasses = !matchReturned ? ["state-unknown"] : !matching ? ["state-discarded"] : error ? ["state-accepted", "state-error"] : ["state-accepted"];
    card.className = `qubit-state ${stateClasses.join(" ")}`;
    card.setAttribute("role", "listitem");
    const heading = document.createElement("div");
    heading.className = "qubit-state-heading";
    const position = document.createElement("strong");
    position.textContent = `Q${index + 1}`;
    const result = document.createElement("span");
    result.textContent = !matchReturned ? "Not returned" : !matching ? "Discarded" : error ? "MATCH · ERROR" : "MATCH · ACCEPTED";
    result.dataset.returnedLabel = result.textContent;
    heading.append(position, result);
    card.append(heading);
    [
      ["Sender bit", animationValue(arrays.alice_bits?.values, index)],
      ["Sender basis", animationValue(arrays.alice_bases?.values, index)],
      ["Receiver basis", animationValue(arrays.bob_bases?.values, index)],
      ["Measurement", animationValue(arrays.bob_bits?.values, index)],
    ].forEach(([label, value]) => {
      const row = document.createElement("div");
      row.className = "qubit-value-row";
      const name = document.createElement("span");
      name.textContent = label;
      const data = document.createElement("strong");
      data.textContent = value;
      data.dataset.returnedValue = value;
      row.append(name, data);
      card.append(row);
    });
    grid.append(card);
    state.quantumStates.push({ index, matching, error });
  }

  updateQuantumPosition();
  const partial = count < 24 || lengths.some((length) => length < count);
  byId("quantum-visualizer-status").textContent = partial
    ? `Insufficient data for 24 complete states; showing ${count} actual returned positions. Missing fields are marked Not returned.`
    : `Showing the first ${count} actual backend-returned positions. Matching bases are accepted; differing bases are discarded.`;
  const reducedMotion = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
  if (reducedMotion) {
    byId("quantum-visualizer-status").textContent += " Reduced-motion preference detected; playback is paused until you choose Play.";
  } else {
    playQuantumAnimation();
  }
}

function renderAttackVisualization(result) {
  const attackEnabled = Boolean(result.attack_enabled);
  const rejected = result.key_status === "REJECTED";
  const insufficient = result.key_status === "INSUFFICIENT_DATA";
  const eveNode = byId("attack-eve-node");
  const eveLink = byId("attack-eve-link");
  eveNode.classList.toggle("hidden", !attackEnabled);
  eveLink.classList.toggle("hidden", !attackEnabled);
  byId("attack-flow").classList.toggle("attacking", attackEnabled);

  const receiverNode = byId("attack-receiver-node");
  if (rejected) receiverNode.textContent = "RECEIVER · MESSAGE BLOCKED";
  else if (insufficient) receiverNode.textContent = "RECEIVER · NOT ASSESSED";
  else receiverNode.textContent = "RECEIVER · KEY ONLY (NO MESSAGE SENT)";

  const qber = formatRate(result.sample_qber);
  const summary = byId("attack-result-summary");
  summary.className = "attack-result-summary";
  if (rejected) {
    summary.classList.add("attack-result-failed");
    const detection = attackEnabled ? "Security check failed — possible interception detected" : "Security check failed";
    summary.textContent = `${detection} · QBER ${qber} · decision ${result.key_status}. Key rejected; message blocked. No ciphertext was created or transmitted, and no delivery occurred. QBER can also rise from noise or faults and does not prove Eve.`;
  } else if (insufficient) {
    summary.classList.add("attack-result-insufficient");
    summary.textContent = `Security decision: insufficient data · QBER ${qber}. The key was not accepted; no ciphertext or delivery is shown.`;
  } else if (attackEnabled) {
    summary.classList.add("attack-result-observed");
    summary.textContent = `Eve interception was simulated · QBER ${qber} · key ${result.key_status}. QBER is consistent with possible interception but does not prove its cause. This BB84 run did not send a message.`;
  } else {
    summary.textContent = `No Eve interception was simulated · QBER ${qber} · security decision ${result.key_status}.`;
  }
}

if (byId("quantum-play")) {
  byId("quantum-play").addEventListener("click", playQuantumAnimation);
  byId("quantum-pause").addEventListener("click", pauseQuantumAnimation);
  byId("quantum-step").addEventListener("click", () => {
    pauseQuantumTimer();
    if (state.quantumStates.length) state.quantumIndex = Math.min(state.quantumIndex + 1, state.quantumStates.length - 1);
    updateQuantumPosition();
    byId("quantum-visualizer-status").textContent = "Paused at the selected returned BB84 state.";
  });
  byId("quantum-replay").addEventListener("click", () => {
    pauseQuantumTimer();
    state.quantumIndex = 0;
    updateQuantumPosition();
    byId("quantum-visualizer-status").textContent = "Replaying returned BB84 states.";
    playQuantumAnimation();
  });
  byId("quantum-speed").addEventListener("change", () => {
    if (state.quantumTimer === null) return;
    pauseQuantumTimer();
    playQuantumAnimation();
  });
}

function renderRun(result) {
  state.currentRun = result;
  state.keyVerifiedSession = null;
  state.currentCircuit = result.attack_enabled ? "attack" : "normal";
  document.querySelectorAll("[data-circuit]").forEach((button) => {
    button.classList.toggle("selected", button.dataset.circuit === state.currentCircuit);
  });
  const arrays = result.arrays;
  byId("metric-qubits").textContent = result.qubits_transmitted;
  byId("metric-matching").textContent = `${result.matching_positions_count} / ${result.qubits_transmitted}`;
  byId("metric-sifted").textContent = result.sifted_length;
  byId("metric-qber").textContent = formatRate(result.sample_qber);
  byId("metric-key").textContent = result.final_key_length;
  const line = byId("decision-line");
  line.className = `decision-line ${result.key_status.toLowerCase()}`;
  byId("decision-status").textContent = result.key_status === "ACCEPTED" ? "KEY ACCEPTED" : result.key_status === "REJECTED" ? "KEY REJECTED" : "INSUFFICIENT DATA";
  byId("decision-reason").textContent = result.reason;
  renderQuantumAnimation(result);
  byId("table-count").textContent = `First ${arrays.alice_bits.values.length} of ${result.qubits_transmitted} positions`;
  const rows = arrays.alice_bits.values.map((aliceBit, index) => {
    const matches = Boolean(arrays.matching_mask.values[index]);
    const bobBit = arrays.bob_bits.values[index];
    const error = matches && aliceBit !== bobBit;
    const rowClass = error ? "error" : matches ? "match" : "discard";
    const resultLabel = error ? '<span class="error-pill">ERROR</span>' : matches ? '<span class="match-pill">MATCH</span>' : '<span class="discard-pill">DISCARD</span>';
    return `<tr class="${rowClass}"><td>${index}</td><td>${aliceBit}</td><td>${arrays.alice_bases.values[index]}</td><td>${arrays.bob_bases.values[index]}</td><td>${bobBit}</td><td>${resultLabel}</td></tr>`;
  });
  byId("bb84-table").innerHTML = rows.join("") || '<tr><td colspan="6" class="empty-cell">No positions returned.</td></tr>';
  byId("dashboard-session").textContent = `SESSION ${result.session_id.slice(0, 8).toUpperCase()}`;
  byId("monitor-qubits").textContent = result.qubits_transmitted;
  byId("monitor-matching").textContent = result.matching_positions_count;
  byId("monitor-sifted").textContent = result.sifted_length;
  byId("monitor-qber").textContent = formatRate(result.sample_qber);
  byId("monitor-attack").textContent = result.attack_enabled ? "INTERCEPT & RESEND" : "NORMAL";
  byId("monitor-interception").textContent = result.interception_flag ? "POSSIBLE DETECTION" : result.key_status === "INSUFFICIENT_DATA" ? "NOT ASSESSED" : "NOT INDICATED";
  byId("monitor-key-status").textContent = result.key_status;
  byId("monitor-message").textContent = state.encrypted ? "ENCRYPTED / SENT" : "NOT SENT";
  byId("monitor-decision").textContent = `Latest run: ${result.key_status} · QBER ${formatRate(result.sample_qber)} · ${result.interception_flag ? "possible interception signal" : "no interception signal indicated"}. QBER is not proof of cause.`;
  byId("attack-qubits").textContent = result.qubits_transmitted;
  byId("attack-matching").textContent = result.matching_positions_count;
  byId("attack-sifted").textContent = result.sifted_length;
  byId("attack-qber").textContent = formatRate(result.sample_qber);
  byId("attack-key-status").textContent = result.key_status;
  byId("attack-interception").textContent = result.interception_flag ? "POSSIBLE DETECTION" : result.key_status === "INSUFFICIENT_DATA" ? "NOT ASSESSED" : "NOT INDICATED";
  const attackPill = byId("attack-status-pill");
  attackPill.textContent = result.attack_enabled ? "ATTACK MODE" : "NORMAL MODE";
  attackPill.className = `status-pill ${result.key_status.toLowerCase()}`;
  renderAttackVisualization(result);
  byId("encrypt-send").disabled = true;
  byId("verify-result").textContent = result.key_status === "ACCEPTED" ? "Key available · verify before sending" : `NOT VERIFIED · ${result.key_status}`;
  byId("verify-result").className = `inline-status ${result.key_status === "ACCEPTED" ? "" : "bad"}`;
  refreshStatus();
  if (state.currentRun) loadCircuit();
}

async function runSimulation(attack = false) {
  const button = byId(attack ? "attack-run" : "run-normal");
  const loading = byId("run-loading");
  const n = Number(byId("qubit-count").value || 256);
  state.lastRequest = { n_qubits: n, attack, intercept_fraction: 1, qber_sample_fraction: .25, qber_threshold: .11, seed: 7 };
  button.disabled = true;
  loading.classList.remove("hidden");
  try {
    const result = await api("/api/bb84/run", { method: "POST", body: JSON.stringify(state.lastRequest) });
    state.encrypted = null;
    byId("cipher-output").classList.add("hidden");
    byId("decrypted-output").classList.add("hidden");
    byId("receiver-state").classList.remove("hidden");
    byId("decrypt-message").disabled = true;
    renderRun(result);
    if (attack) setView("attack");
    else if (button.id === "run-normal") setView("bb84");
  } catch (error) {
    toast(error.message);
  } finally {
    button.disabled = false;
    loading.classList.add("hidden");
  }
}

byId("run-normal").addEventListener("click", () => runSimulation(false));
byId("attack-run").addEventListener("click", () => runSimulation(true));
byId("attack-normal").addEventListener("click", () => runSimulation(false));

async function loadCircuit() {
  if (!state.currentRun) return;
  const attackMode = state.currentCircuit === "attack";
  if (attackMode && !state.currentRun.attack_enabled) {
    byId("circuit-image").innerHTML = '<span class="empty-state">Run an attack simulation to view its attack circuit.</span>';
    byId("circuit-text").textContent = "Attack-mode circuit is not available for this run.";
    return;
  }
  byId("circuit-image").innerHTML = '<span class="loading"><i></i>DRAWING CIRCUIT</span>';
  try {
    const data = await api(`/api/bb84/${state.currentRun.session_id}/circuit`);
    const circuit = attackMode ? data.attack : data.normal;
    byId("circuit-label").textContent = attackMode ? "Intercept-and-resend display circuit" : "Normal transmission circuit";
    byId("circuit-image").innerHTML = `<img alt="Qiskit ${attackMode ? "attack" : "normal"} circuit drawing" src="data:image/png;base64,${circuit.png_base64}">`;
    byId("circuit-text").textContent = circuit.text;
  } catch (error) {
    byId("circuit-image").innerHTML = '<span class="empty-state">Circuit drawing failed.</span>';
    toast(error.message);
  }
}

document.querySelectorAll("[data-circuit]").forEach((button) => button.addEventListener("click", () => {
  state.currentCircuit = button.dataset.circuit;
  document.querySelectorAll("[data-circuit]").forEach((item) => item.classList.toggle("selected", item === button));
  loadCircuit();
}));
byId("reload-circuit").addEventListener("click", loadCircuit);

byId("verify-key").addEventListener("click", () => {
  if (!state.currentRun) {
    toast("Run BB84 before verifying a key.");
    return;
  }
  const accepted = state.currentRun.key_status === "ACCEPTED";
  byId("verify-result").textContent = accepted ? "VERIFIED · key accepted" : `NOT VERIFIED · ${state.currentRun.key_status}`;
  byId("verify-result").className = `inline-status ${accepted ? "ok" : "bad"}`;
  state.keyVerifiedSession = accepted ? state.currentRun.session_id : null;
  syncDepartmentWarning();
});

document.querySelectorAll("#sender-select, #receiver-select").forEach((element) => {
  element.addEventListener("change", () => syncDepartmentSelects(element));
});

const messageTextarea = byId("message-textarea");
if (messageTextarea) {
  messageTextarea.addEventListener("input", updateMessageCounter);
  updateMessageCounter();
}

const advancedToggle = byId("advanced-toggle");
const advancedPanel = byId("advanced-panel");
if (advancedToggle && advancedPanel) {
  advancedToggle.addEventListener("click", () => {
    const isHidden = advancedPanel.classList.toggle("hidden");
    advancedToggle.setAttribute("aria-expanded", String(!isHidden));
    advancedToggle.querySelector("span").textContent = isHidden ? "▾" : "▴";
  });
}

const composerSendButton = byId("composer-send-button");
if (composerSendButton) {
  composerSendButton.addEventListener("click", async () => {
    const sender = byId("sender-select")?.value || "Defence";
    const receiver = byId("receiver-select")?.value || "Home Affairs";
    const sameDepartment = sender === receiver;
    if (sameDepartment) {
      toast("Sender and receiver must be different departments. Please select different departments.");
      syncDepartmentWarning();
      return;
    }
    const spinner = byId("composer-spinner");
    const message = byId("message-textarea")?.value || "";
    if (!message.trim()) {
      toast("Please enter a message before sending.");
      return;
    }
    resetLiveSecurityStatus();
    showStatusValue("status-communication", "IN PROGRESS");
    state.encrypted = null;
    byId("dashboard-decrypt-button").disabled = true;
    byId("dashboard-decrypted-message").textContent = "";
    byId("dashboard-decrypted-message").classList.add("hidden");
    byId("dashboard-decrypt-error").textContent = "";
    byId("dashboard-decrypt-error").classList.add("hidden");
    byId("receiver-inbox").textContent = "Receiver: security checks are in progress.";
    if (spinner) spinner.classList.remove("hidden");
    composerSendButton.disabled = true;
    try {
      const response = await api("/api/messages/send", {
        method: "POST",
        body: JSON.stringify({
          sender,
          receiver,
          message,
          security_mode: "hybrid",
          n_qubits: Number(byId("qubits-input")?.value || 256),
          attack: Boolean(byId("eve-toggle")?.checked),
          intercept_fraction: 1.0,
          qber_threshold: Number(byId("qber-threshold")?.value || 0.11),
          noise_probability: 0.0,
          seed: byId("seed-input") && byId("seed-input").value !== "" ? Number(byId("seed-input").value) : null,
        }),
      });
      updateSecurityStatus(response);
      state.encrypted = response.envelope || null;
      byId("dashboard-decrypt-button").disabled = response.blocked || !state.encrypted;
      byId("dashboard-decrypted-message").classList.add("hidden");
      byId("dashboard-decrypt-error").classList.add("hidden");
      byId("dashboard-decrypted-message").textContent = "";
      if (response.bb84) {
        renderRun({
          ...response.bb84,
          session_id: response.session_id,
          attack_enabled: Boolean(response.step_trace?.[4]?.data?.attack),
          reason: response.reason,
        });
      }
      await refreshHistory();
      const inbox = byId("receiver-inbox");
      if (inbox && response.blocked) {
        inbox.textContent = `Receiver: ${receiver} received no message – ${response.reason || "key rejected"}.`;
      } else if (inbox) {
        inbox.textContent = `Receiver: ${receiver} has an encrypted message. Decrypt it to display the contents.`;
      }
      toast(response.blocked ? (response.reason || "Message withheld.") : "Encrypted and sent securely.");
    } catch (error) {
      const mlkemFailed = error.message.includes("ML-KEM-768 key establishment failed");
      showStatusValue("status-qkd", "RESULT NOT RETURNED");
      showStatusValue("status-qkd-inline", "RESULT NOT RETURNED");
      showStatusValue("status-qber", "RESULT NOT RETURNED");
      showStatusValue("status-pqc", mlkemFailed ? "FAILED" : "NOT PERFORMED", "pqc-status-value");
      showStatusValue("status-hybrid", "NOT PERFORMED");
        showStatusValue("status-aes", "NOT PERFORMED");
        showStatusValue("status-decryption", "NOT PERFORMED");
      showStatusValue("status-communication", "MESSAGE NOT SENT");
      showDemoStage("demo-stage-bb84", "RESULT NOT RETURNED", "failed");
      showDemoStage("demo-stage-mlkem", mlkemFailed ? "FAILED" : "NOT PERFORMED", mlkemFailed ? "failed" : "waiting");
      showDemoStage("demo-stage-hybrid", "NOT PERFORMED", "waiting");
      showDemoStage("demo-stage-aes", "NOT PERFORMED", "waiting");
      showDemoStage("demo-stage-receiver", "NOT PERFORMED", "waiting");
      byId("receiver-inbox").textContent = "Receiver: message was not sent.";
      toast(error.message);
    } finally {
      if (spinner) spinner.classList.add("hidden");
      syncDepartmentWarning();
    }
  });
}

byId("dashboard-decrypt-button").addEventListener("click", async () => {
  const button = byId("dashboard-decrypt-button");
  const output = byId("dashboard-decrypted-message");
  const error = byId("dashboard-decrypt-error");
  error.classList.add("hidden");
  if (!state.currentRun || !state.encrypted) {
    error.textContent = "No encrypted message is available for decryption.";
    error.classList.remove("hidden");
    return;
  }
  button.disabled = true;
  button.textContent = "Decrypting…";
  output.textContent = "";
  output.classList.add("hidden");
  try {
    const response = await api("/api/message/receive", {
      method: "POST",
      body: JSON.stringify({ session_id: state.currentRun.session_id }),
    });
    if (!response.authenticated || typeof response.message !== "string") {
      throw new Error("Message authentication failed; plaintext was withheld.");
    }
    output.textContent = response.message;
    showStatusValue("status-decryption", "AUTHENTICATED");
    showDemoStage("demo-stage-receiver", "AUTHENTICATED · MESSAGE RELEASED", "done");
    showStatusValue("status-communication", "MESSAGE RECEIVED");
    output.classList.remove("hidden");
    byId("receiver-inbox").textContent = "Receiver: message authenticated and decrypted.";
    await refreshHistory();
  } catch (cause) {
    showStatusValue("status-decryption", "FAILED");
    showDemoStage("demo-stage-receiver", "FAILED · PLAINTEXT WITHHELD", "failed");
    output.textContent = "";
    output.classList.add("hidden");
    error.textContent = cause.message;
    error.classList.remove("hidden");
    button.disabled = false;
  } finally {
    button.textContent = "Decrypt Message";
  }
});

async function refreshHistory() {
  try {
    const response = await api("/api/messages");
    const entries = await Promise.all((response.messages || []).slice(0, 8).map(async (entry) => {
      try {
        const detail = await api(`/api/messages/${encodeURIComponent(entry.message_id)}`);
        return { ...entry, timings_seconds: detail.timings_seconds, blocked: detail.blocked };
      } catch {
        return entry;
      }
    }));
    renderHistory(entries);
  } catch (error) {
    toast(error.message);
  }
}

byId("encrypt-send").addEventListener("click", async () => {
  const sender = byId("sender-select")?.value || "Defence";
  const receiver = byId("receiver-select")?.value || "Home Affairs";
  const sameDepartment = sender === receiver;
  if (sameDepartment) {
    toast("Sender and receiver must be different departments. Please select different departments.");
    syncDepartmentWarning();
    return;
  }
  try {
    const payload = {
      sender,
      receiver,
      message: byId("actual-message").value,
      n_qubits: Number(byId("qubit-count").value || 256),
      attack: Boolean(state.lastRequest && state.lastRequest.attack),
      intercept_fraction: 1.0,
      noise_probability: 0.0,
      seed: state.lastRequest && state.lastRequest.seed,
    };
    const response = await api("/api/messages/send", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    const envelope = response.envelope || response.encrypted_message;
    state.encrypted = envelope;
    if (envelope) {
      byId("ciphertext-value").textContent = envelope.ciphertext;
      byId("nonce-value").textContent = envelope.nonce;
      byId("sender-fingerprint").textContent = response.key_fingerprints?.alice || "";
      byId("cipher-output").classList.remove("hidden");
      byId("decrypt-message").disabled = false;
      byId("monitor-message").textContent = "ENCRYPTED / SENT";
      byId("receiver-state").classList.add("hidden");
    }
    toast(response.blocked ? (response.reason || "Message withheld.") : "Actual message encrypted and sent.");
  } catch (error) {
    toast(error.message);
  }
});

byId("decrypt-message").addEventListener("click", async () => {
  if (!state.currentRun || !state.encrypted) return;
  try {
    const response = await api("/api/message/receive", {
      method: "POST",
      body: JSON.stringify({ session_id: state.currentRun.session_id }),
    });
    byId("recovered-message").textContent = response.message;
    byId("receiver-fingerprint").textContent = response.receiver_fingerprint;
    byId("fingerprint-match").textContent = response.fingerprints_match ? "FINGERPRINTS MATCH" : "FINGERPRINT MISMATCH";
    byId("decrypted-output").classList.remove("hidden");
    byId("receiver-state").classList.add("hidden");
    byId("monitor-message").textContent = "DECRYPTED / RECEIVED";
    toast("Receiver authenticated and recovered the message.");
  } catch (error) {
    toast(error.message);
  }
});

function destroyCharts() {
  if (state.qberChart) state.qberChart.destroy();
  state.qberChart = null;
}

function drawComparison(result) {
  if (!result) return;
  destroyCharts();
  const qberSeries = (summary) => {
    const values = Array.isArray(summary?.qber) ? summary.qber : [];
    const decisions = Array.isArray(summary?.decisions) ? summary.decisions : [];
    return values.map((value, index) => decisions[index] === "INSUFFICIENT_DATA" ? null : value);
  };
  const normal = qberSeries(result.normal);
  const attack = qberSeries(result.attack);
  const count = Math.max(normal.length, attack.length);
  const labels = Array.from({ length: count }, (_, index) => index + 1);
  const threshold = labels.map(() => Number.isFinite(result.threshold) ? result.threshold : null);
  state.qberChart = new Chart(byId("qber-chart"), {
    type: "line",
    data: { labels, datasets: [
      { label: "Normal", data: normal, borderColor: "#79aaff", backgroundColor: "#79aaff", pointRadius: 2, spanGaps: false },
      { label: "Attack", data: attack, borderColor: "#f07c70", backgroundColor: "#f07c70", pointRadius: 2, spanGaps: false },
      { label: "Threshold", data: threshold, borderColor: "#f1b86e", backgroundColor: "#f1b86e", pointRadius: 0, borderDash: [5, 4] },
    ] },
    options: chartOptions("QBER"),
  });
  updateComparisonDecision(result);
}

function chartOptions(title, maximum) {
  return {
    responsive: true,
    maintainAspectRatio: false,
    animation: { duration: 250 },
    plugins: { legend: { display: false }, tooltip: { enabled: true } },
    scales: {
      x: { grid: { color: "#253234" }, ticks: { color: "#82948e", maxTicksLimit: 8, font: { size: 9 } } },
      y: { min: 0, ...(maximum ? { max: maximum } : {}), grid: { color: "#253234" }, ticks: { color: "#82948e", font: { size: 9 } }, title: { display: true, text: title, color: "#71847f", font: { size: 9 } } },
    },
  };
}

function comparisonRate(value, available = true) {
  return !available || value == null || !Number.isFinite(value)
    ? "n/a – not enough data"
    : `${(value * 100).toFixed(1)}%`;
}

function updateComparisonDecision(result) {
  const normalDecisions = Array.isArray(result.normal?.decisions) ? result.normal.decisions : [];
  const attackDecisions = Array.isArray(result.attack?.decisions) ? result.attack.decisions : [];
  const decisionCount = (values) => {
    const valid = values.filter((decision) => decision !== "INSUFFICIENT_DATA");
    const rejected = valid.filter((decision) => decision === "REJECTED").length;
    return valid.length ? `${rejected}/${valid.length} rejected` : "n/a – not enough data";
  };
  const insufficient = result.insufficient_data_runs || {};
  const threshold = comparisonRate(result.threshold);
  byId("monitor-decision").textContent = `QBER threshold ${threshold} · attack ${decisionCount(attackDecisions)} · normal ${decisionCount(normalDecisions)} · insufficient runs normal ${insufficient.normal ?? "not returned"}, attack ${insufficient.attack ?? "not returned"}. High QBER may indicate possible interception but does not prove Eve.`;
}

function showComparisonSummary(result) {
  if (!result) return;
  const insufficient = result.insufficient_data_runs || {};
  const normalAvailable = (result.runs ?? 0) - (insufficient.normal ?? 0) > 0;
  const attackAvailable = (result.runs ?? 0) - (insufficient.attack ?? 0) > 0;
  const parts = [
    ["NORMAL MEAN QBER", comparisonRate(result.normal?.mean_qber, normalAvailable)],
    ["ATTACK MEAN QBER", comparisonRate(result.attack?.mean_qber, attackAvailable)],
    ["FALSE ALARM", comparisonRate(result.false_alarm_rate, normalAvailable)],
  ];
  const summary = byId("experiment-summary");
  summary.replaceChildren();
  parts.forEach(([label, value], index) => {
    const group = document.createElement("span");
    group.append(document.createTextNode(`${label} `));
    const metric = document.createElement("strong");
    metric.textContent = value;
    group.append(metric);
    summary.append(group);
    if (index < parts.length - 1) summary.append(document.createTextNode(" · "));
  });
}

async function pollJob(jobId, label) {
  const box = byId("job-progress");
  box.classList.remove("hidden");
  byId("job-label").textContent = label;
  let job;
  do {
    job = await api(`/api/experiments/${jobId}`);
    const progress = Math.max(0, Math.min(1, job.progress || 0));
    byId("progress-value").style.width = `${Math.max(5, progress * 100)}%`;
    byId("job-percent").textContent = `${Math.round(progress * 100)}%`;
    if (job.status === "running") await delay(700);
  } while (job.status === "running");
  if (job.status === "error") throw new Error(job.error || "Experiment failed.");
  byId("progress-value").style.width = "100%";
  byId("job-percent").textContent = "100%";
  return job.result;
}

byId("run-comparison").addEventListener("click", async () => {
  const button = byId("run-comparison");
  button.disabled = true;
  try {
    const comparisonJob = await api("/api/experiments/compare", {
      method: "POST",
      body: JSON.stringify({ runs: 10, n_qubits: 256, base_seed: 21 }),
    });
    const comparison = await pollJob(comparisonJob.job_id, "COMPARING NORMAL / ATTACK RUNS");
    drawComparison(comparison);
    showComparisonSummary(comparison);
    toast("Experiment data is current.");
  } catch (error) {
    toast(error.message);
  } finally {
    button.disabled = false;
    byId("job-progress").classList.add("hidden");
  }
});

async function loadLastComparison() {
  try {
    const response = await api("/api/experiments/last");
    if (response.result) {
      drawComparison(response.result);
      showComparisonSummary(response.result);
    }
  } catch (error) {
    toast(error.message);
  }
}

async function initialize() {
  integrateDashboardSections();
  byId("clock").textContent = new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" }).format(new Date());
  window.setInterval(() => { byId("clock").textContent = new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" }).format(new Date()); }, 1000);
  await loadDepartments();
  await refreshStatus();
  await refreshHistory();
  const last = await api("/api/experiments/last").catch(() => ({ result: null }));
  if (last.result) {
    drawComparison(last.result);
    showComparisonSummary(last.result);
  }
}

initialize();
