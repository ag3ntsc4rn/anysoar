"use strict";

// Live state of the console. The server is the source of truth: every change arrives as an
// "approval" event on /ui/stream, and the page re-renders from `approvals`.
const approvals = new Map();
const $ = (id) => document.getElementById(id);

async function call(path, options = {}) {
  const response = await fetch(path, {
    credentials: "same-origin",
    ...options,
    headers: { "Content-Type": "application/json", "X-Anysoar-Console": "1", ...options.headers },
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.error || `HTTP ${response.status}`);
  return body;
}

function toast(message) {
  const el = $("toast");
  el.textContent = message;
  el.classList.add("show");
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => el.classList.remove("show"), 2500);
}

function ago(ms) {
  const s = Math.max(0, Math.round((Date.now() - ms) / 1000));
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  return m < 60 ? `${m}m ${s % 60}s` : `${Math.floor(m / 60)}h ${m % 60}m`;
}

function card(approval) {
  const node = $("card-template").content.firstElementChild.cloneNode(true);
  const action = approval.action;
  node.dataset.id = approval.id;
  node.classList.toggle("destructive", action.tier === "destructive");
  node.querySelector(".tier").textContent = action.tier || "write";
  node.querySelector(".capability").textContent = action.capability || "";
  node.querySelector(".actor").textContent = approval.actor ? `asked by ${approval.actor}` : "";
  node.querySelector(".waited").dataset.since = approval.created;
  node.querySelector(".summary").textContent = action.summary;
  node.querySelector(".arguments").textContent = JSON.stringify(action.arguments ?? {}, null, 2);

  const form = node.querySelector("form");
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const decision = event.submitter?.value;
    if (!decision) return;
    form.querySelectorAll("button").forEach((b) => (b.disabled = true));
    try {
      await call(`/ui/approvals/${encodeURIComponent(approval.id)}/decide`, {
        method: "POST",
        body: JSON.stringify({ decision, reason: form.elements.reason.value }),
      });
      toast(decision === "approve" ? "Approved" : "Rejected");
    } catch (error) {
      toast(`Could not record the decision: ${error.message}`);
      form.querySelectorAll("button").forEach((b) => (b.disabled = false));
    }
  });
  return node;
}

function historyItem(approval) {
  const li = document.createElement("li");
  const badge = document.createElement("span");
  badge.className = `badge ${approval.status}`;
  badge.textContent = approval.status;
  const what = document.createElement("span");
  what.className = "what";
  what.textContent = approval.action.summary;
  const who = document.createElement("span");
  who.className = "who";
  const by = approval.status === "expired" ? "nobody decided in time" : `by ${approval.approver}`;
  const when = approval.decided ? new Date(approval.decided).toLocaleTimeString() : "";
  who.textContent = [by, approval.reason && `"${approval.reason}"`, when].filter(Boolean).join(" · ");
  li.append(badge, what, who);
  return li;
}

function render() {
  const all = [...approvals.values()];
  const pending = all.filter((a) => a.status === "pending").sort((a, b) => a.created - b.created);
  const decided = all.filter((a) => a.status !== "pending").sort((a, b) => b.decided - a.decided);

  // Keep existing cards (and anything typed into them); add new ones, drop settled ones.
  const container = $("pending");
  const shown = new Map([...container.children].map((el) => [el.dataset.id, el]));
  for (const [id, el] of shown) if (!pending.some((a) => a.id === id)) el.remove();
  for (const approval of pending) if (!shown.has(approval.id)) container.append(card(approval));

  $("history").replaceChildren(...decided.slice(0, 50).map(historyItem));
  $("pending-empty").hidden = pending.length > 0;
  $("history-empty").hidden = decided.length > 0;
  const count = $("pending-count");
  count.textContent = pending.length;
  count.toggleAttribute("data-zero", pending.length === 0);
  document.title = pending.length ? `(${pending.length}) anysoar console` : "anysoar console";
  tick();
}

function tick() {
  document.querySelectorAll(".waited").forEach((el) => {
    el.textContent = `waiting ${ago(Number(el.dataset.since))}`;
  });
}

function connected(live) {
  $("connection").className = `dot ${live ? "live" : "down"}`;
  $("connection-label").textContent = live ? "Live" : "Reconnecting…";
}

async function start() {
  const state = await call("/ui/state");
  $("operator").textContent = state.operator;
  state.approvals.forEach((a) => approvals.set(a.id, a));
  render();

  const stream = new EventSource("/ui/stream");
  stream.addEventListener("open", async () => {
    connected(true);
    // Catch up on anything that changed while disconnected.
    const fresh = await call("/ui/state");
    fresh.approvals.forEach((a) => approvals.set(a.id, a));
    render();
  });
  stream.addEventListener("error", () => connected(false));
  stream.addEventListener("approval", (event) => {
    const approval = JSON.parse(event.data).data;
    approvals.set(approval.id, approval);
    render();
  });
  setInterval(tick, 1000);
}

start().catch((error) => {
  connected(false);
  toast(`Console unavailable: ${error.message}`);
});
