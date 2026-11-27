"use strict";
// Plain JS, no framework. Talks to Python only through window.pywebview.api.
// All text from the API is inserted with textContent, never as HTML.

const $ = (id) => document.getElementById(id);
const api = () => window.pywebview.api;

const JOB_TITLES = {
  setup: "Set up panic button", press_all: "Lock every account", press_user: "Lock account",
  checkup: "Check-up", checkup_again: "Check-up", release: "Release account", report: "New report",
};
const KIND_LABEL = { guarded: "Guarded", checklist: "List", protected: "Protected" };

let S = null;                 // last state()
let questions = [];
let clientLocked = false;     // "Lock app" shows the unlock screen without touching Python
let selected = null;          // selected account id
let reportSel = null;
let job = null;               // running or last job
let stateSig = "";
let pollBusy = false;

/* ---------- helpers ---------- */
function el(tag, props = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === "text") e.textContent = v; else if (k === "class") e.className = v; else e.setAttribute(k, v);
  }
  kids.forEach((c) => e.append(c));
  return e;
}
function toDate(v) {
  if (v === null || v === undefined || v === "") return null;
  const d = typeof v === "number" ? new Date(v > 1e12 ? v : v * 1000) : new Date(v);
  return isNaN(d) ? null : d;
}
function fmt(v) {
  const d = toDate(v);
  if (!d) return v === null || v === undefined ? "" : String(v);
  const today = d.toDateString() === new Date().toDateString();
  return today ? d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
              : d.toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
}

/* ---------- modal stack ---------- */
const stack = [];
function openModal(id, focusId) {
  const o = $(id);
  if (!o.hidden) return;
  stack.push({ id, from: document.activeElement });
  o.hidden = false;
  const target = (focusId && $(focusId)) || o.querySelector("button.default") || o.querySelector("input,button:not([disabled])");
  if (target) target.focus();
}
function closeModal(id) {
  const o = $(id);
  if (o.hidden) return;
  o.hidden = true;
  const i = stack.map((s) => s.id).lastIndexOf(id);
  const [rec] = i >= 0 ? stack.splice(i, 1) : [null];
  const top = stack.length ? stack[stack.length - 1].id : null;
  if (top) { const t = $(top).querySelector("button.default") || $(top).querySelector("button"); if (t) t.focus(); }
  else if (rec && rec.from && document.contains(rec.from) && !rec.from.hidden) rec.from.focus();
}
function closable(id) { return id !== "o-job" || !job || job.done; }
document.addEventListener("click", (e) => {
  if (e.target.closest("[data-close]")) {
    const o = e.target.closest(".overlay");
    if (o && closable(o.id)) closeModal(o.id);
  }
});
document.addEventListener("keydown", (e) => {
  if (!stack.length) return;
  const top = stack[stack.length - 1].id;
  if (e.key === "Escape" && closable(top)) { e.preventDefault(); closeModal(top); return; }
  if (e.key === "Tab") {   // keep focus inside the top dialog
    const items = [...$(top).querySelectorAll("button:not([disabled]),input:not([disabled]),[tabindex='0']")].filter((n) => n.offsetParent !== null);
    if (!items.length) return;
    const first = items[0], last = items[items.length - 1];
    if (!$(top).contains(document.activeElement)) { e.preventDefault(); first.focus(); }
    else if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
  }
});

function alertBox(text) { $("a-text").textContent = text; openModal("o-alert"); }
function confirmBox(text) {
  return new Promise((resolve) => {
    $("c-text").textContent = text;
    const yes = $("c-yes"), no = $("c-no");
    const done = (v) => { yes.onclick = null; no.removeEventListener("click", onNo); closeModal("o-confirm"); resolve(v); };
    const onNo = () => resolve(false);
    yes.onclick = () => done(true);
    no.addEventListener("click", onNo, { once: true });   // close handled by data-close
    openModal("o-confirm", "c-no");
  });
}

/* ---------- state and screens ---------- */
async function refresh() {
  if (pollBusy) return;
  pollBusy = true;
  try {
    S = await api().state();
    questions = S.unlocked ? await api().questions() : [];
    const sig = JSON.stringify([S, questions, clientLocked]);
    if (sig !== stateSig) { stateSig = sig; render(); }
  } catch (err) { /* the app is closing or busy; try again next tick */ }
  pollBusy = false;
}

function render() {
  const showHome = S.unlocked && !clientLocked;
  $("w-home").hidden = !showHome;
  $("w-unlock").hidden = showHome;
  if (showHome) renderHome(); else renderUnlock();
  renderQuestions();
}

function renderUnlock() {
  const has = S.vault_exists;
  $("unlock-fields").hidden = !has;
  $("btn-unlock").hidden = !has;
  $("btn-setup").hidden = has;
  $("unlock-intro").textContent = has ? "Enter your passphrase to open panic button."
    : "No vault found on this Mac yet. Set one up to get started.";
  if (!stack.length && !job_running() && document.activeElement === document.body) (has ? $("pass") : $("btn-setup")).focus();
}

function renderHome() {
  const g = S.guard, ul = $("accounts");
  ul.replaceChildren();
  if (selected && !S.accounts.some((a) => a.id === selected)) selected = null;
  S.accounts.forEach((a) => {
    const row = el("button", { type: "button", class: "acct", role: "option", "aria-selected": String(a.id === selected), "data-id": a.id },
      el("span", { class: "dot " + a.kind, "aria-hidden": "true" }),
      el("span", { class: "name", text: a.id + (a.provider && a.provider !== a.id ? " (" + a.provider + ")" : "") }),
      el("span", { class: "kind", text: KIND_LABEL[a.kind] || a.kind }));
    ul.append(el("li", { role: "none" }, row));
  });
  $("no-accounts").hidden = S.accounts.length > 0;
  const sel = S.accounts.find((a) => a.id === selected);
  $("btn-lock-one").disabled = !sel;
  $("btn-release").disabled = !(sel && sel.kind === "guarded");
  $("st-guard").textContent = "Guard: " + (g.running ? "on" : g.stopping ? "stopping…" : "off");
  $("st-last").textContent = "Last check: " + (g.last_check ? fmt(g.last_check) : "never");
  const n = questions.length || g.questions || 0;
  $("st-questions").textContent = String(n);
  $("st-questions").setAttribute("aria-label", n + " open questions");
  const tg = $("btn-guard-toggle");
  tg.textContent = g.running ? "Stop guard" : "Start guard";
  tg.disabled = g.stopping;
  $("mi-start").disabled = g.running || g.stopping;
  $("mi-stop").disabled = !g.running;
  $("mi-login").setAttribute("aria-checked", String(!!S.login_item));
}

$("accounts").addEventListener("click", (e) => {
  const b = e.target.closest(".acct");
  if (!b) return;
  selected = b.dataset.id;
  renderHome();
  const again = [...$("accounts").children].map((li) => li.firstChild).find((n) => n.dataset.id === selected);
  if (again) again.focus();
});

/* ---------- unlock ---------- */
$("unlock-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const pass = $("pass");
  $("unlock-error").textContent = "";
  if (!pass.value) { $("unlock-error").textContent = "Type your passphrase first."; pass.focus(); return; }
  $("btn-unlock").disabled = true;
  let r;
  try { r = await api().unlock(pass.value, $("remember").checked); } catch (err) { r = { ok: false, error: "Could not reach the app." }; }
  $("btn-unlock").disabled = false;
  if (r && r.ok) { pass.value = ""; clientLocked = false; stateSig = ""; await refresh(); }
  else { $("unlock-error").textContent = (r && r.error) || "That passphrase did not work."; pass.select(); }
});
$("btn-setup").addEventListener("click", () => startJob("setup"));

/* ---------- menu ---------- */
const menubar = $("menubar");
const tops = () => [...menubar.querySelectorAll(":scope > .menu > button")];
function closeMenus(focusTop) {
  tops().forEach((b) => { if (b.getAttribute("aria-expanded") === "true" && focusTop) b.focus(); b.setAttribute("aria-expanded", "false"); $(b.getAttribute("aria-controls")).hidden = true; });
}
function openMenu(btn, focusFirst) {
  closeMenus(false);
  btn.setAttribute("aria-expanded", "true");
  const m = $(btn.getAttribute("aria-controls"));
  m.hidden = false;
  if (focusFirst) { const f = m.querySelector("button:not([disabled])"); if (f) f.focus(); }
}
menubar.addEventListener("click", (e) => {
  const b = e.target.closest("button");
  if (!b) return;
  if (b.parentElement.classList.contains("menu") && b.hasAttribute("aria-controls")) {
    b.getAttribute("aria-expanded") === "true" ? closeMenus(false) : openMenu(b, false);
    return;
  }
  const act = b.dataset.act;
  closeMenus(true);
  if (act) doAct(act);
});
document.addEventListener("click", (e) => { if (!e.target.closest(".menubar")) closeMenus(false); });
menubar.addEventListener("keydown", (e) => {
  const top = e.target.closest(".menu > button[aria-controls]");
  const items = e.target.closest("ul") ? [...e.target.closest("ul").querySelectorAll("button:not([disabled])")] : [];
  const t = tops();
  if (e.key === "Escape") { closeMenus(true); e.preventDefault(); e.stopPropagation(); return; }
  if (top && (e.key === "ArrowDown" || e.key === "ArrowUp")) { e.preventDefault(); openMenu(top, true); }
  else if (top && (e.key === "ArrowRight" || e.key === "ArrowLeft")) {
    e.preventDefault(); const n = t[(t.indexOf(top) + (e.key === "ArrowRight" ? 1 : t.length - 1)) % t.length];
    n.focus(); if (menubar.querySelector("[aria-expanded=true]")) openMenu(n, false);
  } else if (items.length && (e.key === "ArrowDown" || e.key === "ArrowUp")) {
    e.preventDefault(); const i = items.indexOf(document.activeElement);
    items[(i + (e.key === "ArrowDown" ? 1 : items.length - 1)) % items.length].focus();
  }
}, true);

async function doAct(act) {
  if (act === "lock") { clientLocked = true; stateSig = ""; closeAll(); render(); }
  else if (act === "forget") { await api().forget_mac(); await refresh(); alertBox("This Mac will ask for the passphrase next time."); }
  else if (act === "quit") openModal("o-quit");
  else if (act === "add") startJob("setup");
  else if (act === "guard-start") guardStart();
  else if (act === "guard-stop") guardStop();
  else if (act === "login") { await api().set_login_item(!S.login_item); await refresh(); }
  else if (act === "about") openModal("o-about");
}
function closeAll() { [...stack].reverse().forEach((s) => closeModal(s.id)); }

async function guardStart() {
  const r = await api().guard_start();
  if (!r.ok) alertBox(r.error || "The guard could not start.");
  await refresh();
}
async function guardStop() { await api().guard_stop(); await refresh(); }
$("btn-guard-toggle").addEventListener("click", () => (S.guard.running ? guardStop() : guardStart()));

/* ---------- quit ---------- */
$("home-close").addEventListener("click", () => openModal("o-quit"));
async function quit(keep) {
  closeModal("o-quit");
  await api().quit(keep);
}
$("quit-yes").addEventListener("click", () => quit(true));
$("quit-no").addEventListener("click", () => quit(false));

/* ---------- panic ---------- */
$("btn-panic").addEventListener("click", async () => {
  if (await confirmBox("Lock every account now?")) startJob("press_all");
});
$("btn-lock-one").addEventListener("click", async () => {
  if (selected && await confirmBox("Lock " + selected + " now?")) startJob("press_user", selected);
});
$("btn-release").addEventListener("click", () => { if (selected) startJob("release", selected); });
$("btn-add").addEventListener("click", () => startJob("setup"));
$("btn-checkup").addEventListener("click", () => startJob("checkup"));

/* ---------- questions ---------- */
$("st-questions").addEventListener("click", () => { renderQuestions(); openModal("o-questions"); });
function renderQuestions() {
  const list = $("q-list");
  $("q-empty").hidden = questions.length > 0;
  const focused = document.activeElement && document.activeElement.dataset ? document.activeElement.dataset.h : null;
  list.replaceChildren();
  questions.forEach((q) => {
    const mk = (label, ans, cls) => el("button", { type: "button", "data-h": q.handle + ans, class: cls || "", text: label });
    const yes = mk("It was me", "accept"), lock = mk("Lock it down", "lock");
    yes.addEventListener("click", () => answerQ(q.handle, "accept"));
    lock.addEventListener("click", () => answerQ(q.handle, "lock"));
    list.append(el("li", {},
      el("div", { class: "who", text: q.account }),
      el("p", { text: q.text }),
      el("p", { class: "muted", text: "Answer by " + fmt(q.deadline) }),
      el("div", { class: "buttons left" }, yes, lock)));
  });
  if (focused) { const b = list.querySelector('[data-h="' + CSS.escape(focused) + '"]'); if (b) b.focus(); }
}
async function answerQ(handle, ans) {
  await api().answer_question(handle, ans);
  await refresh();
}

/* ---------- jobs ---------- */
function job_running() { return job && !job.done; }
async function startJob(kind, extra = null) {
  if (job_running()) { alertBox("Another task is still running. Wait for it to finish, then try again."); return; }
  let r;
  try { r = await api().start_job(kind, extra); } catch (err) { r = { ok: false, error: "Could not reach the app." }; }
  if (!r.ok) { alertBox(r.error === "busy" ? "Another task is still running. Wait for it to finish, then try again." : (r.error || "That could not be started.")); return; }
  job = { kind, since: 0, done: false, promptId: null, cancelled: false };
  $("job-out").textContent = "";
  $("t-job").textContent = JOB_TITLES[kind] || "Task";
  $("job-status").textContent = "Working…";
  $("job-prompt").hidden = true;
  $("job-cancel").hidden = false; $("job-cancel").disabled = false;
  $("job-close").hidden = true; $("job-again").hidden = true; $("job-x").disabled = true;
  openModal("o-job", "job-cancel");
  pollJob(job);
}
function out(text) {
  const o = $("job-out"), atEnd = o.scrollTop + o.clientHeight >= o.scrollHeight - 8;
  o.append(document.createTextNode(text));
  if (atEnd) o.scrollTop = o.scrollHeight;
}
async function pollJob(j) {
  let events = [];
  try { events = await api().job_events(j.since); }
  catch (err) { out("\n(lost contact with the app)\n"); events = [{ type: "done", code: 1 }]; }
  j.since += events.length;
  let pending = null;
  for (const ev of events) {
    if (ev.type === "output") out(ev.text);
    else if (ev.type === "prompt") pending = ev;
    else if (ev.type === "done") { pending = null; finishJob(j, ev.code); }
  }
  if (j.done) return;
  if (pending && pending.id !== j.promptId) showPrompt(j, pending);
  setTimeout(() => pollJob(j), 300);
}
function finishJob(j, code) {
  j.done = true;
  $("job-prompt").hidden = true;
  $("job-status").textContent = j.cancelled ? "Stopped. Exit status " + code + "." : code === 0 ? "Finished. Exit status 0." : "Finished with a problem. Exit status " + code + ".";
  $("job-cancel").hidden = true;
  $("job-close").hidden = false; $("job-x").disabled = false;
  $("job-again").hidden = !(j.kind === "checkup" || j.kind === "checkup_again");
  if (!$("o-job").hidden) $("job-close").focus();
  refresh();
}

// How a prompt is shown: the text decides the controls.
function classify(p) {
  if (p.secret) return { type: "secret" };
  const t = p.text.trim();
  const yn = /\[y\/n(\/u)?\]\s*[:?]?$/i.exec(t);
  if (yn) return { type: yn[1] ? "ynu" : "yn" };
  const num = /\[(\d+)\s*-\s*(\d+)\]\s*[:?]?$/.exec(t);
  if (num && +num[2] >= +num[1] && +num[2] - +num[1] < 20) return { type: "num", lo: +num[1], hi: +num[2] };
  return { type: "text" };
}
function showPrompt(j, p) {
  j.promptId = p.id;
  const kind = classify(p), box = $("jp-buttons"), input = $("jp-input");
  $("jp-text").textContent = p.text.trim();
  out(p.text.endsWith(" ") ? p.text : p.text + " ");
  box.replaceChildren(); input.value = "";
  const answer = (value, shown) => {
    if (j.promptId !== p.id) return;
    j.promptId = null;
    $("job-prompt").hidden = true;
    out((p.secret ? "••••••" : shown !== undefined ? shown : value) + "\n");
    api().job_answer(p.id, value);
    $("job-cancel").focus();
  };
  const btn = (label, value, def) => {
    const b = el("button", { type: "button", text: label, class: def ? "default" : "" });
    b.addEventListener("click", () => answer(value, label)); box.append(b); return b;
  };
  input.hidden = kind.type !== "text" && kind.type !== "secret";
  input.type = kind.type === "secret" ? "password" : "text";
  input.setAttribute("aria-label", p.text.trim());
  let first;
  if (kind.type === "yn") { first = btn("Yes", "y", true); btn("No", "n"); }
  else if (kind.type === "ynu") { first = btn("Yes", "y", true); btn("No", "n"); btn("Unsure", "u"); }
  else if (kind.type === "num") { for (let i = kind.lo; i <= kind.hi; i++) { const b = btn(String(i), String(i)); b.style.minWidth = "36px"; first = first || b; } }
  else {
    const ok = el("button", { type: "submit", class: "default", text: "OK" }); box.append(ok);
    first = input;
    $("jp-form").onsubmit = (e) => { e.preventDefault(); answer(input.value); };
  }
  if (kind.type === "yn" || kind.type === "ynu" || kind.type === "num") $("jp-form").onsubmit = (e) => e.preventDefault();
  $("job-prompt").hidden = false;
  first.focus();
  $("job-prompt").scrollIntoView({ block: "nearest" });
}
$("job-cancel").addEventListener("click", async () => {
  if (!job || job.done) return;
  job.cancelled = true; $("job-cancel").disabled = true;
  $("job-status").textContent = "Stopping…";
  await api().job_cancel();
});
$("job-close").addEventListener("click", () => closeModal("o-job"));
$("job-again").addEventListener("click", () => { closeModal("o-job"); startJob("checkup_again"); });

/* ---------- reports ---------- */
$("btn-reports").addEventListener("click", async () => { await loadReports(); openModal("o-reports"); });
async function loadReports() {
  const list = (await api().reports()).slice().sort((a, b) => String(b.when).localeCompare(String(a.when)));
  const ul = $("r-list");
  ul.replaceChildren(); reportSel = null; $("r-open").disabled = true;
  $("r-empty").hidden = list.length > 0;
  list.forEach((r) => {
    const b = el("button", { type: "button", class: "acct", role: "option", "aria-selected": "false", "data-name": r.name },
      el("span", { class: "name", text: r.name }), el("span", { class: "kind", text: fmt(r.when) }));
    b.addEventListener("click", () => selectReport(b));
    b.addEventListener("dblclick", () => viewReport(r.name));
    ul.append(el("li", { role: "none" }, b));
  });
}
function selectReport(b) {
  $("r-list").querySelectorAll(".acct").forEach((n) => n.setAttribute("aria-selected", String(n === b)));
  reportSel = b.dataset.name; $("r-open").disabled = false;
}
async function viewReport(name) {
  $("t-viewer").textContent = name;
  $("v-text").textContent = await api().report(name);
  openModal("o-viewer", "v-text");
}
$("r-open").addEventListener("click", () => reportSel && viewReport(reportSel));
$("r-new").addEventListener("click", async () => { closeModal("o-reports"); await startJob("report"); });

/* ---------- start ---------- */
function begin() {
  refresh();
  setInterval(refresh, 2000);
}
function boot() {
  if (window.pywebview && window.pywebview.api) return begin();
  let started = false;
  const go = () => { if (!started) { started = true; begin(); } };
  window.addEventListener("pywebviewready", go, { once: true });
  // Outside the app, only a deliberate ?dev preview gets the fake API.
  setTimeout(() => {
    if (started) return;
    if (window.pywebview && window.pywebview.api) return go();
    if (new URLSearchParams(location.search).has("dev")) {
      const s = document.createElement("script");
      s.src = "dev-api.js"; s.onload = () => { $("dev-banner").hidden = false; go(); };
      document.body.append(s);
    } else {
      document.body.append(el("p", { class: "dev-banner", style: "position:static;margin:20px", text: "panic button must be opened as the app. For a preview add ?dev to the address." }));
    }
  }, 700);
}
boot();
