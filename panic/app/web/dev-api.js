"use strict";
// Fake window.pywebview.api for previews in a normal browser (open index.html?dev).
// Never loaded inside the app. Passphrase: "xp". Nothing here touches a real account.
(function () {
  const now = () => Date.now() / 1000;
  const db = {
    unlocked: false, vault_exists: !new URLSearchParams(location.search).has("novault"), remember: true, login_item: false,
    guard: { running: false, stopping: false, last_check: null, questions: 0 },
    accounts: [
      { id: "you@gmail.com", provider: "google", kind: "guarded" },
      { id: "octo", provider: "github", kind: "guarded" },
      { id: "amazon", provider: "amazon", kind: "checklist" },
      { id: "work-admin", provider: "google", kind: "protected" },
    ],
    questions: [],
  };
  let job = null, jobEvents = [], pid = 0;
  const ok = (v) => Promise.resolve(Object.assign({ ok: true }, v));
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  const SCRIPTS = {
    setup: [ "Welcome. Let's set up panic button.\n", { p: "Choose a passphrase: ", secret: true }, { p: "Repeat the passphrase: ", secret: true },
      "\nGoogle account\n  1. Sign in at the page below.\n", { p: "Open this page in your browser? [y/n] " }, { p: "Press Enter when you have finished these steps. " },
      { p: "Email address: " }, { p: "Number [1-7]: " }, { p: "Where should the key file live? [~/.panic.key] " }, "Saved.\n" ],
    press_all: ["Locking you@gmail.com ... done\n", "Locking octo ... done\n", { p: "Done resetting amazon by hand? [y/n] " }, "All locked.\n"],
    press_user: ["Locking one account ... done\n"],
    checkup: ["Check-up: five questions.\n", { p: "Is two-step sign-in on for your email? [y/n/u] " }, { p: "Do you have a recovery contact? [y/n/u] " }, "\nGood: 1   Fix now: 0   Unknown: 1\n"],
    release: [{ p: "Release octo and stop guarding it? [y/N] " }, "Released.\n"],
    report: ["Writing report ...\n", "Saved press-2026-11-28-1005.txt\n"],
  };
  SCRIPTS.checkup_again = SCRIPTS.checkup;

  async function runScript(j, steps) {
    for (const s of steps) {
      if (j.cancelled) break;
      await sleep(250);
      if (typeof s === "string") s.split("\n").forEach((line, i, all) => { if (line) jobEvents.push({ type: "output", text: line }); if (i < all.length - 1) jobEvents.push({ type: "output", text: "\n" }); });
      else {
        const id = ++pid;
        jobEvents.push({ type: "prompt", id, text: s.p, secret: !!s.secret });
        await new Promise((r) => { j.waiting = { id, r }; });
        j.waiting = null;
      }
    }
    if (j.cancelled) jobEvents.push({ type: "output", text: "Cancelled.\n" });
    jobEvents.push({ type: "done", code: j.cancelled ? 1 : 0 });
    j.done = true;
  }

  const api = {
    state: () => Promise.resolve(JSON.parse(JSON.stringify(Object.assign({}, db, { questions: undefined, guard: Object.assign({}, db.guard, { questions: db.questions.length }) })))),
    unlock: async (pw) => { await sleep(150); if (pw === "xp") { db.unlocked = true; return { ok: true }; } return { ok: false, error: "That passphrase did not work." }; },
    forget_mac: () => { db.remember = false; return ok(); },
    start_job: (kind, extra) => {
      if (job && !job.done) return Promise.resolve({ ok: false, error: "busy" });
      if (!SCRIPTS[kind]) return Promise.resolve({ ok: false, error: "unknown job" });
      jobEvents = []; job = { cancelled: false, done: false, waiting: null };
      runScript(job, SCRIPTS[kind]);
      return ok();
    },
    job_events: (since) => Promise.resolve(jobEvents.slice(since)),
    job_answer: (id, value) => { if (job && job.waiting && job.waiting.id === id) { job.waiting.r(); return Promise.resolve(true); } return Promise.resolve(false); },
    job_cancel: () => { if (job) { job.cancelled = true; if (job.waiting) job.waiting.r(); } return ok(); },
    guard_start: () => { db.guard.running = true; db.guard.last_check = now(); if (!db.questions.length) db.questions.push({ handle: "q1", account: "octo", text: "A new sign-in from Lagos was seen. Was that you?", deadline: now() + 900 }); return ok(); },
    guard_stop: () => { db.guard.running = false; return ok(); },
    questions: () => Promise.resolve(JSON.parse(JSON.stringify(db.questions))),
    answer_question: (h) => { db.questions = db.questions.filter((q) => q.handle !== h); return Promise.resolve(true); },
    reports: () => Promise.resolve([{ name: "press-2026-11-20-0815.txt", when: "2026-11-20T08:15:00" }, { name: "press-2026-11-27-0912.txt", when: "2026-11-27T09:12:00" }]),
    report: (n) => Promise.resolve("Report " + n + "\n\nyou@gmail.com   locked\nocto   locked\namazon   do by hand\n"),
    set_login_item: (on) => { db.login_item = !!on; return ok(); },
    quit: (keep) => { document.title = "quit(" + keep + ")"; return ok(); },
  };
  window.pywebview = { api };
})();
