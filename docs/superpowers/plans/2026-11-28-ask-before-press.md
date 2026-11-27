# Ask Before Press Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The guard asks "It was me / Lock it down" before acting; unanswered risky findings still lock after a deadline, unanswered harmless ones become the new baseline.

**Architecture:** `guard_once` stays pure and gains an "ask" path, used when `wait > 0` in `press`/`contain` mode and not a dry run. Open questions live in the guard state (`state["asks"]`). A new `panic/ask.py` opens a non-blocking macOS dialog and reads its answer. `cli_guard` sleeps in one-second steps between passes, records answers into the state, and runs a pass at once on an answer or a due deadline.

**Tech Stack:** Python 3.12, pytest, osascript (macOS).

**Spec:** `docs/superpowers/specs/2026-11-28-ask-before-press-design.md`

## Global Constraints

- `--wait 0`, `alert` mode and `--dry-run` keep today's behaviour exactly; every existing test passes unchanged.
- Default wait: 900 seconds. `--wait` below 0 is refused.
- Nothing is accepted unless every finding on the account at accept time was in an accept-resolved question.
- Dialog title and text are passed to osascript as argv, never as script source (same rule as `notify.py`).
- Cooldown, protected and released rules are unchanged.
- Commits authored by Riya Dadlani only; no co-author or "generated with" lines.

## Review Focus

- A finding that appears while a question is open must never be accepted by that question's answer.
- An intruder's risky finding that the owner never answers must be acted on at the deadline, also after a guard restart.
- A question whose finding disappears closes with no accept and no act.
- "Lock it down" must act within about a second, not at the next pass.
- A dialog that cannot open must not stop the guard; the deadline still applies.

---

### Task 1: Questions in `guard_once`

**Files:**
- Modify: `panic/guard.py`
- Test: `tests/test_guard_ask.py` (new)

**Interfaces:**
- Produces: `new_state()` adds `"asks": {}`; each entry is `key -> {"account": str, "risky": bool, "event": bool, "deadline": float, "answer": None | "accept" | "lock"}`, keyed by the existing `_key(f)`.
- Produces: `guard_once(..., wait: float = 0, ask=None, accept=None)` where `ask(account_id: str, findings: list[Finding], deadline: float) -> None` and `accept(account_id: str, snapshot: Snapshot) -> None`. `_read` returns `(snapshot, findings)`.

Rules, per account, on the ask path:
1. Every finding not in `asks` gets an entry (deadline `t + wait`); all new ones for the account go to one `ask(...)` call. Triggers are still confirmed by a second read first.
2. After a full, successful read, a non-event entry whose key is no longer found is removed (no act, no accept).
3. Act now if any entry is answered `lock`, or any `risky` entry is past its deadline with no answer. Acting uses today's code (cooldown, downstream targets, `act`) and then clears the account's entries.
4. Event entries answered `accept` are removed.
5. Accept when every remaining non-event entry is answered `accept` or is harmless and past its deadline: re-read; if every current finding's key is among those entries, call `accept(account_id, snapshot)`, set `baselines[account_id] = snapshot` and remove the entries. Otherwise leave them; the new findings got questions in rule 1.

- [ ] **Step 1: Write the failing tests** in `tests/test_guard_ask.py`, reusing `run`, `conn` and `TRIG`/`NOTICE` style helpers from `tests/test_guard.py`:
  - `test_trigger_asks_once_and_does_not_act_before_deadline`: two passes at t and t+10 with `wait=900` → `acts == []`, one `ask` call, `state["asks"][key]["deadline"] == t + 900`.
  - `test_lock_answer_acts_on_next_pass`
  - `test_accept_answer_saves_snapshot_and_clears`: `accept` called with the account's snapshot, `asks == {}`, `acts == []`.
  - `test_unanswered_trigger_acts_at_deadline`
  - `test_unanswered_notice_is_accepted_at_deadline`
  - `test_accept_refused_when_a_new_finding_appeared`: entry for A answered accept; read returns A and B → `accept` not called, B gets an entry.
  - `test_vanished_finding_closes_its_question`: no act, no accept, entry removed.
  - `test_event_trigger_accept_closes_without_snapshot` and `test_event_trigger_unanswered_acts`
  - `test_dry_run_prints_would_ask_and_saves_nothing`
  - `test_alert_mode_and_wait_zero_unchanged`: same lines and acts as without `wait`.
- [ ] **Step 2:** `uv run pytest tests/test_guard_ask.py -q` → fails (unexpected keyword `wait`).
- [ ] **Step 3:** Implement the rules above in `panic/guard.py`; `load_state` fills `asks` for older vaults.
- [ ] **Step 4:** `uv run pytest -q` → all pass.
- [ ] **Step 5:** Commit `feat: guard asks before acting; unanswered harmless changes become the baseline`.

### Task 2: The dialog

**Files:**
- Create: `panic/ask.py`
- Test: `tests/test_ask.py`

**Interfaces:**
- Produces: `open_dialog(title: str, text: str, seconds: int, popen=subprocess.Popen, platform=sys.platform) -> object | None` (None off macOS or on any error); `answer(proc) -> "accept" | "lock" | "none" | None` (None while still open; `"none"` when it gave up, was closed or failed).

- [ ] **Step 1: Write the failing tests:** title and text appear only as trailing argv items; `"button returned:It was me, gave up:false"` → `"accept"`; `"button returned:Lock it down, gave up:false"` → `"lock"`; `"gave up:true"` and a non-zero exit → `"none"`; a running process → `None`; `platform="linux"` → `None`; `popen` raising → `None`.
- [ ] **Step 2:** run → fails (module missing).
- [ ] **Step 3:** Implement with `osascript -e "on run argv" -e 'display dialog (item 2 of argv) with title (item 1 of argv) buttons {"Lock it down", "It was me"} giving up after ((item 3 of argv) as integer)' -e "end run"`.
- [ ] **Step 4:** run → passes.
- [ ] **Step 5:** Commit `feat: ask dialog for the guard`.

### Task 3: Wire it into `panic guard`

**Files:**
- Modify: `panic/cli_guard.py`, `panic/cli.py` (the `--wait` flag)
- Test: `tests/test_cli_guard_ask.py` (new; reuse fixtures from `tests/test_cli.py`)

**Interfaces:**
- Consumes: Task 1's `guard_once(..., wait, ask, accept)` and Task 2's `open_dialog`/`answer`; `main(...)` gains `asker=None` (defaults to `panic.ask`), stored as `a.asker`, so tests inject a fake.
- `ask` callback: logs `guard_question`, notifies as today, opens one dialog per call for the seconds left, and remembers which keys that dialog answers. The notification text ends with "It was me? Run `panic rehearse`. Lock it? Run `panic press --user ID`." and says what happens at the deadline.
- `accept` callback: `s.update` sets `d["baselines"][account_id] = snapshot`, logs `guard_accepted`.
- Between passes: sleep in 1-second steps; on any dialog answer write it into `state["asks"]`, save, and start a pass; also start a pass when the earliest deadline is due. Open questions found in a reloaded state with no live dialog get a new dialog for the time left.

- [ ] **Step 1: Write the failing tests:** `--wait -1` → exit 1 with a message; a planted trigger with `--wait 900 --passes 1` saves one entry in `guard.asks` and presses nothing; a fake asker answering "lock" leads to a press without waiting for the interval; a fake asker answering "accept" saves the new baseline in the vault.
- [ ] **Step 2:** run → fails.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** `uv run pytest -q` → all pass.
- [ ] **Step 5:** Commit `feat: panic guard asks first, --wait sets the deadline`.

### Task 4: Words

**Files:**
- Modify: `README.md` (Guard section, "What it does not promise", Commands table), `site/index.html` (guard screen and hero readout copy)

- [ ] **Step 1:** README: describe the question, the 15-minute default, the risky/harmless table, `--wait 0` for the old behaviour; remove "Your own change that matches a trigger gets pressed" and replace it with how to answer.
- [ ] **Step 2:** Page: the guard screen says it asks first and locks risky changes if nobody answers in 15 minutes; the 15-second test is described as how fast it noticed, not as an automatic press.
- [ ] **Step 3:** Commit `docs: guard asks before it acts`.

### Task 5: Live check on the throwaway Gmail

- [ ] Run `panic guard --interval 30 --wait 120` against the armed throwaway account, create a hiding filter in the browser, and confirm: the dialog appears; "It was me" saves the new baseline; a second filter left unanswered is deleted after about two minutes. Record the result in `docs/live-checks.md`.
