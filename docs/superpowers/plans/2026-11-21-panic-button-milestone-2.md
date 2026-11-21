# Panic Button Milestone 2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `panic guard` detects an intruder's fingerprints and presses by itself, and Microsoft, GitHub, Slack and a guided catalogue join Google as providers.

**Architecture:** Connectors gain two optional read-only methods, `signals` and `events`, that return `Finding`s from a fixed rule list. A new `guard` module polls every armed account, and on a trigger calls the existing `press` with an unattended confirm, then runs `watch_once` each pass. Each new provider is one module implementing the existing `Connector` protocol; GitHub and Slack share a small standard-library HTTP client, Microsoft signs in with `msal`.

**Tech Stack:** Python 3.12 run with `uv`, `pytest`, the existing dependencies, plus `msal`. HTTP for GitHub, Slack and Microsoft Graph is `urllib.request`.

**Spec:** `docs/superpowers/specs/2026-11-21-panic-button-milestone-2-design.md`, which extends `docs/superpowers/specs/2026-11-21-panic-button-design.md`. Read both.

## Global Constraints

- Python 3.12+ through `uv` only (`uv run pytest -q`). The system Python is 3.9 and must not be used.
- One new dependency: `msal`. Nothing else may be added.
- Work only inside `/Users/riyadadlani/panic-button`. Commit locally on branch `milestone-2`; never push.
- No task touches a real account. Every provider call in tests goes through an injected fake. Live checks are Task 11, with the owner.
- The tool never requests a scope or calls an endpoint that returns mail content (message bodies, subjects, snippets).
- No model call anywhere. Detection is the fixed rule list in the spec.
- A protected account is never read for action, pressed, released or deactivated: not by the owner, not by the guard, not when it is downstream of a trigger.
- Nothing irreversible runs automatically: no GitHub member removal, no Slack app uninstall, no password change on a personal account.
- Fail closed: a missing baseline category raises `KeyError("no baseline recorded for <category> on <account>")`. A failed or partial read is never treated as "nothing there" and never as a trigger.
- Organisation privacy: for providers `google_workspace`, `microsoft_365` and `slack`, mail-rule contents never appear in notifications, the audit log, reports or dry-run output. `panic removed --user` is the only place they are printed.
- `Connector.run` and `Connector.check` are called from several threads at once and must be thread-safe.
- Text that came from a provider (rule names, key titles, URLs) is untrusted: it is whitespace-collapsed and code-spanned in reports, and passed to other programs only as an argument, never inside a script string.
- Tests live in `tests/`, are committed, and import the fake with `from fake import FakeConnector`.
- Comments are short and say why. No dates or ticket numbers in comments.
- Existing behaviour is kept: all 212 current tests stay green after every task.

## Review Focus

1. **A throttled or failed list read deletes something.** A 500 or 429 from a list endpoint must make `run` raise and delete nothing; it must not look like an empty list. Test in Tasks 6, 7 and 9.
2. **A list longer than one page.** An attacker's key on page two must be seen and a baseline item on page two must not be deleted. Test pagination in Task 6 (`Api.pages`).
3. **The guard presses twice.** After a restart, or when two passes overlap a slow press, the same trigger must not start a second press. Test in Task 3 (state written before acting) and Task 4 (state survives a new `Session`).
4. **A protected account downstream of a trigger.** The break-glass admin or Slack primary owner reachable through the map must be left out of an automatic press. Test in Task 3.
5. **Provider text reaches a shell or a notification unescaped.** A rule named `"; do shell script "rm -rf ~` must arrive in the notification as plain text. Test in Task 4 (`notify` passes text as arguments).

---

### Task 0: Branch and pending work (done by the controller, not a subagent)

- [ ] Create branch `milestone-2` from `main`.
- [ ] Add `demo/*.mp4` to `.gitignore`.
- [ ] Commit the pending Gmail fixes, `docs/recording-runbook.md`, the milestone 2 spec and this plan. Run `uv run pytest -q` first. Expected: 212 passed.

---

### Task 1: Findings and the shared rule classifier

**Files:**
- Modify: `panic/model.py`, `panic/executor.py` (protocol docs only), `tests/fake.py`
- Create: `panic/signals.py`, `tests/test_signals.py`

**Interfaces:**
- Produces, in `panic/model.py`:
  - `class Severity(StrEnum)`: `TRIGGER = "trigger"`, `NOTICE = "notice"`.
  - `@dataclass(frozen=True) class Finding`: `account: str`, `code: str`, `severity: Severity`, `text: str`, `items: tuple[str, ...] = ()`.
- Produces, in `panic/signals.py`:
  - `TEXT: dict[str, str]`: one plain sentence per code. Codes: `rule_forwards_outside`, `rule_hides_mail`, `forwarding_added`, `delegate_added`, `pop_enabled`, `recovery_changed`, `key_added`, `email_added`, `repo_access_added`, `org_access_added`, `app_consent_added`, `auth_method_added`, `provider_flagged_login`, `changed`, `unreadable`, `events_unreadable`, `new_access`.
  - `drift(account_id: str, baseline: Snapshot, snapshot: Snapshot, classify: Callable[[str, str], str | None]) -> list[Finding]`. For every item of `snapshot` that is not in `baseline` for its category, `classify(category, item)` returns a trigger code or `None`. Returns one `TRIGGER` finding per code (items sorted, as `"category: item"`), plus one `NOTICE` with code `changed` for everything classified `None`. A category absent from `baseline` raises the fail-closed `KeyError`.
  - `gmail_rule_code(item: str, own_domain: str | None) -> str | None`. `item` is the canonical filter JSON the Gmail connectors already store. Returns `rule_forwards_outside` when `action.forward` is set and (`own_domain` is `None` or the address is outside it); `rule_hides_mail` when `action.addLabelIds` contains `TRASH`, or `action.removeLabelIds` contains both `INBOX` and `UNREAD`; otherwise `None`. Unparseable JSON returns `rule_hides_mail` (fail closed).
- Produces, in `panic/executor.py`: the `Connector` protocol docstring states that `signals(account, snapshot, baseline) -> list[Finding]` and `events(account, since: float) -> list[Finding]` are optional and looked up with `getattr`.
- `tests/fake.py`: `FakeConnector` gains `findings: list[Finding]` and `event_findings: list[Finding]` (default empty) and the two methods returning them.

- [ ] **Step 1: Write the failing tests** in `tests/test_signals.py`:

```python
import json, pytest
from panic.model import Severity
from panic.signals import drift, gmail_rule_code

def rule(**action): return json.dumps({"action": action, "criteria": {"from": "x"}}, sort_keys=True)

def test_rule_codes():
    assert gmail_rule_code(rule(forward="a@evil.test"), None) == "rule_forwards_outside"
    assert gmail_rule_code(rule(forward="a@corp.test"), "corp.test") is None
    assert gmail_rule_code(rule(forward="a@evil.test"), "corp.test") == "rule_forwards_outside"
    assert gmail_rule_code(rule(addLabelIds=["TRASH"]), None) == "rule_hides_mail"
    assert gmail_rule_code(rule(removeLabelIds=["INBOX", "UNREAD"]), None) == "rule_hides_mail"
    assert gmail_rule_code(rule(addLabelIds=["STARRED"]), None) is None
    assert gmail_rule_code("not json", None) == "rule_hides_mail"

def test_drift_splits_triggers_from_notices():
    base = {"filters": ["keep"], "pop": []}
    snap = {"filters": ["keep", "bad", "label"], "pop": ["pop"]}
    out = drift("a@x", base, snap, lambda c, i: {"bad": "rule_hides_mail", "pop": "pop_enabled"}.get(i))
    by = {f.code: f for f in out}
    assert by["rule_hides_mail"].severity is Severity.TRIGGER and by["rule_hides_mail"].items == ("filters: bad",)
    assert by["pop_enabled"].severity is Severity.TRIGGER
    assert by["changed"].severity is Severity.NOTICE and by["changed"].items == ("filters: label",)

def test_drift_matches_baseline_returns_nothing():
    assert drift("a@x", {"filters": ["k"]}, {"filters": ["k"]}, lambda c, i: "rule_hides_mail") == []

def test_drift_fails_closed_without_a_baseline_category():
    with pytest.raises(KeyError, match="no baseline recorded for filters on a@x"):
        drift("a@x", {}, {"filters": ["k"]}, lambda c, i: None)
```

- [ ] **Step 2:** Run `uv run pytest tests/test_signals.py -q`. Expected: import error.
- [ ] **Step 3:** Implement the model types, `panic/signals.py`, the protocol docstring and the fake's two methods.
- [ ] **Step 4:** Run `uv run pytest -q`. Expected: all pass.
- [ ] **Step 5:** Commit: `feat: findings model and shared rule classifier`.

---

### Task 2: Signals for the two Google connectors

**Files:**
- Modify: `panic/google_personal.py`, `panic/google_workspace.py`, `tests/test_google_personal.py`, `tests/test_google_workspace.py`, `README.md` (Workspace scopes)

**Interfaces:**
- Consumes: `drift`, `gmail_rule_code`, `Finding`, `Severity` from Task 1.
- Produces:
  - `Personal.signals(account, snapshot, baseline) -> list[Finding]`: `filters` items classified by `gmail_rule_code(item, None)`; any new `forwarding` or `forwarding_addresses` item is `forwarding_added`; a new `imap_pop` item is `pop_enabled`.
  - `Workspace.signals(account, snapshot, baseline)`: `filters` by `gmail_rule_code(item, self.domain)`; `forwarding` and `forwarding_addresses` items outside the domain are `forwarding_added`, inside are `None`; new `delegates` item is `delegate_added`; new `recovery` item is `recovery_changed`; `imap_pop` item `pop` is `pop_enabled` (`imap` is `None`). Every other category is `None`.
  - `Workspace.events(account, since) -> list[Finding]`: Admin SDK Reports API, `activities().list(userKey=account.id, applicationName="login", startTime=<RFC 3339 of since>)`. An activity whose event name is in `SUSPICIOUS = {"suspicious_login", "suspicious_login_less_secure_app", "suspicious_programmatic_login", "account_disabled_hijacked"}` gives one `TRIGGER` finding with code `provider_flagged_login` and `items=(event name,)`. Uses a new scope `https://www.googleapis.com/auth/admin.reports.audit.readonly` added to `google_workspace.SCOPES`.
  - Both refuse a protected admin exactly as `run` does.

- [ ] **Step 1: Write failing tests.** Personal: a snapshot with a new `{"addLabelIds": ["TRASH"]}` filter and `imap_pop: ["pop"]` yields codes `{"rule_hides_mail", "pop_enabled"}`; a new label-only filter yields only `changed`. Workspace: a forward to `x@corp.test` (own domain) yields no trigger; to `x@evil.test` yields `rule_forwards_outside`; a new delegate yields `delegate_added`; `events` with one `suspicious_login` activity and one `login_success` yields exactly one finding; `events` on the admin raises as `run` does.
- [ ] **Step 2:** Run them. Expected: `AttributeError: signals`.
- [ ] **Step 3:** Implement. Reuse each connector's existing snapshot categories; add no new reads to `snapshot`.
- [ ] **Step 4:** Update the README's Workspace setup to list the fifth scope. Run `uv run pytest -q`. Expected: all pass.
- [ ] **Step 5:** Commit: `feat: intruder signals for Gmail and Workspace`.

---

### Task 3: The guard engine

**Files:**
- Create: `panic/guard.py`, `tests/test_guard.py`
- Modify: `panic/graph.py`, `tests/test_graph.py`

**Interfaces:**
- Consumes: `Finding`, `Severity`, `Account`, `Edges`, `Snapshot`; optional connector methods from Task 1.
- Produces, in `panic/graph.py`: `downstream(account: str, edges: Edges) -> list[str]`: the account and everything reachable along `(a, b)` edges, the account first.
- Produces, in `panic/guard.py`:
  - `COOLDOWN_S = 24 * 3600`.
  - `new_state() -> dict`: `{"seen": [], "cursors": {}, "pressed": {}}`. Plain JSON, stored in the vault by Task 4.
  - `guard_once(accounts: list[Account], edges: Edges, connectors: dict, baselines: dict[str, Snapshot], released: set[str], state: dict, mode: str, act: Callable[[list[str], list[Finding]], None], notify: Callable[[Finding], None], save: Callable[[], None], now: Callable[[], float] = time.time, dry_run: bool = False) -> list[str]`. Returns the lines to print; the last is the heartbeat `"<HH:MM:SS> read <n> accounts, <k> findings"`.

Behaviour of one pass, for each account that is not protected, not in `released`, and whose connector has `signals` or `events`:

1. `snapshot`; on any exception, one `NOTICE` finding `unreadable` and move to the next account. Then `signals(account, snapshot, baselines[account.id])` if present.
2. `events(account, state["cursors"].get(id, now()))` if present; on exception a `NOTICE` `events_unreadable`. Then set the cursor to `now()`.
3. Each `NOTICE` whose key `"<account>|<code>|<items joined>"` is not in `state["seen"]` is added to it and passed to `notify`.
4. Snapshot triggers are confirmed by reading `snapshot` and `signals` a second time; a code that is absent the second time is dropped. Event triggers are not re-read.
5. For surviving triggers: `notify` each. In mode `alert`, stop there. If `state["pressed"].get(id, 0) > now() - COOLDOWN_S`, stop there (the line says the watch is handling it). Otherwise `targets = [t for t in downstream(id, edges) if t is armed, not protected, not released]`, set `state["pressed"][t] = now()` for each, call `save()`, then `act(targets, triggers)`.
6. With `dry_run`, steps 3 and 5 neither change `state` nor call `act` or `save`; lines begin `would`.

`mode` is passed through to `act` by the caller's closure; `guard_once` only distinguishes `alert` from the rest.

- [ ] **Step 1: Write failing tests** in `tests/test_guard.py`, using `FakeConnector` with `findings`/`event_findings` set:
  - `test_notice_is_reported_once`: two passes, one `NOTICE`; `notify` called once, `act` never.
  - `test_trigger_presses_account_and_downstream_root_first`: edges `[("mail", "bank")]`, trigger on `mail`; `act` called once with `["mail", "bank"]`.
  - `test_upstream_is_not_pressed`: trigger on `bank`; `act` called with `["bank"]`.
  - `test_protected_and_released_downstream_are_left_out`: `bank` protected, `social` released; `act` gets `["mail"]`.
  - `test_trigger_that_vanishes_on_second_read_is_dropped`: connector returns the finding once, then none; `act` never called.
  - `test_event_trigger_is_not_reread`: `event_findings` has a trigger; `snapshot` is read exactly once.
  - `test_cooldown_blocks_a_second_press`: second pass an hour later; `act` called once in total.
  - `test_state_is_saved_before_acting`: `save` records `state["pressed"]` at call time; assert it already holds the account when `act` runs.
  - `test_unreadable_account_is_a_notice_not_a_trigger`: `snapshot` raises; `act` never called, one `unreadable` notice.
  - `test_alert_mode_never_acts`, `test_dry_run_changes_nothing` (state equal to `new_state()` afterwards).
  - `test_heartbeat_line`: with `now=lambda: 0`, the last line is `"00:00:00 read 1 accounts, 0 findings"` (UTC).
  - In `tests/test_graph.py`: `downstream("a", [("a","b"),("b","c"),("x","a")]) == ["a","b","c"]`.
- [ ] **Step 2:** Run. Expected: import error.
- [ ] **Step 3:** Implement `downstream` and `panic/guard.py`.
- [ ] **Step 4:** Run `uv run pytest -q`. Expected: all pass.
- [ ] **Step 5:** Commit: `feat: guard engine`.

---

### Task 4: `panic guard`, notifications, report section, guard state

**Files:**
- Create: `panic/notify.py`, `tests/test_notify.py`
- Modify: `panic/cli.py`, `panic/cli_arm.py`, `panic/session.py`, `panic/report.py`, `panic/model.py`, `tests/test_cli.py`, `tests/test_report.py`

**Interfaces:**
- Consumes: `guard_once`, `new_state` (Task 3); `executor.press`, `executor.watch_once`, `executor.compile_plan`.
- Produces:
  - `panic/notify.py`: `notify(title: str, text: str, run=subprocess.run, platform=sys.platform) -> None`. Prints `"\a"` and `"<title>: <text>"` to stderr. On `darwin` runs `["osascript", "-e", "on run argv", "-e", "display notification (item 2 of argv) with title (item 1 of argv)", "-e", "end run", title, text]`. Never raises.
  - `panic/model.py`: `Outcome` gains `triggers: list[str] = field(default_factory=list)`. `session.outcome_to_json` / `outcome_from_json` carry it (`d.get("triggers", [])`).
  - `panic/report.py`: `render` adds a `## What triggered this press` section, each trigger whitespace-collapsed and code-spanned, placed after the header; absent when `triggers` is empty.
  - `panic/session.py`: `ORG_PROVIDERS = {"google_workspace", "microsoft_365", "slack"}` and `RULE_CATEGORIES = ("filters", "inbox_rules")`; `_redact` uses both instead of its hard-coded provider and prefix.
  - `panic/cli.py`: command `guard` with `--interval SECONDS` (default 300, values under 30 rejected), `--on-detect {press,contain,alert}` (default `press`), `--dry-run`. `main` gains keyword `sleep=time.sleep`, and a hidden `--passes N` stops after N passes (tests).
  - `panic/cli_arm.py`: approving a baseline in `cmd_rehearse` also removes that account from `d["released"]`.

Behaviour of `cmd_guard`: open the `Session` once. Each pass: reload the vault (as `_watch` does) for accounts, edges, baselines, released, credentials and `data.get("guard") or new_state()`; call `guard_once`; then run `watch_once` over the results of every press younger than 24 hours (move the merge logic out of `_watch` into a helper both use); print the lines; sleep. `save` writes `d["guard"] = state` through `Session.update`. `act` for mode `press` compiles the plan for the targets and calls `executor.press(..., confirm=lambda step: False, log=s.log, checkpoint=...)`, sets `outcome.triggers` to `"<code>: <text>"` for each finding (organisation accounts: no items; personal accounts: items appended), then saves the outcome and writes the report exactly as `cmd_press` does. For mode `contain` the plan is filtered to `step.tier is Tier.API and step.watch is WatchPolicy.REAPPLY`. Every notice and trigger is written to the audit log as `{"event": "guard_notice" | "guard_trigger", "account", "code", "detail"}`. A trigger's notification and printed line end with `Also check: <ids>` listing `graph.resetters(account, edges)` when there are any; those accounts are not pressed. Ctrl-C prints `Guard stopped.` and exits 0.

One narrowing of the spec: `events` is asked per armed account, so a provider event about a user who is not armed is never fetched, and is not reported as a notice.

- [ ] **Step 1: Write failing tests.**
  - `tests/test_notify.py`: with a recording `run` and `platform="darwin"`, `notify("t", '"; do shell script "x')` passes the text as the last argv element unchanged and no `-e` argument contains it; with `platform="linux"` `run` is not called; a `run` that raises does not propagate.
  - `tests/test_report.py`: an `Outcome` with `triggers=["rule_hides_mail: a rule that hides mail"]` renders the section; one with a trigger containing a newline and a backtick renders on one line inside a code span; an empty list renders no section.
  - `tests/test_cli.py` (use the existing `armed` fixture and a `FakeConnector` with `findings`): `guard --passes 1` with a trigger writes an outcome whose `triggers` is non-empty, records every guided step as `needs_you` without calling `input`, and writes a report file; `guard --passes 2` presses once; a second `main([... "guard", "--passes", "1"])` in a new process state (new `Session`) does not press again; `guard --on-detect alert --passes 1` writes no outcome; `guard --on-detect contain --passes 1` runs only reapply steps; `guard --dry-run --passes 1` leaves the vault's `version` unchanged; `guard --interval 5` exits 1 with a one-line error; a trigger on an account that another armed account can reset prints `Also check:` naming it and does not press it; a Workspace-provider account's trigger line and log entry contain no filter contents; `rehearse` approval removes the account from `released`.
- [ ] **Step 2:** Run. Expected: failures on the missing command and section.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `uv run pytest -q`. Expected: all pass.
- [ ] **Step 5:** Commit: `feat: panic guard command with automatic press`.

---

### Task 5: Guided catalogue provider

**Files:**
- Create: `panic/guided.py`, `panic/guided_services.json`, `tests/test_guided.py`
- Modify: `panic/cli.py` (arm flags), `panic/cli_arm.py`, `panic/session.py` (`_connectors`), `tests/test_cli.py`

**Interfaces:**
- Produces:
  - `panic/guided_services.json`: `{"<key>": {"name": str, "verified": bool, "links": {"sign_out": url, "devices": url, "apps": url, "two_factor": url, "recovery": url, "password": url}}}`. Any link may be absent. Starter keys: `apple`, `amazon`, `facebook`, `instagram`, `x`, `linkedin`, `paypal`, `dropbox`, `netflix`. Every entry ships with `"verified": false`; Task 11 flips them.
  - `class Guided` with `provider = "guided"`, `__init__(self, custom: dict | None = None)` where `custom` has the same shape and overrides the file. Account ids are `"<key>:<login>"`.
  - `catalog(account)`: one `Tier.GUIDED` step per link present, in the order `sign_out` (FREEZE), `devices`, `apps`, `two_factor`, `recovery`, `password` (PURGE, last). Titles name the service (`"Amazon: sign out everywhere"`), with `" (link not verified)"` appended when `verified` is false. An unknown key raises `KeyError`.
  - `snapshot` returns `{}`; `run` raises `NotImplementedError`; `check` returns `None`. No `signals`, no `events`.
  - CLI: `panic arm --guided KEY --id LOGIN [--name NAME] [--link KIND=URL ...]`. `--link` creates or extends a custom entry stored in the vault under `credentials["guided"]`; a key not in the catalogue requires at least one `--link`. A URL that does not start with `https://` is refused. Arm asks the recovery question and the "which armed accounts can reset this one" question as the Gmail arm does, records no baseline, and prints `Guided only: the tool cannot read or watch this account.`
  - `session._connectors` returns a `Guided` whenever any armed account has provider `guided`.
  - `cmd_rehearse` prints `<id>: guided only, not read` for these accounts and does not call `snapshot`.

- [ ] **Step 1: Write failing tests**: catalogue order and phases; unverified suffix; custom override; unknown key; `--link javascript:alert(1)` refused; arming `amazon:me@x.test` with an edge from an armed mail account, then a press of the mail account's downstream via `executor.compile_plan`, includes the Amazon steps; rehearse output line.
- [ ] **Step 2:** Run. Expected: import error.
- [ ] **Step 3:** Implement. Write the starter links from each service's own account-security pages; they stay unverified.
- [ ] **Step 4:** Run `uv run pytest -q`. Expected: all pass.
- [ ] **Step 5:** Commit: `feat: guided catalogue for any service`.

---

### Task 6: HTTP client and the GitHub connector

**Files:**
- Create: `panic/http.py`, `panic/github.py`, `tests/test_http.py`, `tests/test_github.py`
- Modify: `panic/cli.py`, `panic/cli_arm.py`, `panic/session.py`, `tests/test_cli.py`

**Interfaces:**
- Produces, in `panic/http.py`:
  - `class ApiError(Exception)` with `.status: int` and `.body: str` (first 200 characters).
  - `class Api`: `__init__(self, base: str, headers: Callable[[], dict[str, str]], open=urllib.request.urlopen, sleep=time.sleep, timeout: float = 30)`.
  - `get(path, params=None) -> Any`; `pages(path, params=None) -> list` following `Link: <...>; rel="next"` until exhausted; `delete(path, gone_ok=True) -> None` (404 is success when `gone_ok`); `send(method, path, body: dict | None = None) -> Any`.
  - 429 and 5xx are retried three times, sleeping `Retry-After` if given, else 1, 2, 4 seconds; then `ApiError`. Any other non-2xx raises `ApiError` at once. Thread-safe.
- Produces, in `panic/github.py`:
  - `class GitHub` with `provider = "github"`, `__init__(self, tokens: dict[str, str], api: Callable[[str], Api] | None = None, now=time.time)`. Account id is the login, or `"org:<name>"` for an organisation; `tokens` is keyed by account id. Base `https://api.github.com`, headers `Authorization: Bearer <token>`, `Accept: application/vnd.github+json`, `X-GitHub-Api-Version: 2022-11-28`.
  - `login(token_account) -> str` (`GET /user`), `is_org_admin(account) -> bool` (`GET /user/memberships/orgs/<name>`, `state == "active"` and `role == "admin"`).
  - `snapshot`, personal: categories `ssh_keys`, `signing_keys`, `gpg_keys`, `emails`, `deploy_keys`, `webhooks`, `collaborators`, `invitations`. Organisation: `org_webhooks`, `outside_collaborators`, `deploy_keys`. Items are canonical JSON strings of the identifying fields without ids (for keys: `{"key", "title"}`; repository items carry `"repo": "owner/name"`). The four per-repository categories cover repositories the account owns (`GET /user/repos?affiliation=owner`), are read at most once per `REPO_REFRESH_S = 3600`, and are served from an in-memory cache in between.
  - `catalog`, personal: API steps `keys` (FREEZE, REAPPLY, covers the three key categories), `emails` (PURGE, REAPPLY), `repo_access` (PURGE, REAPPLY, the four repository categories); guided steps `sign_out` (FREEZE, `https://github.com/settings/sessions`), `tokens` (`https://github.com/settings/tokens`), `apps` (`https://github.com/settings/applications`), `two_factor` (`https://github.com/settings/security`), `password` (`https://github.com/settings/security`, last; its title says the tool's own token should be replaced afterwards with `panic arm --github LOGIN --token-file FILE --reconnect`). Organisation: API step `org_access` (PURGE, REAPPLY) and guided `members` (`https://github.com/orgs/<name>/people`).
  - `run` deletes what is outside the baseline for the step's categories; it re-reads the lists fresh (no cache), never deletes the primary email, and deletes nothing if any list read fails. `check` returns `True` when nothing in the step's categories is outside the baseline.
  - `signals`: new key in any key category is `key_added`; new email is `email_added`; new repository item is `repo_access_added`; new organisation item is `org_access_added`.
  - CLI: `panic arm --github LOGIN --token-file FILE [--org NAME] [--reconnect]`. Arm refuses when the token's login differs from `LOGIN` (casefolded), or, with `--org`, when the login is not an active admin of it. It shows the snapshot for approval as the Gmail arm does. The token is stored in the vault under `credentials["github"][<account id>]`; the token file's contents are never printed.

- [ ] **Step 1: Write failing tests.** `tests/test_http.py` with a fake `open`: two-page `pages`; 429 with `Retry-After: 3` sleeps 3 then succeeds; four 500s raise `ApiError(500)`; 404 on `delete` is success; 403 raises at once. `tests/test_github.py` with a fake `Api`: snapshot shape and canonical items; a baseline SSH key on page two survives `run` and an added key on page two is deleted; the primary email is never deleted even when outside the baseline; a 500 on any list makes `run` raise with no `delete` issued; a missing baseline category raises the fail-closed `KeyError`; repository categories are not re-read within the hour by `snapshot` but are by `run`; `signals` codes; `check`. `tests/test_cli.py`: arm refuses a token for another login; arm with `--org` refuses a non-admin.
- [ ] **Step 2:** Run. Expected: import errors.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `uv run pytest -q`. Expected: all pass.
- [ ] **Step 5:** Commit: `feat: GitHub connector and shared HTTP client`.

---

### Task 7: Microsoft 365 tenant connector

**Files:**
- Create: `panic/graph_mail.py`, `panic/microsoft_365.py`, `tests/test_graph_mail.py`, `tests/test_microsoft_365.py`
- Modify: `pyproject.toml` (`msal`), `panic/cli.py`, `panic/cli_arm.py`, `panic/session.py`, `tests/test_cli.py`

**Interfaces:**
- Consumes: `Api`, `ApiError` (Task 6); `drift` (Task 1).
- Produces, in `panic/graph_mail.py` (shared with Task 8):
  - `rules(api: Api, user: str) -> list[str]`: `GET /users/<user>/mailFolders/inbox/messageRules` (`user` may be `"me"`, giving `/me/...`), each rule as canonical JSON of `{"displayName", "isEnabled", "conditions", "actions"}`.
  - `delete_rules_outside(api, user, keep: list[str]) -> None`: lists, deletes every rule whose canonical form is not in `keep`, then lists again and raises `RuntimeError` if any such rule remains (read-only or hidden rules).
  - `rule_code(item: str, own_domains: set[str] | None) -> str | None`: `rule_forwards_outside` when `actions.forwardTo`, `forwardAsAttachmentTo` or `redirectTo` names an address outside `own_domains` (any address when `None`); `rule_hides_mail` when `actions.delete` or `actions.permanentDelete` is true, or `actions.moveToFolder` is set together with `actions.markAsRead`; unparseable input is `rule_hides_mail`.
- Produces, in `panic/microsoft_365.py`:
  - `class Microsoft365` with `provider = "microsoft_365"`, `__init__(self, cred: dict, api: Api | None = None, token: Callable[[], str] | None = None)`. `cred` is `{"tenant", "client_id", "client_secret", "admin", "domains": [...]}`. The default `token` uses `msal.ConfidentialClientApplication(client_id, authority="https://login.microsoftonline.com/<tenant>", client_credential=client_secret).acquire_token_for_client(["https://graph.microsoft.com/.default"])` and raises `RuntimeError` with Microsoft's `error_description` on failure. Base `https://graph.microsoft.com/v1.0`.
  - `users() -> list[str]` (user principal names, paged), `domains() -> list[str]` (`GET /domains`, verified ones), `verify_admin() -> None` (the admin exists and `accountEnabled`).
  - `snapshot`: `inbox_rules`, `consent_grants` (`GET /users/<id>/oauth2PermissionGrants`, canonical JSON of `{"clientId", "scope"}`), `auth_methods` (`GET /users/<id>/authentication/methods`, `"<@odata.type>:<id>"`).
  - `catalog`: API `disable` (FREEZE, REAPPLY; `PATCH /users/<id>` `{"accountEnabled": false}`; check reads it back), `sign_out` (FREEZE, `POST /users/<id>/revokeSignInSessions`, `lingers_s=3600`, check `None`), `inbox_rules` (PURGE, REAPPLY, `after_read=True`), `consent_grants` (PURGE, REAPPLY, `lingers_s=3600`; `DELETE /oauth2PermissionGrants/<id>`); guided `mailbox_forwarding` and `delegates` (both `https://admin.exchange.microsoft.com/#/mailboxes`, titles say this tool cannot read them) and `password` (`https://entra.microsoft.com/#view/Microsoft_AAD_UsersAndTenants/UserManagementMenuBlade/~/AllUsers`, last).
  - `release(account) -> str`: re-enables the user and returns `"Sign-in restored. Reset the password in the Entra admin centre before telling the user."`
  - The admin guard of the Workspace connector, casefolded, in `run` and `release`.
  - `signals`: `inbox_rules` by `rule_code(item, set(domains))`; a new `consent_grants` item whose scope contains `Mail.`, `Files.` or `full_access` is `app_consent_added`, otherwise `None`; a new `auth_methods` item is `auth_method_added`.
  - `events(account, since)`: `GET /identityProtection/riskDetections` filtered to the user and `detectedDateTime ge <since>`; `riskLevel == "high"` gives `provider_flagged_login`. An `ApiError` propagates (the guard reports `events_unreadable` once).
  - CLI: `panic arm --microsoft-tenant TENANT --client-id ID --client-secret-file FILE --admin UPN`. Arms every user, protects the admin, records a baseline only for users that have none, as the Workspace arm does. `cmd_release` works for this provider and prints the returned sentence in place of a temporary password.

- [ ] **Step 1: Write failing tests** with a fake `Api`: rule canonical form and the three `rule_code` branches for own and foreign domains; `delete_rules_outside` raises when a rule survives; `disable` and its read-back; `sign_out` has no read-back; `consent_grants` deletion keeps baseline grants; admin refused in `run` and `release` whatever its letter case; a 429-exhausted list read makes `run` raise and delete nothing; missing baseline category; `signals` codes including a grant with scope `User.Read` giving `changed` only; `events` returns one finding for one high and one medium detection; `events` on a 403 raises `ApiError`. CLI: arm protects the admin and keeps existing baselines on a re-arm; `release` re-enables.
- [ ] **Step 2:** Run. Expected: import errors.
- [ ] **Step 3:** Add `msal` with `uv add msal`, implement.
- [ ] **Step 4:** Run `uv run pytest -q`. Expected: all pass.
- [ ] **Step 5:** Commit: `feat: Microsoft 365 tenant connector`.

---

### Task 8: Personal Microsoft connector

**Files:**
- Create: `panic/microsoft_personal.py`, `tests/test_microsoft_personal.py`
- Modify: `panic/cli.py`, `panic/cli_arm.py`, `panic/session.py`, `tests/test_cli.py`

**Interfaces:**
- Consumes: `graph_mail` (Task 7), `Api` (Task 6), `drift` (Task 1).
- Produces:
  - `SCOPES = ["MailboxSettings.ReadWrite"]`.
  - `authorize(client_id: str, login_hint: str | None = None) -> dict`: `msal.PublicClientApplication(client_id, authority="https://login.microsoftonline.com/consumers", token_cache=msal.SerializableTokenCache())`, `acquire_token_interactive(SCOPES, login_hint=login_hint)`; returns `{"client_id", "cache": <serialised cache>, "username": <id_token_claims.preferred_username>}`; raises `RuntimeError` with Microsoft's `error_description` on failure.
  - `class MicrosoftPersonal` with `provider = "microsoft_personal"`, `__init__(self, tokens: dict[str, dict], api=None, token: Callable[[str], str] | None = None)`. The default `token` rebuilds the cache and calls `acquire_token_silent`; when that returns nothing it raises `RuntimeError("sign-in expired; run panic arm --microsoft-personal <email> --reconnect")`.
  - `snapshot`: `{"inbox_rules": graph_mail.rules(api, "me")}`.
  - `catalog`: API `inbox_rules` (PURGE, REAPPLY); guided `forwarding` (FREEZE, `https://outlook.live.com/mail/0/options/mail/forwarding`), `sign_out` (FREEZE, `https://account.microsoft.com/security`), `activity` (`https://account.live.com/Activity`), `apps` (`https://account.live.com/consent/Manage`), `security_info` (`https://account.live.com/proofs/manage`), `password` (`https://account.live.com/password/change`, last; title names the `--reconnect` command).
  - `signals`: `inbox_rules` by `graph_mail.rule_code(item, None)`.
  - CLI: `panic arm --microsoft-personal EMAIL --client-id ID [--reconnect]`. As the Gmail arm: recovery question, sign-in, refuse when `username` differs from `EMAIL` (casefolded) and store nothing, show the snapshot, approve, ask for edges. `main` gains an injectable `ms_authorize` for tests.

- [ ] **Step 1: Write failing tests**: snapshot, a forwarding rule to any address triggers, a move-to-folder rule without mark-as-read is `changed`; `run` deletes outside-baseline rules only; expired sign-in message; CLI arm refuses a different signed-in address and stores nothing; `--reconnect` replaces the token and nothing else.
- [ ] **Step 2:** Run. Expected: import errors.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `uv run pytest -q`. Expected: all pass.
- [ ] **Step 5:** Commit: `feat: personal Microsoft connector`.

---

### Task 9: Slack connector

**Files:**
- Create: `panic/slack.py`, `tests/test_slack.py`
- Modify: `panic/cli.py`, `panic/cli_arm.py`, `panic/session.py`, `tests/test_cli.py`

**Interfaces:**
- Consumes: `Api`, `ApiError` (Task 6).
- Produces:
  - `class Slack` with `provider = "slack"`, `__init__(self, cred: dict, web: Api | None = None, scim: Api | None = None, audit: Api | None = None)`. `cred` is `{"token", "plan", "team", "users": {<email>: <slack user id>}, "primary_owner": <email>}`. Bases: `https://slack.com/api`, `https://api.slack.com/scim/v1`, `https://api.slack.com/audit/v1`. Slack's Web API answers 200 with `{"ok": false, "error": ...}`; a helper turns that into `ApiError(200, error)`.
  - `detect_plan() -> str`: `enterprise` when `GET /logs?limit=1` on the audit API succeeds; else `business` when SCIM `GET /Users?count=1` succeeds; else `pro` when `team.accessLogs` succeeds; else `free` (including the `paid_only` error).
  - `members() -> dict[str, str]`: `users.list` paged, email to id, skipping bots and deactivated members; `primary_owner() -> str`.
  - `snapshot`: `{"active": ["true" | "false"]}` from SCIM on `business` and `enterprise`; `{}` otherwise.
  - `catalog` by plan. `enterprise`: API `reset_sessions` (FREEZE, `admin.users.session.reset`, check `None`) then API `deactivate` (FREEZE, REAPPLY, SCIM `PATCH /Users/<id>` `active: false`, check reads `active`). `business`: `deactivate` only. All plans: guided `apps` (`https://<team>.slack.com/apps/manage`). `pro` and `free`: guided `deactivate` (`https://<team>.slack.com/admin`, FREEZE).
  - `release(account) -> str`: SCIM `active: true`; returns `"Member reactivated."` Refuses on `pro` and `free` with a message pointing at the admin page.
  - The primary owner is refused in `run` and `release`, casefolded.
  - No `signals`. `events(account, since)`: `enterprise`: audit `GET /logs?action=anomaly,user_logout_compromised&oldest=<since>`, entries whose actor or entity user id is this member give `provider_flagged_login`. `pro` and `business`: `team.accessLogs` entries for this member first seen after `since` give a `NOTICE` `new_access` with `items=(ip,)`. `free`: `[]`.
  - CLI: `panic arm --slack --token-file FILE`. Detects the plan, arms every member, protects the primary owner, prints the plan and what it allows. `cmd_release` works for this provider.

- [ ] **Step 1: Write failing tests** with fake `Api`s: plan detection for all four outcomes; catalogue per plan; `deactivate` and its read-back; `{"ok": false, "error": "ratelimited"}` on a read makes `run` raise without a SCIM write; primary owner refused whatever its letter case; `release` on `pro` refuses; `events` on `enterprise` matches only this member; on `pro` returns notices not triggers; on `free` returns `[]`. CLI: arm protects the primary owner.
- [ ] **Step 2:** Run. Expected: import errors.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `uv run pytest -q`. Expected: all pass.
- [ ] **Step 5:** Commit: `feat: Slack connector`.

---

### Task 10: README, sandbox demo, live-check list

**Files:**
- Modify: `README.md`, `demo/sandbox_demo.py`, `docs/superpowers/specs/2026-11-21-panic-button-design.md` (milestone 2 line points at the new spec)
- Create: `docs/live-checks.md`

- [ ] **Step 1:** README: a "Guard" section (what triggers, the three modes, that the vault stays open while it runs, that it does not restart after a reboot, how to approve your own change with `rehearse`); setup for each new provider with the exact permissions or token scopes from the spec; a table "Run on a real account" with one row per connector (Gmail personal: yes; all others: no); the commands table gains `guard` and the new `arm` forms; promise 3 and "What it does not promise" updated for unattended running and for what each provider cannot do.
- [ ] **Step 2:** `demo/sandbox_demo.py`: `SimProvider` gains `signals` (new forwarding is `forwarding_added`); add a scene where the attacker adds forwarding while `guard --passes 2 --interval 30` runs with an injected no-op sleep, and the guard presses by itself. The script's final assertions cover it.
- [ ] **Step 3:** `docs/live-checks.md`: for each connector, the ordered checks to run on a real account, taken from the `?` cells and "UNCONFIRMED" notes of the spec's constraints table, each with the expected result.
- [ ] **Step 4:** Run `uv run pytest -q` and `PYTHONPATH=. uv run python demo/sandbox_demo.py`. Expected: all pass; the demo ends with its "Checked" line.
- [ ] **Step 5:** Commit: `docs: guard, new providers and live-check list`.

---

### Task 11: Live checks (needs the owner)

No code unless a check fails.

- [ ] **Step 1:** Throwaway Gmail: start `panic guard`, add the hiding rule in the browser. Expected: within one interval a notification, an automatic press, the rule gone after a page reload, a report naming the trigger. Add a label-only rule. Expected: a notice, no press.
- [ ] **Step 2:** Open every link in `panic/guided_services.json` and every guided link of the new connectors in a real browser; set `verified` to true where the page is the right one, fix the rest.
- [ ] **Step 3:** For each of Microsoft, GitHub and Slack that the owner provides a test account for, run that connector's list in `docs/live-checks.md`. For the others, the README row stays "no".
- [ ] **Step 4:** Record results in the README table and in `docs/live-checks.md`.
