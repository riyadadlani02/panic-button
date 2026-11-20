# Panic Button Milestone 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A local `panic` command that arms Google accounts (Workspace by admin, personal Gmail by owner), then on a press locks them, records how strongly each lock is proven, watches for 24 hours, and writes a report.

**Architecture:** A provider-neutral engine (vault, account map, plan, executor, watch, report, log) talks to connectors through one four-method interface. The engine is built and tested first against a fake connector; the two Google connectors come after. No model, no server, no browser automation.

**Tech Stack:** Python 3.12+ run through `uv` (system Python is 3.9, do not use it), `cryptography`, `argon2-cffi`, `google-api-python-client`, `google-auth`, `google-auth-oauthlib`, `pytest`. CLI is stdlib `argparse`.

**Spec:** `docs/superpowers/specs/2026-11-21-panic-button-design.md`

## Global Constraints

- Work only in `/Users/riyadadlani/panic-button`. Never touch `/Users/riyadadlani/EmmaLiveKit`.
- `requires-python = ">=3.12"`. All commands run as `uv run ...`.
- No dependency beyond the six named above.
- No model call anywhere. No network call outside a connector.
- Nothing is cached in the OS keychain. The vault is opened only for arm, rehearse, press, watch, release, export.
- Connectors never request a scope that reads mail content.
- Every `run` is safe to call twice.
- One action failing never stops the others.
- A result is `VERIFIED` only when a read-back confirmed it. No read-back means `ACCEPTED` (API) or `OWNER_CONFIRMED` (guided).
- A protected (break-glass) account never receives a step.
- Individual mode never changes a password by API.
- Commits are local only. Never push.

## Review Focus

1. Wrong passphrase, wrong key file or a damaged vault file: one clear `VaultError`, no traceback, no partial data. Tests in Tasks 1 and 10.
2. The tool's own credential died since arm (expired or revoked): every step for that account lands in Still open with the reason; other accounts continue; rehearsal reports it. Tests in Tasks 5 and 10.
3. Pressing twice, or again after an interrupted press: same end state, no error, log still accepts entries. Tests in Tasks 2 and 5.
4. Two accounts that reset each other, and a root account with no connector: no crash; dependents are flagged "re-openable from X". Tests in Tasks 3 and 5.
5. Provider rate limit (HTTP 429) or 5xx during `--all`: the call is retried, then reported, never raised to the top. Test in Task 9.

---

## File map

| File | Responsibility |
|---|---|
| `pyproject.toml` | Package, deps, `panic` entry point |
| `panic/model.py` | Enums and dataclasses shared by everything |
| `panic/vault.py` | Split-key encrypted file |
| `panic/log.py` | Hash-chained JSON-lines log |
| `panic/graph.py` | Lock order and "who can reset this" |
| `panic/executor.py` | `Connector` protocol, `compile_plan`, `press`, `watch_once`, `watch`, `outside_baseline` |
| `panic/report.py` | Markdown and JSON report |
| `panic/gmail_settings.py` | Gmail settings calls shared by both connectors |
| `panic/google_personal.py` | Personal Gmail connector |
| `panic/google_workspace.py` | Workspace connector and `release` |
| `panic/cli.py` | Commands |
| `tests/fake.py` | `FakeConnector` |
| `README.md` | Setup for both modes |

---

### Task 1: Project and vault

**Files:**
- Create: `pyproject.toml`, `.gitignore`, `panic/__init__.py`, `panic/vault.py`
- Test: `tests/test_vault.py`

**Interfaces:**
- Produces: `VaultError(Exception)`, `new_keyfile() -> bytes`, `save(path: Path, data: dict, passphrase: str, keyfile: bytes) -> None`, `load(path: Path, passphrase: str, keyfile: bytes) -> dict`

- [ ] **Step 1: Scaffold.** `git init`; `pyproject.toml` with the six dependencies, `[project.scripts] panic = "panic.cli:main"`, pytest as a dev dependency; `.gitignore` with `.venv/`, `__pycache__/`, `*.vault`, `*.key`. Run `uv sync`. Expected: resolves with Python 3.12 or newer.

- [ ] **Step 2: Write the failing tests**

```python
def test_round_trip(tmp_path):
    key = vault.new_keyfile()
    vault.save(tmp_path / "v", {"a": 1}, "pw", key)
    out = vault.load(tmp_path / "v", "pw", key)
    assert out["a"] == 1 and out["version"] == 1 and "saved_at" in out

def test_version_increments(tmp_path):
    key = vault.new_keyfile(); p = tmp_path / "v"
    vault.save(p, {}, "pw", key)
    vault.save(p, vault.load(p, "pw", key), "pw", key)
    assert vault.load(p, "pw", key)["version"] == 2

@pytest.mark.parametrize("pw,swap_key", [("wrong", False), ("pw", True)])
def test_needs_both_pieces(tmp_path, pw, swap_key):
    key = vault.new_keyfile(); p = tmp_path / "v"
    vault.save(p, {"a": 1}, "pw", key)
    with pytest.raises(vault.VaultError):
        vault.load(p, pw, vault.new_keyfile() if swap_key else key)

def test_damaged_file(tmp_path):
    key = vault.new_keyfile(); p = tmp_path / "v"
    vault.save(p, {"a": 1}, "pw", key)
    p.write_bytes(p.read_bytes()[:-5] + b"xxxxx")
    with pytest.raises(vault.VaultError):
        vault.load(p, "pw", key)

def test_file_is_private_and_fresh_each_save(tmp_path):
    key = vault.new_keyfile(); p = tmp_path / "v"
    vault.save(p, {"a": 1}, "pw", key); first = p.read_bytes()
    vault.save(p, {"a": 1}, "pw", key)
    assert p.stat().st_mode & 0o777 == 0o600 and p.read_bytes() != first
```

- [ ] **Step 3: Run.** `uv run pytest tests/test_vault.py -v`. Expected: FAIL, module has no `save`.

- [ ] **Step 4: Implement `panic/vault.py`.** Fixed choices:
  - Key file is 32 random bytes (`secrets.token_bytes`).
  - KDF: `argon2.low_level.hash_secret_raw(passphrase, salt, time_cost=3, memory_cost=65536, parallelism=4, hash_len=32, type=Type.ID)` with a 16-byte random salt, then HKDF-SHA256 over `argon_output + keyfile`, `info=b"panic-vault-v1"`, 32 bytes out.
  - Cipher: `ChaCha20Poly1305`, 12-byte random nonce. New salt and nonce on every save.
  - File: first line is a JSON header `{"format":1,"salt":...,"nonce":...}` (base64); the rest is ciphertext. The header line is the associated data.
  - `save` sets `data["version"] = data.get("version", 0) + 1` and `data["saved_at"]` (UTC ISO), writes to a temp file with mode `0o600`, then `os.replace`.
  - Any decode, tag or JSON failure raises `VaultError("Could not open the vault: wrong passphrase, wrong key file, or damaged file.")`.

- [ ] **Step 5: Run.** Same command. Expected: 6 passed.

- [ ] **Step 6: Commit.** `git add -A && git commit -m "feat: split-key vault"`

---

### Task 2: Tamper-evident log

**Files:**
- Create: `panic/log.py`
- Test: `tests/test_log.py`

**Interfaces:**
- Produces: `append(path: Path, entry: dict) -> None`, `verify(path: Path) -> bool`

- [ ] **Step 1: Write the failing tests**

```python
def test_chain_verifies(tmp_path):
    p = tmp_path / "log.jsonl"
    log.append(p, {"e": 1}); log.append(p, {"e": 2})
    lines = [json.loads(l) for l in p.read_text().splitlines()]
    assert lines[0]["prev"] == "" and lines[1]["prev"] != "" and "at" in lines[0]
    assert log.verify(p)

def test_edit_is_detected(tmp_path):
    p = tmp_path / "log.jsonl"
    log.append(p, {"e": 1}); log.append(p, {"e": 2})
    p.write_text(p.read_text().replace('"e": 1', '"e": 9'))
    assert not log.verify(p)

def test_torn_last_line_does_not_block_new_entries(tmp_path):
    p = tmp_path / "log.jsonl"
    log.append(p, {"e": 1})
    with p.open("a") as f: f.write('{"e": 2, "pre')
    log.append(p, {"e": 3})
    assert not log.verify(p)
    assert json.loads(p.read_text().splitlines()[-1])["e"] == 3
```

- [ ] **Step 2: Run.** `uv run pytest tests/test_log.py -v`. Expected: FAIL.

- [ ] **Step 3: Implement.** `append` writes one JSON line with the caller's keys plus `at` (epoch seconds) and `prev` = SHA-256 hex of the previous line's bytes, `""` for the first. If the file does not end in a newline, write one first. `verify` recomputes the chain and returns `False` on any mismatch or unparsable line; a missing file is `True`.

- [ ] **Step 4: Run.** Expected: 3 passed.

- [ ] **Step 5: Commit.** `git add -A && git commit -m "feat: hash-chained log"`

---

### Task 3: Model and account map

**Files:**
- Create: `panic/model.py`, `panic/graph.py`
- Test: `tests/test_graph.py`

**Interfaces:**
- Produces, in `model.py`:

```python
class Phase(StrEnum):       FREEZE = "freeze"; PURGE = "purge"
class Tier(StrEnum):        API = "api"; GUIDED = "guided"
class Evidence(StrEnum):    VERIFIED = "verified"; ACCEPTED = "accepted"; OWNER_CONFIRMED = "owner_confirmed"
class Status(StrEnum):      LOCKED = "locked"; NEEDS_YOU = "needs_you"; STILL_OPEN = "still_open"
class WatchPolicy(StrEnum): REAPPLY = "reapply"; REPORT = "report"; NONE = "none"

@dataclass(frozen=True)
class Account: id: str; provider: str; protected: bool = False

@dataclass(frozen=True)
class Step:
    account: str; action: str; phase: Phase; tier: Tier; title: str
    link: str | None = None; watch: WatchPolicy = WatchPolicy.NONE; lingers_s: int = 0

@dataclass
class Result: step: Step; status: Status; evidence: Evidence | None = None; detail: str = ""; at: float = 0.0

@dataclass
class Outcome: results: list[Result]; touched: dict[str, list[str]]; started_at: float

Edges = list[tuple[str, str]]          # (a, b): control of a can reset b
Snapshot = dict[str, list[str]]        # category -> human-readable items
```

- Produces, in `graph.py`: `lock_order(accounts: list[str], edges: Edges) -> list[str]`, `resetters(account: str, edges: Edges) -> set[str]`

- [ ] **Step 1: Write the failing tests**

```python
E = [("mail", "bank"), ("mail", "social"), ("social", "forum")]

def test_root_first():
    order = graph.lock_order(["forum", "bank", "social", "mail"], E)
    assert order[0] == "mail" and order.index("social") < order.index("forum")

def test_mutual_recovery_does_not_loop():
    order = graph.lock_order(["a", "b", "c"], [("a", "b"), ("b", "a"), ("a", "c")])
    assert set(order[:2]) == {"a", "b"} and order[2] == "c"

def test_resetters_are_transitive():
    assert graph.resetters("forum", E) == {"social", "mail"}
    assert graph.resetters("mail", E) == set()

def test_unconnected_account_is_kept():
    order = graph.lock_order(["x", "mail", "bank"], E)
    assert order[0] == "mail" and sorted(order) == ["bank", "mail", "x"]
```

- [ ] **Step 2: Run.** `uv run pytest tests/test_graph.py -v`. Expected: FAIL.

- [ ] **Step 3: Implement.** `lock_order` sorts by the number of accounts each one can reach (itself included), largest first, stable on input order. This is a valid root-first order and puts mutually resetting accounts together without cycle handling. `resetters` is every account that can reach the given one, excluding itself. Edges naming accounts not in the list are still followed. Mark the reach computation `# ponytail: BFS per account, O(n^2); fine to thousands of accounts`.

- [ ] **Step 4: Run.** Expected: 4 passed.

- [ ] **Step 5: Commit.** `git add -A && git commit -m "feat: model and account map"`

---

### Task 4: Connector interface, fake connector, plan

**Files:**
- Create: `panic/executor.py`, `tests/fake.py`
- Test: `tests/test_plan.py`

**Interfaces:**
- Consumes: Task 3 model and `graph.lock_order`
- Produces, in `executor.py`:

```python
class Connector(Protocol):
    provider: str
    def catalog(self, account: Account) -> list[Step]: ...     # no network; order = guided presentation order
    def snapshot(self, account: Account) -> Snapshot: ...      # read-only
    def run(self, step: Step, baseline: Snapshot) -> None: ... # safe to call twice
    def check(self, step: Step, baseline: Snapshot) -> bool | None: ...  # None = no read-back exists

def compile_plan(accounts: list[Account], edges: Edges, connectors: dict[str, Connector]) -> list[Step]
def outside_baseline(baseline: Snapshot, current: Snapshot) -> list[str]   # "category: item"
```

- Produces, in `tests/fake.py`: `FakeConnector(provider="fake", steps=[...], fail=set(), no_readback=set())` with attributes `ran: list[str]` (as `"account/action"`), `state: dict[str, bool]` (same keys; `check` returns `state.get(key, False)`, `run` sets it `True`), `snap: Snapshot` (returned by `snapshot`, default `{}`). `run` raises `RuntimeError("boom")` for keys in `fail`; `check` returns `None` for actions in `no_readback`. `catalog` returns `steps` with `account` filled in.

- [ ] **Step 1: Write the failing tests**

```python
ACCTS = [Account("bank", "fake"), Account("mail", "fake"), Account("boss", "fake", protected=True), Account("old", "nowhere")]

def test_plan_is_root_first_freeze_before_purge():
    plan = compile_plan(ACCTS, [("mail", "bank")], {"fake": FakeConnector(steps=[
        Step("", "purge_x", Phase.PURGE, Tier.API, "x"), Step("", "freeze_x", Phase.FREEZE, Tier.API, "x")])})
    assert [(s.account, s.action) for s in plan] == [
        ("mail", "freeze_x"), ("bank", "freeze_x"), ("mail", "purge_x"), ("bank", "purge_x")]

def test_protected_and_unsupported_accounts_get_no_steps():
    plan = compile_plan(ACCTS, [], {"fake": FakeConnector(steps=[Step("", "f", Phase.FREEZE, Tier.API, "f")])})
    assert {s.account for s in plan} == {"bank", "mail"}

def test_outside_baseline():
    assert outside_baseline({"filters": ["a"], "delegates": []}, {"filters": ["a", "b"], "delegates": ["x"], "new": ["n"]}) \
        == ["delegates: x", "filters: b", "new: n"]
```

- [ ] **Step 2: Run.** `uv run pytest tests/test_plan.py -v`. Expected: FAIL.

- [ ] **Step 3: Implement** `Connector`, `compile_plan`, `outside_baseline` and `FakeConnector`. Plan order: all FREEZE steps in lock order, then all PURGE steps in lock order; within one account, catalog order. `outside_baseline` output is sorted.

- [ ] **Step 4: Run.** Expected: 3 passed.

- [ ] **Step 5: Commit.** `git add -A && git commit -m "feat: connector interface and plan"`

---

### Task 5: The press

**Files:**
- Modify: `panic/executor.py`
- Test: `tests/test_press.py`

**Interfaces:**
- Consumes: Task 4
- Produces:

```python
def press(plan: list[Step], accounts: list[Account], edges: Edges, connectors: dict[str, Connector],
          baselines: dict[str, Snapshot], confirm: Callable[[Step], bool], log: Callable[[dict], None],
          dry_run: bool = False, now: Callable[[], float] = time.time) -> Outcome
```

- [ ] **Step 1: Write the failing tests.** Helper `mk(**kw)` builds a `FakeConnector` with steps `freeze` (FREEZE, API), `signout` (FREEZE, API), `purge` (PURGE, API), `guided` (PURGE, GUIDED) and `no_readback={"signout", "guided"}`, merged with `kw`. `by(out, account, action)` returns that `Result`.

```python
A = [Account("mail", "fake"), Account("bank", "fake")]; E = [("mail", "bank")]
def run(c, confirm=lambda s: True, **kw):
    return press(compile_plan(A, E, {"fake": c}), A, E, {"fake": c}, {}, confirm, lambda e: None, **kw)

def test_evidence_levels():
    out = run(mk())
    assert by(out, "mail", "freeze").evidence is Evidence.VERIFIED
    assert by(out, "mail", "signout").evidence is Evidence.ACCEPTED
    assert by(out, "mail", "guided").evidence is Evidence.OWNER_CONFIRMED
    assert all(r.status is Status.LOCKED for r in out.results)

def test_unconfirmed_guided_step_needs_you():
    assert by(run(mk(), confirm=lambda s: False), "mail", "guided").status is Status.NEEDS_YOU

def test_guided_step_marked_done_but_readback_disagrees():
    assert by(run(mk(no_readback={"signout"})), "mail", "guided").status is Status.NEEDS_YOU

def test_failure_is_isolated_and_marks_dependents():
    out = run(mk(fail={"mail/freeze"}))
    assert by(out, "mail", "freeze").status is Status.STILL_OPEN and "boom" in by(out, "mail", "freeze").detail
    assert by(out, "bank", "freeze").status is Status.LOCKED
    assert by(out, "bank", "reopenable").status is Status.STILL_OPEN and "mail" in by(out, "bank", "reopenable").detail

def test_run_succeeds_but_readback_says_no():
    c = mk(); c.run = lambda step, baseline: c.ran.append(step.action)      # never flips state
    assert by(run(c), "mail", "freeze").status is Status.STILL_OPEN

def test_root_without_connector_marks_dependents():
    accts = [Account("outlook", "nowhere"), Account("bank", "fake")]; c = mk()
    out = press(compile_plan(accts, [("outlook", "bank")], {"fake": c}), accts, [("outlook", "bank")], {"fake": c}, {}, lambda s: True, lambda e: None)
    assert "outlook" in by(out, "bank", "reopenable").detail

def test_dead_credential_fails_every_step_for_that_account_only():
    out = run(mk(fail={"mail/freeze", "mail/signout", "mail/purge"}))
    assert {r.status for r in out.results if r.step.account == "mail" and r.step.tier is Tier.API} == {Status.STILL_OPEN}
    assert by(out, "bank", "purge").status is Status.LOCKED

def test_pressing_twice_is_safe():
    c = mk(); first = run(c); second = run(c)
    assert [(r.step.action, r.status) for r in first.results] == [(r.step.action, r.status) for r in second.results]

def test_dry_run_changes_nothing():
    c = mk(); c.snap = {"filters": ["evil"]}
    out = run(c, dry_run=True, confirm=lambda s: pytest.fail("asked during dry run"))
    assert c.ran == [] and out.touched["mail"] == ["filters: evil"]

def test_touched_and_log():
    c = mk(); c.snap = {"filters": ["evil"]}; seen = []
    out = press(compile_plan(A, E, {"fake": c}), A, E, {"fake": c}, {"mail": {"filters": []}, "bank": {"filters": ["evil"]}}, lambda s: True, seen.append)
    assert out.touched == {"mail": ["filters: evil"], "bank": []}
    assert len(seen) == len(out.results) and {"account", "action", "status", "evidence"} <= seen[0].keys()

def test_guided_steps_are_asked_roots_first_after_api_steps():
    asked = []; c = mk()
    run(c, confirm=lambda s: asked.append((s.account, len(c.ran))) or True)
    assert asked == [("mail", 6), ("bank", 6)]
```

- [ ] **Step 2: Run.** `uv run pytest tests/test_press.py -v`. Expected: FAIL.

- [ ] **Step 3: Implement `press`.**
  - Take a snapshot of every account that has a connector; `touched[account] = outside_baseline(baselines.get(account, {}), snapshot)`. A snapshot that raises gives `touched[account] = ["unknown: could not read (<error>)"]`.
  - API steps: all FREEZE steps submitted to one `ThreadPoolExecutor` in plan order and awaited, then all PURGE steps the same way. For each: `run`, then `check`. `True` is LOCKED/VERIFIED, `None` is LOCKED/ACCEPTED, `False` is STILL_OPEN with detail `"provider accepted the call but the read-back still shows it open"`. Any exception is STILL_OPEN with `detail=str(error)`; exceptions never leave the worker.
  - Guided steps after all API steps, serially, plan order: `confirm(step)`; `False` is NEEDS_YOU; `True` then `check`: `True` VERIFIED, `None` OWNER_CONFIRMED, `False` NEEDS_YOU with detail `"marked done but the read-back still shows it open"`.
  - An account is open if it is unprotected and either has no steps in the plan or has a FREEZE step that is not LOCKED. For every account with an open resetter, append one `Result(Step(account, "reopenable", Phase.FREEZE, Tier.API, "Re-openable"), Status.STILL_OPEN, detail="re-openable from " + ", ".join(sorted(open resetters)))`.
  - `dry_run`: snapshots and `touched` only; every plan step is returned as STILL_OPEN with detail `"dry run"`; no `run`, no `confirm`.
  - `log` is called once per result with `account, action, phase, tier, status, evidence, detail`.
  - Results are returned in plan order, re-openable entries last. `Result.at` is `now()` when the step finished.

- [ ] **Step 4: Run.** Expected: 11 passed.

- [ ] **Step 5: Commit.** `git add -A && git commit -m "feat: press with evidence levels"`

---

### Task 6: Watch

**Files:**
- Modify: `panic/executor.py`
- Test: `tests/test_watch.py`

**Interfaces:**
- Produces:

```python
def watch_once(results: list[Result], connectors: dict[str, Connector], accounts: list[Account],
               baselines: dict[str, Snapshot], released: set[str], log: Callable[[dict], None]) -> list[str]
def watch(results, connectors, accounts, baselines, released: Callable[[], set[str]], log,
          hours: float = 24, interval_s: float = 300,
          sleep: Callable[[float], None] = time.sleep, now: Callable[[], float] = time.time) -> None
```

`watch_once` returns one line per change found. `released` holds account ids whose suspension the owner lifted.

- [ ] **Step 1: Write the failing tests.** `locked(action, policy)` builds a LOCKED `Result` for account `mail` with that watch policy; fixture `c` is a `FakeConnector` whose `state` starts all `True`; `seen` is a list used as the log.

```python
def test_reapply_puts_setting_back():
    c.state["mail/fwd"] = False
    lines = watch_once([locked("fwd", WatchPolicy.REAPPLY)], {"fake": c}, A, {}, set(), seen.append)
    assert c.state["mail/fwd"] is True and "mail/fwd" in c.ran and len(lines) == 1 and seen[0]["event"] == "reapplied"

def test_report_policy_never_runs():
    c.state["mail/apps"] = False
    lines = watch_once([locked("apps", WatchPolicy.REPORT)], {"fake": c}, A, {}, set(), seen.append)
    assert c.ran == [] and seen[0]["event"] == "changed" and len(lines) == 1

def test_released_account_is_not_resuspended():
    c.state["mail/suspend"] = False
    assert watch_once([locked("suspend", WatchPolicy.REAPPLY)], {"fake": c}, A, {}, {"mail"}, seen.append) == []

def test_quiet_when_nothing_changed_and_skips_non_locked():
    open_one = Result(Step("mail", "x", Phase.FREEZE, Tier.API, "x", watch=WatchPolicy.REAPPLY), Status.STILL_OPEN)
    assert watch_once([locked("fwd", WatchPolicy.REAPPLY), open_one], {"fake": c}, A, {}, set(), seen.append) == [] and seen == []

def test_a_failing_check_is_reported_not_raised():
    c.check = lambda step, baseline: (_ for _ in ()).throw(RuntimeError("net down"))
    assert "net down" in watch_once([locked("fwd", WatchPolicy.REAPPLY)], {"fake": c}, A, {}, set(), seen.append)[0]

def test_loop_stops_after_window():
    clock = iter(range(0, 100000, 3600)); sleeps = []
    watch([], {}, [], {}, set, lambda e: None, hours=2, interval_s=3600, sleep=sleeps.append, now=lambda: next(clock))
    assert sleeps == [3600]
```

- [ ] **Step 2: Run.** `uv run pytest tests/test_watch.py -v`. Expected: FAIL.

- [ ] **Step 3: Implement.** `watch_once` looks only at LOCKED results whose policy is not NONE and whose `check` is not `None`. The "released" exemption applies only to the action named `suspend`; that name is the contract connectors follow. `watch` is exactly: `deadline = now() + hours * 3600`, then `while now() < deadline:` call `watch_once` with `released()`, print each line, `sleep(interval_s)`.

- [ ] **Step 4: Run.** Expected: 6 passed.

- [ ] **Step 5: Commit.** `git add -A && git commit -m "feat: 24-hour watch"`

---

### Task 7: Report

**Files:**
- Create: `panic/report.py`
- Test: `tests/test_report.py`

**Interfaces:**
- Produces: `render(outcome: Outcome, now: float) -> tuple[str, dict]` (Markdown, JSON-ready dict with keys `locked`, `needs_you`, `still_open`, `touched`, `freeze_seconds`)

- [ ] **Step 1: Write the failing tests.** Fixture `outcome` holds one VERIFIED, one ACCEPTED, one OWNER_CONFIRMED, one NEEDS_YOU with `link="https://example.test/step"`, one STILL_OPEN.

```python
def test_sections_and_evidence_are_never_merged(outcome):
    md, data = report.render(outcome, now=1000.0)
    heads = ["## Locked", "## Needs you", "## Still open", "## Attacker may have touched"]
    assert [md.index(h) for h in heads] == sorted(md.index(h) for h in heads)
    assert "### Verified" in md and "### Accepted by provider" in md and "### Owner confirmed" in md
    assert "https://example.test/step" in md
    assert len(data["locked"]) == 3 and {i["evidence"] for i in data["locked"]} == {"verified", "accepted", "owner_confirmed"}

def test_lingering_access_is_listed_as_open_until_it_expires():
    r = Result(Step("mail", "signout", Phase.FREEZE, Tier.API, "Sign out", lingers_s=3600), Status.LOCKED, Evidence.ACCEPTED, at=500.0)
    _, data = report.render(Outcome([r], {}, 490.0), now=1000.0)
    assert any("may keep working until" in i["detail"] for i in data["still_open"])
    _, later = report.render(Outcome([r], {}, 490.0), now=5000.0)
    assert later["still_open"] == []

def test_no_safe_claim_and_empty_sections_say_nothing():
    md, _ = report.render(Outcome([], {"mail": ["unknown: could not read (x)"]}, 0.0), now=1.0)
    assert "unknown" in md and "safe" not in md.lower() and md.count("Nothing.") == 3

def test_freeze_time_is_measured():
    r = Result(Step("mail", "f", Phase.FREEZE, Tier.API, "f"), Status.LOCKED, Evidence.VERIFIED, at=130.0)
    assert report.render(Outcome([r], {}, 100.0), now=200.0)[1]["freeze_seconds"] == 30.0
```

- [ ] **Step 2: Run.** `uv run pytest tests/test_report.py -v`. Expected: FAIL.

- [ ] **Step 3: Implement.** `freeze_seconds` is the latest `at` among LOCKED FREEZE results minus `started_at`, `None` if there are none or any FREEZE result is not LOCKED. The report states it against the 60-second target. The word "safe" never appears in the output. An empty section prints "Nothing." so an absent section is never mistaken for a clean one. A LOCKED result with `lingers_s > 0` and `at + lingers_s > now` adds a Still open item: `"access granted before the press may keep working until <UTC time>"`.

- [ ] **Step 4: Run.** Expected: 4 passed.

- [ ] **Step 5: Commit.** `git add -A && git commit -m "feat: lockdown report"`

---

### Task 8: Personal Gmail connector

**Files:**
- Create: `panic/gmail_settings.py`, `panic/google_personal.py`
- Test: `tests/test_google_personal.py`

**Interfaces:**
- Consumes: `Connector`, model
- Produces, in `gmail_settings.py` (each takes a Gmail API service object, `userId="me"`):
  `filters(svc) -> list[str]` (one canonical string per filter: sorted-key JSON of `criteria` and `action`, id excluded), `delete_filters_outside(svc, keep: list[str]) -> None`, `forwarding(svc) -> list[str]` (`["on -> addr"]` or `[]`), `imap_pop(svc) -> list[str]` (subset of `["imap", "pop"]` that are enabled), `disable_imap_pop(svc) -> None`
- Produces, in `google_personal.py`: `SCOPES = ["https://www.googleapis.com/auth/gmail.settings.basic"]`, `authorize(client_secrets: Path) -> dict` (token info for the vault, via `InstalledAppFlow.run_local_server`), `Personal(token_info: dict, build=googleapiclient.discovery.build)` implementing `Connector` with `provider = "google_personal"`

Catalog, in this order (this is the guided order the owner sees):

| action | phase | tier | watch | read-back | link |
|---|---|---|---|---|---|
| `imap_pop` | FREEZE | API | REAPPLY | yes | |
| `forwarding_off` | FREEZE | GUIDED | REPORT | yes (`forwarding(svc) == []`) | `https://mail.google.com/mail/u/0/#settings/fwdandpop` |
| `sign_out` | FREEZE | GUIDED | NONE | none, `lingers_s=3600` | `https://myaccount.google.com/device-activity` |
| `filters` | PURGE | API | REAPPLY | yes | |
| `revoke_apps` | PURGE | GUIDED | NONE | none, `lingers_s=3600` | `https://myaccount.google.com/connections` |
| `app_passwords` | PURGE | GUIDED | NONE | none | `https://myaccount.google.com/apppasswords` |
| `delegates` | PURGE | GUIDED | NONE | none | `https://mail.google.com/mail/u/0/#settings/accounts` |
| `recovery` | PURGE | GUIDED | NONE | none | `https://myaccount.google.com/security` |
| `password` | PURGE | GUIDED | NONE | none | `https://myaccount.google.com/signinoptions/password` |

Titles are plain instructions. `revoke_apps` must say: "Remove every connected app except panic-button." `password` must say: "Change your password now. This disconnects panic-button; run `panic arm --personal <email> --reconnect` straight after so the 24-hour watch can continue."

- [ ] **Step 1: Check the nine links.** They are from memory. Fetch each (or ask the owner to open them signed in) and replace any that does not land on the named setting. Expected: nine working links.

- [ ] **Step 2: Write the failing tests** with a `MagicMock` Gmail service injected through `build`:

```python
def test_snapshot_shape():
    assert set(conn.snapshot(ACCT)) == {"filters", "forwarding", "imap_pop"}

def test_filters_deletes_only_what_is_outside_baseline():
    # service lists filters f1 (in baseline) and f2 (not)
    conn.run(step("filters"), {"filters": [canon_f1]})
    svc.users().settings().filters().delete.assert_called_once_with(userId="me", id="f2")

def test_filter_identity_survives_a_changed_id():
    # service lists one filter with f1's criteria/action under a new id
    conn.run(step("filters"), {"filters": [canon_f1]})
    assert not svc.users().settings().filters().delete.called

def test_guided_steps_never_call_the_api():
    with pytest.raises(NotImplementedError): conn.run(step("password"), {})

def test_readbacks():
    assert conn.check(step("forwarding_off"), {}) is False     # service reports enabled
    assert conn.check(step("sign_out"), {}) is None

def test_scope_cannot_read_mail():
    assert google_personal.SCOPES == ["https://www.googleapis.com/auth/gmail.settings.basic"]
```

- [ ] **Step 3: Run.** `uv run pytest tests/test_google_personal.py -v`. Expected: FAIL.

- [ ] **Step 4: Implement** both files. `run` on any GUIDED action raises `NotImplementedError`. Build the service once per connector with `cache_discovery=False`.

- [ ] **Step 5: Run.** Expected: 6 passed.

- [ ] **Step 6: Commit.** `git add -A && git commit -m "feat: personal Gmail connector"`

---

### Task 9: Workspace connector

**Files:**
- Create: `panic/google_workspace.py`
- Test: `tests/test_google_workspace.py`

**Interfaces:**
- Consumes: `gmail_settings`, `Connector`
- Produces: `SCOPES` (exactly: `admin.directory.user`, `admin.directory.user.security`, `gmail.settings.basic`, `gmail.settings.sharing`, each as a full `https://www.googleapis.com/auth/...` URL), `Workspace(sa_info: dict, admin: str, domain: str, build=googleapiclient.discovery.build, sleep=time.sleep)` implementing `Connector` with `provider = "google_workspace"`, plus `users(self) -> list[str]` (primary emails in the tenant) and `release(self, account: Account) -> str` (unsuspends, sets a fresh temporary password with change-at-next-login, returns it)

Directory calls impersonate `admin`; Gmail calls impersonate the target user. All are API tier.

| action | phase | watch | call | read-back |
|---|---|---|---|---|
| `suspend` | FREEZE | REAPPLY | `users.update(suspended=True)` | `users.get().suspended` |
| `sign_out` | FREEZE | NONE | `users.signOut`, `lingers_s=3600` | none |
| `forwarding_off` | FREEZE | REAPPLY | `updateAutoForwarding(enabled=False)` | `getAutoForwarding` |
| `revoke_apps` | PURGE | REPORT | `tokens.list` then `tokens.delete` each, `lingers_s=3600` | list is empty |
| `app_passwords` | PURGE | REPORT | `asps.list` then `asps.delete` each | list is empty |
| `backup_codes` | PURGE | NONE | `verificationCodes.invalidate` | none |
| `forwarding_addresses` | PURGE | REAPPLY | delete every address outside `domain`, and every one outside the baseline | none remain |
| `delegates` | PURGE | REAPPLY | delete all delegates | list is empty |
| `filters` | PURGE | REAPPLY | `gmail_settings.delete_filters_outside` | none outside baseline |
| `imap_pop` | PURGE | REAPPLY | `gmail_settings.disable_imap_pop` | both off |
| `recovery` | PURGE | REAPPLY | `users.update` recovery email and phone to baseline values | equal to baseline |
| `reset_password` | PURGE | NONE | `users.update(password=secrets.token_urlsafe(32), changePasswordAtNextLogin=True)` | none |

Snapshot categories: `forwarding`, `forwarding_addresses`, `delegates`, `filters`, `imap_pop`, `recovery`, `apps`, `app_passwords`.

- [ ] **Step 1: Confirm the five unverified calls against Google's Admin SDK Directory reference** (`users.update` with `suspended`, `tokens.delete`, `asps.delete`, `verificationCodes.invalidate`, `recoveryEmail`/`recoveryPhone` on the user resource). Record the reference URL for each in a comment at the top of the file. If one does not exist as described, stop and report; do not improvise a substitute.

- [ ] **Step 2: Write the failing tests** with `MagicMock` services. `ACCT = Account("a@corp.test", "google_workspace")`; the connector is built with `admin="breakglass@corp.test"`, `domain="corp.test"`, `sleep=sleeps.append`.

```python
def test_suspend_and_readback():
    conn.run(step("suspend"), {}); directory.users().update.assert_called_with(userKey="a@corp.test", body={"suspended": True})
    directory.users().get().execute.return_value = {"suspended": True}; assert conn.check(step("suspend"), {}) is True

def test_sign_out_has_no_readback_and_lingers():
    s = next(x for x in conn.catalog(ACCT) if x.action == "sign_out")
    assert conn.check(s, {}) is None and s.lingers_s == 3600

def test_outside_domain_forwarding_goes_even_if_baselined():
    # addresses: in@corp.test (baselined), out@evil.test (baselined), new@corp.test (not baselined)
    conn.run(step("forwarding_addresses"), {"forwarding_addresses": ["in@corp.test", "out@evil.test"]})
    assert deleted == {"out@evil.test", "new@corp.test"}

def test_all_delegates_removed():
    conn.run(step("delegates"), {"delegates": ["pa@corp.test"]}); assert deleted == {"pa@corp.test"}

def test_gmail_calls_impersonate_the_target_and_directory_calls_the_admin():
    conn.run(step("forwarding_off"), {}); conn.run(step("suspend"), {})
    assert subjects_used == {"gmail": "a@corp.test", "admin": "breakglass@corp.test"}

def test_rate_limit_is_retried_then_reported():
    directory.users().signOut().execute.side_effect = [http_error(429), http_error(503), None]
    conn.run(step("sign_out"), {}); assert sleeps == [1, 2]
    directory.users().signOut().execute.side_effect = [http_error(429)] * 4
    with pytest.raises(HttpError): conn.run(step("sign_out"), {})

def test_running_twice_on_an_already_clean_account_is_quiet():
    # tokens.list returns no items; a 404 on delete is treated as already gone
    conn.run(step("revoke_apps"), {}); conn.run(step("revoke_apps"), {})

def test_release_unsuspends_and_returns_a_temp_password():
    pw = conn.release(ACCT); body = directory.users().update.call_args.kwargs["body"]
    assert body["suspended"] is False and body["changePasswordAtNextLogin"] is True and body["password"] == pw and len(pw) >= 16

def test_scopes_cannot_read_mail():
    assert not any(s.endswith(("gmail.readonly", "gmail.modify", "mail.google.com/")) for s in google_workspace.SCOPES)
```

- [ ] **Step 3: Run.** `uv run pytest tests/test_google_workspace.py -v`. Expected: FAIL.

- [ ] **Step 4: Implement.** One private `_call(request)` wraps every `.execute()`: on HTTP 429 or 5xx it sleeps 1, 2, 4 seconds and retries (four attempts in all), then re-raises. A 404 on any delete is success.

- [ ] **Step 5: Run.** Expected: 9 passed.

- [ ] **Step 6: Commit.** `git add -A && git commit -m "feat: Workspace connector"`

---

### Task 10: Commands

**Files:**
- Create: `panic/cli.py`, `README.md`
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes: everything above
- Produces: `main(argv: list[str] | None = None, connectors: dict[str, Connector] | None = None) -> int` (`connectors` is the test seam; when `None` they are built from the vault's credentials)

Global options: `--vault PATH` (default `~/.panic/panic.vault`), `--keyfile PATH` (or env `PANIC_KEYFILE`, required). Passphrase by `getpass`. Log at `<vault>.log.jsonl`. Report at `<vault>.report.md` and `<vault>.report.json`.

Vault contents: `accounts`, `edges`, `baselines`, `plan`, `credentials` (per provider), `released`, `last_outcome`.

| Command | Behaviour |
|---|---|
| `arm --personal EMAIL --client-secrets FILE` | Refuses unless the owner answers yes to "Do you hold a way to recover EMAIL that does not depend on EMAIL itself (printed backup codes or a security key)?". Authorises, takes a snapshot, prints it, asks for approval, then asks "Which of your armed accounts can reset this one?" to add edges. Creates the vault and a new key file if absent, printing where the key file must be moved. |
| `arm --personal EMAIL --reconnect` | Re-authorises only. |
| `arm --workspace --sa-key FILE --admin EMAIL --domain DOMAIN` | Marks `EMAIL` as the protected break-glass account. Arms every user from `Workspace.users()`. Records baselines without printing them. |
| `map` | Prints each account with what it can reset, then a line `Can reset the most: <id>`. |
| `rehearse` | Takes snapshots, recompiles the plan, and for each account shows what is outside the baseline. Personal: full items, asks to approve each account's new baseline. Workspace: only items in categories `forwarding`, `forwarding_addresses`, `delegates`, `recovery`, as per-user flags; never filter contents. A connector error is printed per account and makes the exit code 1. |
| `press [--user ID ...] [--all] [--dry-run]` | Requires `--user` or `--all`. Unknown or protected `--user` is an error listing valid ids. Runs `press`, saves `last_outcome`, writes the report, prints it, then starts `watch` unless `--dry-run`. |
| `watch` | Resumes watching `last_outcome`. |
| `release --user ID` | Asks for confirmation, calls the connector's `release`, prints the temporary password once, adds the id to `released`. Error for providers without `release`. |
| `report` | Re-renders the report from `last_outcome` at the current time. |
| `export DEST` | Copies the vault file. Refuses if `DEST` is on the same device as the key file (`os.stat().st_dev`). |

On every open: warn if the key file and vault are on the same device. On `press` from a vault whose `saved_at` is over 30 days old: warn that the copy may be stale and that more may be removed than expected.

- [ ] **Step 1: Write the failing tests.** `cli(*args, passphrase="pw", answers=())` calls `main([...], connectors={"fake": fake})` with `getpass` and `input` patched; fixture `armed` writes a vault with accounts `mail`, `bank` (edge mail to bank) and protected `boss`; `patch_watch` replaces `executor.watch` with a mock.

```python
def test_dry_run_changes_nothing_and_writes_no_outcome(armed):
    assert cli("press", "--all", "--dry-run") == 0 and fake.ran == [] and "last_outcome" not in open_vault()

def test_press_all_skips_protected_and_writes_report_and_log(armed, patch_watch):
    assert cli("press", "--all") == 0
    assert not any(k.startswith("boss/") for k in fake.ran)
    assert "## Locked" in report_path.read_text() and log.verify(log_path) and patch_watch.called

def test_press_requires_a_target_and_rejects_protected_or_unknown(armed):
    assert cli("press") != 0 and cli("press", "--user", "boss") != 0 and cli("press", "--user", "nobody") != 0
    assert fake.ran == []

def test_wrong_passphrase_is_one_line_not_a_traceback(armed, capsys):
    assert cli("map", passphrase="wrong") == 1 and "Traceback" not in capsys.readouterr().err

def test_rehearse_reports_a_dead_connector(armed, capsys):
    fake.snapshot = lambda a: (_ for _ in ()).throw(RuntimeError("token expired"))
    assert cli("rehearse") == 1 and "token expired" in capsys.readouterr().out

def test_rehearse_never_absorbs_a_change_without_approval(armed):
    fake.snap = {"filters": ["evil"]}; cli("rehearse", answers=["n", "n"])
    assert open_vault()["baselines"]["mail"].get("filters", []) == []

def test_export_refuses_same_device_as_keyfile(armed, tmp_path):
    assert cli("export", str(tmp_path / "copy.vault")) != 0

def test_release_marks_account(armed):
    fake.release = lambda a: "temp-pass-123456789"
    assert cli("release", "--user", "mail", answers=["y"]) == 0 and "mail" in open_vault()["released"]

def test_map_names_the_root(armed, capsys):
    cli("map"); assert "Can reset the most: mail" in capsys.readouterr().out
```

- [ ] **Step 2: Run.** `uv run pytest tests/test_cli.py -v`. Expected: FAIL.

- [ ] **Step 3: Implement `panic/cli.py`.** `VaultError` and usage errors print one line to stderr and return 1. Guided `confirm` prints the step title and link and reads `y`/`n`.

- [ ] **Step 4: Run the whole suite.** `uv run pytest -v`. Expected: all pass.

- [ ] **Step 5: Write `README.md`:** what it does and does not promise (the five numbered promises from the spec, and the limits), setup for personal mode (create your own Google Cloud OAuth desktop client, enable the Gmail API), setup for Workspace mode (service account, domain-wide delegation, the four scopes, a dedicated break-glass admin), where to keep the key file, how to make a second-device copy, and the command list.

- [ ] **Step 6: Commit.** `git add -A && git commit -m "feat: panic command line"`

---

### Task 11: Live check (needs the owner)

No code. Each step is run with the owner present, on accounts the owner chooses.

- [ ] **Step 1:** Arm a throwaway personal Gmail account. Expected: vault and key file created; snapshot shown and approved.
- [ ] **Step 2:** Add a filter and switch IMAP on in that account by hand, then `panic rehearse`. Expected: both shown as outside the baseline; answer no.
- [ ] **Step 3:** `panic press --user <email> --dry-run`. Expected: plan printed, the filter listed under "Attacker may have touched", account unchanged.
- [ ] **Step 4:** `panic press --user <email>`. Expected: filter gone and IMAP off (Verified), guided steps walked in order, report written, watch running.
- [ ] **Step 5:** Re-add the filter during the watch. Expected: removed within one interval and logged as `reapplied`.
- [ ] **Step 6:** Only if a Workspace test tenant exists: arm it, press one test user, confirm suspend is Verified and sign-out is "Accepted by provider", then `panic release`. If no tenant exists, record in the README that the Workspace connector is tested against mocked responses only.
- [ ] **Step 7:** Record the measured `freeze_seconds` in the README.
