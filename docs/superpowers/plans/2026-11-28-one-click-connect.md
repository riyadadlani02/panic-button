# One-Click Connect Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Spec:** `docs/superpowers/specs/2026-11-28-one-click-connect-design.md`

## Global Constraints

- Built-in IDs come only from `panic/oauth_clients.json` or `PANIC_OAUTH_CLIENTS`; all `null` in the committed file.
- Existing arm routes (client file, `--client-id`, `--token-file`, `--reconnect`) unchanged; all existing tests pass.
- Device code shown, never logged; tokens never printed.
- Commits authored by Riya Dadlani only.

## Review Focus

- Gmail with no address must arm exactly the address Google signed in, and never a different account already armed.
- The GitHub device flow must stop on `access_denied`, `expired_token`, and honour `slow_down`; a cancelled job must stop polling.
- With built-in IDs unset, `panic setup` and arm behave exactly as before.

---

### Task 1: Code

**Files:** create `panic/oauth_clients.json`, `panic/oauth.py` (loading built-in IDs, the GitHub device flow with an injectable poster and clock); modify `panic/cli_arm.py`, `panic/cli.py` (`--personal`, `--microsoft-personal`, `--github` accept no value), `panic/cli_setup.py`; tests `tests/test_oauth.py` plus additions to `tests/test_cli.py`, `tests/test_cli_github.py`, `tests/test_cli_microsoft.py`, `tests/test_cli_setup.py`.
- [ ] Tests first: built-in loading and env override; Gmail arm with no address and no client file uses the built-in client and arms the signed-in address; Outlook arm with no address and no `--client-id`; GitHub device flow (pending → slow_down → success; denied; expired; cancel) and arm taking the login from `/user`; setup shows the short steps only when an ID is set; with IDs unset every old path still works.
- [ ] Implement; full suite; commit `feat: one-click connect for Gmail, Outlook.com and GitHub`.

### Task 2: Words

**Files:** `README.md`, `site/index.html`.
- [ ] README setup sections: the one-click route first (when the seller's sign-in apps are set) and the own-credentials route second; a "For the seller" section listing what to register with Google, Microsoft and GitHub and where the IDs go. Keep the page's wording until the IDs exist (note it in the report).
- [ ] Commit `docs: one-click connect`.

### Task 3: Live check (controller)

- [ ] With `PANIC_OAUTH_CLIENTS` pointing at a local file holding the throwaway project's Google client, sign in through the built-in route in a scratch vault and confirm the address is taken from the sign-in. Record the result.
