# Attack Features Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Close three harmless-classified attack signs, add GitHub runner detection, and add a read-only `panic checkup`.

**Architecture:** Classification changes live in each connector's `signals`. GitHub gains two snapshot categories. Each connector may gain `posture(account) -> list[Check]`; a new `panic/cli_checkup.py` gathers checks and the saved checklist.

**Tech Stack:** Python 3.12, pytest, existing `panic.http.Api` and Google client fakes.

**Spec:** `docs/superpowers/specs/2026-11-28-attack-features-design.md`

## Global Constraints

- New codes and texts in `panic/signals.py` `TEXT`: `app_password_added` "A new app password was created on this account.", `repo_made_public` "A repository was created as public or made public.", `runner_added` "A new self-hosted runner was attached to your repositories."
- A snapshot category missing from an old baseline is adopted from the first read (logged as `baseline_extended`), never reported as unreadable and never accepted for categories the baseline already had.
- Personal access tokens are never revoked automatically.
- `checkup` never writes to a provider. Organisation accounts never show item contents.
- Every existing test passes; commits authored by Riya Dadlani only, no co-author lines.

## Review Focus

- An old vault (baseline without `public_repositories`/`runners`) must keep guarding and must not press on the first read.
- A runner removal must delete only runners outside the baseline, and never when the baseline lacks the category.
- A Workspace app the owner already had (in the baseline) must not become a finding.
- `checkup` with an account that cannot be read reports "Unknown", never "Good".
- Checklist answers survive in the vault and are re-asked after 90 days.

---

### Task 1: Workspace gaps

**Files:** `panic/google_workspace.py`, `panic/signals.py`; tests in `tests/test_google_workspace.py`.
- [ ] Tests first: a new `apps` item → `app_consent_added` TRIGGER; a new `app_passwords` item → `app_password_added` TRIGGER; baseline items → nothing.
- [ ] Implement in `classify`; add the TEXT entry.
- [ ] Full suite; commit `feat: new Workspace apps and app passwords are risky`.

### Task 2: GitHub public repositories and runners

**Files:** `panic/github.py`, `panic/signals.py` (or the guard/press path) for baseline adoption; tests in `tests/test_github.py`, `tests/test_signals.py`.
- **Interfaces:** new categories `public_repositories` (items `"<repo_id>: <owner/name>"` for repos whose `private` is false, from the repository list already fetched) and `runners` (items `"<repo_id>:<runner_id>: <name>"` from `GET /repos/{owner}/{repo}/actions/runners` for repos you own; for an org account `GET /orgs/{org}/actions/runners`, items `"<runner_id>: <name>"`). `runners` joins the per-repository reads that refresh hourly. New items: `public_repositories` → `repo_made_public`, `runners` → `runner_added`. The `repo_access` step (and `org_access` for orgs) also deletes runners outside the baseline (`DELETE .../actions/runners/{id}`), with read-back in `check`.
- **Baseline adoption:** where `drift` raises for a category missing from the baseline, adopt instead: the category's current items count as baseline for that read and the vault baseline is extended once (log `baseline_extended`). Choose the smallest place to do this so all connectors benefit; a missing category must never mean "delete all".
- [ ] Tests first: public repo created → `repo_made_public`; private repo → no trigger; repo flipped to public → trigger; new runner → `runner_added`; press removes only non-baseline runners and reads back; old baseline without the new categories → no finding, no unreadable, baseline extended once; 403 on the runners endpoint (no admin) → category empty for that repo, not unreadable.
- [ ] Implement; full suite; commit `feat: GitHub public repositories and self-hosted runners are watched`.

### Task 3: `panic checkup`

**Files:** create `panic/checkup.py` (the `Check` type, checklist items, report rendering) and `panic/cli_checkup.py`; modify `panic/cli.py` (subcommand), `panic/microsoft_365.py`, `panic/google_workspace.py`, `panic/github.py`, `panic/google_personal.py`, `panic/microsoft_personal.py` (`posture`); tests `tests/test_checkup.py`.
- **Interfaces:** `Check(account: str, name: str, status: "fix" | "unknown" | "good", detail: str, link: str | None)`; connector method `posture(account: Account) -> list[Check]` (optional; missing → no checks). Vault key `checkup`: `{item_key: {"answer": "yes" | "no" | "unsure", "at": float}}`. CLI: `panic checkup [--again]`.
- Posture sources: Microsoft 365 auth method types from `/users/{id}/authentication/methods` (fix when only `phoneAuthenticationMethod` and password); Workspace `users.get` `isEnrolledIn2Sv`; GitHub `GET /user` `two_factor_authentication`, org `GET /orgs/{org}` `two_factor_requirement_enabled`; Gmail/Outlook from their existing reads (POP on, forwarding on → fix).
- Checklist items, asked yes/no/unsure, skipped if answered within 90 days unless `--again`: carrier port-out PIN; passkeys on your main email and bank; iCloud Advanced Data Protection (or "no iPhone"); an offline copy of your photos; a recovery contact you trust. Each "no"/"unsure" becomes a "fix" with a link.
- [ ] Tests first: each connector's posture on fakes (pass, fail, read error → unknown); checklist saved and not re-asked within 90 days; `--again` re-asks; org accounts show ids only; report groups and exit code 0.
- [ ] Implement; full suite; commit `feat: panic checkup reports weak spots and asks what no API can see`.

### Task 4: Words

**Files:** `README.md`, `site/index.html`.
- [ ] README: document the new risky signals and runners in the provider table, the `checkup` command (Commands table and a short section), and a "What panic button cannot stop" list from the spec.
- [ ] Page: a short "What it cannot stop" list in the existing limits screen, and one line about the check-up in the setup screen. Copy only, same markup classes.
- [ ] Commit `docs: new detections, the check-up and what it cannot stop`.

### Task 5: Live check (controller)

- [ ] On the throwaway Gmail: `panic checkup` shows POP and forwarding as good, asks the checklist, saves answers, and does not ask again on a second run. Record in `docs/live-checks.md`.
