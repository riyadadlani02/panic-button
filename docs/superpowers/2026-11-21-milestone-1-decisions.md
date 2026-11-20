# Milestone 1: decisions made during the build

Decisions the build made on the owner's behalf, in order, each with its reason and what it costs if wrong. Format: what was decided — why — cost if wrong.

- **R1.** Task 1 skips `git init`, works on existing branch milestone-1, adds `.superpowers/` to .gitignore — repo was created for the SDD workspace — none.
- **R2.** dry run appends no re-openable results — nothing was attempted so "open" is meaningless — a dry-run report is slightly less informative.
- **R3.** "Nothing." printed once per empty top-level section, never per evidence subsection; empty subsections omitted — test demands count 3 — none.
- **R4.** flag-only rehearsal applies to provider "google_workspace" only; every other provider shows full items and asks approval — spec ties flag-only to org mode — none.
- **R5.** audit-log events in "Attacker may have touched" deferred to milestone 2 (told user) — not in plan — report section thinner.
- **R6.** log chain cannot detect edit/truncation of the final line — Task 10 will add `log.head(path)` and store it in the vault as `log_head` after each press, `panic report` warns on mismatch — closes the gap cheaply — small unplanned addition to log.py in Task 10.
- **R7.** promoted three Task 1 minors into round 1 (key file length check, OSError not masked as VaultError, header-AAD + salt/nonce freshness tests) — security-relevant and cheap while the implementer is resumed — slightly larger fix diff.
- **R8.** promoted into round 1 — `ok is True` for VERIFIED; Ctrl-C in API phase returns partial results; no snapshots of protected accounts (⚠️ resolved: break-glass is never touched, reads included); missing tests; thread-safety note on Connector — press runs during an attack, losing results is the costliest failure — larger fix diff.
- **R9.** ⚠️ thread safety of real connectors — Tasks 8/9 dispatch must require per-thread Google service objects (httplib2 is not thread-safe).
- **R10.** Task 7 minors promoted to a fix round — attacker-controlled text (filter names, provider errors) could forge report headings; LOCKED with evidence None vanished from Markdown — the report is the one thing the owner reads — small fix diff.
- **R11.** `Personal(tokens: dict[str, dict], build=...)` maps account id (email) to token info, replacing the brief's single `token_info` — connectors are keyed by provider, and an owner can arm several Gmail accounts — Task 10 stores credentials["google_personal"] as {email: token_info}.
- **R12.** Task 8 Step 1 (open nine links signed in) cannot be done by a subagent; links kept from the brief, verified in Task 11 live check — wrong link is caught with the owner present.
- **R13.** a missing baseline category means "unknown", never "keep nothing" — applies to every destructive action in Task 9 as well; carry into Task 9 dispatch.
- **R14.** Task 10 lower-cases every email account id at arm and on --user, so protected/break-glass comparisons in the engine are case-insensitive in effect.
- **R15.** the plan is compiled at press time from the vault's accounts and edges, not stored in the vault — compile_plan is deterministic and makes no network call, and a stored plan could go stale against the connector catalog — deviates from the spec's "stored plan" wording; told to user at hand-off.
- **R16.** cli.py at 484 lines accepted unsplit for now — one cohesive command module; splitting is a refactor the final review can call for — a larger file to read.
- **R17.** `map` and `report` also open the vault (they need its data); the constraint's six-command list was incomplete — no other way to read the data — none.
- **R18.** README promise 3 reworded to what the watch does (re-applies API-changeable settings, reports the rest, only while running) even though the spec's wording said "undoes anything the attacker re-adds" — the spec's own anti-goal forbids implying unverified safety — spec wording and README now differ; told to user.
- **R19.** ⚠️ resolved — for google_workspace accounts, filter items outside the baseline are shown as a count with contents withheld in dry-run output and reports; the vault keeps the real items — matches the approved org privacy policy — the admin has less forensic detail in the report.
- **R20.** one fix wave covers C1-C3, I1-I5, I8-I11 and five small items (brief: final-fix-brief.md) — reviewer's "before real accounts" list plus report honesty items — a large wave.
- **R21.** I6 (watch retries Still-open steps, re-checks re-openable accounts when a root closes) deferred to milestone 2; README states the limit — needs watch to mutate and persist results — a transiently failed suspend needs a second press.
- **R22.** I7 (Gmail settings calls for a suspended Workspace user may fail) not acted on blind; Workspace catalog order unchanged; first item of the live check; README states it is unverified — reordering without evidence could weaken the freeze — if true, four purge steps fail on every Workspace press until reordered.
- **R23.** R19 kept (filter contents withheld from the admin-facing report) with a new `panic removed --user` command that prints a user's full removed items — answers the reviewer's objection that withheld items were unrecoverable.
- **R24.** cli.py split into session.py and cli_arm.py (reverses R16) — the fix wave would push it past 700 lines.

- **R25.** Steps that delete evidence wait for the account's first read, using a per-step `after_read` flag (Workspace `forwarding_off`, personal `imap_pop`), rather than delaying every first-phase step — keeps suspend and sign-out immediate — evidence removed by a step that is not flagged could still be missed.

## State after the last re-check

Two fix passes followed the whole-project review (17 items, then 9). Both were independently re-checked: every item addressed, no critical or important finding open. 211 tests pass.

## Known minor items, not fixed

- A step waiting for its account's read can still call the provider after a Ctrl-C has made `press` return; it is reported "interrupted" although it then runs (`executor.py`, `api_after`).
- A read that never returns holds back the `after_read` step for that account; there are no HTTP timeouts anywhere in `panic/`.
- Waiting `after_read` steps each hold a pool worker, which can slow the first phase when many accounts are pressed at once.
- Two commands creating the log file at the same moment, the first time ever, can truncate each other's first line (`session.py`, `Session.log`).
- The report says "Put back during the watch: Nothing." when the log is unreadable or a log write failed during the watch; the warning goes to stderr only.
- If storing watch removals in the vault fails, `panic removed` shows none for the watch; only the redacted log line records it.
- `panic report` covers the latest press only; put-backs during an earlier press's watch appear in no report (`panic removed` still lists the items).
- File locks need a filesystem that supports `flock`; on one that does not, vault saves and log appends fail.
- `panic report` re-renders the latest press into that press's own report file, replacing the copy written at press time.
- Report file names are precise to the second.
- The watch does not retry steps that were Still open at press time (R21).

## Not verified against real Google accounts

- Both Google connectors have run against mocked responses only.
- Whether Gmail settings can be read or changed for a suspended Workspace user (R22). If not, four clean-up steps fail on every Workspace press until the order is changed.
- The nine guided links for personal accounts.
- `updatePop(accessWindow="disabled")` and the real shape of `filters.list`.
- That the tool catches a sign-in as a different account than the one being armed, against Google's real response.
