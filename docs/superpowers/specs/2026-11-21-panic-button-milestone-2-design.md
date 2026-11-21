# Panic button, milestone 2: self-detection and more services

Extends `2026-11-21-panic-button-design.md`. Everything there still holds unless this document says otherwise.

## Intent

The owner asked: "build it for all services and it should detect the hack by itself". Two decisions are theirs and settled:

- When the tool detects a break-in it runs the **full press automatically**.
- Next services: **Microsoft (Outlook / 365), GitHub, Slack, and a guided list for any other service**.

## Goals, non-goals, anti-goals

**Goals**

- `panic guard` notices an intruder's fingerprints within one polling interval and presses without the owner.
- Microsoft 365 tenants, GitHub accounts and Slack workspaces are locked by API as far as each API allows.
- Any other service can be armed as a guided checklist, so every account the owner has can be in the map.
- For every account, arm and rehearse say plainly which steps are automatic, which are guided, and what the tool cannot see.

**Non-goals for this milestone**

- Hardware security key (moves to milestone 3), browser-script tier, app UI, phone alerts.
- Exchange Online PowerShell. Mailbox-level forwarding and mailbox delegates on Microsoft are outside Graph; they are guided steps and listed as not readable.
- Detecting someone who only reads mail on a personal account. No provider gives a personal account its sign-in log by API, and the tool never reads mail content.

**Anti-goals**

- An automatic press that suspends a person for an ordinary change.
- A guard that restarts unattended from a stored passphrase.
- A model deciding what counts as a hack. Detection is a fixed rule list.
- Irreversible automatic actions: no automatic member removal on GitHub, no automatic app uninstall on Slack.

## Constraints (checked against provider docs, 2026-11-21)

Cells marked ? were not confirmed in official docs and must be tested on a real account before they are relied on.

| Provider and account type | By API | Guided only | Detection source |
|---|---|---|---|
| Microsoft 365 tenant (admin) | Disable and re-enable user; revoke sessions; list and delete inbox rules; delete a user's app consent grants; list authentication methods | Mailbox-level forwarding, mailbox delegates (PowerShell only), password reset (delegated-only API), removing authentication methods (?) | Baseline diff of rules, grants, authentication methods; risk detections (needs Entra ID P1 or P2); directory audit log |
| Microsoft personal (Outlook.com) | List and delete inbox rules | Everything else: sign out, password, app access, security info, forwarding | Baseline diff of inbox rules only |
| GitHub personal | Delete SSH, signing and GPG keys; remove emails (not the primary); per repository: deploy keys, webhooks, collaborators, invitations | Tokens, OAuth app access, web sessions, 2FA and recovery codes, password | Baseline diff of the same lists. No security-log API |
| GitHub organisation (owner) | Org webhooks, outside collaborators, deploy keys across repositories | Removing a member, revoking fine-grained tokens (needs a GitHub App), SAML authorisations | Baseline diff; audit log API only on Enterprise Cloud |
| Slack Enterprise Grid | Reset a member's sessions; deactivate and reactivate (SCIM) | App removal, password reset for all | Audit Logs API (`anomaly`, `user_logout_compromised`, app and role events) |
| Slack Business+ | Deactivate and reactivate (SCIM), which signs the member out | Everything else | `team.accessLogs`, `team.integrationLogs` (?) |
| Slack Pro, Free | Nothing | Everything | Pro: `team.accessLogs`. Free: none |

Slack's primary owner and the Microsoft break-glass admin cannot be acted on by these APIs or by this tool.

## Approaches to self-detection

1. **A foreground guard the owner starts (chosen).** `panic guard` opens the vault once, from the passphrase and key file, and polls until stopped. No new secret is stored; the cost is that the vault stays open in memory on that computer for as long as the guard runs.
2. **A scheduled job that opens the vault on each run.** Survives reboots, but needs the passphrase stored on disk, which ends the split key. Rejected.
3. **Provider push (webhooks, log streaming).** Faster, but needs a reachable server. The first design rules out a hosted backend. Rejected.

## Design

### Findings

A connector may implement two more methods:

- `signals(account, snapshot, baseline) -> list[Finding]`: what in this snapshot looks like an intruder.
- `events(account, since) -> list[Finding]`: provider log entries since a time, where the provider has a log.

`Finding(account, code, severity, text, items)`. Severity is `TRIGGER` or `NOTICE`. `code` is a fixed string such as `rule_forwards_outside`. Connectors without these methods are simply not guarded, and arm says so.

### What triggers a press

Only these are `TRIGGER`. Any other difference from the baseline is a `NOTICE`: reported, never acted on.

| Provider | Trigger |
|---|---|
| Google, Microsoft mail | A rule outside the baseline that forwards or redirects (organisation accounts: only to an address outside the organisation's domain; personal accounts: to any address), or that deletes, bins or marks-read-and-archives; a new forwarding address (same outside-only rule for organisations); a new delegate; POP switched on; recovery details changed (where readable) |
| Microsoft 365 tenant | Also: a new app consent grant with mail or files scope; a new authentication method; a risk detection the provider rates high |
| Google Workspace | Also: a login event Google itself marks suspicious (Reports API) |
| GitHub | A new SSH, signing or GPG key; a new email; a new deploy key, webhook, collaborator or invitation |
| Slack | Grid: an `anomaly` or `user_logout_compromised` audit event. Business+ and Pro: nothing triggers; new IPs in access logs are a `NOTICE` |

An ordinary filter (a label, a star, "never spam") is a `NOTICE`. The owner's own legitimate change that matches a trigger, such as adding an SSH key, will be pressed; the way to avoid that is to approve the new baseline with `panic rehearse` straight after making the change. Removed items are kept in the vault, so `panic removed` can hand them back.

### The guard

`panic guard [--interval SECONDS] [--on-detect press|contain|alert] [--dry-run]`. Default interval 300, default `press`.

Each pass, for every armed account that is not protected and not released:

1. Read the snapshot and any events. A failed read is a `NOTICE` ("could not read"), never a trigger.
2. Compute findings. Log and print each `NOTICE` once per distinct finding.
3. On a `TRIGGER`, read the account a second time. Act only if the finding is still there.
4. Notify, then act according to `--on-detect`:
   - `press`: press the account and every account it can reset, root first. Guided steps cannot be confirmed with nobody present, so they are recorded as "Needs you" without being asked. Then the 24-hour watch for those accounts runs inside the guard.
   - `contain`: run only the steps whose watch policy is "reapply" (remove the rule, switch forwarding off), and notify.
   - `alert`: notify only.
5. One automatic press per account per 24 hours. Further triggers inside that window are handled by the watch and notified.

`--dry-run` prints what each pass would have done and changes nothing.

Notification is a macOS notification, a terminal line and bell, the audit log, and the report, which gains a "What triggered this press" section. The guard starts only when the owner starts it and types the passphrase.

### Never lock the owner out, under automatic press

- The protected admin is never pressed, by the owner or by the guard.
- An org press stays reversible with `panic release`. A released account is not pressed again by the guard until its baseline is approved in a rehearsal.
- On personal accounts an automatic press can only run API steps. It never changes a password.
- Org triggers are the strict list above. A staff member's ordinary filter never suspends them.

### Privacy

The guard evaluates rule contents mechanically. For organisation accounts, notifications, log and report name the finding by its code ("a rule that forwards outside the organisation") and withhold the contents; `panic removed --user` prints them.

### Connectors

- **`microsoft_365`**: the operator's own app registration, app-only (client credentials). Press: disable the user (`release` re-enables), revoke sessions (read back from `signInSessionsValidFromDateTime`), delete inbox rules outside the baseline, delete the user's consent grants. Guided: mailbox-level forwarding, delegates, password reset. Missing P1/P2 licence is a one-time `NOTICE` and risk detections are skipped.
- **`microsoft_personal`**: delegated sign-in with the owner's own public-client registration, `MailboxSettings.ReadWrite` only. Press: delete inbox rules outside the baseline. Everything else guided.
- **`github`**: a classic personal access token the owner creates and puts in the vault. Press: delete keys, emails and per-repository deploy keys, webhooks, collaborators and invitations that are outside the baseline. Guided: tokens (including this tool's own), app access, sessions, 2FA, password. Org owners also get org webhooks and outside collaborators. No member is removed automatically.
- **`slack`**: the operator's own Slack app; the plan is detected at arm. Grid: reset the member's sessions, then deactivate. Business+: deactivate (`release` reactivates). Pro and Free: guided only. No app is uninstalled automatically.
- **`guided`**: a catalogue file in the repo, one entry per service with links for sign out everywhere, password, devices, connected apps, 2FA and recovery. A starter set ships; the owner can add any service with their own links (`panic arm --guided NAME --id ...`). No snapshot and no detection, and arm says so. Guided accounts sit in the map, so they are listed in a press when an account that can reset them is hit.

Every guided link is opened once in a real browser during the build. A link that could not be checked is marked unverified in the catalogue and in the plan output.

### Details settled after the builder's review

These are Claude's calls, made to answer a reviewer's questions.

- **What `signals` reads.** The snapshot. Every category that feeds a trigger stores its items as canonical JSON strings, as Gmail filters already are, so rules can be evaluated mechanically. Redaction happens only where items are shown.
- **Who is pressed.** The triggering account and every account reachable from it along the map's edges ("a can reset b"), across providers, root first. Accounts that can reset the triggering one are not pressed; the notification names them as worth checking.
- **What an account is.** Microsoft 365 and Slack: one per user, as Workspace. GitHub: one per login; an organisation the owner runs is armed as its own account.
- **Pacing.** A pass never overlaps the next: the interval is the pause between passes. Per-repository GitHub reads (deploy keys, webhooks, collaborators) run once an hour, limited to repositories the account owns; keys and emails are read every pass.
- **One loop.** The guard calls the existing `press` with a confirm that answers "not asked", then runs `watch_once` for pressed accounts on each later pass. It never sleeps inside a 24-hour watch.
- **Changes made elsewhere.** The guard reloads the vault each pass, so a `rehearse` approval, a `release` or a reconnected token made in another terminal applies from the next pass.
- **Released accounts.** Approving an account's baseline in `panic rehearse` removes it from the released list, which is what lets the guard watch it again.
- **Guard state.** Notices already shown, event cursors and the time of each automatic press are kept in the vault, so a restart neither repeats notices nor presses twice.
- **`contain`.** Runs each connector's "reapply" steps: inbox rules and consent grants on Microsoft; keys, emails, deploy keys, webhooks and collaborators on GitHub; nothing on Slack, where it behaves as `alert`.
- **Arming.** One arm form per provider (tenant id, client id and secret for Microsoft 365; the owner's own public-client id for personal Microsoft, with `--reconnect` as Gmail has; a token file for GitHub; app tokens for Slack). For a guided account `--id` is the login name on that service. Arm asks which armed accounts can reset the new one, as it does today, which is how guided accounts get their edges.
- **Events.** A provider event that names a user who is not armed is a `NOTICE`. The second read applies to snapshot triggers only; a provider's own high-risk verdict is acted on as it stands.
- **Heartbeat.** One line per pass: time, accounts read, findings.

## Done means

- On the throwaway Gmail: with `panic guard` running, a hiding rule added in the browser is noticed within one interval, the guard presses by itself, the rule is gone, and the report names the trigger. A label-only filter produces a `NOTICE` and no press.
- Each new connector passes its tests against recorded response shapes, and has a live-check list. The README states for each connector whether it has run on a real account.
- `panic guard --dry-run` on an untouched account prints nothing but its heartbeat.

## Needed from the owner for live checks

A Microsoft 365 test tenant where they are admin (or a personal Outlook.com account for the personal connector), a test GitHub account with a classic token, and a Slack workspace where they are owner (the plan decides what can be tested). Connectors without a test account ship marked "tested against recorded responses only".

## Calls made by Claude, not the user

- The guard is a foreground process; no service that starts itself after a reboot.
- A second read before any automatic press; one automatic press per account per day.
- Hardware key moves to milestone 3.
- One new dependency: `msal`, Microsoft's own sign-in library. GitHub and Slack use the standard library's HTTP client.
- GitHub uses a classic token, because fine-grained tokens cannot reach several of the endpoints.
- No Exchange Online PowerShell, no automatic GitHub member removal, no automatic Slack app uninstall.
- Notifications are local to the computer running the guard.
- The first design's "no unattended vault opening" now has one exception: a guard the owner started.
