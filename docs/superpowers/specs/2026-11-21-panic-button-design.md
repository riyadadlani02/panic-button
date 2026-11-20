# Panic button: design

Working name `panic-button`; command `panic`. Date: 2026-11-21.

## Intent

When someone thinks an account has been hacked, one press stops the attacker in every connected account, in the right order, and proves it. It is a product for anyone: an individual locking their own accounts, or an organisation's admin locking one staff account or all of them.

The user's goal is "no attack could be carried out once the button is pressed". No tool can promise that literally, so the design turns it into a promise that can be measured:

1. Everything a provider lets software revoke is revoked and then **read back to prove it**, root account first.
2. Anything that cannot be revoked is **listed by name** with when it expires. Unknown counts as open; the report never says "safe" by default.
3. For 24 hours afterwards the tool keeps checking and undoes anything the attacker re-adds.
4. The tool itself is not a master key: a stolen laptop or stolen vault file opens nothing.
5. A lockdown never costs the owner their account.

## Goals, non-goals, anti-goals

**Goals**
- One engine, two modes: *individual* (own accounts) and *org* (admin acts on staff accounts).
- Target for one org account on an API-only provider: all Freeze actions verified within 60 seconds of the press. Measured and reported, not assumed.
- Press works from any clean device, not only the machine that was set up.
- Connector breakage is found before an incident, by rehearsal.

**Non-goals**
- Detecting the hack. The user decides to press.
- Cleaning malware off a device.
- Automating banks or any service whose terms forbid it. Those get guided manual steps only.
- A hosted backend. A graphical app (later milestone, not milestone 1).
- Being a password manager.

**Anti-goals** (failure even if it "works")
- The tool or its vault becoming a way into the accounts.
- A report that implies safety it has not verified.
- Locking the owner out for good.
- An AI model choosing or taking actions during a lockdown.
- Reading or storing mail content.

## Constraints (checked against provider docs, 2026-11-21)

- Google Workspace Admin SDK `users.signOut` ends all web and device sessions; scope `admin.directory.user.security`.
- Gmail `updateAutoForwarding`, and everything else under `gmail.settings.sharing` (forwarding addresses, delegates), is only available to a Workspace service account with domain-wide delegation. A personal Gmail account cannot switch forwarding off through the API.
- `gmail.settings.basic` (filters, IMAP/POP) is a restricted scope. A public app needs Google's restricted-scope verification; unverified apps are capped at 100 users for the life of the project. The annual paid security assessment applies when restricted data is stored on or sent through servers, so a local-only tool should avoid it. Confirm with Google at verification time.
- Personal Google accounts have no API for "sign out everywhere", "remove connected apps" or password change.
- Microsoft Graph `revokeSignInSessions` works for work/school accounts and app permissions, not personal Microsoft accounts, and can take a few minutes to apply.
- Tokens the attacker already holds can outlive revocation for a short time (minutes to about an hour, by provider).

Not yet checked, verify during build: Workspace `users.update suspended=true`, `tokens.delete`, `asps.delete`, `verificationCodes.invalidate`, and reading/restoring recovery email and phone.

## Approaches considered

1. **Everything on one machine.** Keys in the keychain, press from that laptop. Simplest. Rejected: if that laptop is what was hacked or stolen, the attacker holds the button and the keys.
2. **Hosted service.** Keys on our servers, press from anywhere. Easiest to use and sell. Rejected: our server becomes a master key to every customer.
3. **Local engine, split key, press from any clean device. Chosen by the user.** Most to build, and needs a second piece held off the machine.

## Design

### Parts

| Part | Does |
|---|---|
| Vault | One encrypted file holding provider credentials, the account map, the baseline and the plan. |
| Account map | Which account can reset which. Decides the order. |
| Baseline | Snapshot of each account's known-good settings, approved by the owner. |
| Plan | The ordered list of actions, compiled ahead of time. |
| Executor | Runs the plan: Freeze, Purge, Watch. Verifies every action by read-back. |
| Connectors | One per provider. Declares what it can do and how to verify it. |
| Report and log | What was locked, what needs the owner, what is still open, what the attacker touched. |

### Vault and split key

- The vault key is derived from **two pieces together**: a passphrase (Argon2id) and a second secret held off the machine. Milestone 1: a 32-byte key file kept on a USB stick or second device. Milestone 2: a hardware security key (FIDO2 `hmac-secret`).
- Authenticated encryption with the `cryptography` library. No home-made crypto.
- The vault file is safe to copy, because it is useless without both pieces. "Press from a clean device" means: a copy of the vault plus the tool on a second machine or USB stick, unlocked with the passphrase and the second piece.
- The vault is opened only for arm, rehearse, press and watch. Nothing is cached in the OS keychain.
- Losing the second piece loses only the setup. The owner re-arms; no account depends on the vault.
- Copies: the vault on the setup machine is the master. `panic export` writes a copy for a second device; there is no sync in milestone 1. Each vault carries a version number and date. Pressing from a copy older than the master only removes more (a later-approved setting is treated as unknown), and everything removed is listed so it can be restored. The tool warns when a copy is stale and when the key file sits on the same drive as the vault.
- The log is written beside the vault used for that press and is included in the report.
- Least privilege: connectors request scopes that can revoke and change settings but cannot read mail content. Known residue: `gmail.settings.sharing` could itself add forwarding, which is why the vault needs both pieces.

### Account map

- Nodes are accounts. An edge A → B means "control of A can reset B" (recovery email, sign-in-with, recovery phone).
- Org mode reads edges from the directory where the API exposes them. Individual mode asks the owner at setup. No scraping in milestone 1.
- Lock order is roots first. Accounts that can reset each other are locked together as one group.
- `panic map` prints the map and names the accounts that can reset everything else.

### Baseline

- At arm time the tool records each account's forwarding, filters, delegates, recovery details, app passwords and keys, and shows them to the owner to approve.
- At press time anything not in the baseline is treated as attacker-added: removed, and listed in the report.
- Rehearsal shows what changed since the last baseline and asks the owner to approve it. A change is never absorbed silently, so an attacker cannot quietly make their rule "known-good".
- Org mode (approved with the design): the admin does not read staff members' filters. Baselines are recorded automatically at arm. Rehearsal shows the admin only risk flags per user: new forwarding to an outside domain, new delegate, changed recovery details. Because an auto-recorded baseline could already contain an attacker's rule, an org press switches off all outside-domain forwarding and all delegates whether baselined or not, and lists them for restoring.

### The press

No model is involved. The executor runs the stored plan.

1. **Freeze**: stop new use of the account. Org: suspend sign-in, sign out all sessions, switch forwarding off. Individual: every API action available, then the guided steps that have no API.
2. **Purge**: revoke all third-party app access and app passwords; invalidate backup codes; remove non-baseline forwarding addresses, filters, delegates, keys; restore recovery details to baseline; org mode resets the password.
3. **Verify**: every action records how strongly it is known to have worked (see evidence levels under Report).
4. **Watch**: for 24 hours, re-check on a timer. Runs on the pressing device with the vault open; the owner can stop it.

Order is a priority, not a gate:
- API actions on every account start at once; nothing waits. Freezing a dependent account early does no harm.
- Root accounts are started first, and guided steps are presented roots first.
- While a root is still open (failed, waiting on a guided step, or no connector exists for it), every account it can reset is marked "re-openable from X" under Still open, and is re-checked after the root closes and throughout Watch.

What Watch does when something changes:
- Settings (forwarding, filters, delegates, recovery details) that drift from the baseline are put back and logged.
- A suspended org account that is unsuspended by anything other than `panic release` is suspended again.
- New sign-ins and newly connected apps are reported, not revoked, because the tool cannot tell the owner's recovery from the attacker's return. The owner can press again.
- `panic release` ends suspension enforcement for that account; settings checks continue.

Rules for the executor:
- Every action is safe to run twice, so the button can be pressed again and Watch can re-apply.
- One action failing never stops the others. Failures go to "still open".
- `--dry-run` prints the plan and runs only read calls.

### The tool's own access during a press

- Org mode: the vault holds a Workspace service account key with domain-wide delegation. It acts as the break-glass admin, which is never a target, so suspending users or revoking their tokens cannot cut the tool off.
- Individual mode: the vault holds the owner's OAuth refresh token for the tool. The "remove connected apps" step tells the owner to remove everything except this tool. Password change is the last guided step, because it ends the tool's grant; re-authorising the tool follows it so Watch can continue.

### Never lock the owner out

- Arm refuses an account until a recovery path the owner controls is confirmed.
- Org mode never touches the named break-glass admin, even with `--all`.
- Org Freeze is reversible: `panic release` unsuspends after the owner confirms.
- Individual mode never changes a password by itself. Password change is a guided step, done after sessions are gone.
- Recovery details in the baseline are never removed.

### Connectors and tiers

Each connector lists actions. Each action has a phase, a tier, an execute step and a verify step.

| Tier | Means | When |
|---|---|---|
| API | Official API call | Milestone 1 |
| Guided | Deep link to the exact settings page, plain instruction, read-back where an API can read the result | Milestone 1 |
| Script | Fixed, versioned browser script with a confirmation before each action. No free-roaming agent, because page text could misdirect one | Milestone 3 |

Google, first provider, both modes:

| Action | Workspace (org) | Personal Gmail |
|---|---|---|
| Suspend sign-in | API | not possible |
| Sign out everywhere | API | Guided |
| Revoke third-party apps | API | Guided |
| App passwords, backup codes | API | Guided |
| Switch forwarding off | API | Guided, API read-back |
| Remove non-baseline filters | API | API |
| Disable IMAP/POP | API | API |
| Remove non-baseline delegates | API | Guided |
| Reset password | API | Guided |

### Rehearsal

`panic rehearse` opens the vault, runs every connector's read calls, recompiles the plan, and shows baseline changes. It makes no changes to accounts. Rehearsal is attended: it needs the passphrase and the second piece, and neither is ever stored for unattended runs. The "schedule" is a reminder. A failing connector is reported then, not during an incident.

### Report and log

- Report (Markdown plus JSON), four sections: **Locked**, **Needs you** (guided steps not yet confirmed), **Still open** (failed, unsupported, re-openable from an open root, or token lifetime not yet elapsed, with expiry time), **Attacker may have touched** (everything outside the baseline, plus provider audit-log events where an API offers them).
- Every item under Locked carries its evidence level, and the report never merges them:
  - *Verified*: a read-back confirmed the new state.
  - *Accepted by provider*: the API call succeeded but no API can read the state back (for example Workspace sign-out).
  - *Owner confirmed*: a guided step the owner marked done, with no read-back available.
- Log: append-only JSON lines, each entry hashing the previous one, so later edits are detectable.

### Commands

`panic arm`, `panic map`, `panic rehearse`, `panic press [--user X | --all] [--dry-run]`, `panic watch`, `panic release`, `panic report`.

## Milestones

1. **Engine, vault, Google in both modes.** Map, baseline, plan, executor with Freeze/Purge/Verify/Watch, dry-run, report, log, rehearsal. Workspace connector by API; personal Gmail by API plus guided steps. Done means: on a test Workspace user, a press suspends, signs out, revokes app access and strips forwarding, each recorded at its true evidence level; dry-run changes nothing; the report is produced; unit tests run against a fake connector.
2. Microsoft 365 and GitHub connectors; hardware security key.
3. Script tier for personal accounts.
4. App UI, phone trigger for orgs.

## Left to the builder

- Module layout, exact file formats, retry and timeout values, Watch interval.
- CLI wording.
- Test layout, beyond: a fake connector, and one test that proves order (root first) and one that proves a failed action lands in "still open".

## Calls made by Claude, not the user

- Python 3.12, standard-library CLI, `cryptography`, `argon2-cffi`, Google's official client libraries, `pytest`.
- Key file first, hardware key in milestone 2.
- Revoke *all* sessions, app access and app passwords; use the baseline only for settings.
- Watch runs on the pressing device with the vault open for 24 hours.
- Individual mode's map is declared by the owner, not discovered.
- Until Google verification, individuals supply their own Google Cloud OAuth client.
- Lock order is a priority, not a gate.
- Three evidence levels in place of a single "verified".
- Watch restores settings but only reports new sign-ins and new app connections.
- Rehearsal is attended; no unattended vault opening.
- Vault copies are manual exports with a version number; no sync.
- Org credential is a service account acting as the break-glass admin.

## Open

- A real Workspace tenant for live testing. Without one, milestone 1 is proven live on a personal Gmail account only, and the Workspace connector against recorded responses.
- Licence and whether it is open source. Does not block milestone 1.
