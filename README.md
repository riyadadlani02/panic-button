# panic-button

One command that stops an attacker in your connected accounts, root account first, and then shows what it proved and what it could not. `panic guard` can also notice a break-in on its own, ask you about it, and lock risky changes if nobody answers. It runs on your machine; there is no server.

## What it promises

1. Everything a provider lets software revoke is revoked and then read back to prove it, root account first. Some steps have no read-back: on Workspace, sign-out, backup codes and the password reset; on Microsoft 365, sign-out; on Slack Enterprise Grid, the session reset; on a personal account, most guided steps. Those are never called verified: the report marks them "Accepted by provider" or "Owner confirmed".
2. Anything that cannot be revoked is listed by name with when it expires. Unknown counts as open; the report never says "safe" by default.
3. For 24 hours afterwards, while `panic press`, `panic watch` or `panic guard` keeps running, the tool re-checks the settings the API can read and puts back those it can change (the steps marked "reapply" in the table below). Other changes are reported, not undone.
4. The tool itself is not a master key: on the command line, and in the app with "Remember on this Mac" off, a stolen laptop or a stolen vault file opens nothing, because opening needs both your passphrase and a separate key file. With "Remember on this Mac" on (the default in the app), your passphrase sits in the macOS Keychain, so anyone using your unlocked Mac can open the vault. To turn it off, choose File, Forget this Mac, and untick "Remember on this Mac" when you unlock.
5. A lockdown never costs you your account: for personal accounts arming asks you to confirm a recovery path you control; organisation tenants rely on a named break-glass admin (Slack: the primary owner), which no command will act on. No password is changed by API in personal mode.
6. The guard decides from a fixed list of rules, listed under "Guard" below. No model is involved. It re-reads an account before it presses, presses an account at most once in 24 hours, and never presses a protected account.
7. Nothing irreversible runs on its own. No GitHub member is removed and no Slack app is uninstalled. What a press deletes is recorded in the vault as the tool read it, and `panic removed --user ID` prints it so it can be put back by hand. Some of it cannot be restored from that record: a webhook's URL and secret (only the address without its secret and a fingerprint are kept), a GPG key beyond its id, and Workspace app passwords.

## What a Workspace press does to a user

It suspends the account, resets the password to a random value nobody is told, removes every mail delegate, revokes every app's access and every app password, and invalidates backup codes. It also turns off forwarding, IMAP/POP and filters added since the baseline, and puts recovery details back. `panic release` restores sign-in only, with a temporary password shown once; delegates, apps and app passwords stay removed (`panic removed` lists them). Microsoft 365 and Slack presses are smaller; the table below lists them.

## What it does not promise

- Tokens an attacker already holds can outlive revocation for up to about an hour.
- A compromised pressing device defeats the tool. Press from a clean device.
- The guard cannot see someone who only reads mail on a personal account. No provider gives a personal account its sign-in log, and the tool never reads mail content. A change in the settings it can read is the only thing it notices.
- The guard keeps the vault open in memory for as long as it runs. Run it only on a computer you trust.
- The guard does not restart after a reboot, a logout or a crash. You start it again and type the passphrase.
- An automatic press on a personal account runs API steps only. Guided steps are recorded as "Needs you" and nobody is asked to do them. It never changes a password.
- Your own change that matches a trigger gets a question first, not a press. Answer "It was me" and it becomes the new baseline. If nobody answers within the wait (15 minutes by default), a risky change is acted on, so answer in time or stop the guard first. Without a dialog (not macOS, or it failed to open) answer by hand: `panic rehearse` to approve, `panic press --user ID` to lock.
- The guard checks every few minutes (300 seconds by default), so a break-in is noticed up to one interval late. A guard that cannot read an account reports that it could not and does not press; it prints that line every pass and notifies again every hour while it lasts.
- The provider-verdict triggers (a Workspace sign-in Google marks suspicious, a Microsoft 365 risk detection rated high, a Slack Enterprise Grid anomaly) are unproven until checked on a real tenant. Each provider log is read again two hours back from the last read, because entries can appear late; one that appears later than that is missed.
- One address can be armed under only one mail tenant: a user in both Google Workspace and Microsoft 365 is armed under the first and skipped by the second. Slack members are separate accounts (`slack:<email>`), so Slack can be armed beside either.
- Personal Gmail has no API for sign-out, connected apps, forwarding or password change, so those are guided steps you confirm by hand.
- Personal Gmail has no IMAP switch: IMAP is always on. A mail client an attacker connected is cut off only by deleting app passwords, removing connected apps and changing the password, which are guided steps.
- Mailbox-level forwarding and mailbox delegates on Microsoft 365 are outside what the Microsoft Graph API can read. They are guided steps, and the guard cannot see them.
- On a personal Outlook.com account, only inbox rules are read and removed; everything else is guided.
- On GitHub, tokens, OAuth app access, web sessions, two-factor settings and the password are guided. The tool cannot see a stolen personal access token, and its own token is one of them. Without a security-log API it only sees what was added to the lists it reads.
- On Slack, what the tool can do depends on the plan, which is detected when you arm. Only Enterprise Grid can sign a member out and read Slack's audit log. Business+ can deactivate. Pro and Free are guided only.
- A "guided" service (no API) is only a checklist. The tool cannot read it, watch it or detect anything on it, and it locks nothing there.
- A Microsoft 365 user without a mailbox cannot have its inbox rules read, so the guard reports it as unreadable on every pass.
- Google Workspace treats every address outside the one `--domain` given at arm as outside the organisation, including a second domain of the same organisation.
- The watch stops when the process stops.
- The watch does not retry steps that were Still open at press time. Press again.
- Whether Gmail settings can be changed for a suspended Workspace user is unverified; it is the first Workspace item of the live check list.
- On a personal account, sign-out, connected apps, app passwords, delegates, recovery and password are not watched, and forwarding is reported, not undone.
- It does not clean malware or read mail content.

These are not limits of a feature; they are attacks outside its reach. See the next section.

## What panic button cannot stop

- Theft at a vendor you already connected to, such as a data breach on their side.
- SIM swaps at the mobile carrier. Set a port-out PIN with them (`panic checkup` asks).
- Wallet and seed-phrase scams: a seed phrase you gave away cannot be taken back.
- iCloud: Apple has no API for it, so the tool cannot read or lock it.
- Data copied in the first minutes, before any setting changes: the tool acts after the change, not before it.

## Safety check-up

`panic checkup` is a read-only audit. It reads each armed account (personal Gmail: POP and automatic forwarding; Workspace: 2-step verification; Microsoft 365: a second factor beyond SMS or voice; personal Microsoft: inbox rules that forward, with automatic forwarding shown as Unknown because it cannot be read; GitHub: two-factor and whether self-hosted runners can be read) and asks five questions about things no API can see: a port-out PIN with your carrier, passkeys on your main email and bank, iCloud Advanced Data Protection, an offline copy of your photos, and a recovery contact. Results come in three groups: Fix now, Unknown, Good. A "no" or "unsure" answer counts as fix now. It changes nothing on any account. Only your answers are saved in the vault, and each is asked again after 90 days. `panic checkup --again` asks them all now.

GitHub runners are watched only if the token has admin rights; without them the guard cannot see runners at all, and `panic checkup` shows them as Unknown. An ephemeral (autoscaled) runner is a trigger the first time it appears in a repository (an organisation: anywhere in it); once you approve one with "It was me", further ephemeral runners there are not triggers, so an attacker's ephemeral runner on a repository that already autoscales is not caught. A repository made public, or a runner added on one of your own repositories, can be noticed up to an hour late, because those reads are cached; organisation runners are cached the same way. A vault made before this change adopts the new GitHub categories on the first guard read (logged as `baseline_extended`), so anything already there at that moment is treated as already approved.

Measured freeze time: Not yet measured; recorded during the live check.

## Run on a real account

Read this before relying on a connector. "Tested against recorded response shapes only" means the code has run only against copies of what each provider's documentation says it returns, never against the provider itself. The checks that remain are listed in `docs/live-checks.md`.

| Connector | Run on a real account |
|---|---|
| Personal Gmail | yes: pressed, watched and rehearsed on a real throwaway account. The guard ran on it too: a hiding rule added in the browser was noticed within one 30-second interval, pressed, and named in the report. That run used the old immediate press; a star-only rule gave a notice and no press. Asking first also ran there: "It was me" saved a planted hiding filter as the new baseline, and an unanswered one was pressed and deleted at its deadline. Not yet run there: `alert` and `contain` modes, a restart, and a second hiding rule inside 24 hours. |
| Google Workspace | no: tested against recorded response shapes only |
| Microsoft 365 | no: tested against recorded response shapes only |
| Personal Microsoft (Outlook.com) | no: tested against recorded response shapes only |
| GitHub | no: tested against recorded response shapes only |
| Slack | no: tested against recorded response shapes only |
| Guided services | no: tested against recorded response shapes only; links are checked by `scripts/check-guided-links.py`, not by a real press |

## The app

A desktop app for macOS, with the same engine as the command line. Windows is not available yet.

1. Download the `.dmg`, open it, and drag panic button to Applications.
2. The app is unsigned. Try to open it once; macOS refuses. Then open System Settings, Privacy & Security, and choose "Open Anyway" for panic button. The exact steps depend on your macOS version.
3. The first time, a setup wizard asks which account to protect and arms it, the same as `panic setup`. The vault is `~/.panic/panic.vault` and the key file is `~/panic.key` unless you choose otherwise. Keep the key file apart from the vault.

The Home screen lists your accounts, a PANIC button that locks everything, Check-up, Reports, and a Guard switch. The status bar shows whether the guard is on, the last check, and how many questions wait for you. When the guard asks "was this you?", the question appears there, and as a macOS dialog while the window is hidden.

Keychain: the unlock screen has "Remember on this Mac", ticked by default. It stores your passphrase in the macOS Keychain (service `panic-button`) so the app opens without typing it. Anyone using your unlocked Mac can then open the vault. Untick it, or choose File, Forget this Mac, to delete the entry.

Open at login: Guard, Open at login adds `~/Library/LaunchAgents/com.panicbutton.app.plist`. Untick it, or delete that file, to switch it off.

Quitting: the guard runs only while the app runs. Quit asks "Keep guarding in the background?". Yes hides the window and the guard keeps running. No stops the guard and quits.

To build it yourself, run `uv sync --group app`, then `scripts/build-mac-app.sh`. It writes an unsigned `dist/panic-button-<version>.dmg`.

## Install

One command installs the `panic` command for your user (macOS; Linux is untested and shows no notifications). It installs [uv](https://astral.sh/uv) if you do not have it, needs no `sudo`, and is removed with `uv tool uninstall panic`.

```
curl -LsSf https://raw.githubusercontent.com/riyadadlani02/panic-button/main/install.sh | sh
```

Then open a new terminal window and run the guided setup:

```
panic setup
```

`panic setup` asks which account you want to protect, lists the steps for that service, offers to open the pages you need, asks for the address, id or file the service gives you, and then arms the account. It prints the equivalent `panic arm` command each time, and it does nothing that `arm` does not do. The per-service sections below are the same steps in full. It does not create the provider credentials for you: each person or organisation still makes their own.

To work on the code instead, clone the repository and run it in place. The commands in the rest of this file are written this way; with the installed command, drop the `uv run` prefix.

```
uv sync
uv run panic --help
```

Copy the vault to the second device before you need it (`panic export DEST`).

## Try it without an account

Two demos run the tool with no account and no network. Neither proves that a real provider behaves the same; only the live checks in `docs/live-checks.md` can.

```
PYTHONPATH=. uv run python demo/sandbox_demo.py
PYTHONPATH=. uv run python demo/all_services_demo.py [--json run.json]
```

`sandbox_demo.py` runs the real vault, engine and `panic` commands against a made-up mail provider: an attacker adds forwarding, a hiding filter and a rogue app, the press removes them, the attacker re-adds forwarding during a shortened watch, which puts it back, and then `panic guard` presses by itself when forwarding appears between two passes.

`all_services_demo.py` runs the real connectors (GitHub, Outlook.com, Microsoft 365, Google Workspace, Slack Enterprise Grid, and a guided Amazon account) against simulated providers in `demo/lab.py`: small in-memory stand-ins that answer the calls each connector makes. For each service an intruder changes something between two `panic guard` passes, the guard notices and presses by itself, and the demo prints the account before and after, the guard's notification and what the tool did, as saved in the vault, then checks the stand-in's state. It also shows a GitHub repository rename (a notice, nothing deleted), `panic release` and `panic rehearse` on Microsoft 365, and what Slack's other plans get. It proves the tool's logic against providers that behave as their documentation says, not that the real services do. `--json PATH` also writes a record of the run. Everything is written to a temporary folder and removed at the end.

## Setup: personal Gmail


**One click.** When this copy of panic button ships with built-in sign-in apps, run `uv run panic arm --personal` (or `panic setup`). Your browser opens; sign in and click Allow. The rest is the same as below.

**Your own credentials.** The route below uses a Google client that you create.

1. In Google Cloud Console create a project, enable the Gmail API, configure the OAuth consent screen and add yourself as a test user.
2. Create an OAuth client of type "Desktop app" and download its JSON file. Use your own client; nothing is shared with anyone else. An app left in "Testing" issues refresh tokens that expire after seven days: publish the app, or reconnect weekly.
3. Arm the account. You are asked whether you hold a recovery method that does not depend on that mailbox (printed backup codes or a security key); without one, arming is refused.

```
uv run panic --keyfile ~/panic.key arm --personal you@gmail.com --client-secrets client.json
```

Sign in as that same address; if Google's chooser signs you in as another account, nothing is stored. The tool asks for a passphrase, creates the vault and the key file, shows you the account's current filters, forwarding and POP state, and asks you to approve that as the baseline. Then it asks which of your other armed accounts can reset this one.

Changing your password is the last step for each account, and it disconnects the tool. Straight after, run:

```
uv run panic arm --personal you@gmail.com --reconnect
```

The OAuth client is kept in the vault from the first arm, so `--client-secrets` is optional here. A running `panic watch` picks up the new token; there is no need to restart it.

## Setup: Google Workspace

Workspace keeps the admin setup below.

1. Create a service account, enable domain-wide delegation for it, and download its JSON key.
2. In the Admin console authorise the service account's client ID for these four scopes, which every press needs: Admin SDK directory user security, Admin SDK directory user (read/write), Gmail settings basic, Gmail settings sharing. Add a fifth, Admin SDK reports audit (read-only), for the guard to read sign-in alerts; it is requested only for that read, so a press works without it. The exact scope URLs are listed in `panic/google_workspace.py`.
3. Use a dedicated break-glass admin account. It is the identity the tool acts as and is never a target, even with `--all`.

```
uv run panic --keyfile ~/panic.key arm --workspace --sa-key sa.json --admin breakglass@example.com --domain example.com
```

The admin must be the primary address of a super admin. Every user in the domain is armed and baselines are recorded without printing them. Arming again adds new users but never replaces an existing baseline; `rehearse` shows changes as flags and asks before accepting them.

Delete the service-account JSON once armed: it is a tenant-wide key, and the vault already holds a copy.

## Setup: Microsoft 365 tenant

Microsoft 365 keeps the admin setup below.

1. In the Entra admin centre create an app registration in your own tenant and add a client secret. Save the secret alone in a text file.
2. Add these Microsoft Graph application permissions and grant admin consent. They are taken from the calls the tool makes and have not been confirmed on a real tenant: `User.ReadWrite.All` (block sign-in, revoke sessions), `MailboxSettings.ReadWrite` (inbox rules, which are read as settings, never as mail), `DelegatedPermissionGrant.ReadWrite.All` (a user's app consents), `UserAuthenticationMethod.Read.All`, `IdentityRiskEvent.Read.All` (risk detections, which need Entra ID P1 or P2; without the licence the guard shows one notice and skips them) and `Directory.Read.All` (users and domains).
3. Choose a break-glass admin. It is protected and never a target.

```
uv run panic --keyfile ~/panic.key arm --microsoft-tenant TENANT --client-id ID --client-secret-file secret.txt --admin admin@example.com
```

Every user in the tenant is armed and baselines are recorded without printing them. Delete the secret file once armed. `panic release --user ID` re-enables sign-in; the password reset is yours to do in the Entra admin centre.

## Setup: personal Microsoft (Outlook.com, Hotmail)


**One click.** When this copy ships with built-in sign-in apps, run `uv run panic arm --microsoft-personal` (or `panic setup`). Your browser opens; sign in and click Allow.

**Your own credentials.** The route below uses a registration that you create.

1. In Microsoft Entra (app registrations) create your own registration that accepts personal Microsoft accounts, add a "Mobile and desktop" redirect to `http://localhost`, allow public client flows, and add the delegated permission `MailboxSettings.ReadWrite` only. Whether Microsoft lets an unverified publisher get it for a personal account is unconfirmed.
2. Arm. You are asked whether you hold a recovery method that does not depend on that mailbox.

```
uv run panic --keyfile ~/panic.key arm --microsoft-personal you@outlook.com --client-id ID
```

Changing your password disconnects the tool. Straight after, run `uv run panic arm --microsoft-personal you@outlook.com --reconnect` (the client id is kept in the vault).

## Setup: GitHub


**One click.** When this copy ships with built-in sign-in apps, run `uv run panic arm --github` (or `panic setup`). The tool shows a code and opens GitHub; enter the code and click Authorize. It asks for the same scopes as the token below.

**Your own token.** The route below uses a classic token that you create.

1. Create a classic personal access token (not fine-grained; fine-grained tokens cannot reach several of the endpoints) and save it alone in a text file. Scopes, taken from the endpoints the tool calls and not yet confirmed: `repo`, `admin:public_key`, `admin:gpg_key`, `admin:ssh_signing_key`, `user` (to list and remove email addresses), `admin:repo_hook`. For an organisation also `admin:org` and `admin:org_hook`; you must be an active owner of it.
2. Arm. You are asked whether you hold a recovery method that does not depend on that account.

```
uv run panic --keyfile ~/panic.key arm --github LOGIN --token-file token.txt
uv run panic --keyfile ~/panic.key arm --github LOGIN --org ORGANISATION --token-file token.txt
```

An organisation is armed as its own account (`org:NAME`). The tool refuses a token that belongs to another login. The token lives in the vault; delete the file. The tool's own token is one of the tokens you delete in the password step, so after changing your password replace it with `arm --github LOGIN --token-file FILE --reconnect`.

## Setup: Slack

Slack keeps the admin setup below.

1. Create your own Slack app in the workspace and install it as the primary owner. Save its token alone in a text file. Scopes and Slack-plan access are taken from the calls the tool makes and are not confirmed: `users:read` and `users:read.email` (to list members and find the primary owner), `admin.users:write` (Enterprise Grid session reset), `auditlogs:read` (Enterprise Grid audit log), and on Business+ a token that can use SCIM and read `team.accessLogs`.
2. Arm.

```
uv run panic --keyfile ~/panic.key arm --slack --token-file token.txt
```

The tool finds the plan itself and prints what it can do on it. If it cannot tell, it refuses to arm rather than guess a lower plan. The primary owner is protected. Every other member is armed. Slack members are named `slack:<email>` (for example `panic release --user slack:ann@example.com`), so they never clash with the same address in Workspace or Microsoft 365. Arming adds no edge between a mailbox and its Slack member, so a trigger on the mailbox does not press the member.

## For the seller: built-in sign-in apps

The one-click routes use sign-in apps that you register once and ship with the tool. Register these, then put the IDs in `panic/oauth_clients.json`.

- **Google.** Create a Cloud project and enable the Gmail API. Put the consent screen in production. Create an OAuth client of type "Desktop app". Google may require app verification for the Gmail settings scopes.
- **Microsoft.** Register an app that accepts any organisation and personal accounts. Turn on public client flows and add a "Mobile and desktop" redirect to `http://localhost`. Add the delegated permission `MailboxSettings.ReadWrite`. Publisher verification is recommended.
- **GitHub.** Create an OAuth App and enable device flow. No secret is needed.

In `panic/oauth_clients.json`:

- `google`: the downloaded Desktop-app JSON object, as it is.
- `microsoft`: the client ID, as a string.
- `github`: the client ID, as a string.

To test with another file, set `PANIC_OAUTH_CLIENTS=/path/to/file.json`. Rebuild the app afterwards with `scripts/build-mac-app.sh` so the IDs are bundled.

## Setup: any other service (guided)

Add a service as a checklist so it appears in the map. `--id` is your login there. If the service is not in the catalogue (`panic/guided_services.json`), give at least one link.

```
uv run panic --keyfile ~/panic.key arm --guided paypal --id you@example.com
uv run panic --keyfile ~/panic.key arm --guided myservice --id you --name "My service" --link password=https://example.com/password --link two_factor=https://example.com/2fa
```

Link kinds, in the order they are shown: `freeze_card` (freeze your cards), `fraud_help` (report it to the fraud team), `sign_out`, `devices`, `apps`, `two_factor`, `recovery`, `password`. Links must be plain `https://` addresses. Arm asks which armed accounts can reset it.

Nothing is detected or locked for these services. A press opens each official page in order and records what you did. The tool cannot read or watch a guided account, so there is no baseline and no detection.

The catalogue has 36 services:

- India: State Bank of India, HDFC Bank, ICICI Bank, Axis Bank, Kotak Mahindra Bank, Paytm, PhonePe, Google Pay India.
- UK: Barclays, HSBC UK, Lloyds Bank, NatWest, Santander UK, Monzo, Starling Bank.
- US: Chase, Bank of America, Wells Fargo, Citi, Capital One, Venmo, Cash App.
- Global: PayPal, Wise, Revolut, Apple, Amazon, Facebook, Instagram, X, LinkedIn, Netflix.
- Cloud: Dropbox, iCloud, Google Photos and Drive, OneDrive.

There are no phone numbers. To reach a bank's fraud team, call the number on the back of your card.

Each service is marked `verified` in `panic/guided_services.json` only if every one of its links loaded (2xx) on the provider's own domain when last checked. Some banks block automated checks; those stay "link not verified" and the plan marks them so. Results can vary between runs. To re-check and update the file:

```
uv run python scripts/check-guided-links.py --write
```

## Guard

`panic guard` is the self-detection. Start it and leave the terminal open:

```
uv run panic --keyfile ~/panic.key guard
```

It asks for the passphrase once, then reads every armed account that is not protected and not unguarded by `panic release`, every `--interval` seconds (default 300, minimum 30). It prints one line per pass: `<HH:MM:SS> read <n> accounts, <k> findings, <m> skipped`, where skipped counts protected accounts, released accounts not yet resumed, and accounts the tool cannot read for signals. It stops on Ctrl-C. A Ctrl-C during an automatic press ends that press (what it did is saved and reported) and the guard carries on; Ctrl-C again once the press is over stops the guard. Only one guard can run on a vault at a time.

**What counts as risky.** Only these findings are triggers. Any other difference from the baseline is a notice: shown once and written to the audit log. It is never acted on unless you answer "Lock it down"; with a wait set, a notice nobody answers is accepted as the new baseline at the deadline.

| Account | Trigger |
|---|---|
| Gmail, Workspace | A new filter that forwards, bins or deletes mail or skips the inbox (Workspace: forwarding only to an address outside your domain); a new forwarding address (Workspace: only outside your domain); POP switched on; on Workspace also a new delegate, a new connected app, a new app password, changed recovery details, and a sign-in Google itself marks suspicious |
| Microsoft 365 | A new inbox rule that forwards outside the tenant's domains or hides mail; a new app consent with a Mail, Files or full-access scope; a new authentication method; a risk detection Microsoft rates high |
| Personal Microsoft | A new inbox rule that forwards to any address or hides mail |
| GitHub | A new SSH, signing or GPG key; a new email address; a new deploy key, webhook, collaborator or invitation; a repository created as public or made public; a new self-hosted runner (an organisation: a new webhook, deploy key, outside collaborator, public repository or runner) |
| Slack | Enterprise Grid only: an `anomaly` or `user_logout_compromised` audit event for the member. On other plans, new IP addresses in the access log are a notice and nothing triggers |

An ordinary filter (a label, a star) is a notice. A rule the tool cannot parse counts as one that hides mail. A finding is notified once; if it goes away and comes back, it is notified again. On GitHub a renamed repository is a notice, never a trigger (a public repository transferred in counts as made public): repository access is recorded by the repository's id.

**What it does on a trigger.** It reads the account a second time and goes on only if the finding is still there (a provider's own high-risk verdict is acted on as it stands). It then notifies you with a macOS notification, a terminal line and bell, and the audit log, and asks you what to do (below). With `--wait 0`, and for `alert` mode and `--dry-run`, nothing is asked: `--wait 0` acts at once, as the guard first did, and the other two never act. What follows depends on `--on-detect`. A failed automatic press is notified too, and until you press by hand the guard says so instead of claiming the watch is handling it. With `--on-detect`:

- `press` (the default): presses the account and every account it can reset, root first, from `panic map`. Accounts that can reset it are not pressed; the notification names them as worth checking. Guided steps are recorded as "Needs you" and nobody is asked to do them. The 24-hour watch for those accounts then runs inside the guard. The report gains a "What triggered this press" section.
- `contain`: runs only the automatic steps marked "reapply" in the table below (remove the rule, switch POP off, delete new keys), then notifies. It never locks anyone out: it leaves out suspending a Workspace user, blocking sign-in on Microsoft 365 and deactivating a Slack member, and also Workspace's delegate step, which removes every delegate, baselined or not. Where nothing is left to run (Slack, guided services) it prints that there was nothing to contain and writes no report.
- `alert`: notifies and does nothing else.

`--dry-run` prints what each pass would have done and changes, notifies and saves nothing in the accounts or the guard's state. It may still save a refreshed personal Microsoft sign-in to the vault.

**The question.** On macOS a dialog titled "panic: <account>" offers "Lock it down" and "It was me". It says what happens at the deadline and at what time. Nothing is done while it is open.

- "Lock it down" acts within about a second.
- "It was me" re-reads the account and saves its current settings as the new baseline, but only if every current change was in the question. A change that appeared since gets its own question. A sign-in the provider flagged, answered "It was me", just closes.
- No answer by the deadline (`--wait`, default 900 seconds): a risky finding is acted on (press, or contain with `--on-detect contain`). A harmless "changed" notice is accepted as the new baseline.
- Without a dialog (not macOS, or it failed to open) answer by hand: `panic rehearse` to approve, `panic press --user ID` to lock. The deadline still applies.
- Open questions survive a guard restart.

| Finding | If you do not answer |
|---|---|
| Risky (a trigger in the table above) | Acted on at the deadline |
| Harmless ("changed" notice) | Accepted as the new baseline |

`--wait 0` skips the question and acts at once. A negative value, or more than 604800 (7 days), is refused.

Each question is about one item (one rule, one address), so a second item gets its own question and never moves the first deadline; a new risky item on an account keeps the account's first deadline. A risky change that disappears and comes back, within a day, keeps its original deadline, and is acted on at once if that has passed. While an account is in its 24-hour cooldown nothing is asked about it: findings are notified as before. An account that cannot be read is still acted on when a risky question on it falls due or you answer "Lock it down". After a restart each open question gets its own dialog again, with the text it first showed.

**Limits, stated again.** An account is pressed at most once in 24 hours, also when it is downstream of another trigger; later triggers in that window are left to the watch and notified. The protected admin or owner is never pressed. A released account is not guarded again until `panic rehearse` asks "Resume guarding" and you answer yes, and the watch does not lock it again until a new press of that account. For Workspace, Microsoft 365 and Slack, notifications, the log and the report name a finding by its kind and withhold rule contents; `panic removed --user ID` prints them. On GitHub, per-repository reads (deploy keys, webhooks, collaborators, invitations) are repeated once an hour, so those are noticed up to an hour late; keys and email addresses are read every pass.

**Approving your own change.** Answer "It was me" when the guard asks. Or stop the guard, or run it with `--on-detect alert`, before you make a change that matches a trigger, make the change, run `panic rehearse` and approve the new settings as the baseline, then start the guard again. If a press already ran, `panic release --user ID` lifts the lock and takes the account out of the guard; `panic rehearse` shows its state and asks whether to resume guarding it.

## What each provider does

"Automatic" steps are done by the tool and read back where the provider allows it. "Reapply" means the watch puts the setting back if the attacker returns it. Everything else is guided: the tool opens the link, you do it and confirm.

| Connector | Automatic | Guided only |
|---|---|---|
| Personal Gmail | Turn off POP (reapply); delete filters outside the baseline (reapply) | Forwarding (reported, not undone), sign-out, connected apps, app passwords, delegates, recovery details, password |
| Google Workspace | Suspend, sign out, forwarding, connected apps, app passwords, backup codes, forwarding addresses, delegates, filters, IMAP and POP, recovery details, random password | None |
| Microsoft 365 | Block sign-in (reapply); sign out of every session (no read-back); delete inbox rules outside the baseline (reapply); delete the user's own app consent grants outside the baseline (reapply) | Mailbox forwarding, mailbox delegates, password reset. Authentication methods are read and a new one triggers the guard, but none is removed. |
| Personal Microsoft | Delete inbox rules outside the baseline (reapply) | Forwarding, sign-out, sign-in activity, connected apps, recovery phone and email, password |
| GitHub account | Delete SSH, signing and GPG keys outside the baseline; delete emails outside the baseline (the primary address stays); delete deploy keys, webhooks, collaborators, invitations and self-hosted runners on repositories you own (all reapply). Public repositories and runners are watched (runners only if the token has admin rights); tokens are never revoked. | Sign-out of sessions, personal access tokens (including the tool's own), connected apps, two-factor and recovery codes, password |
| GitHub organisation | Delete webhooks, deploy keys, outside collaborators and self-hosted runners outside the baseline (reapply) | Members and owners: review and remove by hand |
| Slack Enterprise Grid | Sign the member out of every session; deactivate (reapply), which `release` reverses | Removing apps |
| Slack Business+ | Deactivate (reapply), which `release` reverses | Removing apps |
| Slack Pro, Free | None | Deactivate in the admin page, removing apps. `release` cannot reactivate. |
| Guided service | None | Whatever links the service has: sign out everywhere, devices, connected apps, two-step verification, recovery details, password |

## The key file

The vault opens only with the passphrase and the key file together. Keep them apart: move the key file to a USB stick or a second device and pass it with `--keyfile` (or set `PANIC_KEYFILE`). If the key file and vault sit on the same device, the tool warns you. Neither is ever cached.

## A second-device copy

Press must work from a clean device. Copy the vault to a USB stick with `panic export /Volumes/STICK/panic.vault`. It refuses a destination on the same device as the key file. Keep the key file on a different stick. A copy more than 30 days old triggers a warning at press time, because more may be removed than you expect.

## Commands

Global options: `--vault PATH` (default `~/.panic/panic.vault`), `--keyfile PATH` or `PANIC_KEYFILE`.

| Command | Does |
|---|---|
| `setup` | Guided setup: explains each service, asks what it needs, then runs `arm` for you. Repeats until you stop. |
| `arm --personal EMAIL --client-secrets FILE` | Arm a personal Gmail account (recovery check, baseline, reset edges). `--reconnect` re-authorises only. |
| `arm --workspace --sa-key FILE --admin EMAIL --domain DOMAIN` | Arm every user in a Workspace domain; the admin is protected. |
| `arm --microsoft-tenant TENANT --client-id ID --client-secret-file FILE --admin UPN` | Arm every user of a Microsoft 365 tenant; the admin is protected. |
| `arm --microsoft-personal EMAIL --client-id ID` | Arm an Outlook.com or Hotmail account. `--reconnect` re-authorises only. |
| `arm --github LOGIN --token-file FILE [--org NAME]` | Arm a GitHub account, or an organisation you own. `--reconnect` replaces the token only. |
| `arm --slack --token-file FILE` | Arm a Slack workspace; the plan is detected and the primary owner is protected. |
| `arm --guided KEY --id LOGIN [--name NAME] [--link KIND=URL ...]` | Add a service with no API as a checklist. |
| `checkup [--again]` | Read every armed account, ask five questions no API can answer, and list what to fix. Changes nothing on any account. `--again` asks every question again. |
| `map` | Which account can reset which, and which to lock first. |
| `rehearse` | Read every account, show what is outside its baseline, offer to approve it as the new baseline, ask whether to resume guarding each released account, and recompile the plan. Changes nothing in the accounts. |
| `guard [--interval SECONDS] [--on-detect press\|contain\|alert] [--wait SECONDS] [--dry-run]` | Poll every armed account, ask you about a finding, and act on a risky one if nobody answers. Default every 300 seconds, minimum 30, default `press`. `--wait` is the time to answer, default 900 (15 minutes); `--wait 0` acts at once. |
| `press --user ID ... / --all [--dry-run]` | Lock the chosen accounts root first, write the report, then watch for 24 hours. `--dry-run` changes nothing. |
| `watch` | Resume the 24-hour watch. |
| `release --user ID` | Undo the lock: unsuspend a Workspace user with a temporary password, re-enable a Microsoft 365 user, reactivate a Slack member. The account stays out of the guard until `rehearse` resumes it. Other accounts cannot be released. |
| `report` | Re-render the report from the last press, list earlier reports; warns if the audit log was changed. |
| `removed --user ID` | Print, for every press newest first, what it removed from that account and what was outside its baseline, then what the watch removed; unredacted, so it can be restored. |
| `export DEST` | Copy the vault file. |

Each press writes its report to `<vault>.report-<YYYYMMDDTHHMMSSZ>.md` and `.json`, named by the press start time (UTC) and never overwritten by a later press; the vault keeps every press. The hash-chained audit log is `<vault>.log.jsonl`. All are readable only by you. The report's `Put back during the watch` section lists each setting the watch re-applied, how often, and what it removed (organisation accounts: contents withheld; `panic removed` shows them).
