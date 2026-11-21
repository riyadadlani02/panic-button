# panic-button

One command that stops an attacker in your connected accounts, root account first, and then shows what it proved and what it could not. It runs on your machine; there is no server.

## What it promises

1. Everything a provider lets software revoke is revoked and then read back to prove it, root account first. Some steps have no read-back: on Workspace, sign-out, backup codes and the password reset; on a personal account, most guided steps. Those are never called verified: the report marks them "Accepted by provider" or "Owner confirmed".
2. Anything that cannot be revoked is listed by name with when it expires. Unknown counts as open; the report never says "safe" by default.
3. For 24 hours afterwards, while `panic press` or `panic watch` keeps running, the tool re-checks the settings the API can read and puts back those it can change (filters and POP, plus IMAP on Workspace; for Workspace also suspension, forwarding, delegates and recovery details). Other changes are reported, not undone.
4. The tool itself is not a master key: a stolen laptop or a stolen vault file opens nothing, because opening needs both your passphrase and a separate key file.
5. A lockdown never costs you your account: for personal accounts arming asks you to confirm a recovery path you control; Workspace relies on the named break-glass admin, which no command will act on. No password is changed by API in personal mode.

## What a Workspace press does to a user

It suspends the account, resets the password to a random value nobody is told, removes every mail delegate, revokes every app's access and every app password, and invalidates backup codes. It also turns off forwarding, IMAP/POP and filters added since the baseline, and puts recovery details back. `panic release` restores sign-in only, with a temporary password shown once; delegates, apps and app passwords stay removed (`panic removed` lists them).

## What it does not promise

- Tokens an attacker already holds can outlive revocation for up to about an hour.
- A compromised pressing device defeats the tool. Press from a clean device.
- Personal Gmail has no API for sign-out, connected apps, forwarding or password change, so those are guided steps you confirm by hand.
- The Workspace connector has been tested against mocked responses only.
- Personal Gmail has no IMAP switch: IMAP is always on. A mail client an attacker connected is cut off only by deleting app passwords, removing connected apps and changing the password, which are guided steps.
- The watch stops when the process stops.
- The watch does not retry steps that were Still open at press time. Press again.
- Whether Gmail settings can be changed for a suspended Workspace user is unverified; it is the first item of the live check.
- On a personal account, sign-out, connected apps, app passwords, delegates, recovery and password are not watched, and forwarding is reported, not undone.
- It does not detect the hack, clean malware, or read mail content.

Measured freeze time: Not yet measured; recorded during the live check.

## Install

Install the tool and copy the vault to the second device before you need it.

```
uv sync
uv run panic --help
```

## Try it without an account

```
PYTHONPATH=. uv run python demo/sandbox_demo.py
```

It runs the real vault, engine and `panic` commands against an in-memory mail provider: an attacker adds forwarding, a hiding filter and a rogue app, the press removes them, and the attacker re-adds forwarding during a shortened watch, which puts it back. Nothing touches the network.

## Setup: personal Gmail

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

1. Create a service account, enable domain-wide delegation for it, and download its JSON key.
2. In the Admin console authorise the service account's client ID for exactly these four scopes: Admin SDK directory user security, Admin SDK directory user (read/write), Gmail settings basic, and Gmail settings sharing. The exact scope URLs are listed in `panic/google_workspace.py`.
3. Use a dedicated break-glass admin account. It is the identity the tool acts as and is never a target, even with `--all`.

```
uv run panic --keyfile ~/panic.key arm --workspace --sa-key sa.json --admin breakglass@example.com --domain example.com
```

The admin must be the primary address of a super admin. Every user in the domain is armed and baselines are recorded without printing them. Arming again adds new users but never replaces an existing baseline; `rehearse` shows changes as flags and asks before accepting them.

Delete the service-account JSON once armed: it is a tenant-wide key, and the vault already holds a copy.

## The key file

The vault opens only with the passphrase and the key file together. Keep them apart: move the key file to a USB stick or a second device and pass it with `--keyfile` (or set `PANIC_KEYFILE`). If the key file and vault sit on the same device, the tool warns you. Neither is ever cached.

## A second-device copy

Press must work from a clean device. Copy the vault to a USB stick with `panic export /Volumes/STICK/panic.vault`. It refuses a destination on the same device as the key file. Keep the key file on a different stick. A copy more than 30 days old triggers a warning at press time, because more may be removed than you expect.

## Commands

Global options: `--vault PATH` (default `~/.panic/panic.vault`), `--keyfile PATH` or `PANIC_KEYFILE`.

| Command | Does |
|---|---|
| `arm --personal EMAIL --client-secrets FILE` | Arm a personal Gmail account (recovery check, baseline, reset edges). `--reconnect` re-authorises only. |
| `arm --workspace --sa-key FILE --admin EMAIL --domain DOMAIN` | Arm every user in a Workspace domain; the admin is protected. |
| `map` | Which account can reset which, and which to lock first. |
| `rehearse` | Read every account, show what is outside its baseline, and recompile the plan. Changes nothing in the accounts. |
| `press --user ID ... / --all [--dry-run]` | Lock the chosen accounts root first, write the report, then watch for 24 hours. `--dry-run` changes nothing. |
| `watch` | Resume the 24-hour watch. |
| `release --user ID` | Unsuspend a Workspace user with a temporary password, shown once. |
| `report` | Re-render the report from the last press, list earlier reports; warns if the audit log was changed. |
| `removed --user ID` | Print, for every press newest first, what it removed from that account and what was outside its baseline, then what the watch removed; unredacted, so it can be restored. |
| `export DEST` | Copy the vault file. |

Each press writes its report to `<vault>.report-<YYYYMMDDTHHMMSSZ>.md` and `.json`, named by the press start time (UTC) and never overwritten by a later press; the vault keeps every press. The hash-chained audit log is `<vault>.log.jsonl`. All are readable only by you. The report's `Put back during the watch` section lists each setting the watch re-applied, how often, and what it removed (Workspace filter contents withheld; `panic removed` shows them).
