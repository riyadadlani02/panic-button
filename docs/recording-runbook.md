# Recording runbook: a live attack and a press on a throwaway Gmail

A 4 to 5 minute technical walkthrough. The attacker is you, in a second browser window signed in to the same throwaway account, standing in for a stolen session.

## What the take can honestly show

On a personal Gmail account the tool does two things itself and reads each back:

- deletes every filter that is not in the baseline;
- turns off POP (and IMAP, see the open question below).

The other seven steps are links it opens for you to click, because Google gives personal accounts no API for them: forwarding, sign out devices, connected apps, app passwords, delegates, recovery details, password. Say this on camera. The dramatic "attacker is thrown out" moment comes from your click on the sign-out and password steps, not from the tool.

## What the first real run showed

Run off camera on a throwaway personal Gmail:

- Arming, rehearsal, dry run, press, watch, report and `removed` all worked. The planted filter was deleted and POP switched off, both read back as Verified, and the ordinary filter was untouched.
- The watch's five-minute pass removed a re-planted filter and logged it.
- Gmail's settings page shows stale data. Reload the whole page (Cmd-R) before showing a change; switching settings tabs is not enough.
- A filter created in the web page took over a minute to appear to the API. After re-planting, wait about 90 seconds before forcing a watch pass, or let the five-minute pass catch it and cut the wait.
- Personal Gmail has no IMAP switch, so the step is now "Turn off POP access" and the README says IMAP stays on.
- Guided links now carry the account (`?authuser=<email>`), so they open the right account when several are signed in. Sign-out, app passwords and password ask for the Google password first.

Not exercised yet: the seven guided steps answered "y", including the password change and `--reconnect`.

## Prepare once

1. A throwaway Gmail account (the victim), with 2-step verification on and backup codes printed. Arming refuses an account with no recovery method outside the mailbox.
2. Optional: a second mailbox, as the attacker's forwarding target.
3. A Google Cloud project created while signed in as the throwaway account, so no personal address appears on the consent screen. Enable the Gmail API, set the consent screen to Testing, add the throwaway as a test user, create a Desktop OAuth client and download its JSON. Details: README, "Setup: personal Gmail".
4. Make the mailbox look used: one ordinary filter (a newsletter label) and a few emails. The ordinary filter surviving the press is a good beat.
5. Put the key file on a USB stick: `export PANIC_KEYFILE=/Volumes/<stick>/panic.key`.

## Off-camera check (must pass first)

Run the whole shot list below once without recording. Stop and fix if any of these is wrong:

- arming signs in as the throwaway address and shows its filters, forwarding and IMAP/POP state;
- the planted filter is deleted and reads back as Verified; the ordinary filter is untouched;
- each of the seven links opens the right Google page;
- a re-planted filter is removed by the next watch pass.

## Screen layout

- Left: browser, the owner's window, on Gmail Settings, "Filters and Blocked Addresses".
- Right: a second browser profile or private window, the attacker, signed in to the same account.
- Bottom: terminal in `~/panic-button`, large font. A second tab ready for the reconnect.
- Hide the bookmarks bar and any other signed-in account. Never show the client JSON file.

## Shot list

| Time | Where | Do | Viewer sees |
|---|---|---|---|
| 0:00 | Terminal | `uv run panic map`, then `uv run panic rehearse` | The armed account; nothing outside the baseline |
| 0:30 | Attacker | Create a filter: from `bank` or subject `security alert`, then Skip Inbox, Mark as read, Delete | Alerts will now vanish silently |
| 0:50 | Attacker | Settings, "Forwarding and POP/IMAP": enable POP for all mail. With a second mailbox: add it as a forwarding address and confirm it | A copy of everything can be pulled out |
| 1:15 | Terminal | `uv run panic rehearse`, answer `n` | The tool lists what is outside the baseline |
| 1:40 | Terminal | `uv run panic press --user <email> --dry-run` | The plan and "Attacker may have touched"; nothing changed |
| 2:00 | Terminal | `uv run panic press --user <email>` | Freeze, then purge, each with its evidence level |
| 2:15 | Owner | Reload the page (Cmd-R) on the Filters tab and the POP section | Planted filter gone, ordinary filter still there, POP off |
| 2:30 | Terminal and owner | Walk the guided steps, clicking each link and answering `y` | Sign-out and the password change |
| 3:15 | Attacker | Refresh | Google's sign-in page: the session is dead |
| 3:25 | Second tab | `uv run panic arm --personal <email> --reconnect` | The tool reconnects; the running watch picks it up |
| 3:45 | Owner | Re-create the hiding filter, saying "suppose one session was missed" | |
| 3:55 | Terminal | Wait 90 seconds (cut it), Ctrl-C the watch, then `uv run panic watch` | A pass runs at once and removes the filter. Say that the watch otherwise checks every five minutes |
| 4:20 | Terminal | Ctrl-C, `uv run panic report`, `uv run panic removed --user <email>` | Locked / Needs you / Still open, "Put back during the watch", and the removed filter in full |

## Before publishing

Check every frame for: an email address you did not mean to show, the consent screen's support address, your home folder name in a path or prompt, and backup codes.
