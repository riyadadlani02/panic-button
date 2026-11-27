# Ask before press: design

## Why

The owner may be the one who changed a setting. Today the guard presses the moment it sees a trigger, which locks people out of their own legitimate changes. The guard should ask first, and treat silence as consent for harmless changes, while still protecting a sleeping owner from a real takeover.

## Approaches

- **Lock risky, accept the rest (chosen by Riya, 28 Nov 2026).** Ask first. If nobody answers by the deadline, risky findings still lock and harmless ones are accepted as the new baseline.
- Accept everything on silence. Rejected: a 2 a.m. intruder's rule would be accepted and kept, which is the attack the product is sold on.
- Never accept on silence, keep asking. Rejected: the owner asked for ignored alerts to count as consent.

## Behaviour

**Every finding becomes a question.** The alert names the account and the change and offers two answers: "It was me" and "Lock it down". It says what happens if nobody answers and when.

| Finding | "It was me" | "Lock it down" | No answer by the deadline |
|---|---|---|---|
| Risky (today's triggers: outside forwarding, a rule that hides or deletes mail, new key, app, MFA method or delegate, provider-flagged sign-in) | Accept | Act now | Act |
| Harmless (today's "changed" notice) | Accept | Act now | Accept |

- **Act** means what `--on-detect` says today: `press` (default) or `contain`.
- **Accept** re-reads the account. If everything it finds now was in the question, that snapshot becomes the account's new baseline, logged as an accepted change. If something new appeared meanwhile, the accept is refused and the new findings get their own question. Nothing unseen is ever accepted.
- **Provider-flagged sign-ins** have no snapshot to accept: "It was me" closes the question.
- **Deadline:** `--wait SECONDS`, default 900 (15 minutes). `--wait 0` keeps today's immediate press.
- `alert` mode and `--dry-run` never act and never accept; a dry run prints "would ask".
- The cooldown (at most one press per account per 24 hours), protected admins and released accounts behave as today.

## Where the answer comes from

- **macOS:** a dialog with the two buttons, opened without blocking the guard. Between passes the guard checks for an answer every second, so "Lock it down" acts within about a second.
- **Anywhere, and if the dialog cannot open:** the alert says how to answer by hand: `panic rehearse` to accept, `panic press --user ID` to lock. The deadline still applies.
- The XP-style app (a later project) replaces the dialog.

## State and edge cases

- Open questions are saved in the guard state with their deadline, so a restarted guard keeps the deadline and opens a new dialog for the time left.
- A second change on the same account while a question is open gets its own question; the first deadline does not move.
- If the owner approves a change with `panic rehearse` while a question is open, the next pass finds nothing and closes the question.
- A risky finding that disappears before the deadline (the intruder removed it) closes the question; the change is not accepted and nothing is pressed.

## Effect on what we say publicly

The guard no longer presses within seconds by default. The page and film say it caught a hidden rule in 15 seconds and pressed by itself. After this change: it notices within one check, asks you, and locks risky changes after 15 minutes if you don't answer. The page, README and film need updating to match.

## Left to the builder

Dialog wording, how questions are keyed, and log event names.
