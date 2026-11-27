# Attack-driven detections and safety check-up: design

Approved by Riya on 28 Nov 2026. Source: `docs/2026-11-28-attack-analysis.md` (17 incidents, Nov 2025 to Nov 2026; about 6 addressable, 11 out of reach for an account-settings tool).

## Why

Since the guard asks first, anything classed as harmless is accepted automatically when nobody answers. Three attack signs from last year are classed harmless today. The analysis also shows that posture (2FA type, passkeys, SIM PIN, offline photos) prevents more than detection does.

## What changes

**A. Gaps closed (harmless → risky)**
- Google Workspace: a new connected app (`apps`) → `app_consent_added`.
- Google Workspace: a new app password (`app_passwords`) → new code `app_password_added`.
- GitHub: a new public repository, or a repository made public → new code `repo_made_public`. Private repositories stay harmless.

**B. New GitHub detection: self-hosted runners**
- New category `runners` (per repository you own; per organisation for an org account). A new runner → new code `runner_added`, risky. The existing repository-access step also removes runners outside the baseline.
- Personal access tokens are never revoked automatically (a 2026 worm wipes the disk when its stolen token is revoked). Unchanged: tokens stay a guided step.

**C. `panic checkup`**
- Reads, never changes. Each connector may offer `posture(account)` returning checks with a pass, fail or unknown result, a detail line and a fix link:
  - Microsoft 365: per user, only SMS or voice as a second factor; no passkey, authenticator app or Windows Hello.
  - Google Workspace: per user, 2-step verification not enrolled.
  - GitHub: two-factor off on the account; organisation does not require two-factor.
  - Gmail and Outlook.com: POP on, forwarding on (from what the tool already reads).
- A short checklist of things no API can see, asked once and saved in the vault, re-asked after 90 days or with `--again`: carrier port-out PIN, passkeys on main accounts, iCloud Advanced Data Protection, an offline copy of photos, a trusted recovery contact.
- Output: a report grouped by "Fix now", "Unknown" and "Good", each with its link. Organisation accounts show counts and user ids, never item contents.

**D. Honest limits**
README and product page get a short "What panic button cannot stop" list from the analysis: theft at a vendor you already connected, malware on your computer, SIM swaps at the carrier, wallet and seed-phrase scams, iCloud (no API), and data copied in the first minutes before any setting changes.

## Constraints

- A category new to a connector must not break old vaults: when the baseline lacks it, the first read records it as the baseline for that category (logged), instead of failing as unreadable.
- No new automatic action beyond removing runners outside the baseline.
- `checkup` never writes to any account; only its checklist answers are saved, in the vault.
- Commits authored by Riya Dadlani only.

## Approaches

- **Chosen:** close the classification gaps, one new GitHub category, and a read-only check-up.
- Rejected for now: new-device sign-in alerts (need Entra ID P1 or the Workspace activity log; provider-flagged sign-ins already cover the strongest cases); a vendor-breach "revoke this app everywhere" command (worth a later project).
