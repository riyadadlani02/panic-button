# Live checks

Checks to run on real accounts before relying on a connector. Each connector's checks are ordered safest and most informative first. Use throwaway accounts, tenants and workspaces only. Everything below was tested against recorded response shapes, except personal Gmail's press, watch and rehearsal, which ran on a real throwaway account.

Before each check, make a vault and key file you can delete afterwards, and pass `--vault` and `--keyfile` explicitly. Write down what you saw, including a failure. A failed check means the README's claim for that connector is not yet true; change the README, not the check.

## Personal Gmail

Press, watch and rehearse have run on a real throwaway account. The guard has not.

1. `panic rehearse`: expect "matches the baseline" for the account and a plan listing POP and filters as API steps.
2. `panic guard --dry-run --interval 30`, stopped with Ctrl-C after one pass: expect the "Guarding every 30s" line and one heartbeat line ("read 1 accounts, 0 findings, 0 skipped"), and nothing else.
3. `panic guard --on-detect alert --interval 30`. In the Gmail web page add a filter that only applies a label. Expect, within one interval, a notice that something else on the account changed, no press, and no "outcomes" in `panic report`. Gmail's page can show stale data: reload the whole page.
4. In the same run, add a filter that skips the inbox and marks as read (or deletes) and one that forwards. Expect a notification naming the trigger and, because the mode is `alert`, no press.
5. Stop the guard. Remove the test filters in the browser, run `panic rehearse` and approve the baseline if it shows a difference. Start `panic guard --interval 30` (mode `press`). Add a hiding filter in the browser. Expect: noticed within one interval, a notification, the filter deleted, POP off, guided steps listed under "Needs you" with nobody asked, and a "What triggered this press" section in the report.
6. Add a second hiding filter inside 24 hours. Expect a notification and no second press; the watch removes it on its next pass.
7. Stop and restart the guard. Expect no repeated notices and no second press.

Known delay: a filter created in the web page can take over a minute to reach the API. If check 3 or 5 sees nothing within one interval, wait a minute before calling it a failure.

Results on the throwaway account (21 November 2026):

- Checks 1 and 2 passed as written.
- Check 5 passed in its main part: with `panic guard --interval 30` running, a hiding filter (subject "security alert", mark as read, delete) added in the browser was noticed on the next pass, about 15 seconds later, the notification said "Pressing now", the filter was deleted and read back as Verified, the seven guided steps were listed under "Needs you" with nobody asked, and the report had a "What triggered this press" section. Gmail's page showed the filter gone after a reload.
- A star-only filter added a minute later gave the notice "Something else on this account changed since the baseline" and no press. On the following pass the 24-hour watch from the press removed it ("was changed, put back"). So for 24 hours after a press every new filter is removed, harmless or not; outside that window a harmless filter is only reported.
- Not run: checks 3 and 4 (`alert` mode), 6 (a second hiding filter inside 24 hours) and 7 (restart).

## Google Workspace

Never run on a real tenant. Use a test tenant and a test user, and a separate break-glass admin.

1. `panic arm --workspace ...` then `panic map` and `panic rehearse`. Expect every user armed, the admin shown as protected, and "no flagged changes" for each user.
2. The fifth scope. Before arming, authorise only the four press scopes in domain-wide delegation. Expect arm, `panic rehearse` and `panic press --user TESTUSER --dry-run` to work, and `panic guard --dry-run --interval 30` to show a notice that the activity log could not be read. Then add `admin.reports.audit.readonly` and expect no such notice.
3. `panic press --user TESTUSER --dry-run`: expect the plan and nothing changed.
4. Gmail settings on a suspended user. `panic press --user TESTUSER`. Expect the filters, forwarding, IMAP and POP steps to read back as Verified after the suspend. If they fail on the suspended user, the step order has to change (settings first, suspend last); record the exact error.
5. `panic release --user TESTUSER`: expect a temporary password shown once and sign-in restored.
6. Reports API event names. In the test tenant, trigger a Google-flagged sign-in if you can (a sign-in from an unusual location through a VPN). Within two hours of that sign-in, start `panic guard --on-detect alert --interval 30`: the guard reads the log from two hours before it started. Expect a notification naming a provider-flagged sign-in within one interval, and no second notification for the same event on later passes. Compare the event names Google logged (in the Admin console's audit log) with `SUSPICIOUS` in `panic/google_workspace.py` and correct the set.
7. `panic guard --interval 30` on the test user with a new forwarding address outside the domain: expect an automatic press. Then one inside the domain: expect no trigger.
8. Second domain. If the organisation has a second domain, add a forwarding address in it: the tool treats it as outside and presses. Record this; it is a known limit, not a fix in this milestone.

## Microsoft 365

Use a test tenant where you are admin, a test user and a separate break-glass admin.

1. `panic arm --microsoft-tenant ...`. If it refuses to read users or the admin, note the error: it points at a missing application permission or admin consent.
2. `panic rehearse`: expect "no flagged changes". Without Entra ID P1 or P2, `panic guard --dry-run --interval 30` should show one notice, once (the generic "activity log could not be read" wording; the tool has no licence-specific message), and carry on. Record whether the notice appears and what the provider's error was.
3. Consent grants. Have the test user consent to an app, then `panic rehearse`. Expect the grant to appear. Confirm that `GET /users/<id>/oauth2PermissionGrants` returns only that user's own (Principal) grants. If it returns tenant-wide grants as well, the tool must not touch them.
4. `panic press --user TESTUSER --dry-run`, then `panic press --user TESTUSER`. Expect inbox rules and the user's own consent grants deleted and read back as Verified.
5. Block sign-in. If the "Block sign-in" step fails with an authorisation error, the app needs an Entra admin role (for example User Administrator) in addition to the application permission. Record which.
6. `panic release --user TESTUSER`: expect sign-in restored and a reminder to reset the password in the Entra admin centre.
7. Guard: with `panic guard --interval 30`, add an inbox rule that forwards outside the tenant's domains: expect a press. Add one that forwards inside the domain: expect no trigger.
8. Authentication methods are read and signalled, not removed. Add a method for the test user: expect a trigger and a press, and the method still present afterwards, with the report not claiming it was removed.
9. Mailbox-level forwarding and mailbox delegates cannot be read through Graph. Set each on the test mailbox in the Exchange admin centre: expect that neither is noticed, and that the plan lists both as guided steps.
10. A user without a mailbox (an unlicensed account). Expect it armed with no baseline or reported unreadable by the guard on every pass. Record the error Graph returns.
11. Internal rule recipients. Add an inbox rule that forwards to another user in the tenant and read the stored rule (`panic removed` after a press, or the baseline). Record whether Graph gives the recipient as an address with "@" or as a legacy Exchange address without one; the latter would be counted as outside the organisation and trigger a press.
12. Stable rule forms. Run `panic rehearse` twice with no change in between. Expect "no flagged changes" both times; a difference means the stored canonical rule is not stable between reads. Do the same for Gmail filters on Workspace (check 1).

## Personal Microsoft (Outlook.com)

1. Registration. Create the public-client registration with `MailboxSettings.ReadWrite` and run `panic arm --microsoft-personal ADDRESS --client-id ID`. Record whether Microsoft allows this for an Outlook.com account without publisher verification, and what the consent screen says. If it does not, the connector cannot be used as built.
2. `panic rehearse`: expect "matches the baseline". Add an inbox rule in Outlook on the web and rehearse again: expect it to be listed.
3. Rule delete and read-back. `panic press --user ADDRESS --dry-run`, then `panic press --user ADDRESS`. Expect the added rule deleted and read back as Verified, with an ordinary rule in the baseline untouched.
4. Token refresh. Leave the vault alone for over an hour, then run `panic rehearse` again. Expect it to work without a new sign-in, and the vault to have the rotated token (the next run works after a restart). A "sign-in expired" message means the refresh was not saved.
5. Guard: `panic guard --interval 30`, add a rule that forwards to any address or deletes mail: expect a press with inbox rules deleted and the other steps under "Needs you".
6. Every guided link in the plan (forwarding, sign-out, sign-in activity, connected apps, recovery, password): open each in a browser while signed in and record whether it lands on the right page. They are marked "(link not verified)" until you do.
7. `panic arm --microsoft-personal ADDRESS --reconnect` after a password change: expect it to work with the client id kept in the vault.

## GitHub

Use a throwaway account with a classic token and a few repositories.

1. Token scopes. Create the token with the scopes the README lists, run `panic arm --github LOGIN --token-file FILE`, and note each endpoint that answers 403 or 404 (keys, signing keys, GPG keys, emails, deploy keys, webhooks, collaborators, invitations). Remove scopes one at a time to find the smallest set that works, and correct the README.
2. `panic rehearse`: expect "matches the baseline". Add an SSH key in the web page and rehearse again: expect it to be listed.
3. The primary email is never removed. Add a second email, run `panic press --user LOGIN`, and expect the second one removed and the primary one still there.
4. Webhook fingerprints. Add a webhook whose URL carries a secret. Expect the plan, report and `panic removed` to show the URL without the secret, plus a short fingerprint, and the webhook to be deleted by the press.
5. Rate limit. On an account with many repositories (or an organisation with hundreds), run `panic guard --dry-run --interval 30` for several passes. Expect per-repository reads to repeat only once an hour. Watch the remaining rate limit in the token's headers and note how many calls one read of all repositories takes.
6. Guard: `panic guard --interval 30`, add an SSH key in the web page: expect a press that deletes it. Approving a key you added yourself with `panic rehearse` first should prevent that.
7. Organisation: arm with `--org`, add an outside collaborator, expect a press that removes them and a "Members" guided step.
8. Check that guided steps are listed (sessions, tokens including the tool's own, apps, two-factor, password), and that after a password change `arm --github LOGIN --token-file NEWFILE --reconnect` replaces the token.

## Slack

What can be tested depends on the plan. Record the plan the tool printed.

1. `panic arm --slack --token-file FILE`. Expect the detected plan and the line saying what the tool can do on it. If a non-Enterprise token gets a 403 or 404 from the audit API, plan detection falls through to the next probe; if it gets a 401 instead, arm fails with an error. Record the status and the error name, per plan.
2. If the token cannot list emails, expect arm to refuse and name the `users:read.email` scope. Confirm that scope is the one missing.
3. `panic rehearse`: expect "matches the baseline" on Enterprise and Business+ (the baseline is only the member's active flag) and nothing to compare on Pro and Free.
4. Business+ and Enterprise: `panic press --user slack:EMAIL --dry-run`, then `panic press --user slack:EMAIL` on a test member (Slack account ids are `slack:` and the member's email). Expect the member deactivated and read back as Verified. If SCIM answers with an error, record the exact `PATCH` body and the response; the body shape `{"active": false}` is unconfirmed.
5. `panic release --user slack:EMAIL`: expect "Member reactivated" and the member able to sign in.
6. Enterprise Grid: expect the "Sign the member out of every session" step to succeed. If `admin.users.session.reset` answers with a missing `team_id` error, the call needs the workspace's team id; record the exact error.
7. `team.accessLogs` on Pro and Business+: run `panic guard --interval 30` and sign in from a new network. Expect a notice that new access appeared on the member's account, without the address (organisation accounts withhold a finding's items), and no press. Record whether Pro answers the call at all.
8. Enterprise Grid audit log: expect an `anomaly` or `user_logout_compromised` event for a member to produce a trigger. This is hard to cause on purpose; if no real event appears, record that the trigger path was not exercised.
9. Enterprise Grid workspace addresses. In a Grid organisation, check that `auth.test` returns a workspace address the guided links can use (`https://NAME.slack.com/...`). Record the form it takes.
10. Pro and Free: expect the plan to list "Deactivate the member" as a guided step with a link to the admin page, and `panic release` to refuse.

## Guided catalogue

Every link in `panic/guided_services.json` is marked `"verified": false`.

1. For each service, open every link in a browser while signed in to a throwaway account on that service. Record whether the page loads and is the right one.
2. For each link that works, set `"verified": true` for that service in the file once all of its links work. Remove or fix a link that does not.
3. `panic arm --guided KEY --id LOGIN` for one service, then `panic rehearse` (expect "guided only, not read") and `panic press --user KEY:LOGIN --dry-run`. Expect the links listed, marked "(link not verified)" until the entry is verified, and no "verified" claim anywhere for these steps.
