# One-click connect: design

Approved by Riya, 28 Nov 2026 ("Approve"). Project 2 of 5.

## What

- `panic/oauth_clients.json` holds the public sign-in app IDs shipped with the tool: `{"google": null | {installed-app client config}, "microsoft": null | "<client id>", "github": null | "<client id>"}`. All `null` until Riya registers the apps. `PANIC_OAUTH_CLIENTS=/path/file.json` overrides it (for tests and the live check; never committed with real IDs from a test project).
- Gmail: `panic arm --personal` may be given without an address. With no `--client-secrets`, the built-in Google client is used if set. With no address, the signed-in address (from Google) is the account. With an address, the existing "signed in as someone else" check stays.
- Outlook.com: `--client-id` defaults to the built-in Microsoft ID; the address may be omitted and taken from the sign-in's `preferred_username`.
- GitHub: `panic arm --github` may be given without a login and without `--token-file`; it then runs GitHub's OAuth device flow with the built-in client ID (scopes as the classic token today), prints the code and opens `https://github.com/login/device`, polls until approved, denied or expired, and takes the login from `GET /user`. The existing token-file route is unchanged. `--reconnect` works the same way.
- `panic setup` (and the app's wizard, which runs it): when a built-in ID is set, that service's steps become "Your browser will open. Sign in and click Allow." and it asks nothing else (apart from arm's own recovery and reset questions). When unset, today's steps appear.
- Workspace, Microsoft 365 and Slack are unchanged.

## Constraints

- No client secret that matters is shipped (installed-app Google configs carry a non-confidential secret by design; Microsoft and GitHub device/public flows need none).
- Tokens stay in the vault as today; nothing leaves the user's computer except to the provider.
- The device-flow code is shown to the user but never logged; the token never printed.
- Every existing arm path and test keeps working.
- Commits authored by Riya Dadlani only.
