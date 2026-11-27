# Desktop app (Windows XP style) and Mac installer: design

Requested by Riya, 28 Nov 2026: "i want a installer to install it instead of command line … retro style app, like windows xp apps". Decided by Riya: the passphrase is saved in the macOS Keychain and the guard starts by itself at login.

## Why

Buyers who are not technical will not use a terminal. The app must let them set up accounts, keep the guard running, answer its questions, press the button, and read reports, all in windows that look like a Windows XP program.

## Approaches

- **Chosen: a native window (pywebview 6.x) showing a local page styled with XP.css 0.2.6 (MIT), with the existing engine running inside the app.** pywebview uses the system web view on Mac (WebKit) and on Windows (Edge WebView2), so the Windows version later reuses the same UI.
- Rejected: Tkinter (cannot look like XP without redrawing every control); a local web server opened in the browser (does not feel like an app; another port to secure).

## How it works

**One engine, no second code path.** The app runs the same `panic` commands the CLI runs, in a worker thread. Every prompt the commands make (`input`, `getpass`, yes/no questions) is routed to the window as an XP dialog, and the command's printed output is shown in an XP window. Only one command runs at a time. This keeps every rule the CLI already enforces (recovery check, protected admin, baselines) without re-implementing them.

**Unlock.** On first open the app asks for the passphrase (or creates the vault through the setup wizard) and saves it in the Keychain under the service `panic-button`, keyed by the vault path. A "Remember on this Mac" box is on by default; untick it to be asked every time. "Forget this Mac" removes it. The key file is still required: if it is on a USB stick that is not plugged in, the app says so and the guard does not start.

**Guard.** Runs in a background thread while the app is open, with the current defaults (check every 5 minutes, ask first, 15-minute wait). Its questions appear in the app ("It was me" / "Lock it down"); the macOS dialog is used only when the app window is hidden. A login item (a LaunchAgent in `~/Library/LaunchAgents`) opens the app at login and the guard starts once unlocked from the Keychain. A Start/Stop switch and the login item can be turned off in the app.

**Screens**

```
┌─ panic button ─────────────────────────────── _ □ X ┐
│ File  Accounts  Guard  Help                          │
│ ┌ Accounts ───────────────┐  ┌─────────────────────┐ │
│ │ ● you@gmail.com  Guarded │  │                     │ │
│ │ ● octo (GitHub)  Guarded │  │      ( PANIC )      │ │
│ │ ○ amazon         List    │  │                     │ │
│ │ [ Add account… ]         │  │ Lock everything now │ │
│ └──────────────────────────┘  └─────────────────────┘ │
│ Guard: ON  last check 01:31  [ Stop ]   Questions: 0  │
│ [ Check-up ]  [ Reports ]                             │
└───────────────────────────────────────────────────────┘
```

1. Setup wizard: the `panic setup` steps as Next/Back dialogs, opening provider pages in the browser.
2. Home: accounts with their state, the PANIC button (with an "Are you sure?" dialog), the guard switch, last check time, open questions.
3. Questions: each open question with "It was me" and "Lock it down" and its deadline.
4. Check-up: the five questions and the Fix now / Unknown / Good list.
5. Reports: past press reports, newest first.

**Installer.** A `.dmg` with the `.app` (PyInstaller) and an Applications shortcut, built by a script in the repo. Unsigned: macOS shows an "unidentified developer" warning on first open; the download page and README explain how to allow it (System Settings, Privacy & Security, Open Anyway). Signing and notarisation can be added later without changing the app.

## Constraints and edge cases

- Saving the passphrase in the Keychain means anyone using the unlocked Mac can open the vault. The product page and README must say so, replacing the claim that a stolen laptop opens nothing, and say how to switch it off.
- The app must never show item contents for organisation accounts (same rule as the CLI).
- Closing the window keeps the guard running only if the user chooses "Keep guarding in the background"; quitting stops it and says so.
- No network service is opened by the app; the UI talks to Python in-process only.
- Windows is a later project (the engine uses Mac-only file locks and notifications); nothing here may make that harder.
- Commits authored by Riya Dadlani only.

## Left to the builder

Exact dialog wording, the app icon (a red button drawn in the XP style, original artwork), menu contents beyond the sketch, and the PyInstaller options.
