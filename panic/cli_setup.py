"""`panic setup`: a guided walk through arming one account at a time. It only asks and explains; `arm` does the work."""
import os
import shlex
import sys
import webbrowser
from pathlib import Path

from panic import oauth
from panic.guided import grouped_services, load_services
from panic.oauth import GITHUB_SCOPES
from panic.session import CliError, _yes
from panic.vault import VaultError

DEFAULT_KEY = "~/panic.key"
ENTRA = "https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade"
# Services that sign in with an app the tool ships: (oauth_clients.json key, bare arm flag).
ONE_CLICK = {"gmail": ("google", "--personal"), "outlook": ("microsoft", "--microsoft-personal"), "github": ("github", "--github")}

# (key, menu label, steps, pages to open, fixed arm arguments, questions as (arm flag, prompt, kind))
SERVICES = [
    ("gmail", "Gmail (personal)", [
        "In Google Cloud Console create a project and enable the Gmail API.",
        "Configure the OAuth consent screen and add your own address as a test user.",
        'Create an OAuth client of type "Desktop app" and download its JSON file.',
        "Have printed backup codes or a security key ready: arming is refused without one.",
    ], ["https://console.cloud.google.com/apis/library/gmail.googleapis.com", "https://console.cloud.google.com/apis/credentials"],
     [], [("--personal", "Your Gmail address", "text"), ("--client-secrets", "Path to the downloaded client JSON file", "file")]),
    ("outlook", "Outlook.com or Hotmail (personal)", [
        "In Microsoft Entra create an app registration that accepts personal Microsoft accounts.",
        'Add a "Mobile and desktop" redirect to http://localhost and allow public client flows.',
        "Add the delegated permission MailboxSettings.ReadWrite only, then copy the application (client) id.",
    ], [ENTRA], [], [("--microsoft-personal", "Your Outlook.com or Hotmail address", "text"), ("--client-id", "Application (client) id", "text")]),
    ("github", "GitHub (your account or an organisation you own)", [
        "Create a classic personal access token (not fine-grained). The page opens with the scopes ticked.",
        "For an organisation also tick admin:org and admin:org_hook.",
        "Save the token alone in a text file. Delete that file once armed: the vault keeps a copy.",
    ], [f"https://github.com/settings/tokens/new?scopes={GITHUB_SCOPES}&description=panic-button"], [],
     [("--github", "Your GitHub login", "text"), ("--org", "Organisation to arm instead of your own account (Enter for none)", "optional"),
      ("--token-file", "Path to the token file", "file")]),
    ("workspace", "Google Workspace (whole domain, admin only)", [
        "Create a service account, enable domain-wide delegation and download its JSON key.",
        "In the Admin console authorise its client ID for the scopes listed in the README (Setup: Google Workspace).",
        "Choose a dedicated break-glass super admin. The tool acts as it and never locks it.",
        "Delete the JSON key once armed: it is a tenant-wide key and the vault keeps a copy.",
    ], ["https://console.cloud.google.com/iam-admin/serviceaccounts", "https://admin.google.com/ac/owl/domainwidedelegation"],
     ["--workspace"], [("--sa-key", "Path to the service-account JSON key", "file"), ("--admin", "Break-glass admin address", "text"),
                       ("--domain", "Domain (for example example.com)", "text")]),
    ("m365", "Microsoft 365 (whole tenant, admin only)", [
        "In the Entra admin centre create an app registration in your tenant and add a client secret.",
        "Save the secret alone in a text file. Delete that file once armed.",
        "Add the Microsoft Graph application permissions listed in the README (Setup: Microsoft 365 tenant) and grant admin consent.",
        "Choose a break-glass admin. It is protected and never locked.",
    ], [ENTRA], [], [("--microsoft-tenant", "Tenant (id or domain)", "text"), ("--client-id", "Application (client) id", "text"),
                     ("--client-secret-file", "Path to the client secret file", "file"), ("--admin", "Break-glass admin address", "text")]),
    ("slack", "Slack (whole workspace, primary owner only)", [
        "Create your own Slack app in the workspace and install it as the primary owner.",
        "Give it the scopes listed in the README (Setup: Slack). Locking members needs Business+ or Enterprise Grid.",
        "Save its token alone in a text file. Delete that file once armed.",
    ], ["https://api.slack.com/apps"], ["--slack"], [("--token-file", "Path to the token file", "file")]),
    ("other", "Another service (a checklist of links; nothing is read)", [], [], [],
     [("--guided", "Which service (" + grouped_services() + ")", "text"), ("--id", "Your login there", "text")]),
]


def _clean(path: str) -> str:
    """A path as typed or dragged into the terminal: quotes and escaped spaces removed."""
    path = path.strip()
    if len(path) > 1 and path[0] == path[-1] and path[0] in "'\"":
        path = path[1:-1]
    return path.replace("\\ ", " ")


def _ask(prompt: str, kind: str) -> str:
    while True:
        value = _clean(input(f"{prompt}: "))
        if not value:
            if kind == "optional":
                return ""
            raise CliError("Nothing entered; this account was not set up.")
        if kind != "file" or Path(value).expanduser().is_file():
            return value
        print(f"No file at {value}. Try again, or press Enter to stop.")


def collect(key: str, opener) -> list[str]:
    """Explain one service, then ask its questions. Returns the arguments for `panic arm`."""
    _, label, steps, pages, fixed, questions = next(s for s in SERVICES if s[0] == key)
    print(f"\n{label}")
    if key in ONE_CLICK and oauth.builtin(ONE_CLICK[key][0]):
        print("  Your browser will open. Sign in and click Allow.")
        return [ONE_CLICK[key][1]]
    for i, step in enumerate(steps, 1):
        print(f"  {i}. {step}")
    if pages:
        print("\n".join(f"  {p}" for p in pages))
        if _yes("Open " + ("this page" if len(pages) == 1 else "these pages") + " in your browser?"):
            for p in pages:
                opener(p)
        input("Press Enter when you have finished these steps. ")
    argv = list(fixed)
    for flag, prompt, kind in questions:
        value = _ask(prompt, kind)
        if value:
            argv += [flag, value]
    if key == "other" and argv[1].lower() not in load_services():
        raise CliError(f"{argv[1]} is not in the catalogue. Add it with your own links: "
                       "panic arm --guided KEY --id LOGIN --name NAME --link password=https://...")
    return argv


def _choose() -> str:
    print("\nWhich account do you want to protect?")
    for i, (_, label, *_rest) in enumerate(SERVICES, 1):
        print(f"  {i}. {label}")
    while True:
        pick = input(f"Number [1-{len(SERVICES)}]: ").strip()
        if pick.isdigit() and 1 <= int(pick) <= len(SERVICES):
            return SERVICES[int(pick) - 1][0]


def run(a, parser) -> int:
    key = a.keyfile or os.environ.get("PANIC_KEYFILE")
    if not key:
        print("The key file is the second half of the lock on your vault. Keep it on a USB stick, not on this computer.")
        key = _clean(input(f"Where should the key file live? [{DEFAULT_KEY}] ")) or DEFAULT_KEY
    opener, armed = getattr(a, "open_url", None) or webbrowser.open, False
    while True:
        try:
            arm = ["arm", *collect(_choose(), opener)]
            print("\nThe same thing as a command: panic " + shlex.join(["--keyfile", key, *arm]))
            b = parser.parse_args(["--vault", a.vault, "--keyfile", key, *arm])
            for k, v in vars(a).items():  # the pieces main() injects (connectors, sign-in, notifier)
                if not hasattr(b, k):
                    setattr(b, k, v)
            armed |= b.fn(b) == 0
        except (CliError, VaultError) as e:
            print(f"error: {e}", file=sys.stderr)
        if not _yes("\nSet up another account?"):
            break
    if armed:
        k = shlex.join(["--keyfile", key])
        print(f"\nNext:\n  panic {k} rehearse   check every account against what you approved"
              f"\n  panic {k} guard      leave this running; it presses by itself when an account looks taken over"
              f"\n  panic {k} press --all --dry-run   see what a press would do, changing nothing")
    return 0 if armed else 1
