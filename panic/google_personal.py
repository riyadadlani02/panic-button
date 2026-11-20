"""Connector for an individual's own Gmail account."""
import threading
from pathlib import Path

import googleapiclient.discovery
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
import json

from panic import gmail_settings as gs
from panic.model import Account, Phase, Snapshot, Step, Tier, WatchPolicy

# Settings only: this scope cannot read mail content.
SCOPES = ["https://www.googleapis.com/auth/gmail.settings.basic"]

F, P, A, G = Phase.FREEZE, Phase.PURGE, Tier.API, Tier.GUIDED
R, REP, N = WatchPolicy.REAPPLY, WatchPolicy.REPORT, WatchPolicy.NONE
# (action, phase, tier, watch, lingers_s, link, title)
_CATALOG = [
    ("imap_pop", F, A, R, 0, None, "Turn off IMAP and POP access"),
    ("forwarding_off", F, G, REP, 0, "https://mail.google.com/mail/u/0/#settings/fwdandpop",
     "Turn off forwarding and remove every forwarding address"),
    ("sign_out", F, G, N, 3600, "https://myaccount.google.com/device-activity",
     "Sign out of every device you do not recognise, or all of them"),
    ("filters", P, A, R, 0, None, "Delete filters that were added without you"),
    ("revoke_apps", P, G, N, 3600, "https://myaccount.google.com/connections",
     "Remove every connected app except panic-button."),
    ("app_passwords", P, G, N, 0, "https://myaccount.google.com/apppasswords",
     "Delete every app password"),
    ("delegates", P, G, N, 0, "https://mail.google.com/mail/u/0/#settings/accounts",
     "Remove every delegate who can access your mail"),
    ("recovery", P, G, N, 0, "https://myaccount.google.com/security",
     "Check that your recovery phone and email are yours"),
    ("password", P, G, N, 0, "https://myaccount.google.com/signinoptions/password",
     "Change your password now. This disconnects panic-button; run "
     "`panic arm --personal <email> --reconnect` straight after so the 24-hour watch can continue."),
]
_TIER = {c[0]: c[2] for c in _CATALOG}


def authorize(client_secrets: Path) -> dict:
    creds = InstalledAppFlow.from_client_secrets_file(str(client_secrets), SCOPES).run_local_server(port=0)
    return json.loads(creds.to_json())


class Personal:
    provider = "google_personal"

    def __init__(self, tokens: dict[str, dict], build=googleapiclient.discovery.build):
        self._tokens, self._build = tokens, build
        self._local = threading.local()  # the Google HTTP client is not thread-safe

    def _svc(self, account_id: str):
        cache = self._local.__dict__.setdefault("svcs", {})
        if account_id not in cache:
            if account_id not in self._tokens:
                raise KeyError(f"no token for account {account_id}")
            creds = Credentials.from_authorized_user_info(self._tokens[account_id], SCOPES)
            cache[account_id] = self._build("gmail", "v1", credentials=creds, cache_discovery=False)
        return cache[account_id]

    def catalog(self, account: Account) -> list[Step]:
        return [Step(account.id, a, ph, t, title, link, w, l) for a, ph, t, w, l, link, title in _CATALOG]

    def snapshot(self, account: Account) -> Snapshot:
        svc = self._svc(account.id)
        return {"filters": gs.filters(svc), "forwarding": gs.forwarding(svc), "imap_pop": gs.imap_pop(svc)}

    @staticmethod
    def _known_filters(step: Step, baseline: Snapshot) -> list[str]:
        # A missing key must never mean "keep nothing": that would delete every filter.
        if "filters" not in baseline:
            raise KeyError(f"no baseline recorded for filters on {step.account}")
        return baseline["filters"]

    def run(self, step: Step, baseline: Snapshot) -> None:
        if _TIER[step.action] is Tier.GUIDED:
            raise NotImplementedError(f"{step.action} is a guided step")
        svc = self._svc(step.account)
        if step.action == "imap_pop":
            gs.disable_imap_pop(svc)
        else:
            gs.delete_filters_outside(svc, self._known_filters(step, baseline))

    def check(self, step: Step, baseline: Snapshot) -> bool | None:
        if step.action == "imap_pop":
            return gs.imap_pop(self._svc(step.account)) == []
        if step.action == "forwarding_off":
            return gs.forwarding(self._svc(step.account)) == []
        if step.action == "filters":
            keep = self._known_filters(step, baseline)
            return all(f in keep for f in gs.filters(self._svc(step.account)))
        return None
