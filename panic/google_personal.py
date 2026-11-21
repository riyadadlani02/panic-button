"""Connector for an individual's own Gmail account."""
import threading
from urllib.parse import quote

import googleapiclient.discovery
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
import json

from panic import gmail_settings as gs
from panic.model import Account, Finding, Phase, Snapshot, Step, Tier, WatchPolicy
from panic.signals import drift, gmail_rule_code

# Settings only: this scope cannot read mail content.
SCOPES = ["https://www.googleapis.com/auth/gmail.settings.basic"]

F, P, A, G = Phase.FREEZE, Phase.PURGE, Tier.API, Tier.GUIDED
R, REP, N = WatchPolicy.REAPPLY, WatchPolicy.REPORT, WatchPolicy.NONE
# (action, phase, tier, watch, lingers_s, link, title)
# Links carry the account: with several Google accounts signed in, a bare link opens the first one.
# Personal Gmail has no IMAP switch (IMAP is always on), so only POP is read and turned off.
_CATALOG = [
    ("imap_pop", F, A, R, 0, None, "Turn off POP access"),
    ("forwarding_off", F, G, REP, 0, "https://mail.google.com/mail/?authuser={email}#settings/fwdandpop",
     "Turn off forwarding and remove every forwarding address"),
    ("sign_out", F, G, N, 3600, "https://myaccount.google.com/device-activity?authuser={email}",
     "Sign out of every device you do not recognise, or all of them"),
    ("filters", P, A, R, 0, None, "Delete filters that were added without you"),
    ("revoke_apps", P, G, N, 3600, "https://myaccount.google.com/connections?authuser={email}",
     "Remove every connected app except panic-button."),
    ("app_passwords", P, G, N, 0, "https://myaccount.google.com/apppasswords?authuser={email}",
     "Delete every app password"),
    ("delegates", P, G, N, 0, "https://mail.google.com/mail/?authuser={email}#settings/accounts",
     "Remove every delegate who can access your mail"),
    ("recovery", P, G, N, 0, "https://myaccount.google.com/security?authuser={email}",
     "Check that your recovery phone and email are yours"),
    ("password", P, G, N, 0, "https://myaccount.google.com/signinoptions/password?authuser={email}",
     "Change your password now. This disconnects panic-button; run "
     "`panic arm --personal <email> --reconnect` straight after so the 24-hour watch can continue."),
]
_TIER = {c[0]: c[2] for c in _CATALOG}
_AFTER_READ = {"imap_pop"}  # turning it off erases the POP state the first read records


def authorize(client_config: dict, login_hint: str | None = None) -> dict:
    hint = {"login_hint": login_hint} if login_hint else {}
    creds = InstalledAppFlow.from_client_config(client_config, SCOPES).run_local_server(port=0, **hint)
    return json.loads(creds.to_json())


def signed_in_address(token_info: dict, build=googleapiclient.discovery.build) -> str:
    # The chooser lets the owner pick any account; the primary send-as address says which one it was.
    creds = Credentials.from_authorized_user_info(token_info, SCOPES)
    svc = build("gmail", "v1", credentials=creds, cache_discovery=False)
    for s in svc.users().settings().sendAs().list(userId="me").execute().get("sendAs", []):
        if s.get("isPrimary"):
            return s["sendAsEmail"]
    raise ValueError("the signed-in account has no primary address")


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
        email = quote(account.id, safe="@")
        return [Step(account.id, a, ph, t, title, link and link.format(email=email), w, l, a in _AFTER_READ)
                for a, ph, t, w, l, link, title in _CATALOG]

    def snapshot(self, account: Account) -> Snapshot:
        svc = self._svc(account.id)
        return {"filters": gs.filters(svc), "forwarding": gs.forwarding(svc),
                "forwarding_addresses": gs.forwarding_addresses(svc), "imap_pop": gs.imap_pop(svc, imap=False)}

    def signals(self, account: Account, snapshot: Snapshot, baseline: Snapshot) -> list[Finding]:
        def classify(cat: str, item: str) -> str | None:
            if cat == "filters":
                return gmail_rule_code(item, None)
            return {"forwarding": "forwarding_added", "forwarding_addresses": "forwarding_added",
                    "imap_pop": "pop_enabled"}.get(cat)
        return drift(account.id, baseline, snapshot, classify)

    @staticmethod
    def _known(step: Step, baseline: Snapshot, category: str) -> list[str]:
        # A missing key must never mean "keep nothing": that would delete every filter.
        if category not in baseline:
            raise KeyError(f"no baseline recorded for {category} on {step.account}")
        return baseline[category]

    def run(self, step: Step, baseline: Snapshot) -> None:
        if _TIER[step.action] is Tier.GUIDED:
            raise NotImplementedError(f"{step.action} is a guided step")
        svc = self._svc(step.account)
        if step.action == "imap_pop":
            gs.disable_imap_pop(svc, imap=False)
        else:
            gs.delete_filters_outside(svc, self._known(step, baseline, "filters"))

    def check(self, step: Step, baseline: Snapshot) -> bool | None:
        if step.action == "imap_pop":
            return gs.imap_pop(self._svc(step.account), imap=False) == []
        if step.action == "forwarding_off":  # the title promises every address is gone, so both are read
            keep = self._known(step, baseline, "forwarding_addresses")
            svc = self._svc(step.account)
            return gs.forwarding(svc) == [] and all(a in keep for a in gs.forwarding_addresses(svc))
        if step.action == "filters":
            keep = self._known(step, baseline, "filters")
            return all(f in keep for f in gs.filters(self._svc(step.account)))
        return None
