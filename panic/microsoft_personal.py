"""Connector for an individual's own Outlook.com / Hotmail account, signed in by the owner."""
import sys
import threading
from collections.abc import Callable

from panic import graph_mail
from panic.checkup import Check
from panic.http import Api
from panic.model import Account, Finding, Phase, Snapshot, Step, Tier, WatchPolicy
from panic.signals import drift

BASE = "https://graph.microsoft.com/v1.0"
AUTHORITY = "https://login.microsoftonline.com/consumers"
# Settings only: this scope cannot read mail content.
SCOPES = ["MailboxSettings.ReadWrite"]
EXPIRED = "sign-in expired; run panic arm --microsoft-personal <email> --reconnect"

F, P, A, G = Phase.FREEZE, Phase.PURGE, Tier.API, Tier.GUIDED
R, N = WatchPolicy.REAPPLY, WatchPolicy.NONE
# (action, phase, tier, watch, lingers_s, link, title)
# A personal account cannot be named in these links; every one is unverified until opened in a browser.
_CATALOG = [
    ("inbox_rules", P, A, R, 0, None, "Delete inbox rules added since the baseline"),
    ("forwarding", F, G, N, 0, "https://outlook.live.com/mail/0/options/mail/forwarding",
     "Turn off forwarding"),
    ("sign_out", F, G, N, 3600, "https://account.microsoft.com/security",
     "Sign out of every device you do not recognise"),
    ("activity", P, G, N, 0, "https://account.live.com/Activity", "Review recent sign-in activity"),
    ("apps", P, G, N, 3600, "https://account.live.com/consent/Manage",
     "Remove every connected app except panic-button"),
    ("security_info", P, G, N, 0, "https://account.live.com/proofs/manage",
     "Check that your recovery phone and email are yours"),
    ("password", P, G, N, 0, "https://account.live.com/password/change",
     "Change your password now. This disconnects panic-button; run "
     "`panic arm --microsoft-personal <email> --reconnect` straight after so the 24-hour watch can continue."),
]
_TIER = {c[0]: c[2] for c in _CATALOG}


def authorize(client_id: str, login_hint: str | None = None) -> dict:
    import msal
    cache = msal.SerializableTokenCache()
    app = msal.PublicClientApplication(client_id, authority=AUTHORITY, token_cache=cache)
    r = app.acquire_token_interactive(SCOPES, login_hint=login_hint)
    if "access_token" not in r:
        raise RuntimeError(r.get("error_description") or r.get("error") or "unknown error")
    return {"client_id": client_id, "cache": cache.serialize(),
            "username": (r.get("id_token_claims") or {}).get("preferred_username", "")}


class MicrosoftPersonal:
    provider = "microsoft_personal"

    def __init__(self, tokens: dict[str, dict], api: Api | None = None, token: Callable[[str], str] | None = None,
                 on_refresh: Callable[[str, dict], None] | None = None):
        self._tokens, self._on_refresh, self._shared_api = dict(tokens), on_refresh, api
        self._lock, self._apis, self._dirty = threading.Lock(), {}, set()  # dirty: rotated but not yet saved
        self._token = token or self._silent

    def _silent(self, account_id: str) -> str:
        with self._lock:  # msal's cache is not thread-safe, and a rotation must be saved once
            if account_id not in self._tokens:
                raise KeyError(f"no token for account {account_id}")
            import msal
            tok = self._tokens[account_id]
            cache = msal.SerializableTokenCache()
            cache.deserialize(tok["cache"])
            app = msal.PublicClientApplication(tok["client_id"], authority=AUTHORITY, token_cache=cache)
            known = app.get_accounts()
            r = app.acquire_token_silent(SCOPES, account=known[0]) if known else None
            if cache.has_state_changed:  # msal rotates refresh tokens: a stale stored cache would stop working
                self._tokens[account_id] = {**tok, "cache": cache.serialize()}
                self._dirty.add(account_id)
            if account_id in self._dirty and self._on_refresh:
                try:  # a failed save must not throw away a valid token; the next call retries it
                    self._on_refresh(account_id, self._tokens[account_id])
                    self._dirty.discard(account_id)
                except Exception as e:
                    print(f"Warning: could not save the refreshed sign-in for {account_id}: "
                          f"{type(e).__name__}: {e}", file=sys.stderr)
        if not r or "access_token" not in r:
            raise RuntimeError(EXPIRED)
        return r["access_token"]

    def _api_for(self, account_id: str) -> Api:
        if self._shared_api:
            return self._shared_api
        if account_id not in self._apis:  # the token is per account, the Api's header callable takes none
            self._apis[account_id] = Api(BASE, lambda: {"Authorization": f"Bearer {self._token(account_id)}"})
        return self._apis[account_id]

    def catalog(self, account: Account) -> list[Step]:
        return [Step(account.id, a, ph, t, title + ("" if t is A else " (link not verified)"), link, w, l)
                for a, ph, t, w, l, link, title in _CATALOG]

    def snapshot(self, account: Account) -> Snapshot:
        return {"inbox_rules": graph_mail.rules(self._api_for(account.id), "me")}

    def posture(self, account: Account) -> list[Check]:
        a = account.id
        fwd = any(graph_mail.rule_code(r, None) == "rule_forwards_outside" for r in graph_mail.rules(self._api_for(a), "me"))
        rules = (Check(a, "forwarding_rules", "fix", "An inbox rule forwards your mail",
                       "https://outlook.live.com/mail/0/options/mail/rules") if fwd
                 else Check(a, "forwarding_rules", "good", "No inbox rule forwards your mail"))
        return [rules, Check(a, "forwarding", "unknown", "This tool cannot read automatic forwarding: check it is off",
                             "https://outlook.live.com/mail/0/options/mail/forwarding")]

    def signals(self, account: Account, snapshot: Snapshot, baseline: Snapshot) -> list[Finding]:
        return drift(account.id, baseline, snapshot,
                     lambda cat, item: graph_mail.rule_code(item, None) if cat == "inbox_rules" else None)

    @staticmethod
    def _known(step: Step, baseline: Snapshot, category: str) -> list[str]:
        # A missing key must never mean "keep nothing": that would delete every rule.
        if category not in baseline:
            raise KeyError(f"no baseline recorded for {category} on {step.account}")
        return baseline[category]

    def run(self, step: Step, baseline: Snapshot) -> None:
        if _TIER[step.action] is Tier.GUIDED:
            raise NotImplementedError(f"{step.action} is a guided step")
        graph_mail.delete_rules_outside(self._api_for(step.account), "me", self._known(step, baseline, "inbox_rules"))

    def check(self, step: Step, baseline: Snapshot) -> bool | None:
        if step.action == "inbox_rules":
            keep = self._known(step, baseline, "inbox_rules")
            return all(r in keep for r in graph_mail.rules(self._api_for(step.account), "me"))
        return None
