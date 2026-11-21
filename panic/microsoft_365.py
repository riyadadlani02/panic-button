"""Connector for a Microsoft 365 tenant, driven by an app registration over Microsoft Graph."""
import json
import threading
from collections.abc import Callable
from datetime import datetime, timezone
from urllib.parse import quote

from panic import graph_mail
from panic.http import Api
from panic.model import Account, Finding, Phase, Severity, Snapshot, Step, Tier, WatchPolicy
from panic.signals import TEXT, drift

BASE = "https://graph.microsoft.com/v1.0"
EXCHANGE = "https://admin.exchange.microsoft.com/#/mailboxes"
ENTRA = "https://entra.microsoft.com/#view/Microsoft_AAD_UsersAndTenants/UserManagementMenuBlade/~/AllUsers"
RELEASED = "Sign-in restored. Reset the password in the Entra admin centre before telling the user."

F, P, A, G = Phase.FREEZE, Phase.PURGE, Tier.API, Tier.GUIDED
R, N = WatchPolicy.REAPPLY, WatchPolicy.NONE
# (action, phase, tier, watch, lingers_s, after_read, link, title)
_CATALOG = [
    ("disable", F, A, R, 0, False, None, "Block sign-in for the account"),
    ("sign_out", F, A, N, 3600, False, None, "Sign the user out of every session"),
    ("inbox_rules", P, A, R, 0, True, None, "Delete inbox rules added since the baseline"),
    ("consent_grants", P, A, R, 3600, False, None, "Revoke app consents added since the baseline"),
    ("mailbox_forwarding", P, G, N, 0, False, EXCHANGE,
     "This tool cannot read mailbox forwarding: check and turn it off in the Exchange admin centre"),
    ("delegates", P, G, N, 0, False, EXCHANGE,
     "This tool cannot read mailbox delegates: remove any you do not recognise in the Exchange admin centre"),
    ("password", P, G, N, 0, False, ENTRA, "Reset the password in the Entra admin centre"),
]
_RISKY_SCOPES = ("Mail.", "Files.", "full_access")


def _j(**fields) -> str:
    return json.dumps(fields, sort_keys=True)


def _msal_token(cred: dict) -> Callable[[], str]:
    lock, app = threading.Lock(), []

    def token() -> str:
        with lock:  # one app instance; msal serves repeat calls from its own cache
            if not app:
                import msal
                app.append(msal.ConfidentialClientApplication(
                    cred["client_id"], authority=f"https://login.microsoftonline.com/{cred['tenant']}",
                    client_credential=cred["client_secret"]))
            r = app[0].acquire_token_for_client(["https://graph.microsoft.com/.default"])
        if "access_token" not in r:
            raise RuntimeError(f"Microsoft sign-in failed: {r.get('error_description') or r.get('error') or 'unknown error'}")
        return r["access_token"]
    return token


class Microsoft365:
    provider = "microsoft_365"

    def __init__(self, cred: dict, api: Api | None = None, token: Callable[[], str] | None = None):
        self.admin, self._domains = cred["admin"], {d.casefold() for d in cred.get("domains", [])}
        token = token or _msal_token(cred)
        self._api = api or Api(BASE, lambda: {"Authorization": f"Bearer {token()}"})

    @staticmethod
    def _u(acct: str) -> str:
        return f"/users/{quote(acct, safe='@')}"

    def users(self) -> list[str]:
        return [u["userPrincipalName"] for u in graph_mail.pages(self._api, "/users", {"$select": "userPrincipalName", "$top": 999})]

    def domains(self) -> list[str]:
        return [d["id"] for d in graph_mail.pages(self._api, "/domains") if d.get("isVerified")]

    def verify_admin(self) -> None:
        u = self._api.get(self._u(self.admin), {"$select": "accountEnabled"}) or {}
        if u.get("accountEnabled") is not True:
            raise ValueError(f"{self.admin} does not exist or is disabled")

    def catalog(self, account: Account) -> list[Step]:
        return [Step(account.id, a, ph, t, title, link, w, ling, ar) for a, ph, t, w, ling, ar, link, title in _CATALOG]

    # -- reads ---------------------------------------------------------
    def _grants(self, acct: str) -> list[tuple[str, str]]:
        return [(g["id"], _j(clientId=g.get("clientId"), scope=g.get("scope")))
                for g in graph_mail.pages(self._api, f"{self._u(acct)}/oauth2PermissionGrants")]

    def snapshot(self, account: Account) -> Snapshot:
        a = account.id
        methods = graph_mail.pages(self._api, f"{self._u(a)}/authentication/methods")
        return {"inbox_rules": graph_mail.rules(self._api, a), "consent_grants": [g for _, g in self._grants(a)],
                "auth_methods": [f"{m['@odata.type']}:{m['id']}" for m in methods]}

    def signals(self, account: Account, snapshot: Snapshot, baseline: Snapshot) -> list[Finding]:
        self._refuse_admin(account.id)

        def classify(cat: str, item: str) -> str | None:
            if cat == "inbox_rules":
                return graph_mail.rule_code(item, self._domains)
            if cat == "auth_methods":
                return "auth_method_added"
            if cat == "consent_grants":
                try:
                    scope = str(json.loads(item).get("scope") or "")
                except (ValueError, AttributeError):
                    return None
                return "app_consent_added" if any(s in scope for s in _RISKY_SCOPES) else None
            return None
        return drift(account.id, baseline, snapshot, classify)

    def events(self, account: Account, since: float) -> list[Finding]:
        self._refuse_admin(account.id)
        when = datetime.fromtimestamp(since, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        who = account.id.replace("'", "''")
        found = graph_mail.pages(self._api, "/identityProtection/riskDetections", {
            "$filter": f"userPrincipalName eq '{who}' and detectedDateTime ge {when}"})
        return [Finding(account.id, "provider_flagged_login", Severity.TRIGGER, TEXT["provider_flagged_login"],
                        (str(d.get("riskEventType") or "risk detection"),))
                for d in found if d.get("riskLevel") == "high"]

    # -- writes --------------------------------------------------------
    @staticmethod
    def _known(step: Step, baseline: Snapshot, category: str) -> list[str]:
        # A missing key must never mean "keep nothing": that would delete everything.
        if category not in baseline:
            raise KeyError(f"no baseline recorded for {category} on {step.account}")
        return baseline[category]

    def _refuse_admin(self, account_id: str) -> None:
        if account_id.casefold() == self.admin.casefold():
            raise ValueError(f"refusing to act on the admin account {account_id}")

    def run(self, step: Step, baseline: Snapshot) -> None:
        a, act = step.account, step.action
        self._refuse_admin(a)
        if act == "disable":
            self._api.send("PATCH", self._u(a), {"accountEnabled": False})
        elif act == "sign_out":
            self._api.send("POST", f"{self._u(a)}/revokeSignInSessions")
        elif act == "inbox_rules":
            graph_mail.delete_rules_outside(self._api, a, self._known(step, baseline, act))
        elif act == "consent_grants":
            keep = self._known(step, baseline, act)
            for ident, item in self._grants(a):
                if item not in keep:
                    self._api.delete(f"/oauth2PermissionGrants/{quote(ident, safe='')}")
        else:
            raise ValueError(f"unknown action {act}")

    def check(self, step: Step, baseline: Snapshot) -> bool | None:
        a, act = step.account, step.action
        if act == "disable":
            return (self._api.get(self._u(a), {"$select": "accountEnabled"}) or {}).get("accountEnabled") is False
        if act == "inbox_rules":
            keep = self._known(step, baseline, act)
            return all(r in keep for r in graph_mail.rules(self._api, a))
        if act == "consent_grants":
            keep = self._known(step, baseline, act)
            return all(g in keep for _, g in self._grants(a))
        return None

    def release(self, account: Account) -> str:
        self._refuse_admin(account.id)
        self._api.send("PATCH", self._u(account.id), {"accountEnabled": True})
        return RELEASED
