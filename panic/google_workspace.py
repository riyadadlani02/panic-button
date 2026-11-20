"""Connector for Google Workspace accounts, driven by a domain-wide-delegation service account."""
# Admin SDK Directory API v1 reference, confirmed for each call used here:
#   users.update (PUT, suspended/password/changePasswordAtNextLogin/recoveryEmail/recoveryPhone):
#     https://developers.google.com/workspace/admin/directory/reference/rest/v1/users
#     https://developers.google.com/workspace/admin/directory/reference/rest/v1/users/update
#   tokens.list / tokens.delete (clientId):
#     https://developers.google.com/workspace/admin/directory/reference/rest/v1/tokens/list
#     https://developers.google.com/workspace/admin/directory/reference/rest/v1/tokens/delete
#   asps.list / asps.delete (codeId):
#     https://developers.google.com/workspace/admin/directory/reference/rest/v1/asps/list
#     https://developers.google.com/workspace/admin/directory/reference/rest/v1/asps/delete
#   verificationCodes.invalidate:
#     https://developers.google.com/workspace/admin/directory/reference/rest/v1/verificationCodes/invalidate
import secrets
import threading
import time

import googleapiclient.discovery
from google.oauth2 import service_account
from googleapiclient.errors import HttpError

from panic import gmail_settings as gs
from panic.model import Account, Phase, Snapshot, Step, Tier, WatchPolicy

_AUTH = "https://www.googleapis.com/auth/"
# Settings and directory only: none of these can read mail content.
SCOPES = [_AUTH + s for s in ("admin.directory.user", "admin.directory.user.security",
                              "gmail.settings.basic", "gmail.settings.sharing")]

F, P = Phase.FREEZE, Phase.PURGE
R, REP, N = WatchPolicy.REAPPLY, WatchPolicy.REPORT, WatchPolicy.NONE
# (action, phase, watch, lingers_s, title)
_CATALOG = [
    ("suspend", F, R, 0, "Suspend the account"),
    ("sign_out", F, N, 3600, "Sign the user out of every session"),
    ("forwarding_off", F, R, 0, "Turn off automatic forwarding"),
    ("revoke_apps", P, REP, 3600, "Revoke every app's access"),
    ("app_passwords", P, REP, 0, "Delete every app password"),
    ("backup_codes", P, N, 0, "Invalidate backup codes"),
    ("forwarding_addresses", P, R, 0, "Remove forwarding addresses outside the domain or baseline"),
    ("delegates", P, R, 0, "Remove every mailbox delegate"),
    ("filters", P, R, 0, "Delete filters added since the baseline"),
    ("imap_pop", P, R, 0, "Turn off IMAP and POP"),
    ("recovery", P, R, 0, "Restore recovery email and phone to the baseline"),
    ("reset_password", P, N, 0, "Set a random password and force a change"),
]
_AFTER_READ = {"forwarding_off"}  # turning it off erases the forwarding address the first read records


class Workspace:
    provider = "google_workspace"

    def __init__(self, sa_info: dict, admin: str, domain: str,
                 build=googleapiclient.discovery.build, sleep=time.sleep):
        self._sa, self.admin, self.domain = sa_info, admin, domain
        self._build, self._sleep = build, sleep
        self._local = threading.local()  # the Google HTTP client is not thread-safe

    def _svc(self, api: str, subject: str):
        cache = self._local.__dict__.setdefault("svcs", {})
        if (api, subject) not in cache:
            creds = service_account.Credentials.from_service_account_info(self._sa, scopes=SCOPES, subject=subject)
            name, version = ("admin", "directory_v1") if api == "admin" else ("gmail", "v1")
            cache[(api, subject)] = self._build(name, version, credentials=creds, cache_discovery=False)
        return cache[(api, subject)]

    def _dir(self):
        return self._svc("admin", self.admin)

    def _gmail(self, account: str):
        return self._svc("gmail", account)

    def _call(self, request, gone_ok: bool = False):
        for attempt in range(4):
            try:
                return request.execute()
            except HttpError as e:
                status = e.resp.status
                if gone_ok and status == 404:
                    return None
                if not (status == 429 or status >= 500) or attempt == 3:
                    raise
                self._sleep(2 ** attempt)

    def users(self) -> list[str]:
        out, kw = [], {"domain": self.domain, "maxResults": 500}
        while True:
            r = self._call(self._dir().users().list(**kw))
            out += [u["primaryEmail"] for u in r.get("users", [])]
            if not r.get("nextPageToken"):
                return out
            kw["pageToken"] = r["nextPageToken"]

    def verify_admin(self) -> None:
        # An alias would leave the real primary address unprotected, and only a super admin can act for all users.
        u = self._call(self._dir().users().get(userKey=self.admin))
        if str(u.get("primaryEmail", "")).casefold() != self.admin.casefold() or u.get("isAdmin") is not True:
            raise ValueError(f"{self.admin} is not the primary address of a super admin")

    def catalog(self, account: Account) -> list[Step]:
        return [Step(account.id, a, ph, Tier.API, title, None, w, l, a in _AFTER_READ) for a, ph, w, l, title in _CATALOG]

    # -- reads ---------------------------------------------------------
    def _recovery(self, acct: str) -> list[str]:
        u = self._call(self._dir().users().get(userKey=acct))
        return [f"{k}:{u[f]}" for k, f in (("email", "recoveryEmail"), ("phone", "recoveryPhone")) if u.get(f)]

    def _items(self, request, key: str, field: str) -> list[str]:
        return [str(i[field]) for i in (self._call(request) or {}).get(key, [])]

    def _tokens(self, acct):
        return self._items(self._dir().tokens().list(userKey=acct), "items", "clientId")

    def _asps(self, acct):
        return self._items(self._dir().asps().list(userKey=acct), "items", "codeId")

    def _fwd_addrs(self, acct):
        return self._items(self._gmail(acct).users().settings().forwardingAddresses().list(userId="me"),
                           "forwardingAddresses", "forwardingEmail")

    def _delegates(self, acct):
        return self._items(self._gmail(acct).users().settings().delegates().list(userId="me"),
                           "delegates", "delegateEmail")

    def snapshot(self, account: Account) -> Snapshot:
        a = account.id
        g = self._gmail(a)
        return {"forwarding": gs.forwarding(g), "forwarding_addresses": self._fwd_addrs(a),
                "delegates": self._delegates(a), "filters": gs.filters(g), "imap_pop": gs.imap_pop(g),
                "recovery": self._recovery(a), "apps": self._tokens(a), "app_passwords": self._asps(a)}

    # -- writes --------------------------------------------------------
    @staticmethod
    def _known(step: Step, baseline: Snapshot, category: str) -> list[str]:
        # A missing key must never mean "keep nothing": that would delete everything.
        if category not in baseline:
            raise KeyError(f"no baseline recorded for {category} on {step.account}")
        return baseline[category]

    def _outside_domain(self, addr: str) -> bool:
        return not addr.lower().endswith("@" + self.domain.lower())

    def _update(self, acct: str, body: dict):
        self._call(self._dir().users().update(userKey=acct, body=body))

    def _refuse_admin(self, account_id: str) -> None:
        # Break-glass: second guard behind the engine. Addresses ignore case.
        if account_id.casefold() == self.admin.casefold():
            raise ValueError(f"refusing to act on the admin account {account_id}")

    def run(self, step: Step, baseline: Snapshot) -> None:
        a, act = step.account, step.action
        self._refuse_admin(a)
        d = self._dir()
        if act == "suspend":
            self._update(a, {"suspended": True})
        elif act == "sign_out":
            self._call(d.users().signOut(userKey=a))
        elif act == "forwarding_off":
            self._call(self._gmail(a).users().settings().updateAutoForwarding(
                userId="me", body={"enabled": False}))
        elif act == "revoke_apps":
            for c in self._tokens(a):
                self._call(d.tokens().delete(userKey=a, clientId=c), gone_ok=True)
        elif act == "app_passwords":
            for c in self._asps(a):
                self._call(d.asps().delete(userKey=a, codeId=c), gone_ok=True)
        elif act == "backup_codes":
            self._call(d.verificationCodes().invalidate(userKey=a))
        elif act == "forwarding_addresses":
            addrs = self._fwd_addrs(a)
            for x in addrs:  # outsiders go whether or not they were baselined
                if self._outside_domain(x):
                    self._del_fwd(a, x)
            keep = self._known(step, baseline, act)
            for x in addrs:
                if x not in keep and not self._outside_domain(x):
                    self._del_fwd(a, x)
        elif act == "delegates":
            for x in self._delegates(a):
                self._call(self._gmail(a).users().settings().delegates().delete(
                    userId="me", delegateEmail=x), gone_ok=True)
        elif act == "filters":
            gs.delete_filters_outside(self._gmail(a), self._known(step, baseline, act), call=self._call)
        elif act == "imap_pop":
            gs.disable_imap_pop(self._gmail(a))
        elif act == "recovery":
            known = {i.split(":", 1)[0]: i.split(":", 1)[1] for i in self._known(step, baseline, act)}
            self._update(a, {"recoveryEmail": known.get("email", ""), "recoveryPhone": known.get("phone", "")})
        elif act == "reset_password":  # the value is never kept: nobody should know it
            self._update(a, {"password": secrets.token_urlsafe(32), "changePasswordAtNextLogin": True})
        else:
            raise ValueError(f"unknown action {act}")

    def _del_fwd(self, acct: str, addr: str):
        self._call(self._gmail(acct).users().settings().forwardingAddresses().delete(
            userId="me", forwardingEmail=addr), gone_ok=True)

    def check(self, step: Step, baseline: Snapshot) -> bool | None:
        a, act = step.account, step.action
        if act == "suspend":
            return self._call(self._dir().users().get(userKey=a)).get("suspended") is True
        if act == "forwarding_off":
            return gs.forwarding(self._gmail(a)) == []
        if act == "revoke_apps":
            return self._tokens(a) == []
        if act == "app_passwords":
            return self._asps(a) == []
        if act == "forwarding_addresses":
            keep = self._known(step, baseline, act)
            return all(x in keep and not self._outside_domain(x) for x in self._fwd_addrs(a))
        if act == "delegates":
            return self._delegates(a) == []
        if act == "filters":
            keep = self._known(step, baseline, act)
            return all(f in keep for f in gs.filters(self._gmail(a)))
        if act == "imap_pop":
            return gs.imap_pop(self._gmail(a)) == []
        if act == "recovery":
            return sorted(self._recovery(a)) == sorted(self._known(step, baseline, act))
        return None

    def release(self, account: Account) -> str:
        self._refuse_admin(account.id)
        pw = secrets.token_urlsafe(32)
        self._update(account.id, {"suspended": False, "password": pw, "changePasswordAtNextLogin": True})
        return pw
