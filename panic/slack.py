"""Connector for a Slack workspace, driven by the owner's own app. What it can do depends on the plan."""
from collections.abc import Callable
from urllib.parse import quote, urlsplit

from panic.http import Api, ApiError
from panic.model import Account, Finding, Phase, Severity, Snapshot, Step, Tier, WatchPolicy
from panic.signals import TEXT

WEB, SCIM, AUDIT = "https://slack.com/api", "https://api.slack.com/scim/v1", "https://api.slack.com/audit/v1"
RELEASED = "Member reactivated."
PLANS = ("enterprise", "business", "pro", "free")
# Only these answers mean "this plan does not have it"; anything else during detection is a failure.
_NOT_ON_PLAN = {"paid_only", "not_allowed_token_type", "missing_scope", "feature_not_enabled"}
ALLOWS = {
    "enterprise": "can sign members out and deactivate them, and the guard reads Slack's audit log",
    "business": "can deactivate members, and the guard reports new sign-ins from the access log",
    "pro": "cannot lock members itself (guided steps only); the guard reports new sign-ins from the access log",
    "free": "cannot lock or read anything on this plan (guided steps only)",
}

F, P, A, G = Phase.FREEZE, Phase.PURGE, Tier.API, Tier.GUIDED
R, N = WatchPolicy.REAPPLY, WatchPolicy.NONE


def _absent(e: ApiError) -> bool:
    return e.status in (403, 404) or (e.status == 200 and e.body in _NOT_ON_PLAN)


def _obj(r, what: str) -> dict:
    if not isinstance(r, dict):
        raise ApiError(200, "", f"Slack {what}: unexpected response")
    return r


def _cursor_pages(fetch: Callable[[dict], dict], key: str, what: str) -> list:
    """Follows response_metadata.next_cursor; a missing list or a repeated cursor is an error, never 'no more'."""
    out, cursor, seen = [], None, set()
    while True:
        r = _obj(fetch({"limit": 200, **({"cursor": cursor} if cursor else {})}), what)
        if not isinstance(r.get(key), list):
            raise ApiError(200, "", f"Slack {what}: expected a list")
        out += r[key]
        meta = r.get("response_metadata")
        cursor = meta.get("next_cursor") if isinstance(meta, dict) else None
        if not cursor:
            return out
        if not isinstance(cursor, str) or cursor in seen:
            raise ApiError(200, "", f"Slack {what}: bad paging cursor")
        seen.add(cursor)


def _user_id(entry, field: str) -> str | None:
    side = entry.get(field) if isinstance(entry, dict) else None
    user = side.get("user") if isinstance(side, dict) else None
    return user.get("id") if isinstance(user, dict) else None


class Slack:
    provider = "slack"

    def __init__(self, cred: dict, web: Api | None = None, scim: Api | None = None, audit: Api | None = None):
        self._token = cred["token"]  # never printed, logged or put in a message
        self.plan, self.team = cred.get("plan", "free"), cred.get("team", "")
        self._users = {k.casefold(): v for k, v in cred.get("users", {}).items()}
        self.owner = cred.get("primary_owner", "")

        def headers() -> dict[str, str]:
            return {"Authorization": f"Bearer {self._token}"}
        self._web, self._scim, self._audit = (web or Api(WEB, headers), scim or Api(SCIM, headers),
                                              audit or Api(AUDIT, headers))

    # -- API plumbing --------------------------------------------------
    def _call(self, method: str, params: dict | None = None, body: dict | None = None) -> dict:
        """Slack reports failure as HTTP 200 with ok=false; that is raised like any other API failure."""
        r = (self._web.get(f"/{method}", params) if body is None else self._web.send("POST", f"/{method}", body))
        r = _obj(r, method)
        if r.get("ok") is not True:
            err = str(r.get("error") or "unknown")[:60]
            raise ApiError(200, err, f"Slack {method}: {err}")
        return r

    def _scim_get(self, path: str, params: dict | None = None) -> dict:
        return _obj(self._scim.get(path, params), "SCIM")

    def _audit_get(self, params: dict) -> dict:
        return _obj(self._audit.get("/logs", params), "audit log")

    # -- discovery -----------------------------------------------------
    def detect_plan(self) -> str:
        probes = (("enterprise", lambda: self._audit_get({"limit": 1})),
                  ("business", lambda: self._scim_get("/Users", {"count": 1})),
                  ("pro", lambda: self._call("team.accessLogs", {"count": 1})))
        for plan, probe in probes:
            try:
                probe()
                return plan
            except ApiError as e:
                if not _absent(e):
                    raise
        return "free"

    def workspace(self) -> str:
        host = urlsplit(str(self._call("auth.test").get("url") or "")).hostname or ""
        label, _, rest = host.partition(".")
        if not label or rest != "slack.com":
            raise ApiError(200, "", "Slack auth.test: unexpected workspace address")
        return label

    def _members(self) -> list[dict]:
        return _cursor_pages(lambda p: self._call("users.list", p), "members", "users.list")

    @staticmethod
    def _email(m) -> str | None:
        profile = m.get("profile") if isinstance(m, dict) else None
        email = profile.get("email") if isinstance(profile, dict) else None
        return email.casefold() if isinstance(email, str) and email else None

    def members(self) -> dict[str, str]:
        return {e: m["id"] for m in self._members()
                if not m.get("is_bot") and not m.get("deleted") and m.get("id") != "USLACKBOT"
                and (e := self._email(m))}

    def primary_owner(self) -> str:
        for m in self._members():
            if m.get("is_primary_owner") and self._email(m):
                return self._email(m)
        raise ValueError("could not find the primary owner's email; the token needs the users:read.email scope")

    def verify_admin(self) -> None:
        self._call("auth.test")

    def users(self) -> list[str]:
        return list(self._users)

    def _id(self, acct: str) -> str:
        key = acct.casefold()
        if key not in self._users:  # joined after arming
            self._users = {**self._users, **self.members()}
        if key not in self._users:
            raise ValueError(f"no Slack user id for {acct}")
        return self._users[key]

    def _active(self, acct: str) -> bool:
        a = self._scim_get(f"/Users/{quote(self._id(acct), safe='')}").get("active")
        if not isinstance(a, bool):
            raise ApiError(200, "", "Slack SCIM: no active flag")
        return a

    # -- catalogue and reads -------------------------------------------
    def catalog(self, account: Account) -> list[Step]:
        a, t = account.id, quote(self.team, safe="")
        apps = Step(a, "apps", P, G, "Review the installed apps and remove any you do not recognise",
                    f"https://{t}.slack.com/apps/manage")
        if self.plan in ("pro", "free"):
            return [Step(a, "deactivate", F, G, "Deactivate the member in the Slack admin page",
                         f"https://{t}.slack.com/admin", N), apps]
        deactivate = Step(a, "deactivate", F, A, "Deactivate the member", None, R)
        if self.plan == "enterprise":
            return [Step(a, "reset_sessions", F, A, "Sign the member out of every session"), deactivate, apps]
        return [deactivate, apps]

    def snapshot(self, account: Account) -> Snapshot:
        if self.plan in ("enterprise", "business"):
            return {"active": ["true" if self._active(account.id) else "false"]}
        return {}

    def events(self, account: Account, since: float) -> list[Finding]:
        self._refuse_owner(account.id)
        if self.plan == "free":
            return []
        uid = self._id(account.id)
        if self.plan == "enterprise":
            entries = _cursor_pages(lambda p: self._audit_get({**p, "action": "anomaly,user_logout_compromised",
                                                              "oldest": int(since)}), "entries", "audit log")
            hits = sorted({str(e.get("action") or "anomaly") for e in entries
                           if uid in (_user_id(e, "actor"), _user_id(e, "entity"))})
            return [Finding(account.id, "provider_flagged_login", Severity.TRIGGER,
                            TEXT["provider_flagged_login"], tuple(hits))] if hits else []
        ips, page = set(), 1
        while True:
            r = self._call("team.accessLogs", {"count": 1000, "page": page})
            logins, paging = r.get("logins"), r.get("paging")
            pages = paging.get("pages") if isinstance(paging, dict) else None
            if not isinstance(logins, list) or not isinstance(pages, int):
                raise ApiError(200, "", "Slack team.accessLogs: unexpected response")
            ips |= {str(e.get("ip")) for e in logins if isinstance(e, dict) and e.get("user_id") == uid
                    and isinstance(e.get("date_first"), (int, float)) and e["date_first"] > since}
            if page >= pages:
                break
            page += 1
        return [Finding(account.id, "new_access", Severity.NOTICE, TEXT["new_access"], (ip,)) for ip in sorted(ips)]

    # -- writes --------------------------------------------------------
    def _refuse_owner(self, account_id: str) -> None:
        if account_id.casefold() == self.owner.casefold():
            raise ValueError(f"refusing to act on the primary owner {account_id}")

    def _set_active(self, acct: str, active: bool) -> None:
        self._scim.send("PATCH", f"/Users/{quote(self._id(acct), safe='')}", {"active": active})

    def run(self, step: Step, baseline: Snapshot) -> None:
        a, act = step.account, step.action
        self._refuse_owner(a)
        if act == "reset_sessions":
            self._call("admin.users.session.reset", body={"user_id": self._id(a)})
        elif act == "deactivate":
            self._set_active(a, False)
        else:
            raise ValueError(f"unknown action {act}")

    def check(self, step: Step, baseline: Snapshot) -> bool | None:
        if step.action == "deactivate":
            return self._active(step.account) is False
        return None

    def release(self, account: Account) -> str:
        self._refuse_owner(account.id)
        if self.plan in ("pro", "free"):
            raise ValueError(f"this plan cannot reactivate members through the tool: use https://{quote(self.team, safe='')}.slack.com/admin")
        self._set_active(account.id, True)
        return RELEASED
