"""In-memory stand-ins for the providers, so the real connectors run with no account and no network.

Each stand-in holds one account's (or tenant's) state and answers exactly the calls its connector makes, the
way the provider documents them; anything else raises. The plain methods (add_ssh_key, add_inbox_rule, ...)
are how the demo plays the intruder or the owner. describe() is the state in words, for people.
"""
import itertools
import time
from types import SimpleNamespace as NS
from urllib.parse import unquote

from googleapiclient.errors import HttpError

from panic.http import ApiError

_ids = itertools.count(101)


def _not_found(what: str):
    raise ApiError(404, "", f"{what}: HTTP 404")


def _drop(items: list, match) -> bool:
    """Removes the first item that matches; False when there was none."""
    for i, x in enumerate(items):
        if match(x):
            del items[i]
            return True
    return False


# -- GitHub --------------------------------------------------------------

class GitHubLab:
    """A personal GitHub account over the REST API (classic token)."""

    def __init__(self, login: str, primary_email: str):
        self.login = login
        self.keys, self.signing_keys, self.gpg_keys = [], [], []
        self.emails = [{"email": primary_email, "primary": True}]
        self.repos: dict[int, dict] = {}  # by id: a rename changes full_name only

    # the owner and the intruder
    def add_ssh_key(self, title: str) -> None:
        self.keys.append({"id": next(_ids), "key": f"ssh-ed25519 AAAAC3{title}", "title": title})

    def add_repo(self, name: str) -> str:
        full = f"{self.login}/{name}"
        self.repos[next(_ids)] = {"full_name": full, "keys": [], "hooks": [], "collaborators": [self.login],
                                  "invitations": []}
        return full

    def add_deploy_key(self, repo: str, title: str) -> None:
        self._repo(repo)["keys"].append({"id": next(_ids), "key": f"ssh-ed25519 AAAAD3{title}", "title": title})

    def add_collaborator(self, repo: str, login: str) -> None:
        self._repo(repo)["collaborators"].append(login)

    def rename_repo(self, repo: str, new_name: str) -> str:
        r = self._repo(repo)
        r["full_name"] = f"{self.login}/{new_name}"
        return r["full_name"]

    def describe(self, account: str = "") -> dict[str, list[str]]:
        repos = sorted(self.repos.values(), key=lambda r: r["full_name"])
        return {
            "SSH keys": [k["title"] for k in self.keys],
            "Email addresses": [e["email"] + (" (primary)" if e.get("primary") else "") for e in self.emails],
            "Repositories": [r["full_name"] for r in repos],
            "Deploy keys": [f"{r['full_name']}: {k['title']}" for r in repos for k in r["keys"]],
            "Collaborators": [f"{r['full_name']}: {c}" for r in repos for c in r["collaborators"] if c != self.login],
        }

    # the API the connector calls
    def _repo(self, full: str) -> dict:
        return next((r for r in self.repos.values() if r["full_name"] == full), None) or _not_found(f"/repos/{full}")

    def _repo_path(self, path: str) -> tuple[dict, str, str | None]:
        parts = path.strip("/").split("/")  # repos, owner, name, kind[, id or login]
        if len(parts) < 4 or parts[0] != "repos":
            _not_found(path)
        return self._repo(unquote(f"{parts[1]}/{parts[2]}")), parts[3], unquote(parts[4]) if len(parts) > 4 else None

    def get(self, path: str, params=None):
        return {"login": self.login} if path == "/user" else _not_found(path)

    def pages(self, path: str, params=None) -> list:
        own = {"/user/keys": self.keys, "/user/ssh_signing_keys": self.signing_keys, "/user/gpg_keys": self.gpg_keys,
               "/user/emails": self.emails}
        if path in own:
            return [dict(x) for x in own[path]]
        if path == "/user/repos":
            return [{"id": i, "full_name": r["full_name"]} for i, r in self.repos.items()]
        repo, kind, _ = self._repo_path(path)
        if kind == "collaborators":  # GitHub lists the owner as a collaborator of their own repository
            return [{"login": c} for c in repo["collaborators"]]
        return [dict(x) for x in repo[kind]] if kind in ("keys", "hooks", "invitations") else _not_found(path)

    def delete(self, path: str, gone_ok: bool = True) -> None:
        own = {"/user/keys/": self.keys, "/user/ssh_signing_keys/": self.signing_keys, "/user/gpg_keys/": self.gpg_keys}
        prefix = next((p for p in own if path.startswith(p)), None)
        if prefix:
            found = _drop(own[prefix], lambda k: str(k["id"]) == path.removeprefix(prefix))
        else:
            repo, kind, ident = self._repo_path(path)
            if kind == "collaborators":
                found = _drop(repo["collaborators"], lambda c: c == ident)
            else:
                found = _drop(repo.get(kind, []), lambda x: str(x["id"]) == ident)
        if not found and not gone_ok:
            _not_found(path)

    def send(self, method: str, path: str, body=None):
        if (method, path) != ("DELETE", "/user/emails"):
            _not_found(path)
        for addr in body["emails"]:  # the primary address cannot be deleted
            _drop(self.emails, lambda e: e["email"] == addr and not e.get("primary"))


# -- Microsoft Graph inbox rules (shared) ----------------------------------

def _rule(name: str, forward_to: str | None, move_to: str | None) -> dict:
    actions = {}
    if forward_to:
        actions["forwardTo"] = [{"emailAddress": {"address": forward_to}}]
    if move_to:
        actions["moveToFolder"] = move_to
    return {"id": f"rule-{next(_ids)}", "displayName": name, "sequence": 1, "isEnabled": True,
            "conditions": {}, "actions": actions}


def _rule_line(r: dict) -> str:
    a = r["actions"]
    did = [f"forwards to {x['emailAddress']['address']}" for x in a.get("forwardTo", [])]
    did += [f"moves to {a['moveToFolder']}"] if a.get("moveToFolder") else []
    return f"\"{r['displayName']}\": " + (", ".join(did) or "no action")


def _delete_rule(rules: list, rule_id: str, path: str, gone_ok: bool) -> None:
    if not _drop(rules, lambda r: r["id"] == rule_id) and not gone_ok:
        _not_found(path)


class OutlookLab:
    """A personal Outlook.com mailbox, as Graph shows it to MailboxSettings.ReadWrite: inbox rules only."""
    RULES = "/me/mailFolders/inbox/messageRules"

    def __init__(self, address: str):
        self.address, self.rules = address, []

    def add_inbox_rule(self, name: str, forward_to: str | None = None, move_to: str | None = None) -> None:
        self.rules.append(_rule(name, forward_to, move_to))

    def describe(self, account: str = "") -> dict[str, list[str]]:
        return {"Inbox rules": [_rule_line(r) for r in self.rules]}

    def get(self, path: str, params=None):
        return {"value": [dict(r) for r in self.rules]} if path == self.RULES else _not_found(path)

    def delete(self, path: str, gone_ok: bool = True) -> None:
        if not path.startswith(self.RULES + "/"):
            _not_found(path)
        _delete_rule(self.rules, unquote(path.removeprefix(self.RULES + "/")), path, gone_ok)


# -- Microsoft 365 -------------------------------------------------------

class Microsoft365Lab:
    """A Microsoft 365 tenant over Graph with application permissions."""

    def __init__(self, domain: str):
        self.domain = domain
        self.users: dict[str, dict] = {}
        self.grants: list[dict] = []  # oauth2PermissionGrants, tenant-wide ones included
        self.risks: list[dict] = []

    def add_user(self, upn: str) -> None:
        self.users[upn] = {"id": f"oid-{next(_ids)}", "userPrincipalName": upn, "accountEnabled": True,
                           "sessions": ["Windows laptop"], "rules": [],
                           "methods": [{"@odata.type": "#microsoft.graph.passwordAuthenticationMethod", "id": "pw"}]}

    def add_inbox_rule(self, upn: str, name: str, forward_to: str | None = None, move_to: str | None = None) -> None:
        self.users[upn]["rules"].append(_rule(name, forward_to, move_to))

    def add_consent(self, upn: str | None, app: str, scope: str) -> None:
        """upn None: an admin consented for every user (AllPrincipals)."""
        self.grants.append({"id": f"grant-{next(_ids)}", "clientId": app, "scope": scope, "resourceId": "graph",
                            "consentType": "AllPrincipals" if upn is None else "Principal",
                            "principalId": None if upn is None else self.users[upn]["id"]})

    def sign_in(self, upn: str, device: str) -> None:
        self.users[upn]["sessions"].append(device)

    def describe(self, account: str) -> dict[str, list[str]]:
        if account == self.domain:
            return {"App consents for every user": [f"{g['clientId']} ({g['scope']})" for g in self.grants
                                                    if g["consentType"] == "AllPrincipals"]}
        u = self.users[account]
        return {"Sign-in": ["allowed" if u["accountEnabled"] else "blocked"],
                "Signed-in sessions": list(u["sessions"]),
                "Inbox rules": [_rule_line(r) for r in u["rules"]],
                "App consents": [f"{g['clientId']} ({g['scope']})" for g in self.grants if g["principalId"] == u["id"]]}

    def _user(self, upn: str) -> dict:
        return self.users.get(upn) or _not_found(f"/users/{upn}")

    def get(self, path: str, params=None):
        params = params or {}
        if path == "/users":
            return {"value": [{"userPrincipalName": u} for u in self.users]}
        if path == "/domains":
            return {"value": [{"id": self.domain, "isVerified": True}]}
        if path == "/identityProtection/riskDetections":
            return {"value": [d for d in self.risks
                              if f"userPrincipalName eq '{d['userPrincipalName']}'" in params.get("$filter", "")]}
        parts = path.strip("/").split("/")
        if parts[0] != "users" or len(parts) < 2:
            _not_found(path)
        u, rest = self._user(unquote(parts[1])), "/".join(parts[2:])
        if not rest:
            return {k: u[k] for k in ("id", "userPrincipalName", "accountEnabled")}
        if rest == "mailFolders/inbox/messageRules":
            return {"value": [dict(r) for r in u["rules"]]}
        if rest == "oauth2PermissionGrants":
            # Grants that apply to the user: their own and every tenant-wide one. The connector keeps only their own.
            return {"value": [dict(g) for g in self.grants if g["principalId"] in (u["id"], None)]}
        if rest == "authentication/methods":
            return {"value": [dict(m) for m in u["methods"]]}
        _not_found(path)

    def send(self, method: str, path: str, body=None):
        parts = path.strip("/").split("/")
        if parts[0] != "users" or len(parts) < 2:
            _not_found(path)
        u = self._user(unquote(parts[1]))
        if method == "PATCH" and len(parts) == 2:
            u["accountEnabled"] = bool(body["accountEnabled"])
        elif method == "POST" and parts[2:] == ["revokeSignInSessions"]:
            u["sessions"].clear()
        else:
            _not_found(path)

    def delete(self, path: str, gone_ok: bool = True) -> None:
        parts = path.strip("/").split("/")
        if parts[0] == "oauth2PermissionGrants" and len(parts) == 2:
            if not _drop(self.grants, lambda g: g["id"] == unquote(parts[1])) and not gone_ok:
                _not_found(path)
        elif parts[0] == "users" and parts[2:5] == ["mailFolders", "inbox", "messageRules"] and len(parts) == 6:
            _delete_rule(self._user(unquote(parts[1]))["rules"], unquote(parts[5]), path, gone_ok)
        else:
            _not_found(path)


# -- Google Workspace ----------------------------------------------------

class _Request:
    """What googleapiclient hands back: nothing happens until execute()."""

    def __init__(self, run):
        self.execute = run


def _http_404():
    raise HttpError(NS(status=404, reason="Not Found"), b"{}")


class WorkspaceLab:
    """A Google Workspace domain: the Admin SDK directory, Gmail settings and the login audit log."""

    def __init__(self, domain: str):
        self.domain = domain
        self.users: dict[str, dict] = {}
        self.logins: list[dict] = []  # login audit events

    def add_user(self, email: str, admin: bool = False, apps=(), recovery_email: str = "") -> None:
        self.users[email] = {"isAdmin": admin, "suspended": False, "password_resets": 0, "backup_codes": "valid",
                             "recoveryEmail": recovery_email, "recoveryPhone": "", "apps": list(apps), "asps": [],
                             "sessions": ["Chrome on Mac"], "autoforward": None, "forwarding_addresses": [],
                             "delegates": [], "filters": [], "imap": True, "pop": "disabled"}

    def add_forwarding(self, email: str, to: str) -> None:
        """Adds a forwarding address and turns automatic forwarding on to it."""
        u = self.users[email]
        u["forwarding_addresses"].append(to)
        u["autoforward"] = to

    def add_delegate(self, email: str, delegate: str) -> None:
        self.users[email]["delegates"].append(delegate)

    def describe(self, account: str) -> dict[str, list[str]]:
        u = self.users[account]
        return {"Account": ["suspended" if u["suspended"] else "active"]
                + ([f"password reset by the tool {u['password_resets']} time(s)"] if u["password_resets"] else [])
                + ([f"backup codes {u['backup_codes']}"] if u["backup_codes"] != "valid" else []),
                "Signed-in sessions": list(u["sessions"]),
                "Automatic forwarding": [f"on, to {u['autoforward']}"] if u["autoforward"] else ["off"],
                "Forwarding addresses": list(u["forwarding_addresses"]),
                "Mail delegates": list(u["delegates"]),
                "Connected apps": list(u["apps"]),
                "IMAP and POP": [x for x, on in (("IMAP on", u["imap"]), ("POP on", u["pop"] != "disabled")) if on]
                or ["both off"]}

    def build(self, name: str, version: str, credentials, **_):
        """Stands in for googleapiclient.discovery.build: the subject is whom the service account acts as."""
        subject = credentials._subject
        if name == "gmail":
            return self._gmail(subject)
        return self._reports() if version == "reports_v1" else self._directory()

    def _user(self, email: str) -> dict:
        return self.users.get(email) or _http_404()

    @staticmethod
    def _call(fn):
        return lambda **kw: _Request(lambda: fn(**kw))

    def _directory(self):
        c = self._call

        def get(userKey):
            u = self._user(userKey)
            return {"primaryEmail": userKey, "isAdmin": u["isAdmin"], "suspended": u["suspended"],
                    "recoveryEmail": u["recoveryEmail"], "recoveryPhone": u["recoveryPhone"]}

        def update(userKey, body):
            u = self._user(userKey)
            for k, v in body.items():
                if k == "password":
                    u["password_resets"] += 1
                elif k in ("suspended", "recoveryEmail", "recoveryPhone"):
                    u[k] = v
            return get(userKey)

        def sign_out(userKey):
            self._user(userKey)["sessions"].clear()

        def remove(field, key):
            def run(userKey, **kw):
                if not _drop(self._user(userKey)[field], lambda x: x == kw[key]):
                    _http_404()
            return run

        def invalidate(userKey):
            self._user(userKey)["backup_codes"] = "invalidated"

        users = NS(get=c(get), update=c(update), signOut=c(sign_out),
                   list=c(lambda domain, maxResults, pageToken=None: {"users": [
                       {"primaryEmail": e} for e in self.users if e.endswith("@" + domain)]}))
        tokens = NS(list=c(lambda userKey: {"items": [{"clientId": a} for a in self._user(userKey)["apps"]]}),
                    delete=c(remove("apps", "clientId")))
        asps = NS(list=c(lambda userKey: {"items": [{"codeId": a} for a in self._user(userKey)["asps"]]}),
                  delete=c(remove("asps", "codeId")))
        codes = NS(invalidate=c(invalidate))
        return NS(users=lambda: users, tokens=lambda: tokens, asps=lambda: asps, verificationCodes=lambda: codes)

    def _reports(self):
        def activities(userKey, applicationName, startTime, pageToken=None):
            return {"items": [e for e in self.logins if e["actor"]["email"] == userKey and e["id"]["time"] >= startTime]}
        acts = NS(list=self._call(activities))
        return NS(activities=lambda: acts)

    def _gmail(self, email: str):
        c, u = self._call, self._user(email)

        def update_forwarding(userId, body):
            u["autoforward"] = u["autoforward"] if body.get("enabled") else None

        def remove(field):
            def run(userId, **kw):
                if not _drop(u[field], lambda x: x == next(iter(kw.values()))):
                    _http_404()
            return run

        def update_imap(userId, body):
            u["imap"] = bool(body["enabled"])

        def update_pop(userId, body):
            u["pop"] = body["accessWindow"]

        fwd = NS(list=c(lambda userId: {"forwardingAddresses": [
            {"forwardingEmail": a, "verificationStatus": "accepted"} for a in u["forwarding_addresses"]]}),
            delete=c(remove("forwarding_addresses")))
        delegates = NS(list=c(lambda userId: {"delegates": [
            {"delegateEmail": d, "verificationStatus": "accepted"} for d in u["delegates"]]}),
            delete=c(remove("delegates")))
        filters = NS(list=c(lambda userId: {"filter": [dict(f) for f in u["filters"]]}),
                     delete=c(lambda userId, id: _drop(u["filters"], lambda f: f["id"] == id) or _http_404()))
        settings = NS(
            getAutoForwarding=c(lambda userId: {"enabled": True, "emailAddress": u["autoforward"],
                                                "disposition": "leaveInInbox"} if u["autoforward"] else {"enabled": False}),
            updateAutoForwarding=c(update_forwarding),
            getImap=c(lambda userId: {"enabled": u["imap"]}), updateImap=c(update_imap),
            getPop=c(lambda userId: {"accessWindow": u["pop"]}), updatePop=c(update_pop),
            forwardingAddresses=lambda: fwd, delegates=lambda: delegates, filters=lambda: filters)
        return NS(users=lambda: NS(settings=lambda: settings))


# -- Slack ---------------------------------------------------------------

class SlackLab:
    """A Slack workspace: Web API, SCIM and (Enterprise Grid only) the audit log. One object serves all three."""

    def __init__(self, team: str, plan: str):
        self.team, self.plan = team, plan
        self.members: dict[str, dict] = {}  # by user id
        self.audit: list[dict] = []
        self.access_logs: list[dict] = []

    def add_member(self, email: str, primary_owner: bool = False) -> str:
        uid = f"U{next(_ids)}"
        self.members[uid] = {"id": uid, "email": email, "primary_owner": primary_owner, "active": True,
                             "sessions": ["Slack desktop app"]}
        return uid

    def _uid(self, email: str) -> str:
        return next(i for i, m in self.members.items() if m["email"] == email)

    def sign_in(self, email: str, where: str, ip: str = "203.0.113.9") -> None:
        uid = self._uid(email)
        self.members[uid]["sessions"].append(where)
        self.access_logs.append({"user_id": uid, "ip": ip, "date_first": time.time(), "date_last": time.time()})

    def log_anomaly(self, email: str) -> None:
        """What Slack writes to the audit log when it flags a member's session as anomalous."""
        uid = self._uid(email)
        self.audit.append({"id": f"audit-{next(_ids)}", "date_create": int(time.time()), "action": "anomaly",
                           "actor": {"user": {"id": uid}}, "entity": {"user": {"id": uid}}})

    def describe(self, account: str) -> dict[str, list[str]]:
        m = self.members[self._uid(account.removeprefix("slack:"))]
        return {"Member": ["active" if m["active"] else "deactivated"], "Signed-in sessions": list(m["sessions"])}

    def _absent(self, what: str):  # how Slack answers a call the plan does not include
        raise ApiError(403, "", f"{what}: HTTP 403")

    def get(self, path: str, params=None):
        params = params or {}
        if path == "/auth.test":
            return {"ok": True, "url": f"https://{self.team}.slack.com/", "team": self.team}
        if path == "/users.list":
            return {"ok": True, "response_metadata": {"next_cursor": ""}, "members": [
                {"id": i, "deleted": not m["active"], "is_bot": False, "is_primary_owner": m["primary_owner"],
                 "profile": {"email": m["email"]}} for i, m in self.members.items()]}
        if path == "/team.accessLogs":
            if self.plan == "free":
                return {"ok": False, "error": "paid_only"}
            return {"ok": True, "logins": [dict(e) for e in self.access_logs], "paging": {"pages": 1, "page": 1}}
        if path == "/logs":
            if self.plan != "enterprise":
                self._absent("audit log")
            wanted = set(str(params.get("action", "")).split(",")) - {""}
            return {"response_metadata": {"next_cursor": ""}, "entries": [
                dict(e) for e in self.audit if e["date_create"] >= params.get("oldest", 0)
                and (not wanted or e["action"] in wanted)]}
        if path.startswith("/Users"):
            if self.plan not in ("enterprise", "business"):
                self._absent("SCIM")
            if path == "/Users":
                return {"Resources": [{"id": i, "active": m["active"]} for i, m in self.members.items()]}
            m = self.members.get(unquote(path.removeprefix("/Users/"))) or _not_found(path)
            return {"id": m["id"], "userName": m["email"], "active": m["active"]}
        _not_found(path)

    def send(self, method: str, path: str, body=None):
        if (method, path) == ("POST", "/admin.users.session.reset"):
            if self.plan != "enterprise":
                return {"ok": False, "error": "not_allowed_token_type"}
            m = self.members.get(body["user_id"])
            if not m:
                return {"ok": False, "error": "user_not_found"}
            m["sessions"].clear()
            return {"ok": True}
        if method == "PATCH" and path.startswith("/Users/"):
            if self.plan not in ("enterprise", "business"):
                self._absent("SCIM")
            m = self.members.get(unquote(path.removeprefix("/Users/"))) or _not_found(path)
            m["active"] = bool(body["active"])
            if not m["active"]:  # a deactivated member is signed out everywhere
                m["sessions"].clear()
            return {"id": m["id"], "active": m["active"]}
        _not_found(path)
