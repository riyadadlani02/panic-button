"""Connector for a GitHub user account or organisation, over the REST API with a classic personal access token."""
import hashlib
import json
import threading
import time
from collections.abc import Callable
from urllib.parse import quote, urlsplit

from panic.checkup import Check
from panic.http import Api, ApiError
from panic.model import Account, Finding, Phase, Snapshot, Step, Tier, WatchPolicy
from panic.signals import drift

BASE = "https://api.github.com"
TOKENS = "https://github.com/settings/tokens"
REPO_REFRESH_S = 3600  # per-repository reads cost one call per repo, so the guard reuses them for an hour

F, P, A, G = Phase.FREEZE, Phase.PURGE, Tier.API, Tier.GUIDED
R, N = WatchPolicy.REAPPLY, WatchPolicy.NONE
KEY_CATS = ("ssh_keys", "signing_keys", "gpg_keys")
REPO_CATS = ("deploy_keys", "webhooks", "collaborators", "invitations")
ORG_CATS = ("org_webhooks", "outside_collaborators", "deploy_keys")
# "<id>: <owner/name>", so names stay visible; no step touches it and a change there is only a notice.
REPOS = "repositories"
PUBLIC = "public_repositories"  # the same items, public ones only: a new one is risky
# Self-hosted runners: "<repo_id>:<runner_id>: <name>" on your repositories, "<runner_id>: <name>" on an organisation.
RUNNERS = "runners"
SNAPSHOT_CATS = {False: (*KEY_CATS, "emails", REPOS, PUBLIC, *REPO_CATS, RUNNERS),
                 True: (*ORG_CATS, REPOS, PUBLIC, RUNNERS)}
# API steps and the categories each one covers, in the order it deletes.
STEP_CATS = {"keys": KEY_CATS, "emails": ("emails",), "repo_access": (*REPO_CATS, RUNNERS),
             "org_access": (*ORG_CATS, RUNNERS)}
# (action, phase, tier, watch, link, title); links and titles take {name} (login or organisation).
_PERSONAL = [
    ("keys", F, A, R, None, "Delete SSH, signing and GPG keys that were added without you"),
    ("emails", P, A, R, None, "Remove email addresses that were added without you (the primary one stays)"),
    ("repo_access", P, A, R, None,
     "Remove deploy keys, webhooks, collaborators, invitations and self-hosted runners on your repositories "
     "that were added without you"),
    ("sign_out", F, G, N, "https://github.com/settings/sessions", "Sign out of every session you do not recognise"),
    ("tokens", P, G, N, "https://github.com/settings/tokens",
     "Delete every personal access token you do not recognise, except the one panic-button uses"),
    ("apps", P, G, N, "https://github.com/settings/applications", "Remove every authorised app you do not recognise"),
    ("two_factor", P, G, N, "https://github.com/settings/security",
     "Check that two-factor authentication, recovery codes and passkeys are yours"),
    ("password", P, G, N, "https://github.com/settings/security",
     "Change your password now. Afterwards replace panic-button's own token with "
     "`panic arm --github {name} --token-file FILE --reconnect`."),
]
_ORG = [
    ("org_access", P, A, R, None,
     "Remove webhooks, deploy keys, outside collaborators and self-hosted runners that were added without you"),
    ("members", P, G, N, "https://github.com/orgs/{name}/people",
     "Review the members and owners; remove anyone you do not recognise"),
]


def _j(**fields) -> str:
    return json.dumps(fields, sort_keys=True)


def _hook_item(h: dict, **extra) -> str:
    # Hook URLs often carry a secret: keep scheme://host/path and a fingerprint of the whole URL, never the secret.
    url = h["config"].get("url", "")
    try:
        u = urlsplit(url)
        host = u.hostname and (f"{u.hostname}:{u.port}" if u.port else u.hostname)
        plain = f"{u.scheme}://{host}{u.path}" if host else ""
    except ValueError:
        plain = ""
    return _j(url=plain, fingerprint=hashlib.sha256(url.encode()).hexdigest()[:12], events=sorted(h["events"]), **extra)


def _read_list(api: Api, path: str, make, params: dict | None = None,
               key: str | None = None) -> list[tuple[str, tuple | None]]:
    return [make(x) for x in api.pages(path, params, key)]


# Each reader returns (item, delete) pairs: delete is (path, body) or None when the item must never be removed.
def _keys(path):
    return lambda api, _: _read_list(api, path, lambda k: (_j(key=k["key"], title=k["title"]), (f"{path}/{k['id']}", None)))


def _gpg(api, _):
    return _read_list(api, "/user/gpg_keys",
                      lambda k: (_j(key=k["key_id"], title=k.get("name") or ""), (f"/user/gpg_keys/{k['id']}", None)))


def _emails(api, _):
    def make(e):
        return _j(email=e["email"]), (None if e.get("primary") else ("/user/emails", {"emails": [e["email"]]}))
    return _read_list(api, "/user/emails", make)


def _hooks(path):
    return lambda api, _: _read_list(api, path, lambda h: (_hook_item(h), (f"{path}/{h['id']}", None)))


def _outside(api, org):
    return _read_list(api, f"/orgs/{org}/outside_collaborators",
                      lambda u: (_j(login=u["login"]), (f"/orgs/{org}/outside_collaborators/{quote(u['login'])}", None)))


_READERS = {
    "ssh_keys": _keys("/user/keys"), "signing_keys": _keys("/user/ssh_signing_keys"), "gpg_keys": _gpg,
    "emails": _emails,
    "org_webhooks": lambda api, org: _hooks(f"/orgs/{org}/hooks")(api, org), "outside_collaborators": _outside,
}


# Items name the repository by its numeric id: a rename or transfer must never make baselined access look new.
# Paths use the current name, read fresh before any delete.
def _repo_deploy_keys(api, repo, rid):
    return _read_list(api, f"/repos/{repo}/keys", lambda k: (_j(key=k["key"], title=k["title"], repo_id=rid),
                                                              (f"/repos/{repo}/keys/{k['id']}", None)))


def _repo_webhooks(api, repo, rid):
    return _read_list(api, f"/repos/{repo}/hooks", lambda h: (
        _hook_item(h, repo_id=rid), (f"/repos/{repo}/hooks/{h['id']}", None)))


def _repo_collaborators(api, repo, rid):
    owner = repo.split("/")[0].casefold()  # the owner is listed as a collaborator of their own repository
    rows = api.pages(f"/repos/{repo}/collaborators", {"affiliation": "direct"})
    return [(_j(login=u["login"], repo_id=rid), (f"/repos/{repo}/collaborators/{quote(u['login'])}", None))
            for u in rows if u["login"].casefold() != owner]


def _invitee(i: dict) -> dict:
    # An invitation by email has no invitee account yet.
    if isinstance(i.get("invitee"), dict):
        return {"login": i["invitee"]["login"]}
    return {"email": i["email"]} if i.get("email") else {"id": i["id"]}


def _repo_invitations(api, repo, rid):
    return _read_list(api, f"/repos/{repo}/invitations", lambda i: (
        _j(**_invitee(i), permissions=i.get("permissions", ""), repo_id=rid),
        (f"/repos/{repo}/invitations/{i['id']}", None)))


def _rate_limited(e: ApiError) -> bool:
    # GitHub answers a rate limit with 403 too; read as "no runners" it would drop the owner's from a baseline.
    return (e.headers.get("x-ratelimit-remaining") == "0" or e.headers.get("retry-after") is not None
            or "rate limit" in e.body.lower())


def _no_admin(e: ApiError) -> bool:
    return e.status == 404 or (e.status == 403 and not _rate_limited(e))


def _runners(api, path, make):
    try:
        return _read_list(api, path, lambda r: (make(r), (f"{path}/{r['id']}", None)), {"per_page": 100}, "runners")
    except ApiError as e:
        # ponytail: a hidden read reads as no runners; if the token loses and regains admin rights, an accepted baseline can drop the owner's runner — re-arm after changing token rights.
        if _no_admin(e):  # no admin rights there: none we can see
            return []
        raise


def _runners_hidden(api, path) -> bool:
    try:
        api.pages(path, {"per_page": 100}, "runners")
    except ApiError as e:
        if _no_admin(e):
            return True
        raise
    return False


def _eph(r) -> str:
    return "ephemeral " if r.get("ephemeral") else ""  # a prefix: a runner's name must not be able to fake it


def _repo_runners(api, repo, rid):
    return _runners(api, f"/repos/{repo}/actions/runners", lambda r: f"{_eph(r)}{rid}:{r['id']}: {r['name']}")


def _org_runners(api, org):
    return _runners(api, f"/orgs/{org}/actions/runners", lambda r: f"{_eph(r)}{r['id']}: {r['name']}")


_REPO_READERS = {"deploy_keys": _repo_deploy_keys, "webhooks": _repo_webhooks, "collaborators": _repo_collaborators,
                 "invitations": _repo_invitations, RUNNERS: _repo_runners}
_HOURLY = (*_REPO_READERS, REPOS, PUBLIC)


def _is_org(account_id: str) -> bool:
    return account_id.startswith("org:")


class GitHub:
    provider = "github"

    def __init__(self, tokens: dict[str, str], api: Callable[[str], Api] | None = None, now=time.time):
        self._tokens, self._api_for, self._now = tokens, api, now
        self._lock = threading.Lock()  # guards the cache; Api itself is safe to share
        self._cache: dict[tuple[str, str], tuple[float, list]] = {}

    def _api(self, account_id: str) -> Api:
        if account_id not in self._tokens:
            raise KeyError(f"no token for account {account_id}")
        if self._api_for:
            return self._api_for(account_id)
        token = self._tokens[account_id]
        return Api(BASE, lambda: {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                                  "X-GitHub-Api-Version": "2022-11-28"})

    def login(self, token_account: str) -> str:
        return self._api(token_account).get("/user")["login"]

    def is_org_admin(self, account: Account) -> bool:
        name = quote(account.id.removeprefix("org:"), safe="")
        try:
            m = self._api(account.id).get(f"/user/memberships/orgs/{name}")
        except ApiError as e:
            if e.status == 404:
                return False
            raise
        return m.get("state") == "active" and m.get("role") == "admin"

    def catalog(self, account: Account) -> list[Step]:
        org = _is_org(account.id)
        name = account.id.removeprefix("org:")
        return [Step(account.id, a, ph, t, title.format(name=name), link and link.format(name=quote(name, safe="")), w)
                for a, ph, t, w, link, title in (_ORG if org else _PERSONAL)]

    def _read(self, account: Account, cats) -> dict[str, list]:
        api, name, repos, out = self._api(account.id), account.id.removeprefix("org:"), None, {}
        org = _is_org(account.id)
        for cat in cats:
            if cat == RUNNERS and org:
                out[cat] = _org_runners(api, quote(name, safe=""))
            elif cat in _HOURLY:
                if repos is None:
                    rows = (api.pages(f"/orgs/{name}/repos", {"type": "all", "per_page": 100}) if org
                            else api.pages("/user/repos", {"affiliation": "owner", "per_page": 100}))
                    repos = [(r["id"], r["full_name"], r.get("private") is False) for r in rows]
                if cat in (REPOS, PUBLIC):
                    out[cat] = [(f"{rid}: {full}", None) for rid, full, public in repos if public or cat == REPOS]
                else:
                    out[cat] = [e for rid, full, _ in repos for e in _REPO_READERS[cat](api, quote(full, safe="/"), rid)]
            else:
                out[cat] = _READERS[cat](api, name)
        return out

    def _entries(self, account: Account, cats, fresh: bool) -> dict[str, list]:
        out, need = {}, []
        with self._lock:
            for c in cats:
                hit = self._cache.get((account.id, c))
                if not fresh and hit and self._now() - hit[0] < REPO_REFRESH_S:
                    out[c] = hit[1]
                else:
                    need.append(c)
        if need:
            got = self._read(account, need)
            stamp = self._now()
            with self._lock:  # a fresh read also refreshes the cache, or the press's closing snapshot would be stale
                self._cache.update({(account.id, c): (stamp, es) for c, es in got.items() if c in _HOURLY})
            out.update(got)
        return {c: out[c] for c in cats}

    def snapshot(self, account: Account) -> Snapshot:
        entries = self._entries(account, SNAPSHOT_CATS[_is_org(account.id)], fresh=False)
        return {c: [item for item, _ in es] for c, es in entries.items()}

    def posture(self, account: Account) -> list[Check]:
        api, a = self._api(account.id), account.id
        if _is_org(a):
            q = quote(a.removeprefix("org:"), safe="")
            on = api.get(f"/orgs/{q}").get("two_factor_requirement_enabled")  # hidden from non-owners
            link, paths = f"https://github.com/organizations/{q}/settings/security", lambda: [f"/orgs/{q}/actions/runners"]
            texts = ("The organisation requires two-factor authentication",
                     "The organisation does not require two-factor authentication",
                     "Could not read whether the organisation requires two-factor authentication")
        else:
            on = api.get("/user").get("two_factor_authentication")
            link = "https://github.com/settings/security"
            paths = lambda: [f"/repos/{quote(r['full_name'], safe='/')}/actions/runners"
                             for r in api.pages("/user/repos", {"affiliation": "owner", "per_page": 100})]
            texts = ("Two-factor authentication is on", "Two-factor authentication is off",
                     "Could not read whether two-factor authentication is on")
        out = [Check(a, "two_factor", "good", texts[0]) if on
               else Check(a, "two_factor", "unknown" if on is None else "fix", texts[2 if on is None else 1], link)]
        # The guard reads these as "no runners", so a new one would go unseen.
        try:
            paths = paths()
            hidden = sum(_runners_hidden(api, p) for p in paths)
        except Exception:  # a failed listing or read must not hide the 2FA result
            return [*out, Check(a, "runners", "unknown", "Could not read whether self-hosted runners can be read", TOKENS)]
        where = f"on {hidden} of {len(paths)} repositories" if not _is_org(a) else "in the organisation"
        out.append(Check(a, "runners", "unknown", f"Self-hosted runners cannot be read {where}: the token lacks admin "
                         "rights, so the guard would not see a new one", TOKENS) if hidden
                   else Check(a, "runners", "good", "Self-hosted runners can be read"))
        return out

    def signals(self, account: Account, snapshot: Snapshot, baseline: Snapshot) -> list[Finding]:
        org = _is_org(account.id)
        known = {i.split(":")[0] for i in baseline.get(PUBLIC, [])}

        def scope(item: str) -> str:  # an organisation's runners share one scope
            return "" if org else item.removeprefix("ephemeral ").split(":")[0]
        # ponytail: on a scope that already autoscales, an attacker's ephemeral runner is not caught.
        autoscaled = {scope(i) for i in baseline.get(RUNNERS, []) if i.startswith("ephemeral ")}

        def classify(cat: str, item: str) -> str | None:
            if cat == REPOS:
                return None
            if cat == RUNNERS:  # autoscaled runners register per job: harmless once the owner approved one there
                return None if item.startswith("ephemeral ") and scope(item) in autoscaled else "runner_added"
            if cat == PUBLIC:  # a renamed public repository keeps its id
                return None if item.split(":")[0] in known else "repo_made_public"
            if org:
                return "org_access_added"
            return "key_added" if cat in KEY_CATS else "email_added" if cat == "emails" else "repo_access_added"
        return drift(account.id, baseline, snapshot, classify)

    @staticmethod
    def _known(step: Step, baseline: Snapshot, category: str) -> list[str]:
        # A missing key must never mean "keep nothing": that would delete every key.
        if category not in baseline:
            raise KeyError(f"no baseline recorded for {category} on {step.account}")
        return baseline[category]

    def _known_all(self, step: Step, baseline: Snapshot) -> dict[str, list[str]]:
        """The categories the step acts on, each with what it keeps."""
        cats = STEP_CATS[step.action]
        if set(cats) & set(_REPO_READERS):
            # A baseline from before items carried repo_id matches nothing: it must not mean "delete all".
            self._known(step, baseline, REPOS)
        # A baseline armed before runners were watched removes no runner; the guard adopts them on its next read.
        return {c: self._known(step, baseline, c) for c in cats if c != RUNNERS or c in baseline}

    def run(self, step: Step, baseline: Snapshot) -> None:
        if step.action not in STEP_CATS:
            raise NotImplementedError(f"{step.action} is a guided step")
        known = self._known_all(step, baseline)
        entries = self._entries(Account(step.account, self.provider), known, fresh=True)  # every list read before any delete
        api = self._api(step.account)
        for cat in known:
            for item, delete in entries[cat]:
                if item in known[cat] or delete is None:
                    continue
                path, body = delete
                if body is None:
                    api.delete(path)
                else:
                    try:
                        api.send("DELETE", path, body)
                    except ApiError as e:
                        if e.status != 404:
                            raise

    def check(self, step: Step, baseline: Snapshot) -> bool | None:
        if step.action not in STEP_CATS:
            return None
        known = self._known_all(step, baseline)
        entries = self._entries(Account(step.account, self.provider), known, fresh=True)
        return all(item in known[c] for c, es in entries.items() for item, _ in es)
