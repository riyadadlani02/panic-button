"""Connector for a GitHub user account or organisation, over the REST API with a classic personal access token."""
import hashlib
import json
import threading
import time
from collections.abc import Callable
from urllib.parse import quote, urlsplit

from panic.http import Api, ApiError
from panic.model import Account, Finding, Phase, Snapshot, Step, Tier, WatchPolicy
from panic.signals import drift

BASE = "https://api.github.com"
REPO_REFRESH_S = 3600  # per-repository reads cost one call per repo, so the guard reuses them for an hour

F, P, A, G = Phase.FREEZE, Phase.PURGE, Tier.API, Tier.GUIDED
R, N = WatchPolicy.REAPPLY, WatchPolicy.NONE
KEY_CATS = ("ssh_keys", "signing_keys", "gpg_keys")
REPO_CATS = ("deploy_keys", "webhooks", "collaborators", "invitations")
ORG_CATS = ("org_webhooks", "outside_collaborators", "deploy_keys")
SNAPSHOT_CATS = {False: (*KEY_CATS, "emails", *REPO_CATS), True: ORG_CATS}
# API steps and the categories each one covers, in the order it deletes.
STEP_CATS = {"keys": KEY_CATS, "emails": ("emails",), "repo_access": REPO_CATS, "org_access": ORG_CATS}
# (action, phase, tier, watch, link, title); links and titles take {name} (login or organisation).
_PERSONAL = [
    ("keys", F, A, R, None, "Delete SSH, signing and GPG keys that were added without you"),
    ("emails", P, A, R, None, "Remove email addresses that were added without you (the primary one stays)"),
    ("repo_access", P, A, R, None,
     "Remove deploy keys, webhooks, collaborators and invitations on your repositories that were added without you"),
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
     "Remove webhooks, deploy keys and outside collaborators that were added without you"),
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


def _read_list(api: Api, path: str, make, params: dict | None = None) -> list[tuple[str, tuple | None]]:
    return [make(x) for x in api.pages(path, params)]


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


def _repo_deploy_keys(api, repo):
    return _read_list(api, f"/repos/{repo}/keys", lambda k: (_j(key=k["key"], title=k["title"], repo=repo),
                                                              (f"/repos/{repo}/keys/{k['id']}", None)))


def _repo_webhooks(api, repo):
    return _read_list(api, f"/repos/{repo}/hooks", lambda h: (
        _hook_item(h, repo=repo), (f"/repos/{repo}/hooks/{h['id']}", None)))


def _repo_collaborators(api, repo):
    owner = repo.split("/")[0].casefold()  # the owner is listed as a collaborator of their own repository
    rows = api.pages(f"/repos/{repo}/collaborators", {"affiliation": "direct"})
    return [(_j(login=u["login"], repo=repo), (f"/repos/{repo}/collaborators/{quote(u['login'])}", None))
            for u in rows if u["login"].casefold() != owner]


def _repo_invitations(api, repo):
    return _read_list(api, f"/repos/{repo}/invitations", lambda i: (
        _j(login=i["invitee"]["login"], permissions=i.get("permissions", ""), repo=repo),
        (f"/repos/{repo}/invitations/{i['id']}", None)))


_REPO_READERS = {"deploy_keys": _repo_deploy_keys, "webhooks": _repo_webhooks, "collaborators": _repo_collaborators,
                 "invitations": _repo_invitations}


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
        for cat in cats:
            if cat in _REPO_READERS:
                if repos is None:
                    rows = (api.pages(f"/orgs/{name}/repos", {"type": "all", "per_page": 100}) if _is_org(account.id)
                            else api.pages("/user/repos", {"affiliation": "owner", "per_page": 100}))
                    repos = [quote(r["full_name"], safe="/") for r in rows]
                out[cat] = [e for r in repos for e in _REPO_READERS[cat](api, r)]
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
                self._cache.update({(account.id, c): (stamp, es) for c, es in got.items() if c in _REPO_READERS})
            out.update(got)
        return {c: out[c] for c in cats}

    def snapshot(self, account: Account) -> Snapshot:
        entries = self._entries(account, SNAPSHOT_CATS[_is_org(account.id)], fresh=False)
        return {c: [item for item, _ in es] for c, es in entries.items()}

    def signals(self, account: Account, snapshot: Snapshot, baseline: Snapshot) -> list[Finding]:
        org = _is_org(account.id)

        def classify(cat: str, item: str) -> str:
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

    def run(self, step: Step, baseline: Snapshot) -> None:
        if step.action not in STEP_CATS:
            raise NotImplementedError(f"{step.action} is a guided step")
        cats = STEP_CATS[step.action]
        known = {c: self._known(step, baseline, c) for c in cats}
        entries = self._entries(Account(step.account, self.provider), cats, fresh=True)  # every list read before any delete
        api = self._api(step.account)
        for cat in cats:
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
        cats = STEP_CATS[step.action]
        known = {c: self._known(step, baseline, c) for c in cats}
        entries = self._entries(Account(step.account, self.provider), cats, fresh=True)
        return all(item in known[c] for c, es in entries.items() for item, _ in es)
