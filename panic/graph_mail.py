"""Inbox rules over Microsoft Graph: shared by the tenant connector and the personal one."""
import json
from urllib.parse import quote

from panic.http import Api


def pages(api: Api, path: str, params: dict | None = None) -> list:
    """Every item of a Graph collection; Api.pages only knows GitHub's Link headers."""
    out, seen = [], set()
    while path and path not in seen:  # a server that loops its own nextLink must not loop us
        seen.add(path)
        page = api.get(path, params) or {}
        out += page.get("value", [])
        path, params = page.get("@odata.nextLink"), None  # the next link already carries the query
    return out


def _base(user: str) -> str:
    return "/me" if user == "me" else f"/users/{quote(user, safe='@')}"


def _path(user: str) -> str:
    return f"{_base(user)}/mailFolders/inbox/messageRules"


def _canon(r: dict) -> str:
    return json.dumps({k: r.get(k) for k in ("displayName", "isEnabled", "conditions", "actions")}, sort_keys=True)


def rules(api: Api, user: str) -> list[str]:
    return [_canon(r) for r in pages(api, _path(user))]


def delete_rules_outside(api: Api, user: str, keep: list[str]) -> None:
    for r in pages(api, _path(user)):
        if _canon(r) not in keep:
            api.delete(f"{_path(user)}/{quote(r['id'], safe='')}")
    left = [r for r in rules(api, user) if r not in keep]
    if left:  # read-only or hidden rules survive a delete
        raise RuntimeError(f"{len(left)} inbox rule(s) could not be deleted")


def rule_code(item: str, own_domains: set[str] | None) -> str | None:
    try:
        actions = json.loads(item).get("actions") or {}
        for key in ("forwardTo", "forwardAsAttachmentTo", "redirectTo"):
            for rcpt in actions.get(key) or []:
                addr = str((rcpt.get("emailAddress") or {}).get("address") or "")
                if own_domains is None or addr.rpartition("@")[2].casefold() not in own_domains:
                    return "rule_forwards_outside"
        if actions.get("delete") or actions.get("permanentDelete") or (
                actions.get("moveToFolder") and actions.get("markAsRead")):
            return "rule_hides_mail"
    except (ValueError, AttributeError, TypeError):
        return "rule_hides_mail"  # fail closed: a rule we cannot read may hide mail
    return None
