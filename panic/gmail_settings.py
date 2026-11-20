"""Gmail settings calls shared by the personal and Workspace connectors."""
import json

from googleapiclient.errors import HttpError


def _s(svc):
    return svc.users().settings()


def _canon(f: dict) -> str:  # id excluded: Gmail may reissue ids for the same filter
    def norm(d):  # list order is not meaningful, Gmail may reorder it
        return {k: sorted(v) if isinstance(v, list) else v for k, v in d.items()}
    return json.dumps({"criteria": norm(f.get("criteria", {})), "action": norm(f.get("action", {}))}, sort_keys=True)


def _exec(request, gone_ok: bool = False):
    try:
        return request.execute()
    except HttpError as e:
        if gone_ok and e.resp.status == 404:
            return None
        raise


def _list(svc, call=_exec) -> list[dict]:
    return (call(_s(svc).filters().list(userId="me")) or {}).get("filter", [])


def filters(svc) -> list[str]:
    return [_canon(f) for f in _list(svc)]


def delete_filters_outside(svc, keep: list[str], call=None) -> None:
    call = call or _exec  # call(request, gone_ok=False) lets a connector add retries
    for f in _list(svc, call):
        if _canon(f) not in keep:
            call(_s(svc).filters().delete(userId="me", id=f["id"]), gone_ok=True)  # already gone is fine


def forwarding(svc) -> list[str]:
    r = _s(svc).getAutoForwarding(userId="me").execute()
    return [f"on -> {r.get('emailAddress', '')}"] if r.get("enabled") else []


def forwarding_addresses(svc) -> list[str]:
    r = _exec(_s(svc).forwardingAddresses().list(userId="me")) or {}
    return [a["forwardingEmail"] for a in r.get("forwardingAddresses", [])]


def imap_pop(svc) -> list[str]:
    on = []
    # Fail closed: a missing field must not read as "off".
    if _s(svc).getImap(userId="me").execute()["enabled"]:
        on.append("imap")
    if _s(svc).getPop(userId="me").execute()["accessWindow"] != "disabled":
        on.append("pop")
    return on


def disable_imap_pop(svc) -> None:
    _s(svc).updateImap(userId="me", body={"enabled": False}).execute()
    _s(svc).updatePop(userId="me", body={"accessWindow": "disabled"}).execute()
