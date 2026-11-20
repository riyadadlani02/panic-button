"""`panic arm` and `panic rehearse`: recording accounts and their approved baselines."""
import json
from pathlib import Path

from panic import executor, google_personal
from panic.model import Account, Step
from panic.session import CliError, Session, _connectors, _unprotected, _warn, _yes

# Workspace rehearsal shows these as flags only; their contents are never printed.
WORKSPACE_FLAGS = ("forwarding", "forwarding_addresses", "delegates", "recovery")


def _plan_lines(plan: list[Step]) -> list[str]:
    return [f"  {st.account}: {st.title} ({st.phase}, {st.tier})" for st in plan]


# -- arm ----------------------------------------------------------------

def _authorize(a) -> dict:
    try:
        return a.authorize(Path(a.client_secrets))
    except Exception as e:
        raise CliError(f"sign-in failed: {e}")


def _print_snapshot(snap: dict) -> None:
    for cat, items in snap.items():
        print(f"{cat}:")
        for i in items or ["(none)"]:
            print(f"  - {i}")


def _arm_personal(a) -> int:
    if not a.client_secrets:
        raise CliError("--client-secrets FILE is required to sign in.")
    email = a.personal.lower()
    if a.reconnect:
        s = Session(a)
        if not any(x.id == email and x.provider == "google_personal" for x in s.accounts):
            raise CliError(f"{email} is not armed. Arm it first, without --reconnect.")
        s.data["credentials"].setdefault("google_personal", {})[email] = _authorize(a)
        s.save()
        print(f"Reconnected {email}.")
        return 0
    if not _yes(f"Do you hold a way to recover {email} that does not depend on {email} itself "
                "(printed backup codes or a security key)?"):
        _warn(f"Not armed: set up a recovery method for {email} that does not depend on it, then arm again.")
        return 1
    s = Session(a, create=True)
    existing = next((x for x in s.accounts if x.id == email), None)
    if existing and (existing.protected or existing.provider != "google_personal"):
        raise CliError(f"{email} is already armed ({"protected, " if existing.protected else ""}{existing.provider}); refusing to replace it.")
    token = _authorize(a)
    account = Account(email, "google_personal")
    try:
        conn = (a.connectors or {}).get("google_personal") or google_personal.Personal({email: token})
        snap = conn.snapshot(account)
    except Exception as e:
        raise CliError(f"could not read {email}: {e}")
    _print_snapshot(snap)
    if not _yes(f"Is this what {email} should look like when it is safe? Approve it as the baseline?"):
        print("Nothing saved.")
        return 1
    armed = [x for x in _unprotected(s) if x != email]
    picks: list[str] = []
    while armed:
        raw = input(f"Which of your armed accounts can reset this one? ({', '.join(armed)}; "
                    "comma-separated, empty for none) ")
        picks = [p.strip().lower() for p in raw.split(",") if p.strip()]
        unknown = [p for p in picks if p not in armed]
        if not unknown:
            break
        print("Not armed accounts: " + ", ".join(unknown))
    s.upsert(account, snap)
    s.data["credentials"].setdefault("google_personal", {})[email] = token
    s.data["edges"] += [[p, email] for p in picks if [p, email] not in s.data["edges"]]
    s.save()
    print(f"Armed {email}.")
    return 0


def _arm_workspace(a) -> int:
    if not (a.sa_key and a.admin and a.domain):
        raise CliError("--workspace needs --sa-key FILE, --admin EMAIL and --domain DOMAIN.")
    from panic.google_workspace import Workspace
    try:
        sa_info = json.loads(Path(a.sa_key).expanduser().read_text())
    except (OSError, ValueError) as e:
        raise CliError(f"could not read the service-account key {a.sa_key}: {e}")
    admin = a.admin.lower()
    s = Session(a, create=True)
    prior = {x.id: x for x in s.accounts}
    if admin in prior and prior[admin].provider != "google_workspace":
        raise CliError(f"{admin} is already armed as a {prior[admin].provider} account; refusing to replace it.")
    try:
        ws = (a.connectors or {}).get("google_workspace") or Workspace(sa_info, admin, a.domain)
        users = list(dict.fromkeys([u.lower() for u in ws.users()] + [admin]))
    except Exception as e:
        raise CliError(f"could not list the Workspace users: {e}")
    failed: list[str] = []
    for u in users:
        acct = Account(u, "google_workspace", protected=(u == admin or (u in prior and prior[u].protected)))
        snap = None
        if not acct.protected:  # the break-glass admin is never read either
            try:
                snap = ws.snapshot(acct)
            except Exception:
                failed.append(u)
        s.upsert(acct, snap)
    for u in users:  # a recovery address that is itself armed can reset the user
        for item in s.data["baselines"].get(u, {}).get("recovery", []):
            r = item.removeprefix("email:").lower() if item.startswith("email:") else None
            if r and r != u and r in users and [r, u] not in s.data["edges"]:
                s.data["edges"].append([r, u])
    s.data["credentials"]["google_workspace"] = {"sa_info": sa_info, "admin": admin, "domain": a.domain}
    s.save()
    if failed:
        _warn("Warning: armed with no baseline (could not be read): " + ", ".join(failed))
    print(f"Armed {len(users)} accounts; {admin} is the protected break-glass account.")
    return 0


def cmd_arm(a) -> int:
    if a.workspace:
        return _arm_workspace(a)
    if a.personal:
        return _arm_personal(a)
    raise CliError("Give --personal EMAIL or --workspace.")


# -- rehearse -----------------------------------------------------------

def cmd_rehearse(a) -> int:
    s = Session(a)
    conns, bad, changed = _connectors(a, s), False, False
    base = s.data["baselines"]
    for acct in s.accounts:
        conn = conns.get(acct.provider)
        if acct.protected or conn is None:
            continue
        try:
            snap = conn.snapshot(acct)
        except Exception as e:
            print(f"{acct.id}: ERROR {e}")
            bad = True
            continue
        out = executor.outside_baseline(base.get(acct.id, {}), snap)
        if acct.provider == "google_workspace":
            flags = sorted({o.split(":", 1)[0] for o in out} & set(WORKSPACE_FLAGS))
            print(f"{acct.id}: " + ("changed since baseline: " + ", ".join(flags) if flags else "no flagged changes"))
        elif not out:
            print(f"{acct.id}: matches the baseline")
        else:
            print(f"{acct.id}: outside the baseline:")
            print("\n".join(f"  - {o}" for o in out))
            if _yes(f"Approve this as the new baseline for {acct.id}?"):
                base[acct.id] = snap
                changed = True
    print("Plan:")
    print("\n".join(_plan_lines(executor.compile_plan(s.accounts, s.edges, conns))) or "  (no steps)")
    if changed:  # an unchanged rehearsal must not reset saved_at on an exported copy
        s.save()
    return 1 if bad else 0
