"""`panic arm` and `panic rehearse`: recording accounts and their approved baselines."""
import json
from pathlib import Path

from panic import executor, google_personal
from panic.model import Account, Step
from panic.session import RULE_CATEGORIES, YES, CliError, Session, _connectors, _redact, _unprotected, _upsert, _warn, _yes

# Workspace rehearsal shows these as flags only; their contents are never printed.
WORKSPACE_FLAGS = ("forwarding", "forwarding_addresses", "delegates", "recovery", "consent_grants", "auth_methods")


def _plan_lines(plan: list[Step]) -> list[str]:
    return [f"  {st.account}: {st.title} ({st.phase}, {st.tier})" for st in plan]


# -- arm ----------------------------------------------------------------

def _client_config(a) -> dict:
    try:
        return json.loads(Path(a.client_secrets).expanduser().read_text())
    except (OSError, ValueError) as e:
        raise CliError(f"could not read the OAuth client file {a.client_secrets}: {e}")


def _sign_in(a, config: dict, email: str) -> dict:
    try:
        token = a.authorize(config, login_hint=email)
        who = a.whoami(token)
    except Exception as e:
        raise CliError(f"sign-in failed: {e}")
    if who.casefold() != email.casefold():  # the chooser lets the owner pick any account
        raise CliError(f"signed in as {who}, not {email}; nothing was stored. Gmail treats dotted and "
                       "googlemail.com variants as the same mailbox, but they must be typed here exactly as "
                       "Google shows the primary address.")
    return token


def _print_snapshot(snap: dict) -> None:
    for cat, items in snap.items():
        print(f"{cat}:")
        for i in items or ["(none)"]:
            print(f"  - {i}")


def _set_token(d: dict, email: str, token: dict) -> None:
    d["credentials"].setdefault("google_personal", {})[email] = token


def _pick_resetters(s: Session, acct_id: str) -> list[str]:
    armed = [x for x in _unprotected(s) if x != acct_id]
    picks: list[str] = []
    while armed:
        raw = input(f"Which of your armed accounts can reset this one? ({', '.join(armed)}; "
                    "comma-separated, empty for none) ")
        picks = [p.strip().lower() for p in raw.split(",") if p.strip()]
        unknown = [p for p in picks if p not in armed]
        if not unknown:
            break
        print("Not armed accounts: " + ", ".join(unknown))
    return picks


def _arm_personal(a) -> int:
    email = a.personal.lower()
    if a.reconnect:
        s = Session(a)
        if not any(x.id == email and x.provider == "google_personal" for x in s.accounts):
            raise CliError(f"{email} is not armed. Arm it first, without --reconnect.")
        stored = s.data["credentials"].get("google_client")
        if not (a.client_secrets or stored):
            raise CliError("--client-secrets FILE is required to sign in.")
        token = _sign_in(a, _client_config(a) if a.client_secrets else stored, email)
        s.update(lambda d: _set_token(d, email, token))
        print(f"Reconnected {email}.")
        return 0
    if not a.client_secrets:
        raise CliError("--client-secrets FILE is required to sign in.")
    config = _client_config(a)
    if not _yes(f"Do you hold a way to recover {email} that does not depend on {email} itself "
                "(printed backup codes or a security key)?"):
        _warn(f"Not armed: set up a recovery method for {email} that does not depend on it, then arm again.")
        return 1
    s = Session(a, create=True)
    existing = next((x for x in s.accounts if x.id == email), None)
    if existing and (existing.protected or existing.provider != "google_personal"):
        raise CliError(f"{email} is already armed ({"protected, " if existing.protected else ""}{existing.provider}); refusing to replace it.")
    token = _sign_in(a, config, email)
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
    picks = _pick_resetters(s, email)

    def change(d: dict) -> None:
        _upsert(d, account, snap)
        _set_token(d, email, token)
        d["credentials"].setdefault("google_client", config)  # lets --reconnect run without the file
        d["edges"] += [[p, email] for p in picks if [p, email] not in d["edges"]]

    s.update(change)
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
    return _arm_org(a, "google_workspace", "Workspace", admin, lambda: Workspace(sa_info, admin, a.domain),
                    lambda ws: {"sa_info": sa_info, "admin": admin, "domain": a.domain})


def _arm_microsoft(a) -> int:
    if not (a.client_id and a.client_secret_file and a.admin):
        raise CliError("--microsoft-tenant needs --client-id ID, --client-secret-file FILE and --admin UPN.")
    from panic.microsoft_365 import Microsoft365
    try:
        secret = Path(a.client_secret_file).expanduser().read_text().strip()
    except OSError as e:
        raise CliError(f"could not read the client secret file {a.client_secret_file}: {e.strerror}")
    if not secret or any(c.isspace() for c in secret):
        raise CliError(f"{a.client_secret_file} should hold the client secret and nothing else.")
    admin = a.admin.lower()
    cred = {"tenant": a.microsoft_tenant, "client_id": a.client_id, "client_secret": secret, "admin": admin}
    return _arm_org(a, "microsoft_365", "Microsoft 365", admin, lambda: Microsoft365(cred),
                    lambda ms: {**cred, "domains": ms.domains()})


def _arm_org(a, provider: str, label: str, admin: str, connect, credential) -> int:
    """Arms every user of an organisation tenant and protects its admin; baselines are only ever added."""
    s = Session(a, create=True)
    prior = {x.id: x for x in s.accounts}
    if admin in prior and prior[admin].provider != provider:
        raise CliError(f"{admin} is already armed as a {prior[admin].provider} account; refusing to replace it.")
    ws = (a.connectors or {}).get(provider) or connect()
    try:
        ws.verify_admin()
    except Exception as e:
        raise CliError(f"refusing to arm: {e}")
    try:
        users = list(dict.fromkeys([u.lower() for u in ws.users()] + [admin]))
    except Exception as e:
        raise CliError(f"could not list the {label} users: {e}")
    try:
        cred = credential(ws)
    except Exception as e:
        raise CliError(f"could not read the {label} settings: {e}")
    other = [u for u in users if u in prior and prior[u].provider != provider]
    if other:
        _warn("Warning: already armed under another provider, skipped: " + ", ".join(other))
    users = [u for u in users if u not in other]
    failed: list[str] = []
    armed: list[tuple[Account, dict | None]] = []
    for u in users:
        acct = prior.get(u) or Account(u, provider)
        if u == admin:  # the break-glass admin is always protected, whatever it was before
            acct = Account(u, provider, protected=True)
        snap = None
        # Re-arm never replaces a baseline: that would absorb whatever an attacker has added since.
        if not acct.protected and u not in s.data["baselines"]:  # the break-glass admin is never read either
            try:
                snap = ws.snapshot(acct)
            except Exception:
                failed.append(u)
        armed.append((acct, snap))

    def change(d: dict) -> None:
        for acct, snap in armed:
            _upsert(d, acct, snap)
        for u in users:  # a recovery address that is itself armed can reset the user
            for item in d["baselines"].get(u, {}).get("recovery", []):
                r = item.removeprefix("email:").lower() if item.startswith("email:") else None
                if r and r != u and r in users and [r, u] not in d["edges"]:
                    d["edges"].append([r, u])
        d["credentials"][provider] = cred

    s.update(change)
    if failed:
        _warn("Warning: armed with no baseline (could not be read): " + ", ".join(failed))
    print(f"Armed {len(users)} accounts; {admin} is the protected break-glass account.")
    return 0


def _guided_entry(d: dict, key: str, name: str | None, links: dict) -> dict | None:
    """The custom entry for key after adding links, or None when the catalogue already covers it."""
    from panic.guided import load_services
    custom = d["credentials"].get("guided", {})
    base = custom.get(key) or load_services().get(key)
    if not links:
        if base is None:
            raise CliError(f"{key} is not in the catalogue; give at least one --link KIND=URL.")
        return None
    return {"name": name or (base or {}).get("name") or key.title(),
            "verified": base["verified"] if base else True,  # a link the owner typed is the owner's to trust
            "links": {**(base or {}).get("links", {}), **links}}


def _arm_guided(a) -> int:
    from panic.guided import KINDS, valid_link
    if not a.id:
        raise CliError("--guided needs --id LOGIN.")
    key, links = a.guided.lower(), {}
    for item in a.link:
        kind, _, url = item.partition("=")
        if kind not in {k for k, _, _ in KINDS}:
            raise CliError(f"unknown link kind {kind!r}; use one of " + ", ".join(k for k, _, _ in KINDS) + ".")
        if not valid_link(url):
            raise CliError(f"refusing {kind} link: it must be a plain https:// address with a host and no login part")
        links[kind] = url
    s = Session(a, create=True)
    entry = _guided_entry(s.data, key, a.name, links)
    acct_id = f"{key}:{a.id}"
    existing = next((x for x in s.accounts if x.id == acct_id), None)
    if existing and (existing.protected or existing.provider != "guided"):
        raise CliError(f"{acct_id} is already armed ({existing.provider}); refusing to replace it.")
    if not _yes(f"Do you hold a way to recover {acct_id} that does not depend on the account that can reset it "
                "(printed backup codes or a security key)?"):
        _warn(f"Not armed: set up a recovery method for {acct_id} that does not depend on it, then arm again.")
        return 1
    picks = _pick_resetters(s, acct_id)

    def change(d: dict) -> None:
        _upsert(d, Account(acct_id, "guided"), None)  # nothing readable, so no baseline
        if entry:
            d["credentials"].setdefault("guided", {})[key] = entry
        d["edges"] += [[p, acct_id] for p in picks if [p, acct_id] not in d["edges"]]

    s.update(change)
    print(f"Armed {acct_id}.")
    print("Guided only: the tool cannot read or watch this account.")
    return 0


def _arm_github(a) -> int:
    from panic.github import GitHub
    if not a.token_file:
        raise CliError("--github needs --token-file FILE.")
    try:
        token = Path(a.token_file).expanduser().read_text().strip()
    except OSError as e:
        raise CliError(f"could not read the token file {a.token_file}: {e.strerror}")
    if not token or any(c.isspace() for c in token):
        raise CliError(f"{a.token_file} should hold the token and nothing else.")
    login = a.github.lower()
    acct_id = f"org:{a.org.lower()}" if a.org else login
    account = Account(acct_id, "github")
    reconnect = bool(a.reconnect)
    if not reconnect and not _yes(f"Do you hold a way to recover {login} that does not depend on {login} itself "
                                  "(printed recovery codes or a security key)?"):
        _warn(f"Not armed: set up a recovery method for {login} that does not depend on it, then arm again.")
        return 1
    s = Session(a) if reconnect else Session(a, create=True)
    existing = next((x for x in s.accounts if x.id == acct_id), None)
    if reconnect and not (existing and existing.provider == "github"):
        raise CliError(f"{acct_id} is not armed. Arm it first, without --reconnect.")
    if existing and (existing.protected or existing.provider != "github"):
        raise CliError(f"{acct_id} is already armed ({'protected, ' if existing.protected else ''}{existing.provider}); refusing to replace it.")
    conn = (a.connectors or {}).get("github") or GitHub({acct_id: token})
    try:
        who = conn.login(acct_id)
        if who.casefold() != login.casefold():
            raise CliError(f"the token belongs to {who}, not {login}; nothing was stored.")
        if a.org and not conn.is_org_admin(account):
            raise CliError(f"{who} is not an active admin of {a.org}; nothing was stored.")
    except CliError:
        raise
    except Exception as e:
        raise CliError(f"could not check the token: {e}")
    if reconnect:
        s.update(lambda d: d["credentials"].setdefault("github", {}).__setitem__(acct_id, token))
        print(f"Reconnected {acct_id}.")
        return 0
    try:
        snap = conn.snapshot(account)
    except Exception as e:
        raise CliError(f"could not read {acct_id}: {e}")
    _print_snapshot(snap)
    if not _yes(f"Is this what {acct_id} should look like when it is safe? Approve it as the baseline?"):
        print("Nothing saved.")
        return 1
    picks = _pick_resetters(s, acct_id)

    def change(d: dict) -> None:
        _upsert(d, account, snap)
        d["credentials"].setdefault("github", {})[acct_id] = token
        d["edges"] += [[p, acct_id] for p in picks if [p, acct_id] not in d["edges"]]

    s.update(change)
    print(f"Armed {acct_id}.")
    return 0


def cmd_arm(a) -> int:
    if a.guided:
        return _arm_guided(a)
    if a.workspace:
        return _arm_workspace(a)
    if a.microsoft_tenant:
        return _arm_microsoft(a)
    if a.github:
        return _arm_github(a)
    if a.personal:
        return _arm_personal(a)
    raise CliError("Give --personal EMAIL, --workspace, --microsoft-tenant TENANT, --github LOGIN or --guided KEY.")


# -- rehearse -----------------------------------------------------------

def cmd_rehearse(a) -> int:
    s = Session(a)
    conns, bad, approved = _connectors(a, s.data), False, {}
    base = s.data["baselines"]
    for acct in s.accounts:
        conn = conns.get(acct.provider)
        if acct.protected or conn is None:
            continue
        if acct.provider == "guided":
            print(f"{acct.id}: guided only, not read")
            continue
        try:
            snap = conn.snapshot(acct)
        except Exception as e:
            print(f"{acct.id}: ERROR {e}")
            bad = True
            continue
        out = executor.outside_baseline(base.get(acct.id, {}), snap)
        if acct.provider in ("google_workspace", "microsoft_365"):
            flags = sorted({o.split(":", 1)[0] for o in out} & set(WORKSPACE_FLAGS))
            flags += [i for i in _redact({acct.id: out}, [acct])[acct.id] if i.startswith(RULE_CATEGORIES)]
            print(f"{acct.id}: " + ("changed since baseline: " + ", ".join(flags) if flags else "no flagged changes"))
            if out and input(f"Accept {acct.id}'s current settings as the new baseline? [y/N] ").strip().lower() in YES:
                approved[acct.id] = snap
        elif not out:
            print(f"{acct.id}: matches the baseline")
        else:
            print(f"{acct.id}: outside the baseline:")
            print("\n".join(f"  - {o}" for o in out))
            if _yes(f"Approve this as the new baseline for {acct.id}?"):
                approved[acct.id] = snap
    print("Plan:")
    print("\n".join(_plan_lines(executor.compile_plan(s.accounts, s.edges, conns))) or "  (no steps)")
    if approved:  # an unchanged rehearsal must not reset saved_at on an exported copy
        def change(d: dict) -> None:
            d["baselines"].update(approved)
            d["released"] = [r for r in d.get("released", []) if r not in approved]  # enforcement resumes
        s.update(change)
    return 1 if bad else 0
