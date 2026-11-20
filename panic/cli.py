"""The `panic` command line: wires the vault, connectors, engine and report together."""
import argparse
import getpass
import json
import os
import shutil
import sys
import time
from dataclasses import asdict, replace
from datetime import datetime, timezone
from pathlib import Path

from panic import executor, google_personal, log, report, vault
from panic.graph import lock_order, resetters
from panic.model import Account, Evidence, Outcome, Phase, Result, Status, Step, Tier, WatchPolicy
from panic.vault import VaultError

DEFAULT_VAULT = "~/.panic/panic.vault"
STALE_DAYS = 30
WATCH_HOURS = 24
# Workspace rehearsal shows these as flags only; their contents are never printed.
WORKSPACE_FLAGS = ("forwarding", "forwarding_addresses", "delegates", "recovery")
YES = ("y", "yes")


class CliError(Exception):
    pass


class _Parser(argparse.ArgumentParser):
    def error(self, message):  # one line, exit code 1
        print(f"error: {message}", file=sys.stderr)
        raise SystemExit(1)


def _warn(msg: str) -> None:
    print(msg, file=sys.stderr)


def _yes(prompt: str) -> bool:
    return input(prompt + " [y/n] ").strip().lower() in YES


def _private_write(path: Path, data: bytes, exclusive: bool = False) -> None:
    flags = os.O_WRONLY | os.O_CREAT | (os.O_EXCL if exclusive else os.O_TRUNC)
    fd = os.open(path, flags, 0o600)
    os.fchmod(fd, 0o600)  # an older, looser file keeps its mode otherwise
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def _guard(what: str, fn) -> None:
    """Run one post-press step; a failure is one warning and never hides the report."""
    try:
        fn()
    except (Exception, KeyboardInterrupt) as e:
        _warn(f"Warning: could not {what}: {e or type(e).__name__}")


def _redact(touched: dict, accounts: list[Account]) -> dict:
    """Org policy: an admin never reads a staff member's filter contents."""
    ws = {a.id for a in accounts if a.provider == "google_workspace"}
    out = {}
    for acct, items in touched.items():
        if acct in ws:
            hidden = [i for i in items if i.startswith("filters:")]
            items = [i for i in items if not i.startswith("filters:")]
            if hidden:
                items.append(f"filters: {len(hidden)} not in baseline (contents withheld)")
        out[acct] = items
    return out


def _dev(path: Path) -> int:
    return (path if path.exists() else path.parent).stat().st_dev


def _same_device(a: Path, b: Path) -> bool:
    return _dev(a) == _dev(b)


class Session:
    """An open vault: keeps passphrase and key in memory for the life of the process."""

    def __init__(self, a, create: bool = False):
        k = a.keyfile or os.environ.get("PANIC_KEYFILE")
        if not k:
            raise CliError("Give --keyfile or set PANIC_KEYFILE.")
        self.path, self.keypath = Path(a.vault).expanduser(), Path(k).expanduser()
        self.log_path = Path(f"{self.path}.log.jsonl")
        self.new = self.new_key = False
        if self.path.exists():
            if not self.keypath.exists():
                raise CliError(f"Key file not found: {self.keypath}")
            self.key = self.keypath.read_bytes()
            self.passphrase = getpass.getpass("Passphrase: ")
            self.data = vault.load(self.path, self.passphrase, self.key)
            if _same_device(self.keypath, self.path):
                _warn("Warning: the key file and the vault are on the same device; keep the key file elsewhere.")
        elif create:
            self.new = True
            self.new_key = not self.keypath.exists()
            self.key = vault.new_keyfile() if self.new_key else self.keypath.read_bytes()
            if len(self.key) != 32:
                raise CliError(f"{self.keypath} is not a valid key file (expected 32 bytes).")
            self.passphrase = getpass.getpass("Choose a passphrase: ")
            if not self.passphrase:
                raise CliError("The passphrase must not be empty.")
            if getpass.getpass("Repeat the passphrase: ") != self.passphrase:
                raise CliError("The passphrases do not match.")
            self.data = {"accounts": [], "edges": [], "baselines": {}, "credentials": {}, "released": []}
        else:
            raise CliError(f"No vault at {self.path}. Run `panic arm` first.")

    @property
    def accounts(self) -> list[Account]:
        return [Account(**x) for x in self.data["accounts"]]

    @property
    def edges(self) -> list[tuple[str, str]]:
        return [tuple(e) for e in self.data["edges"]]

    def save(self) -> None:
        if self.new:
            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.new_key:  # before the vault: a vault without its key file is unopenable
            self.keypath.parent.mkdir(parents=True, exist_ok=True)
            _private_write(self.keypath, self.key, exclusive=True)
        vault.save(self.path, self.data, self.passphrase, self.key)
        if self.new_key:
            print(f"Key file written to {self.keypath}. Move it to a USB stick or second device now; "
                  "the vault cannot be opened without it.")
        self.new = self.new_key = False

    def log(self, entry: dict) -> None:
        if not self.log_path.exists():  # log.append would create it world-readable
            _private_write(self.log_path, b"")
        log.append(self.log_path, entry)

    def upsert(self, account: Account, snap: dict | None) -> None:
        self.data["accounts"] = [x for x in self.data["accounts"] if x["id"] != account.id] + [asdict(account)]
        if snap is not None:
            self.data["baselines"][account.id] = snap


def _connectors(a, s: Session) -> dict:
    if a.connectors is not None:
        return a.connectors
    from panic.google_workspace import Workspace
    cred, out = s.data["credentials"], {}
    if "google_personal" in cred:
        out["google_personal"] = google_personal.Personal(cred["google_personal"])
    if "google_workspace" in cred:
        w = cred["google_workspace"]
        out["google_workspace"] = Workspace(w["sa_info"], w["admin"], w["domain"])
    return out


def _unprotected(s: Session) -> list[str]:
    return [x.id for x in s.accounts if not x.protected]


def outcome_to_json(o: Outcome) -> dict:
    return json.loads(json.dumps(asdict(o)))  # enums become their values


def outcome_from_json(d: dict) -> Outcome:
    def step(x):
        return Step(**{**x, "phase": Phase(x["phase"]), "tier": Tier(x["tier"]), "watch": WatchPolicy(x["watch"])})

    results = [Result(step(r["step"]), Status(r["status"]), Evidence(r["evidence"]) if r["evidence"] else None,
                      r["detail"], r["at"]) for r in d["results"]]
    return Outcome(results, d["touched"], d["started_at"])


def _last_outcome(s: Session) -> Outcome:
    if "last_outcome" not in s.data:
        raise CliError("No press has been recorded yet. Run `panic press` first.")
    return outcome_from_json(s.data["last_outcome"])


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


# -- map / rehearse -----------------------------------------------------

def cmd_map(a) -> int:
    s = Session(a)
    back = [(y, x) for x, y in s.edges]  # reversed, so "resetters" walks forward
    for acct in s.accounts:
        reach = sorted(resetters(acct.id, back))
        print(f"{acct.id}{' (protected)' if acct.protected else ''}: can reset " + (", ".join(reach) or "nothing"))
    ids = _unprotected(s)
    if ids:
        print(f"Can reset the most: {lock_order(ids, s.edges)[0]}")
    return 0


def _plan_lines(plan: list[Step]) -> list[str]:
    return [f"  {st.account}: {st.title} ({st.phase}, {st.tier})" for st in plan]


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


# -- press / watch / report ---------------------------------------------

def _publish_report(s: Session, outcome: Outcome) -> None:
    shown = replace(outcome, touched=_redact(outcome.touched, s.accounts))
    md, data = report.render(shown, time.time())

    def write():
        _private_write(Path(f"{s.path}.report.md"), md.encode())
        _private_write(Path(f"{s.path}.report.json"), json.dumps(data, indent=2).encode())

    _guard("write the report files", write)
    print(md)


def _confirm(step: Step) -> bool:
    print(f"\n{step.account}: {step.title}" + (f"\n  {step.link}" if step.link else ""))
    return _yes("Done?")


def _watch(a, s: Session, outcome: Outcome, conns: dict) -> int:
    hours = WATCH_HOURS - (time.time() - outcome.started_at) / 3600
    if hours <= 0:
        print("The 24-hour watch window has ended.")
        return 0
    released = set(s.data.get("released", []))

    def reload() -> set[str]:
        nonlocal released
        try:
            released = set(vault.load(s.path, s.passphrase, s.key).get("released", []))
        except Exception:
            pass  # keep the last set read
        return released

    print(f"Watching for {hours:.1f} more hours. Press Ctrl-C to stop; resume with `panic watch`.")
    try:
        executor.watch(outcome.results, conns, s.accounts, s.data["baselines"], reload, s.log, hours=hours)
    except KeyboardInterrupt:
        print("Watch stopped. Resume with `panic watch`.")
    finally:  # watch entries moved the log head; keep report's tamper check honest
        try:
            fresh = vault.load(s.path, s.passphrase, s.key)
            fresh["log_head"] = log.head(s.log_path)
            vault.save(s.path, fresh, s.passphrase, s.key)
        except Exception as e:
            _warn(f"Warning: could not update the log checkpoint: {e}")
    return 0


def cmd_press(a) -> int:
    if not (a.user or a.all):
        raise CliError("Say who to lock: --user ID (repeatable) or --all.")
    s = Session(a)
    valid = _unprotected(s)
    ids = [u.lower() for u in a.user]
    wrong = [u for u in ids if u not in valid]
    if wrong:
        raise CliError(f"Not a valid target: {', '.join(wrong)}. Valid ids: {', '.join(valid) or 'none'}.")
    targets = set(valid) if a.all else set(ids)
    saved = datetime.fromisoformat(s.data["saved_at"]) if "saved_at" in s.data else None
    if saved and (datetime.now(timezone.utc) - saved).days > STALE_DAYS:
        _warn(f"Warning: this vault copy is over {STALE_DAYS} days old and may be stale; "
              "more may be removed than you expect.")
    conns, accounts = _connectors(a, s), s.accounts
    plan = executor.compile_plan([x for x in accounts if x.id in targets], s.edges, conns)
    if a.dry_run:
        out = executor.press(plan, accounts, s.edges, conns, s.data["baselines"], _confirm, lambda e: None, dry_run=True)
        print("Dry run: nothing was changed. The press would run:")
        print("\n".join(_plan_lines(plan)) or "  (no steps)")
        for acct, items in _redact(out.touched, accounts).items():
            if items:
                print(f"{acct}: outside the baseline:")
                print("\n".join(f"  - {i}" for i in items))
        return 0
    # press absorbs Ctrl-C and EOF, so everything below still runs after an interrupt.
    out = executor.press(plan, accounts, s.edges, conns, s.data["baselines"], _confirm, s.log)
    def save():
        s.data["last_outcome"] = outcome_to_json(out)
        s.data["log_head"] = log.head(s.log_path)
        s.save()

    _guard("save the outcome to the vault", save)
    _publish_report(s, out)
    return _watch(a, s, out, conns)


def cmd_watch(a) -> int:
    s = Session(a)
    return _watch(a, s, _last_outcome(s), _connectors(a, s))


def cmd_report(a) -> int:
    s = Session(a)
    outcome = _last_outcome(s)
    if not log.verify(s.log_path) or log.head(s.log_path) != s.data.get("log_head", ""):
        _warn("Warning: the audit log has been changed since the last press.")
    _publish_report(s, outcome)
    return 0


# -- release / export ---------------------------------------------------

def cmd_release(a) -> int:
    s = Session(a)
    uid = a.user.lower()
    acct = next((x for x in s.accounts if x.id == uid and not x.protected), None)
    if acct is None:
        raise CliError(f"Not a valid account: {uid}. Valid ids: {', '.join(_unprotected(s)) or 'none'}.")
    conn = _connectors(a, s).get(acct.provider)
    if not hasattr(conn, "release"):
        raise CliError(f"{acct.provider} accounts cannot be released by this tool.")
    if not _yes(f"Release {uid}? This unsuspends it and sets a temporary password."):
        print("Nothing changed.")
        return 1
    try:
        pw = conn.release(acct)
    except Exception as e:
        raise CliError(f"could not release {uid}: {e}")
    s.data["released"] = sorted({*s.data.get("released", []), uid})
    s.save()
    print(f"Released {uid}. Temporary password (shown once): {pw}")
    return 0


def cmd_export(a) -> int:
    s_path, dest = Path(a.vault).expanduser(), Path(a.dest).expanduser()
    k = a.keyfile or os.environ.get("PANIC_KEYFILE")
    if not k or not Path(k).expanduser().exists():
        raise CliError("Give an existing --keyfile (or set PANIC_KEYFILE); it is used to check the copy goes elsewhere.")
    if not s_path.exists():
        raise CliError(f"No vault at {s_path}. Run `panic arm` first.")
    if _same_device(Path(k).expanduser(), dest):
        raise CliError("DEST is on the same device as the key file; a copy there would not protect the vault.")
    shutil.copyfile(s_path, dest)
    os.chmod(dest, 0o600)
    print(f"Vault copied to {dest}.")
    return 0


# -- entry point --------------------------------------------------------

def _parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)  # lets global options follow the command too
    common.add_argument("--vault", default=argparse.SUPPRESS, help=f"vault path (default {DEFAULT_VAULT})")
    common.add_argument("--keyfile", default=argparse.SUPPRESS, help="key file path (or env PANIC_KEYFILE)")
    p = _Parser(prog="panic", description="Lock down connected accounts, root first, and prove it.")
    p.add_argument("--vault", default=DEFAULT_VAULT, help=f"vault path (default {DEFAULT_VAULT})")
    p.add_argument("--keyfile", default=None, help="key file path (or env PANIC_KEYFILE)")
    sub = p.add_subparsers(dest="command", required=True, parser_class=_Parser)

    def add(name, fn, help_):
        sp = sub.add_parser(name, parents=[common], help=help_, description=help_)
        sp.set_defaults(fn=fn)
        return sp

    arm = add("arm", cmd_arm, "Add an account (or a Workspace domain) and record its baseline.")
    arm.add_argument("--personal", metavar="EMAIL")
    arm.add_argument("--client-secrets", metavar="FILE", help="your Google OAuth desktop client file")
    arm.add_argument("--reconnect", action="store_true", help="re-authorise an armed account only")
    arm.add_argument("--workspace", action="store_true")
    arm.add_argument("--sa-key", metavar="FILE", help="Workspace service-account key file")
    arm.add_argument("--admin", metavar="EMAIL", help="protected break-glass admin")
    arm.add_argument("--domain")
    add("map", cmd_map, "Show which accounts can reset which.")
    add("rehearse", cmd_rehearse, "Read every account and show what is outside its baseline.")
    press = add("press", cmd_press, "Lock accounts down, root first, then watch for 24 hours.")
    press.add_argument("--user", action="append", default=[], metavar="ID", help="account to lock (repeatable)")
    press.add_argument("--all", action="store_true", help="every account except protected ones")
    press.add_argument("--dry-run", action="store_true", help="show the plan; change nothing")
    add("watch", cmd_watch, "Resume the 24-hour watch after a press.")
    rel = add("release", cmd_release, "Unsuspend one account with a temporary password.")
    rel.add_argument("--user", required=True, metavar="ID")
    add("report", cmd_report, "Show the report from the last press at the current time.")
    exp = add("export", cmd_export, "Copy the vault file to DEST (a second device).")
    exp.add_argument("dest", metavar="DEST")
    return p


def main(argv: list[str] | None = None, connectors: dict | None = None, authorize=None) -> int:
    try:
        a = _parser().parse_args(argv)
        a.connectors, a.authorize = connectors, authorize or google_personal.authorize
        return a.fn(a)
    except SystemExit as e:  # --help, or a usage error already printed
        return int(e.code or 0)
    except (CliError, VaultError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    except (EOFError, KeyboardInterrupt):
        print("Cancelled.", file=sys.stderr)
        return 1
