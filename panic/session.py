"""Shared command-line plumbing: the open vault, private files, redaction and outcome (de)serialisation."""
import fcntl
import getpass
import json
import os
import sys
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import asdict
from pathlib import Path

from panic import google_personal, log, vault
from panic.model import Account, Evidence, Outcome, Phase, Result, Status, Step, Tier, WatchPolicy

YES = ("y", "yes")
ORG_PROVIDERS = {"google_workspace", "microsoft_365", "slack"}
RULE_CATEGORIES = ("filters", "inbox_rules")
WATCH_HOURS = 24


class CliError(Exception):
    pass


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


def _redact(touched: dict, accounts: list[Account]) -> dict:
    """Org policy: an admin never reads a staff member's filter contents."""
    org = {a.id for a in accounts if a.provider in ORG_PROVIDERS}
    out = {}
    for acct, items in touched.items():
        if acct in org:
            for cat in RULE_CATEGORIES:
                hidden = [i for i in items if i.startswith(f"{cat}:")]
                items = [i for i in items if not i.startswith(f"{cat}:")]
                if hidden:
                    items.append(f"{cat}: {len(hidden)} not in baseline (contents withheld)")
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

    def update(self, change: Callable[[dict], None]) -> None:
        """Reload, apply this writer's change, save: keys another process saved meanwhile survive."""
        if self.new:
            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with self._locked():
            if self.new:
                if self.path.exists():  # another command created it first; saving would erase its accounts
                    raise CliError(f"A vault appeared at {self.path} meanwhile; nothing was saved. Run the command again.")
                change(self.data)
                self._create()
                return
            fresh = vault.load(self.path, self.passphrase, self.key)
            change(fresh)
            vault.save(self.path, fresh, self.passphrase, self.key)
            self.data = fresh

    @contextmanager
    def _locked(self):
        # The whole reload-change-save holds it, so two commands never overwrite each other's change.
        fd = os.open(f"{self.path}.lock", os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)  # releases the lock

    def _create(self) -> None:
        if self.new_key:  # before the vault: a vault without its key file is unopenable
            self.keypath.parent.mkdir(parents=True, exist_ok=True)
            _private_write(self.keypath, self.key, exclusive=True)
        vault.save(self.path, self.data, self.passphrase, self.key)
        if self.new_key:
            print(f"Key file written to {self.keypath}. Move it to a USB stick or second device now; "
                  "the vault cannot be opened without it.")
        self.new = self.new_key = False

    def log(self, entry: dict) -> None:
        if entry.get("removed"):
            acct, items = entry.get("account"), entry["removed"]
            try:  # the vault keeps them whole so `panic removed` can hand them back
                self.update(lambda d: d.setdefault("watch_removed", {}).setdefault(acct, []).extend(items))
            except Exception as e:  # the log line matters more than the vault copy
                entry = {**entry, "detail": f"{entry.get('detail', '')}; could not save the removed items: {e}"}
            entry = {**entry, "removed": _redact({acct: items}, self.accounts)[acct]}
        if not self.log_path.exists():  # log.append would create it world-readable
            _private_write(self.log_path, b"")
        log.append(self.log_path, entry)


def _upsert(d: dict, account: Account, snap: dict | None) -> None:
    d["accounts"] = [x for x in d["accounts"] if x["id"] != account.id] + [asdict(account)]
    if snap is not None:
        d["baselines"][account.id] = snap


def _connectors(a, data: dict, s: "Session | None" = None) -> dict:
    if a.connectors is not None:
        return a.connectors
    from panic.google_workspace import Workspace
    cred, out = data["credentials"], {}
    if "google_personal" in cred:
        out["google_personal"] = google_personal.Personal(cred["google_personal"])
    if "microsoft_personal" in cred:
        from panic.microsoft_personal import MicrosoftPersonal

        def save(acct: str, token: dict) -> None:  # msal rotates refresh tokens; the vault must keep the new one
            s.update(lambda d: d["credentials"]["microsoft_personal"].__setitem__(acct, token))
        out["microsoft_personal"] = MicrosoftPersonal(cred["microsoft_personal"], on_refresh=s and save)
    if "google_workspace" in cred:
        w = cred["google_workspace"]
        out["google_workspace"] = Workspace(w["sa_info"], w["admin"], w["domain"])
    if "microsoft_365" in cred:
        from panic.microsoft_365 import Microsoft365
        out["microsoft_365"] = Microsoft365(cred["microsoft_365"])
    if "slack" in cred:
        from panic.slack import Slack
        out["slack"] = Slack(cred["slack"])
    if "github" in cred:
        from panic.github import GitHub
        out["github"] = GitHub(cred["github"])
    if any(x["provider"] == "guided" for x in data["accounts"]):
        from panic.guided import Guided
        out["guided"] = Guided(cred.get("guided"))
    if s is not None:
        s.conns_from = _built_from(data)
    return out


def _built_from(d: dict) -> tuple:
    return d["credentials"], sorted((x["id"], x["provider"]) for x in d["accounts"])


def _reload(a, s: Session, conns: dict, last: dict) -> dict:
    """The vault as saved now (the last good copy if it cannot be read); connectors refreshed in place.

    Rebuilt only when what they were built from changed, so a connector's own cache (GitHub's hourly
    repository reads) outlives a pass."""
    try:
        fresh = vault.load(s.path, s.passphrase, s.key)
    except Exception:
        return last
    if _built_from(fresh) == getattr(s, "conns_from", None):
        return fresh
    new = _connectors(a, fresh, s)
    if new is not conns:
        conns.clear()
        conns.update(new)
    return fresh


def _recent_results(outcomes: list[Outcome], now: float) -> list[Result]:
    """Results of presses inside the watch window; a later press wins, unless it would unwatch a lock."""
    latest: dict[tuple[str, str], Result] = {}
    for o in outcomes:
        if now - o.started_at < WATCH_HOURS * 3600:
            for r in o.results:
                k = (r.step.account, r.step.action)
                if r.status is Status.LOCKED or k not in latest or latest[k].status is not Status.LOCKED:
                    latest[k] = r
    return list(latest.values())


def _unprotected(s: Session) -> list[str]:
    return [x.id for x in s.accounts if not x.protected]


def outcome_to_json(o: Outcome) -> dict:
    return json.loads(json.dumps(asdict(o)))  # enums become their values


def outcome_from_json(d: dict) -> Outcome:
    def step(x):
        return Step(**{**x, "phase": Phase(x["phase"]), "tier": Tier(x["tier"]), "watch": WatchPolicy(x["watch"])})

    results = [Result(step(r["step"]), Status(r["status"]), Evidence(r["evidence"]) if r["evidence"] else None,
                      r["detail"], r["at"]) for r in d["results"]]
    return Outcome(results, d["touched"], d["started_at"], d.get("removed", {}), d.get("triggers", []))


def _outcomes(s: Session) -> list[Outcome]:
    return [outcome_from_json(x) for x in s.data.get("outcomes", [])]


def _last_outcome(s: Session) -> Outcome:
    if not s.data.get("outcomes"):
        raise CliError("No press has been recorded yet. Run `panic press` first.")
    return _outcomes(s)[-1]


def _record_outcome(d: dict, o: Outcome) -> None:
    """Adds a press to the vault's list, or replaces its own earlier checkpoint."""
    entry, rest = outcome_to_json(o), d.setdefault("outcomes", [])
    j = next((k for k, x in enumerate(rest) if x["started_at"] == o.started_at), None)
    if j is None:
        rest.append(entry)
    else:
        rest[j] = entry
