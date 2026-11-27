"""What the page calls (window.pywebview.api). pywebview exposes every public name, so only the page's methods are
public; the Runner, the guard and the passphrase stay in underscore attributes and are never returned."""
import json
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from panic import ask, notify, vault
from panic.app import keychain, login_item
from panic.app.bridge import Busy
from panic.app.guard_thread import GuardStopping, GuardThread
from panic.vault import VaultError

PREFS = "~/Library/Application Support/panic-button/prefs.json"  # never the passphrase
JOBS = {"setup": ["setup"], "press_all": ["press", "--all"], "checkup": ["checkup"],
        "checkup_again": ["checkup", "--again"], "report": ["report"]}
FOR_ACCOUNT = {"press_user": "press", "release": "release"}
STAMP = "%Y%m%dT%H%M%SZ"


class Api:
    def __init__(self, runner, *, window=None, keyring=None, guard=GuardThread, prefs=PREFS, home=None, ask=ask,
                 notifier=notify.notify, **main_kwargs):
        self._runner, self._window, self._keyring, self._guard_cls = runner, window, keyring, guard
        self._prefs, self._home, self._ask, self._notifier = Path(prefs).expanduser(), home, ask, notifier
        self._kw = main_kwargs
        self._vault = Path(runner.vault)
        self._passphrase = self._new_passphrase = None
        self._guard = None
        self._remember, self._hidden, self._quitting = True, False, False
        self._last_check = None
        self._accounts, self._accounts_from = [], None
        self._lock = threading.Lock()

    # -- unlock --

    def state(self) -> dict:
        self._after_setup()
        g = self._guard
        return {"unlocked": self._runner.unlocked, "vault_exists": self._vault.exists(), "remember": self._remember,
                "login_item": login_item.installed(self._home),
                "guard": {"running": bool(g and g.running), "stopping": bool(g and g.stopping),
                          "last_check": self._last_check, "questions": len(g.questions()) if g else 0},
                "accounts": self._read_accounts()}

    def unlock(self, passphrase, remember=True) -> dict:
        try:
            self._runner.unlock(passphrase)
        except VaultError as e:
            return {"ok": False, "error": str(e)}
        except OSError as e:
            if Path(self._runner.keyfile).exists():
                return {"ok": False, "error": f"Could not open the vault: {e.strerror or e}"}
            return {"ok": False, "error": f"The key file was not found at {self._runner.keyfile}. "
                                          "Plug in the drive that holds it, then try again."}
        self._remember = bool(remember)
        out = {"ok": True}
        try:
            if self._remember:
                keychain.set(self._vault, passphrase, self._keyring)
            else:
                keychain.delete(self._vault, self._keyring)
        except Exception as e:  # unlocked all the same; the page shows only ok
            out["note"] = f"The Keychain was not updated: {type(e).__name__}"
        self._opened(passphrase)
        return out

    def forget_mac(self) -> dict:
        keychain.delete(self._vault, self._keyring)
        self._remember = False
        return {"ok": True}

    def _launch(self) -> None:
        """At start: unlock silently from the Keychain, and guard unless the owner switched the guard off."""
        if not self._vault.exists():
            return
        try:
            pw = keychain.get(self._vault, self._keyring)
            if pw is None:
                return
            self._runner.unlock(pw)
        except Exception:  # a stale entry or a missing key file: the page asks
            return
        self._opened(pw)

    def _opened(self, passphrase) -> None:
        with self._lock:
            self._passphrase = passphrase
            if self._guard is None:
                self._guard = self._guard_cls(self._runner.vault, self._runner.keyfile, passphrase,
                                              on_question=self._on_question, on_notice=self._notifier,
                                              press_lock=self._runner.press_lock, now=self._checked, **self._kw)
        if self._pref("guard", True):
            self.guard_start()

    def _read_accounts(self) -> list[dict]:
        """Read from the vault itself; decrypted again only when the file changes."""
        if not self._runner.unlocked:
            return []
        try:
            st = self._vault.stat()
            if (st.st_mtime_ns, st.st_size) != self._accounts_from:
                d = vault.load(self._vault, self._passphrase, Path(self._runner.keyfile).read_bytes())
                self._accounts = [{"id": a["id"], "provider": a["provider"],
                                   "kind": "protected" if a.get("protected") else
                                   "checklist" if a["provider"] == "guided" else "guarded"} for a in d["accounts"]]
                self._accounts_from = (st.st_mtime_ns, st.st_size)
        except (OSError, VaultError):
            pass  # key file unplugged: the last list read
        return self._accounts

    # -- jobs --

    def start_job(self, kind, extra=None) -> dict:
        if kind in JOBS:
            argv = JOBS[kind]
        elif kind in FOR_ACCOUNT and isinstance(extra, str) and extra:
            argv = [FOR_ACCOUNT[kind], f"--user={extra}"]  # one token: an id can never read as an option
        elif kind in FOR_ACCOUNT:
            return {"ok": False, "error": "Choose an account first."}
        else:
            return {"ok": False, "error": "unknown job"}
        if not self._runner.unlocked and kind != "setup":
            return {"ok": False, "error": "Unlock panic button first."}
        try:
            self._runner.start(argv)
        except Busy:  # a running setup keeps the passphrase it was given
            return {"ok": False, "error": "busy"}
        self._new_passphrase = None
        return {"ok": True}

    def job_events(self, since=0) -> list[dict]:
        job = self._runner.job
        events = job.events(int(since)) if job else []
        self._after_setup()
        return events

    def job_answer(self, prompt_id, value) -> bool:
        job = self._runner.job
        if not job:
            return False
        asked = next((e for e in job.events() if e["type"] == "prompt" and e["id"] == prompt_id), None)
        ok = job.answer(prompt_id, value)
        if ok and asked and asked["secret"] and asked["text"].startswith("Choose a passphrase"):
            self._new_passphrase = value  # a vault created by setup opens with it once the job ends
        return ok

    def job_cancel(self) -> dict:
        if self._runner.job:
            self._runner.job.cancel()
        return {"ok": True}

    def _after_setup(self) -> None:
        job, pw = self._runner.job, self._new_passphrase
        if pw is None or not job or not job.done:
            return
        self._new_passphrase = None
        if not self._runner.unlocked and self._vault.exists():
            self.unlock(pw, self._remember)

    # -- guard --

    def guard_start(self) -> dict:
        if not self._guard:
            return {"ok": False, "error": "Unlock panic button first."}
        self._set_pref("guard", True)
        try:
            self._guard.start()
        except GuardStopping as e:
            return {"ok": False, "error": str(e)}
        for _ in range(10):  # a guard that ends at once (another one runs for this vault) says why
            if not self._guard.running:
                lines = "".join(self._guard.output).strip().splitlines()
                return {"ok": False, "error": lines[-1] if lines else "The guard stopped."}
            time.sleep(0.05)
        return {"ok": True}

    def guard_stop(self) -> dict:
        self._set_pref("guard", False)
        if self._guard:
            self._guard.stop()
        return {"ok": True}

    def questions(self) -> list[dict]:
        return self._guard.questions() if self._guard else []

    def answer_question(self, handle, answer) -> bool:
        return bool(self._guard and answer in ("accept", "lock") and self._guard.answer(handle, answer))

    def _checked(self) -> float:
        self._last_check = time.time()
        return self._last_check

    def _on_question(self, q) -> None:
        if self._hidden:
            self._dialog(q)

    def _dialog(self, q) -> None:
        """The macOS dialog, while the window is hidden; its answer reaches the guard like the page's."""
        def run():
            proc = self._ask.open_dialog(f"panic: {q['account']}", q["text"], q["deadline"] - time.time())
            if proc is None:
                return
            while (r := self._ask.answer(proc)) is None:
                time.sleep(0.5)
            if r in ("accept", "lock"):
                self._guard.answer(q["handle"], r)
        threading.Thread(target=run, daemon=True).start()

    # -- reports --

    def _report_files(self) -> dict[str, Path]:
        if not self._runner.unlocked:
            return {}
        return {p.name: p for p in self._vault.parent.glob(f"{self._vault.name}.report-*.md")}

    def reports(self) -> list[dict]:
        out = []
        for name in self._report_files():
            try:
                when = datetime.strptime(name.split(".report-")[-1][:-3], STAMP).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
            out.append({"name": name, "when": when.strftime("%Y-%m-%dT%H:%M:%SZ")})
        return sorted(out, key=lambda r: r["when"])

    def report(self, name) -> str:
        p = self._report_files().get(name)
        return p.read_text() if p else ""

    # -- app --

    def set_login_item(self, on) -> dict:
        (login_item.install if on else login_item.remove)(self._home)
        return {"ok": True}

    def quit(self, keep_guarding) -> dict:
        if keep_guarding:
            self._hidden = True
            for q in self.questions():
                self._dialog(q)
            self._window.hide()
            return {"ok": True}
        self._quitting = True
        if self._runner.job:
            self._runner.job.cancel()
        if self._guard:
            self._guard.stop()
        # ponytail: waits as long as an in-flight press takes; the guard's own lock wait ends on the stop
        with self._runner.press_lock:
            self._window.destroy()
        return {"ok": True}

    def _show(self) -> None:
        """The Dock icon was clicked."""
        self._hidden = False
        self._window.show()

    def _closing(self) -> bool:
        """The window's close button or Cmd-Q: the page asks whether to keep guarding."""
        if self._quitting:
            return True
        if self._hidden:
            self._show()
        threading.Thread(target=self._window.evaluate_js, args=("openModal('o-quit')",), daemon=True).start()
        return False

    def _pref(self, key, default):
        try:
            return json.loads(self._prefs.read_text()).get(key, default)
        except (OSError, ValueError):
            return default

    def _set_pref(self, key, value) -> None:
        try:
            d = json.loads(self._prefs.read_text())
        except (OSError, ValueError):
            d = {}
        d[key] = value
        self._prefs.parent.mkdir(parents=True, exist_ok=True)
        self._prefs.write_text(json.dumps(d))
