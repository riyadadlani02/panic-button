"""What the page calls (window.pywebview.api). Only the CONTRACT methods are handed to window.expose (see __main__),
never the object, so the page cannot walk to the Runner, the guard or the passphrase."""
import functools
import json
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from panic import ask, notify
from panic.app import keychain, login_item
from panic.app.bridge import Busy
from panic.app.guard_thread import GuardStopping, GuardThread
from panic.vault import VaultError

CONTRACT = ("state", "unlock", "forget_mac", "start_job", "job_events", "job_answer", "job_cancel", "guard_start",
            "guard_stop", "questions", "answer_question", "reports", "report", "set_login_item", "quit")
PREFS = "~/Library/Application Support/panic-button/prefs.json"  # never the passphrase
JOBS = {"setup": ["setup"], "press_all": ["press", "--all"], "checkup": ["checkup"],
        "checkup_again": ["checkup", "--again"], "report": ["report"]}
FOR_ACCOUNT = {"press_user": "press", "release": "release"}
STAMP = "%Y%m%dT%H%M%SZ"


def _says_errors(fn):
    """The page gets {ok: false, error} instead of a Python exception."""
    @functools.wraps(fn)
    def wrapper(*a, **kw):
        try:
            return fn(*a, **kw)
        except Exception as e:
            return {"ok": False, "error": f"{type(e).__name__}: {e}"}
    return wrapper


class Api:
    def __init__(self, runner, *, window=None, keyring=None, guard=GuardThread, prefs=PREFS, home=None, ask=ask,
                 notifier=notify.notify, **main_kwargs):
        self._runner, self._window, self._keyring, self._guard_cls = runner, window, keyring, guard
        self._prefs, self._home, self._ask, self._notifier = Path(prefs).expanduser(), home, ask, notifier
        self._kw = main_kwargs
        self._vault = Path(runner.vault)
        self._new_passphrase = None  # a vault being created by setup; the Runner holds the unlocked one
        self._guard = None
        self._asked: set = set()  # questions with a macOS dialog open
        self._remember, self._hidden, self._quitting = True, False, False
        self._last_check = None
        self._notice = None  # said on the unlock screen, e.g. a key file missing at launch
        self._accounts, self._accounts_from = [], None
        self._lock = threading.Lock()

    # -- unlock --

    def state(self) -> dict:
        self._after_setup()
        g = self._guard
        return {"unlocked": self._runner.unlocked, "vault_exists": self._vault.exists(), "remember": self._remember,
                "login_item": login_item.installed(self._home), "notice": self._notice,
                "guard": {"running": bool(g and g.running), "stopping": bool(g and g.stopping),
                          "last_check": self._last_check, "questions": len(g.questions()) if g else 0,
                          "error": g.error if g else None},
                "accounts": self._read_accounts()}

    @_says_errors
    def unlock(self, passphrase, remember=True) -> dict:
        try:
            self._runner.unlock(passphrase)
        except VaultError as e:
            return {"ok": False, "error": str(e)}
        except OSError as e:
            if Path(self._runner.keyfile).exists():
                return {"ok": False, "error": f"Could not open the vault: {e.strerror or e}"}
            return {"ok": False, "error": self._no_key()}
        self._remember, self._notice = bool(remember), None
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

    @_says_errors
    def forget_mac(self) -> dict:
        keychain.delete(self._vault, self._keyring)
        self._remember = False
        return {"ok": True}

    def _no_key(self) -> str:
        return f"The key file was not found at {self._runner.keyfile}. Plug in the drive that holds it, then try again."

    def _launch(self) -> None:
        """At start: unlock silently from the Keychain, and guard unless the owner switched the guard off."""
        if not self._vault.exists():
            return
        if not Path(self._runner.keyfile).exists():
            self._notice = self._no_key()
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
                d = self._runner.read()
                self._accounts = [{"id": a["id"], "provider": a["provider"],
                                   "kind": "protected" if a.get("protected") else
                                   "checklist" if a["provider"] == "guided" else "guarded"} for a in d["accounts"]]
                self._accounts_from = (st.st_mtime_ns, st.st_size)
        except (OSError, VaultError):
            pass  # key file unplugged: the last list read
        return self._accounts

    # -- jobs --

    @_says_errors
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
        # A running guard re-applies the press on every pass; the job's own 24-hour watch would hold the window.
        watch = kind not in ("press_all", "press_user") or not (self._guard and self._guard.running)
        try:
            self._runner.start(argv, watch=watch)
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
            with self._lock:
                self._new_passphrase = value  # a vault created by setup opens with it once the job ends
        return ok

    @_says_errors
    def job_cancel(self) -> dict:
        if self._runner.job:
            self._runner.job.cancel()
        return {"ok": True}

    def _after_setup(self) -> None:
        with self._lock:  # two polls must not both take it
            job, pw = self._runner.job, self._new_passphrase
            if pw is None or not job or not job.done:
                return
            self._new_passphrase = None
        if not self._runner.unlocked and self._vault.exists():
            self.unlock(pw, self._remember)

    # -- guard --

    @_says_errors
    def guard_start(self) -> dict:
        if not self._guard:
            return {"ok": False, "error": "Unlock panic button first."}
        try:
            self._guard.start()
        except GuardStopping as e:
            return {"ok": False, "error": str(e)}
        for _ in range(10):  # a guard that ends at once (another one runs for this vault) says why
            if not self._guard.running:
                lines = "".join(self._guard.output).strip().splitlines()
                return {"ok": False, "error": lines[-1] if lines else "The guard stopped."}
            time.sleep(0.05)
        self._set_pref("guard", True)
        return {"ok": True}

    @_says_errors
    def guard_stop(self) -> dict:
        if self._guard:
            self._guard.stop()
        self._set_pref("guard", False)  # after the stop: a failed save never leaves the guard running
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
        with self._lock:
            if q["handle"] in self._asked:
                return
            self._asked.add(q["handle"])

        def still_open():
            return any(x["handle"] == q["handle"] for x in self._guard.questions())

        def run():
            try:
                proc = self._ask.open_dialog(f"panic: {q['account']}", q["text"], q["deadline"] - time.time())
                if proc is None:
                    return
                while (r := self._ask.answer(proc)) is None:
                    if not still_open():  # answered in the window, or past its deadline
                        self._ask.close(proc)
                        return
                    time.sleep(0.5)
                if r in ("accept", "lock"):
                    self._guard.answer(q["handle"], r)
            finally:
                with self._lock:
                    self._asked.discard(q["handle"])
        threading.Thread(target=run, daemon=True).start()

    # -- reports --

    def _report_files(self) -> dict[str, Path]:
        if not self._runner.unlocked:
            return {}
        return {p.name: p for p in self._vault.parent.glob(f"{self._vault.name}.report-*.md")}

    @_says_errors
    def reports(self) -> list[dict]:
        out = []
        for name in self._report_files():
            try:
                when = datetime.strptime(name.split(".report-")[-1][:-3], STAMP).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
            out.append({"name": name, "when": when.strftime("%Y-%m-%dT%H:%M:%SZ")})
        return sorted(out, key=lambda r: r["when"])

    @_says_errors
    def report(self, name) -> str:
        p = self._report_files().get(name)
        return p.read_text() if p else ""

    # -- app --

    @_says_errors
    def set_login_item(self, on) -> dict:
        (login_item.install if on else login_item.remove)(self._home)
        return {"ok": True}

    @_says_errors
    def quit(self, keep_guarding) -> dict:
        if keep_guarding:
            self._hidden = True
            for q in self.questions():
                self._dialog(q)
            self._window.hide()
            return {"ok": True}
        job = self._runner.job
        if job:
            job.cancel()
        if self._guard:
            while not self._guard.stop():  # a pass ends only between steps, so a quit never cuts one short
                pass
        # ponytail: waits as long as an in-flight press takes. Other jobs (setup may wait on a browser sign-in) are
        # only cancelled, so quit never hangs on them.
        while job and not job.done and job.argv[4] in ("press", "release"):
            time.sleep(0.1)
        with self._runner.press_lock:
            self._quitting = True  # only now may the window close: a second close before this would kill the press
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
        threading.Thread(target=self._window.evaluate_js, args=("askQuit()",), daemon=True).start()
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
