"""`panic guard` in a background thread, with its questions answered in the app instead of a macOS dialog."""
import collections
import itertools
import threading
import time
from pathlib import Path

from panic import cli
from panic.app.bridge import routed

ANSWERS = ("accept", "lock", "none")  # "none": dismissed, as a dialog closed without a button


class GuardStopping(Exception):
    pass


class _Asker:
    """The guard's dialog protocol (panic.ask): open_dialog returns a handle, answer(handle) polls it."""

    def __init__(self, on_question):
        self.on_question, self.open = on_question, {}
        self._ids, self._lock = itertools.count(1), threading.Lock()

    def open_dialog(self, title: str, text: str, seconds: float):
        q = {"handle": next(self._ids), "account": title.removeprefix("panic: "), "text": text,
             "deadline": time.time() + max(1, seconds), "answer": None}
        with self._lock:
            self.open[q["handle"]] = q
        self.on_question(self.shown(q))
        return q["handle"]

    @staticmethod
    def shown(q: dict) -> dict:
        return {k: q[k] for k in ("handle", "account", "text", "deadline")}

    def answer(self, handle):
        with self._lock:
            q = self.open.get(handle)
            if q is None:
                return "none"
            if q["answer"] is None and time.time() < q["deadline"]:
                return None
            del self.open[handle]
            return q["answer"] or "none"  # past the deadline unanswered: a dialog that gave up


class _StoppableLock:
    """The shared press lock, as the guard waits for it: a stop request ends the wait."""

    def __init__(self, lock, stop):
        self._lock, self._stop = lock, stop

    def __enter__(self):
        while not self._lock.acquire(timeout=0.2):
            if self._stop.is_set():
                raise KeyboardInterrupt  # cmd_guard un-marks the targets, then stops

    def __exit__(self, *exc):
        self._lock.release()


class GuardThread:
    def __init__(self, vault, keyfile, passphrase, on_question=lambda q: None, on_notice=lambda title, text: None,
                 press_lock=None, **main_kwargs):
        self.vault, self.keyfile = str(Path(vault).expanduser()), str(Path(keyfile).expanduser())
        self._passphrase, self.on_notice, self._kw = passphrase, on_notice, main_kwargs
        self.press_lock = press_lock or threading.Lock()
        self._asker = _Asker(on_question)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.output: collections.deque[str] = collections.deque(maxlen=2000)
        self.code: int | None = None
        self.error: str | None = None  # why the guard ended when nobody stopped it

    @property
    def _alive(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    @property
    def running(self) -> bool:
        return self._alive and not self._stop.is_set()

    @property
    def stopping(self) -> bool:
        """Asked to stop, still finishing a pass: shown as off, cannot be started yet."""
        return self._alive and self._stop.is_set()

    def start(self, timeout: float = 3) -> None:
        if self.running:
            return
        if self.stopping:
            self._thread.join(timeout)
            if self._alive:
                raise GuardStopping("The guard is still finishing a pass; start it again in a moment.")
        self._stop.clear()
        self.code = self.error = None
        with self._asker._lock:  # a new run reopens its questions from the vault
            self._asker.open.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 3) -> bool:
        """True once the guard has ended. A pass in progress finishes first; its questions close now and reopen
        from the vault on the next start, since nothing would read an answer given meanwhile."""
        with self._asker._lock:
            self._stop.set()
            self._asker.open.clear()
        if self._thread:
            self._thread.join(timeout)
        return not self._alive

    def questions(self) -> list[dict]:
        with self._asker._lock:
            if not self.running:
                return []
            return [self._asker.shown(q) for q in self._asker.open.values()
                    if q["answer"] is None and q["deadline"] > time.time()]

    def answer(self, handle, value: str) -> bool:
        if value not in ANSWERS:
            raise ValueError(f"answer must be one of {', '.join(ANSWERS)}")
        with self._asker._lock:
            q = self._asker.open.get(handle)
            if not self.running or q is None or q["answer"] is not None or q["deadline"] <= time.time():
                return False
            q["answer"] = value
            return True

    def _sleep(self, seconds: float) -> None:  # cmd_guard ends on KeyboardInterrupt with "Guard stopped."
        if self._stop.wait(seconds):
            raise KeyboardInterrupt

    def _run(self) -> None:
        try:
            with routed(self):
                self.code = cli.main(["--vault", self.vault, "--keyfile", self.keyfile, "guard"], asker=self._asker,
                                     notifier=self.on_notice, sleep=self._sleep,
                                     press_lock=_StoppableLock(self.press_lock, self._stop), **self._kw)
        except Exception as e:
            self.output.append(f"{type(e).__name__}: {e}\n")
        finally:
            if not self._stop.is_set():  # ended on its own: the owner thinks it still guards
                lines = "".join(self.output).strip().splitlines()
                self.error = lines[-1].removeprefix("error: ").rstrip(".") if lines else "it ended"
                self.on_notice("panic: guard", f"The guard stopped: {self.error}. Open panic button to start it.")

    # -- handler, called on the guard's thread --

    def _write(self, s: str) -> None:
        self.output.append(s)

    def _prompt(self, text: str, secret: bool) -> str:
        if secret and text.startswith("Passphrase"):
            return self._passphrase
        raise EOFError  # the guard asks nothing else; never answered by default
