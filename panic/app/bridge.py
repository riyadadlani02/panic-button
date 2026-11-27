"""Runs panic commands in a worker thread with their prompts and output routed to the app, one at a time."""
import builtins
import contextlib
import getpass
import itertools
import sys
import threading
from pathlib import Path

from panic import cli, vault

_routes: dict[int, object] = {}  # thread id -> handler with prompt(text, secret) and write(text)
_real_input, _real_getpass = builtins.input, getpass.getpass
WHOLE_JOB_LOCKED = {"arm", "setup", "release"}  # press takes the lock itself, around the press only


def _input(prompt=""):
    h = _routes.get(threading.get_ident())
    return h.prompt(str(prompt), False) if h else _real_input(prompt)


def _getpass(prompt="Password: ", stream=None):
    h = _routes.get(threading.get_ident())
    return h.prompt(str(prompt), True) if h else _real_getpass(prompt, stream)


class _Out:
    """sys.stdout/stderr: a routed thread writes to its handler, every other thread to the real stream."""

    def __init__(self, stream):
        self._stream = stream

    def write(self, s):
        h = _routes.get(threading.get_ident())
        if h:
            h.write(s)
            return len(s)
        return self._stream.write(s) if self._stream else len(s)  # a windowed app may have no stream

    def flush(self):
        if self._stream:
            self._stream.flush()

    def __getattr__(self, name):
        return getattr(self._stream, name)


def install() -> None:
    """Idempotent; re-wraps a stream someone replaced since (pytest does between tests)."""
    builtins.input, getpass.getpass = _input, _getpass
    for name in ("stdout", "stderr"):
        if not isinstance(getattr(sys, name), _Out):
            setattr(sys, name, _Out(getattr(sys, name)))


@contextlib.contextmanager
def routed(handler):
    install()
    _routes[threading.get_ident()] = handler
    try:
        yield
    finally:
        del _routes[threading.get_ident()]


class Busy(Exception):
    pass


class Job:
    """One `panic.cli.main(argv)` run. A prompt waits until answer() or cancel(); it is never answered by default."""

    def __init__(self, argv, secret=None, lock=None, **main_kwargs):
        self.argv, self._secret, self._lock, self._kw = list(argv), secret, lock, main_kwargs
        self._events: list[dict] = []
        self._cond = threading.Condition()
        self._ids = itertools.count(1)
        self._waiting = self._value = None
        self._cancelled = threading.Event()
        self.done = False

    def start(self) -> "Job":
        threading.Thread(target=self._run, daemon=True).start()
        return self

    def _emit(self, event: dict) -> None:
        with self._cond:
            self._events.append(event)
            self.done = self.done or event["type"] == "done"

    def _sleep(self, seconds: float) -> None:  # the post-press watch wakes on cancel
        if self._cancelled.wait(seconds):
            raise KeyboardInterrupt

    @contextlib.contextmanager
    def _held(self):
        if self._lock is None:
            yield
            return
        if not self._lock.acquire(blocking=False):
            print("Waiting for the guard to finish pressing.")
            while not self._lock.acquire(timeout=0.2):
                if self._cancelled.is_set():
                    raise EOFError
        try:
            yield
        finally:
            self._lock.release()

    def _run(self) -> None:
        code = 1
        with routed(self):
            try:
                with self._held():
                    code = cli.main(self.argv, sleep=self._sleep, **self._kw)
            except (EOFError, KeyboardInterrupt):
                print("Cancelled.", file=sys.stderr)
            except BaseException as e:  # the window must see the end of every job
                print(f"error: {type(e).__name__}: {e}", file=sys.stderr)
        self._emit({"type": "done", "code": code})

    # -- handler, called on the job's thread --

    def write(self, s: str) -> None:
        if s:
            self._emit({"type": "output", "text": s})

    def prompt(self, text: str, secret: bool) -> str:
        if secret and self._secret and (v := self._secret(text)) is not None:
            return v
        with self._cond:
            if self._cancelled.is_set():
                raise EOFError
            pid = self._waiting = next(self._ids)
            self._events.append({"type": "prompt", "id": pid, "text": text, "secret": secret})
            while self._waiting == pid and not self._cancelled.is_set():
                self._cond.wait()
            if self._waiting == pid:  # cancelled
                self._waiting = None
                raise EOFError
            v, self._value = self._value, None
            return v

    # -- app side --

    def events(self, since: int = 0) -> list[dict]:
        with self._cond:
            return list(self._events[since:])

    def answer(self, prompt_id: int, value: str) -> bool:
        """Answers only the prompt waiting now; an old or unknown id changes nothing."""
        with self._cond:
            if self._waiting is None or self._waiting != prompt_id:
                return False
            self._waiting, self._value = None, str(value)
            self._cond.notify_all()
            return True

    def cancel(self) -> None:
        with self._cond:
            self._cancelled.set()
            self._cond.notify_all()


class Runner:
    """At most one Job at a time, against one vault; answers the vault's passphrase prompt itself once unlocked."""

    def __init__(self, vault_path, keyfile, press_lock=None, **main_kwargs):
        self.vault, self.keyfile = str(Path(vault_path).expanduser()), str(Path(keyfile).expanduser())
        self.press_lock = press_lock or threading.Lock()
        self.passphrase: str | None = None
        self.job: Job | None = None
        self._kw = main_kwargs
        self._starting = threading.Lock()

    def unlock(self, passphrase: str) -> None:
        vault.load(Path(self.vault), passphrase, Path(self.keyfile).read_bytes())  # VaultError when wrong
        self.passphrase = passphrase

    def _secret(self, text: str) -> str | None:
        return self.passphrase if text.startswith("Passphrase") else None  # "Choose a passphrase" goes to the page

    def start(self, argv: list[str]) -> Job:
        with self._starting:
            if self.job and not self.job.done:
                raise Busy("busy")
            lock = self.press_lock if argv and argv[0] in WHOLE_JOB_LOCKED else None
            self.job = Job(["--vault", self.vault, "--keyfile", self.keyfile, *argv], secret=self._secret, lock=lock,
                           press_lock=self.press_lock, **self._kw)
            return self.job.start()
