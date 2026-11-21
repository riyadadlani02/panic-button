"""Sandbox demo: the real vault, engine and `panic` commands against a simulated provider.

No network and no real account. Run: PYTHONPATH=. uv run python demo/sandbox_demo.py
"""
import builtins
import getpass
import itertools
import tempfile
from dataclasses import replace
from pathlib import Path

from panic import executor, log, session, vault
from panic.cli import main
from panic.model import Phase, Step, Tier, WatchPolicy
from panic.signals import drift

MAIL, BANK, SOCIAL, ADMIN, OLD = "mail@demo.test", "bank@demo.test", "social@demo.test", "admin@demo.test", "old@elsewhere.test"

STEPS = [
    Step("", "sign_out", Phase.FREEZE, Tier.API, "Sign out every device", lingers_s=3600),
    Step("", "forwarding", Phase.FREEZE, Tier.API, "Remove forwarding not in the baseline", watch=WatchPolicy.REAPPLY,
         after_read=True),
    Step("", "filters", Phase.PURGE, Tier.API, "Remove filters not in the baseline", watch=WatchPolicy.REAPPLY),
    Step("", "apps", Phase.PURGE, Tier.API, "Revoke connected apps", watch=WatchPolicy.REPORT, lingers_s=3600),
    Step("", "password", Phase.PURGE, Tier.GUIDED, "Change your password now.", link="https://example.test/password"),
]


class SimProvider:
    """An in-memory mail provider. `down` accounts raise, like a provider that cannot be reached."""
    provider = "sim"

    def __init__(self, accounts):
        self.state = {a: {"sessions": 1, "forwarding": [], "filters": ["label: newsletters"], "apps": []} for a in accounts}
        self.down = set()

    def _acct(self, account_id):
        if account_id in self.down:
            raise RuntimeError("provider unreachable")
        return self.state[account_id]

    def catalog(self, account):
        return [replace(s, account=account.id) for s in STEPS]

    def snapshot(self, account):
        s = self._acct(account.id)
        return {k: list(s[k]) for k in ("forwarding", "filters", "apps")}

    def signals(self, account, snapshot, baseline):
        # New forwarding is the one thing this provider treats as a takeover; other changes are notices.
        return drift(account.id, baseline, snapshot, lambda cat, item: "forwarding_added" if cat == "forwarding" else None)

    def run(self, step, baseline):
        s = self._acct(step.account)
        if step.action == "sign_out":
            s["sessions"] = 0
        elif step.action in ("forwarding", "filters"):
            s[step.action] = [x for x in s[step.action] if x in baseline[step.action]]  # KeyError = no baseline
        elif step.action == "apps":
            s["apps"] = []

    def check(self, step, baseline):
        s = self._acct(step.account)
        if step.action in ("forwarding", "filters"):
            return all(x in baseline[step.action] for x in s[step.action])
        if step.action == "apps":
            return s["apps"] == []
        return None  # sign_out and password have no read-back


def say(text):
    print(f"\n\033[1m=== {text} ===\033[0m")


def demo():
    tmp = Path(tempfile.mkdtemp(prefix="panic-demo-"))
    vpath, kpath = tmp / "panic.vault", tmp / "panic.key"
    sim = SimProvider([MAIL, BANK, SOCIAL])

    # Scripted owner: passphrase from memory, "y" to every step, "n" to absorbing changes into a baseline.
    getpass.getpass = lambda prompt="": "demo passphrase"
    def answer(prompt=""):
        reply = "n" if "baseline" in prompt.lower() else "y"
        print(f"{prompt}{reply}")
        return reply
    builtins.input = answer
    session._same_device = lambda a, b: False  # the demo keeps vault and key in one temp folder

    def panic(*args, **kw):
        print(f"\n$ panic {' '.join(args)}")
        return main(["--vault", str(vpath), "--keyfile", str(kpath), *args], connectors={"sim": sim}, **kw)

    say("1. Arm: record each account's known-good settings (written straight to the vault; this simulated provider has no `panic arm` form)")
    key = vault.new_keyfile()
    kpath.write_bytes(key)
    vault.save(vpath, {
        "accounts": [{"id": MAIL, "provider": "sim", "protected": False},
                     {"id": BANK, "provider": "sim", "protected": False},
                     {"id": SOCIAL, "provider": "sim", "protected": False},
                     {"id": OLD, "provider": "none", "protected": False},     # no connector exists for it
                     {"id": ADMIN, "provider": "sim", "protected": True}],   # break-glass: never touched
        "edges": [[MAIL, BANK], [MAIL, SOCIAL], [OLD, BANK]],
        "baselines": {a: sim.snapshot(type("A", (), {"id": a})) for a in (MAIL, BANK, SOCIAL)},
        "credentials": {}, "released": [],
    }, "demo passphrase", key)
    print(f"Vault: {vpath}\nKey file: {kpath}")
    panic("map")

    say("2. The attack: forwarding, a hiding filter and a rogue app on the root mailbox")
    sim.state[MAIL].update(sessions=3, forwarding=["thief@evil.test"],
                           filters=["label: newsletters", "from:bank -> delete"], apps=["Totally Legit Sync"])
    sim.down.add(SOCIAL)  # one provider is unreachable during the incident
    print(sim.state[MAIL])

    say("3. Dry run: what a press would do, with nothing changed")
    panic("press", "--all", "--dry-run")
    print("\nState after the dry run (unchanged):", sim.state[MAIL])

    say("4. PRESS")
    real_watch, ticks, struck = executor.watch, itertools.count(), []

    def short_watch(results, conns, accounts, baselines, released, log_, hours=24, **_):
        def sleep(_s):  # between pass 1 and pass 2 the attacker comes back
            if not struck:
                struck.append(1)
                sim.state[MAIL]["forwarding"].append("thief2@evil.test")
                print("\n[attacker re-adds forwarding to thief2@evil.test during the watch]")
        return real_watch(results, conns, accounts, baselines, released, log_,
                          hours=3 / 3600, interval_s=0, sleep=sleep, now=lambda: next(ticks))

    executor.watch = short_watch  # two passes instead of 24 hours
    panic("press", "--all")
    executor.watch = real_watch
    print("\nState after the press and watch:", sim.state[MAIL])

    say("5. Afterwards: the report re-rendered from the vault, and what was removed")
    panic("report")
    print("\nNote the \"Put back during the watch\" section: the re-added forwarding, and when the watch removed it.")
    panic("removed", "--user", MAIL)

    say("6. The guard: the attacker returns while `panic guard` is running, and it presses by itself")
    sim.down.clear()  # the unreachable provider is back
    pressed_before = len(vault.load(vpath, "demo passphrase", key)["outcomes"])

    def attacker_between_passes(_seconds):  # stands in for the 30 s pause between guard passes
        sim.state[MAIL]["forwarding"].append("thief3@evil.test")
        print("\n[attacker adds forwarding to thief3@evil.test while the guard sleeps]")

    rc = panic("guard", "--passes", "2", "--interval", "30", sleep=attacker_between_passes,
               notifier=lambda title, text: print(f"[notification] {title}: {text}"))
    print("\nState after the guard:", sim.state[MAIL])
    outcomes = vault.load(vpath, "demo passphrase", key)["outcomes"]
    assert rc == 0 and len(outcomes) == pressed_before + 1, "the guard did not press"
    assert outcomes[-1]["triggers"][0].startswith("forwarding_added: "), outcomes[-1]["triggers"]
    assert sim.state[MAIL]["forwarding"] == [], "the guard pressed but the forwarding is still there"

    say("7. Evidence")
    log_path = Path(f"{vpath}.log.jsonl")
    print(f"Audit log entries: {len(log_path.read_text().splitlines())}, chain intact: {log.verify(log_path)}")
    print("Files:", ", ".join(sorted(p.name for p in tmp.iterdir())))
    assert sim.state[MAIL]["forwarding"] == [] and sim.state[MAIL]["filters"] == ["label: newsletters"]
    assert sim.state[MAIL]["apps"] == [] and sim.state[MAIL]["sessions"] == 0
    print("Checked: the root mailbox is back to its baseline, the re-added forwarding was removed, "
          "and the guard pressed by itself when forwarding appeared.")


if __name__ == "__main__":
    demo()
