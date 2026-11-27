"""All-services demo: the real `panic` commands and connectors, against simulated providers (demo/lab.py).

One scenario per service: an intruder changes something, `panic guard` notices and presses, the account is put
back. Every printed outcome is read back from the run: the vault's saved outcome, the stand-in's state and the
text the guard passed to its notifier. It proves the tool's logic, not that the real services behave the same.

Run: PYTHONPATH=. uv run python demo/all_services_demo.py [--json PATH]
"""
import argparse
import contextlib
import io
import json
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from demo.lab import GitHubLab, Microsoft365Lab, OutlookLab, SlackLab, WorkspaceLab
from panic import vault
from panic.cli import main as panic_main
from panic.github import GitHub
from panic.google_workspace import Workspace
from panic.guided import Guided
from panic.microsoft_365 import Microsoft365
from panic.microsoft_personal import MicrosoftPersonal
from panic.model import Account, Tier
from panic.slack import ALLOWS, Slack

SIMULATED = ("SIMULATED PROVIDERS: the real panic-button connectors, running against stand-ins. "
             "No real account is touched.")
PASSPHRASE = "demo passphrase"
STATUS = {("locked", "verified"): "done, read back", ("locked", "accepted"): "done, accepted by provider (no read-back)",
          ("locked", "owner_confirmed"): "done, owner confirmed", ("needs_you", None): "needs you",
          ("still_open", None): "STILL OPEN"}


class Failed(Exception):
    pass


class Checks:
    def __init__(self):
        self.n = 0

    def __call__(self, ok: bool, what: str) -> None:
        if not ok:
            raise Failed(what)
        self.n += 1


class Vault:
    """One temporary vault, and `panic` run against it with a scripted owner."""

    def __init__(self, root: Path, name: str, connectors):
        self.dir = root / name
        self.dir.mkdir()
        self.path, self.key = self.dir / "panic.vault", self.dir / "panic.key"
        self.connectors = connectors  # a fresh set per command, as each `panic` run is a new process
        self.notes: list[tuple[str, str]] = []

    def file(self, name: str, text: str) -> str:
        p = self.dir / name
        p.write_text(text)
        return str(p)

    def panic(self, *args, answers=(), sleep=None, **kw) -> tuple[int, list[str]]:
        queue = list(answers)

        def answer(prompt=""):
            if not queue:
                raise Failed(f"`panic {args[0]}` asked an unexpected question: {prompt}")
            return queue.pop(0)

        out, err = io.StringIO(), io.StringIO()
        with patch("builtins.input", answer), patch("getpass.getpass", lambda prompt="": PASSPHRASE), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = panic_main(["--vault", str(self.path), "--keyfile", str(self.key), *args],
                            connectors=self.connectors(), sleep=sleep or (lambda s: None),
                            notifier=lambda title, text: self.notes.append((title, text)), **kw)
        if rc != 0 or queue:
            raise Failed(f"`panic {' '.join(args)}` exited {rc} with answers left {queue}: {err.getvalue().strip()}")
        return rc, out.getvalue().splitlines()

    def data(self) -> dict:
        return vault.load(self.path, PASSPHRASE, self.key.read_bytes())


def guard_lines(lines: list[str]) -> list[str]:
    """The guard's own pass lines, without the full report it also prints."""
    return [x for x in lines if x.startswith(("notify ", "press ", "Guard:", "[")) or " accounts, " in x
            or ": was changed" in x or "already handling" in x]


def added(before: dict, after: dict) -> dict:
    out = {h: [x for x in lines if x not in before.get(h, [])] for h, lines in after.items()}
    return {h: v for h, v in out.items() if v}


def fmt(state: dict) -> str:
    return "; ".join(f"{h}: {', '.join(lines)}" for h, lines in state.items()) or "nothing"


def show(title: str, state: dict) -> None:
    print(f"  {title}:")
    for heading, lines in state.items():
        print(f"    {heading}: {', '.join(lines) if lines else '(none)'}")


def say(text: str) -> None:
    print(f"\n\033[1m=== {text} ===\033[0m")


def per_user(describe, users: list[str]) -> dict:
    return {f"{u.split('@')[0]}: {h}": lines for u in users for h, lines in describe(u).items()}


def actions_for(outcome: dict, account: str) -> list[dict]:
    return [{"title": r["step"]["title"], "status": r["status"], "evidence": r["evidence"]}
            for r in outcome["results"] if r["step"]["account"] == account]


def show_actions(actions: list[dict]) -> None:
    print("  What the tool did (the outcome it saved in the vault):")
    for a in actions:
        print(f"    [{STATUS.get((a['status'], a['evidence']), a['status'])}] {a['title']}")


def summary_row(name: str, outcome: dict | None, actions: list[dict], trigger: str | None = None) -> list[str]:
    codes = trigger or (", ".join(dict.fromkeys(t.split(":")[0] for t in outcome["triggers"])) if outcome else "-")
    done = [a for a in actions if a["status"] == "locked"]
    left = [a for a in actions if a["status"] != "locked"]
    return [name, codes, f"{len(done)} step(s), {sum(a['evidence'] == 'verified' for a in done)} read back",
            f"{len(left)} step(s)" + (f" ({sum(a['status'] == 'still_open' for a in left)} still open)"
                                    if any(a["status"] == "still_open" for a in left) else "")]


def record(key, name, account, kind, before, attacked, headline, note, actions, after, extra):
    return {"key": key, "name": name, "account": account, "kind": kind, "before": before,
            "attack": {"headline": headline, "added": added(before, attacked)}, "notification": note,
            "actions": actions, "after": after, "extra": extra}


def trigger_notes(v: Vault, account: str, since: int) -> list[str]:
    return [t for title, t in v.notes[since:] if title == f"panic: {account}"]


def press_story(v: Vault, lines: list[str], account: str, notes_from: int) -> tuple[dict, list[str]]:
    for x in guard_lines(lines):
        print(f"    {x if x.startswith('[') else 'guard: ' + x}")
    notes = trigger_notes(v, account, notes_from)
    for n in notes:
        print(f"    [notification] {n}")
    outcomes = v.data().get("outcomes", [])
    if not outcomes:
        raise Failed(f"the guard saved no press for {account}")
    return outcomes[-1], notes


# -- scenarios -----------------------------------------------------------

def github(root: Path, check: Checks, ctx: dict) -> tuple[dict, list]:
    login, repo = "octo-owner", "octo-owner/website"
    lab = GitHubLab(login, "owner@example.test")
    lab.add_ssh_key("work-laptop")
    lab.add_repo("website")
    lab.add_deploy_key(repo, "ci-deploy")
    lab.add_collaborator(repo, "dana")
    v = Vault(root, "github", lambda: {"github": GitHub({login: "sim-token"}, api=lambda _id: lab)})
    say(f"1. GitHub (personal account {login})")
    before = lab.describe(login)
    show("Before", before)
    v.panic("arm", "--github", login, "--token-file", v.file("token.txt", "sim-token"), answers=["y", "y"])
    print(f"  $ panic arm --github {login}: baseline approved. $ panic guard: two passes, the intruder strikes between them.")
    attacked = {}

    def intruder(_seconds):
        lab.add_ssh_key("attacker-box")
        lab.add_collaborator(repo, "mallory")
        attacked.update(lab.describe(login))
        print(f"[intruder, between two guard passes] {fmt(added(before, attacked))}")

    n = len(v.notes)
    _, lines = v.panic("guard", "--wait", "0", "--passes", "2", "--interval", "30", sleep=intruder)
    outcome, notes = press_story(v, lines, login, n)
    acts = actions_for(outcome, login)
    show_actions(acts)
    after = lab.describe(login)
    show("After", after)
    check("work-laptop" in after["SSH keys"] and "attacker-box" not in after["SSH keys"], "GitHub SSH keys not restored")
    check(after["Collaborators"] == [f"{repo}: dana"], "GitHub collaborators not restored")
    check(after["Deploy keys"] == [f"{repo}: ci-deploy"], "GitHub baselined deploy key lost")
    print(f"  Check: gone: {fmt(added(after, attacked))}. Kept: {fmt({h: after[h] for h in ('SSH keys', 'Deploy keys', 'Collaborators')})}.")

    print("  Then the owner renames the repository, and the guard runs again.")
    new = lab.rename_repo(repo, "website-v2")
    n, presses = len(v.notes), len(v.data()["outcomes"])
    _, lines = v.panic("guard", "--wait", "0", "--passes", "1")
    for x in guard_lines(lines):
        print(f"    {x if x.startswith('[') else 'guard: ' + x}")
    rename_notes = trigger_notes(v, login, n)
    for t in rename_notes:
        print(f"    [notification] {t}")
    renamed = lab.describe(login)
    check(len(v.data()["outcomes"]) == presses, "GitHub rename caused a press")
    check(bool(rename_notes) and not any("Pressing" in t for t in rename_notes), "GitHub rename gave no notice")
    check(renamed["Deploy keys"] == [f"{new}: ci-deploy"] and renamed["Collaborators"] == [f"{new}: dana"],
          "GitHub rename deleted something")
    print(f"  Check: renamed to {new}; a notice, no press; still there: {fmt({h: renamed[h] for h in ('Deploy keys', 'Collaborators')})}.")
    extra = [f"Owner renamed {repo} to {new}: notice \"{t}\"; nothing deleted" for t in rename_notes]
    rec = record("github", "GitHub", login, "personal", before, attacked,
                 "An intruder added an SSH key to the account and a collaborator to the repository.",
                 notes[0] if notes else None, acts, after, extra)
    return rec, summary_row("GitHub", outcome, acts)


def outlook(root: Path, check: Checks, ctx: dict) -> tuple[dict, list]:
    addr = "sam@outlook.test"
    amazon = f"amazon:{addr}"
    lab = OutlookLab(addr)
    lab.add_inbox_rule("Newsletters", move_to="Newsletters")
    v = Vault(root, "outlook", lambda: {"microsoft_personal": MicrosoftPersonal({addr: {}}, api=lab),
                                        "guided": Guided()})
    say(f"2. Outlook.com (personal Microsoft account {addr})")
    before = lab.describe(addr)
    show("Before", before)
    v.panic("arm", "--microsoft-personal", addr, "--client-id", "sim-client", answers=["y", "y"],
            ms_authorize=lambda client_id, login_hint=None: {"client_id": client_id, "cache": "", "username": login_hint})
    v.panic("arm", "--guided", "amazon", "--id", addr, answers=["y", addr])
    edges = v.data()["edges"]
    print(f"  $ panic arm --microsoft-personal {addr}; $ panic arm --guided amazon (can be reset by: "
          f"{', '.join(a for a, b in edges if b == amazon)})")
    attacked = {}

    def intruder(_seconds):
        lab.add_inbox_rule("Sync", forward_to="collect@evil.test")
        attacked.update(lab.describe(addr))
        print(f"[intruder, between two guard passes] {fmt(added(before, attacked))}")

    n = len(v.notes)
    _, lines = v.panic("guard", "--wait", "0", "--passes", "2", "--interval", "30", sleep=intruder)
    outcome, notes = press_story(v, lines, addr, n)
    acts = actions_for(outcome, addr)
    show_actions(acts)
    after = lab.describe(addr)
    show("After", after)
    check(after == before, "Outlook rules not back to the baseline")
    check(any(a["title"].startswith("Delete inbox rules") and a["status"] == "locked" for a in acts),
          "Outlook rule step not locked")
    print(f"  Check: gone: {fmt(added(after, attacked))}. Kept: {fmt(after)}.")
    ctx["outlook"] = (addr, outcome, notes, edges)
    return (record("outlook", "Outlook.com", addr, "personal", before, attacked,
                   "An intruder added an inbox rule that forwards mail to an outside address.",
                   notes[0] if notes else None, acts, after, []), summary_row("Outlook.com", outcome, acts))


def guided(root: Path, check: Checks, ctx: dict) -> tuple[dict, list]:
    if "outlook" not in ctx:
        raise Failed("the Outlook scenario did not run, so there was no press to reach Amazon")
    addr, outcome, notes, edges = ctx["outlook"]
    amazon = f"amazon:{addr}"
    say(f"6. Any other service, guided (Amazon, {amazon})")
    g_acts = actions_for(outcome, amazon)
    g_before = {"Can be reset by": [a for a, b in edges if b == amazon], "Readable by the tool": ["no (no API)"]}
    show("Before", g_before)
    print(f"  The same automatic press of {addr} reached {amazon}, because the mailbox can reset it.")
    show_actions(g_acts)
    g_after = {"Needs you": [a["title"] for a in g_acts if a["status"] == "needs_you"]}
    show("After", g_after)
    own = [r for r in outcome["results"] if r["step"]["account"] == amazon and r["step"]["tier"] == Tier.GUIDED]
    check(bool(own) and all(r["status"] == "needs_you" for r in own), "Amazon steps not listed as Needs you")
    reopen = [r["detail"] for r in outcome["results"] if r["step"]["account"] == amazon and r["step"]["action"] == "reopenable"]
    open_ = [r["step"]["title"] for r in outcome["results"]
             if r["step"]["account"] == addr and r["step"]["phase"] == "freeze" and r["status"] != "locked"]
    print(f"  Check: {len(own)} Amazon steps under \"Needs you\", none done by the tool"
          + (f"; also marked {reopen[0]}, whose freeze steps are still open: {'; '.join(open_)}." if reopen else "."))
    return (record("guided", "Amazon (guided)", amazon, "personal", g_before, g_before,
                   f"The intruder holds {addr}, which can reset Amazon.",
                   notes[0] if notes else None, g_acts, g_after,
                   [f"Pressed because {addr} triggered: {t}" for t in outcome["triggers"]]),
            summary_row("Amazon (guided)", outcome, g_acts, trigger=f"via {addr}"))


def microsoft_365(root: Path, check: Checks, ctx: dict) -> tuple[dict, list]:
    domain = "contoso.test"
    admin, alex, bea = f"admin@{domain}", f"alex@{domain}", f"bea@{domain}"
    lab = Microsoft365Lab(domain)
    for u in (admin, alex, bea):
        lab.add_user(u)
    lab.add_inbox_rule(alex, "Receipts", move_to="Receipts")
    lab.add_consent(bea, "Calendar Helper", "Calendars.Read")
    lab.add_consent(None, "Company Directory", "User.Read Mail.Read")
    v = Vault(root, "m365", lambda: {"microsoft_365": Microsoft365({"admin": admin, "domains": [domain]}, api=lab,
                                                                   token=lambda: "sim")})
    say(f"3. Microsoft 365 (tenant {domain}, protected admin {admin})")
    users = [alex, bea, admin]
    snap = lambda: {**per_user(lab.describe, users), **lab.describe(domain)}
    before = snap()
    show("Before", before)
    v.panic("arm", "--microsoft-tenant", "contoso", "--client-id", "sim", "--client-secret-file",
            v.file("secret.txt", "sim-secret"), "--admin", admin)
    print(f"  $ panic arm --microsoft-tenant: every user armed, {admin} protected. $ panic guard: two passes.")
    attacked = {}

    def intruder(_seconds):
        lab.sign_in(alex, "unknown browser")
        lab.add_inbox_rule(alex, "Sync", forward_to="drop@evil.test")
        lab.add_consent(alex, "Mail Sync Pro", "Mail.ReadWrite offline_access")
        attacked.update(snap())
        print(f"[intruder, between two guard passes] {fmt(added(before, attacked))}")

    n = len(v.notes)
    _, lines = v.panic("guard", "--wait", "0", "--passes", "2", "--interval", "30", sleep=intruder)
    outcome, notes = press_story(v, lines, alex, n)
    acts = actions_for(outcome, alex)
    show_actions(acts)
    after = snap()
    show("After", after)
    a, b = lab.describe(alex), lab.describe(bea)
    check(a["Sign-in"] == ["blocked"] and a["Signed-in sessions"] == [], "M365 user not blocked and signed out")
    check(a["Inbox rules"] == [before[f"alex: Inbox rules"][0]] and a["App consents"] == [], "M365 rule or grant left")
    check({k: v_ for k, v_ in after.items() if not k.startswith("alex:")} ==
          {k: v_ for k, v_ in before.items() if not k.startswith("alex:")}, "M365 other users or tenant grant changed")
    print(f"  Check: alex blocked and cleaned; bea, the admin and the tenant-wide consent unchanged.")

    extra = []
    _, lines = v.panic("release", "--user", alex, answers=["y"])
    print(f"  $ panic release --user {alex}: {lines[-1]}")
    extra.append(f"panic release: {lines[-1]}")
    check(lab.describe(alex)["Sign-in"] == ["allowed"], "M365 release did not restore sign-in")
    _, lines = v.panic("guard", "--wait", "0", "--passes", "1")
    for x in guard_lines(lines):
        print(f"    {x if x.startswith('[') else 'guard: ' + x}")
    check(lab.describe(alex)["Sign-in"] == ["allowed"], "M365 watch locked a released user again")
    print(f"  Check: the next guard pass left alex's sign-in {lab.describe(alex)['Sign-in'][0]}.")
    extra.append(f"Next guard pass after release: {guard_lines(lines)[-1]}; alex's sign-in stays "
                 f"{lab.describe(alex)['Sign-in'][0]}")
    _, lines = v.panic("rehearse", answers=["y"])
    print(f"  $ panic rehearse: answered yes to \"Resume guarding {alex}?\"")
    check(alex not in v.data().get("unguarded", []), "M365 rehearse did not resume guarding")
    _, lines = v.panic("guard", "--wait", "0", "--passes", "1")
    for x in guard_lines(lines):
        print(f"    {x if x.startswith('[') else 'guard: ' + x}")
    extra.append(f"panic rehearse resumed guarding; next guard pass: {guard_lines(lines)[-1]}")
    check(lab.describe(alex)["Sign-in"] == ["allowed"], "M365 guard locked alex again after resume")
    print(f"  Check: alex is guarded again and still allowed to sign in.")
    rec = record("m365", "Microsoft 365", domain, "organisation", before, attacked,
                 "An intruder signed in as a staff member, added an inbox rule forwarding outside the organisation "
                 "and consented an app to read their mail.", notes[0] if notes else None, acts, after,
                 extra + [f"Also notified: {t}" for t in notes[1:]])
    return rec, summary_row("Microsoft 365", outcome, acts)


def _service_account() -> dict:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    return {"type": "service_account", "client_email": "panic@sim.iam.gserviceaccount.com", "private_key": key,
            "token_uri": "https://oauth2.googleapis.com/token", "project_id": "sim"}


def workspace(root: Path, check: Checks, ctx: dict) -> tuple[dict, list]:
    domain = "northwind.test"
    admin, kim, lee = f"admin@{domain}", f"kim@{domain}", f"lee@{domain}"
    lab = WorkspaceLab(domain)
    lab.add_user(admin, admin=True)
    lab.add_user(kim, apps=["Zoom"], recovery_email="kim.home@mail.test")
    lab.add_user(lee)
    sa = _service_account()
    v = Vault(root, "workspace", lambda: {"google_workspace": Workspace(sa, admin, domain, build=lab.build)})
    say(f"4. Google Workspace (domain {domain}, protected admin {admin})")
    users = [kim, lee]
    snap = lambda: per_user(lab.describe, users)
    before = snap()
    show("Before", before)
    v.panic("arm", "--workspace", "--sa-key", v.file("sa.json", json.dumps(sa)), "--admin", admin, "--domain", domain)
    print(f"  $ panic arm --workspace: every user armed, {admin} protected. $ panic guard: two passes.")
    attacked = {}

    def intruder(_seconds):
        lab.add_forwarding(kim, "exfil@evil.test")
        lab.add_delegate(kim, f"temp-assistant@{domain}")
        lab.add_forwarding(lee, f"team-inbox@{domain}")  # lee's own change, inside the domain
        attacked.update(snap())
        print(f"[intruder on kim, and lee's own change, between two guard passes] {fmt(added(before, attacked))}")

    n = len(v.notes)
    _, lines = v.panic("guard", "--wait", "0", "--passes", "2", "--interval", "30", sleep=intruder)
    outcome, notes = press_story(v, lines, kim, n)
    lee_notes = trigger_notes(v, lee, n)
    for t in lee_notes:
        print(f"    [notification] {t}")
    acts = actions_for(outcome, kim)
    show_actions(acts)
    after = snap()
    show("After", after)
    k, l_ = lab.describe(kim), lab.describe(lee)
    check(k["Account"][0] == "suspended" and k["Automatic forwarding"] == ["off"], "Workspace user not suspended")
    check(k["Forwarding addresses"] == [] and k["Mail delegates"] == [], "Workspace forwarding or delegate left")
    check(l_["Account"] == ["active"] and l_["Automatic forwarding"] == [f"on, to team-inbox@{domain}"],
          "Workspace in-domain forward was acted on")
    check(bool(lee_notes) and not any("Pressing" in t for t in lee_notes), "Workspace in-domain forward gave no notice")
    check(all(r["step"]["account"] == kim for r in outcome["results"] if r["step"]["account"] != "-"),
          "Workspace press touched another user")
    print(f"  Check: kim suspended and cleaned; lee's in-domain forward is a notice only and lee is untouched.")
    rec = record("workspace", "Google Workspace", domain, "organisation", before, attacked,
                 "An intruder forwarded a user's mail to an outside address and added a mail delegate.",
                 notes[0] if notes else None, acts, after,
                 [f"Also notified: {t}" for t in notes[1:]] + [f"Notice for {lee}: {t}" for t in lee_notes])
    return rec, summary_row("Google Workspace", outcome, acts)


def _slack_cred(lab: SlackLab, owner: str) -> dict:
    return {"token": "sim-token", "plan": lab.plan, "team": lab.team, "primary_owner": owner,
            "users": {m["email"]: i for i, m in lab.members.items()}}


def slack(root: Path, check: Checks, ctx: dict) -> tuple[dict, list]:
    owner, ana, ben = "owner@acme.test", "ana@acme.test", "ben@acme.test"
    lab = SlackLab("acme", "enterprise")
    for e in (owner, ana, ben):
        lab.add_member(e, primary_owner=e == owner)
    v = Vault(root, "slack", lambda: {"slack": Slack(_slack_cred(lab, owner), web=lab, scim=lab, audit=lab)})
    say(f"5. Slack Enterprise Grid (workspace acme, protected primary owner {owner})")
    ids = [f"slack:{ana}", f"slack:{ben}", f"slack:{owner}"]
    snap = lambda: per_user(lab.describe, ids)
    before = snap()
    show("Before", before)
    _, lines = v.panic("arm", "--slack", "--token-file", v.file("token.txt", "sim-token"))
    print(f"  $ panic arm --slack: {lines[-1]}")
    attacked = {}

    def intruder(_seconds):
        lab.sign_in(ana, "unknown browser")
        lab.log_anomaly(ana)
        attacked.update(snap())
        print(f"[intruder, between two guard passes] {fmt(added(before, attacked))}; "
              f"Slack logs an `anomaly` audit event for {ana}")

    n = len(v.notes)
    _, lines = v.panic("guard", "--wait", "0", "--passes", "2", "--interval", "30", sleep=intruder)
    outcome, notes = press_story(v, lines, ids[0], n)
    acts = actions_for(outcome, ids[0])
    show_actions(acts)
    after = snap()
    show("After", after)
    check(lab.describe(ids[0]) == {"Member": ["deactivated"], "Signed-in sessions": []}, "Slack member not locked")
    check({k: x for k, x in after.items() if not k.startswith("slack:ana:")} ==
          {k: x for k, x in before.items() if not k.startswith("slack:ana:")}, "Slack other members changed")
    check(any(a["title"].startswith("Sign the member out") and a["status"] == "locked" for a in acts),
          "Slack session reset not run")
    print("  Check: ana signed out and deactivated; ben and the owner untouched.")
    _, lines = v.panic("release", "--user", ids[0], answers=["y"])
    print(f"  $ panic release --user {ids[0]}: {lines[-1]}")
    check(lab.describe(ids[0])["Member"] == ["active"], "Slack release did not reactivate")

    print("  Other Slack plans (the same connector, read from its catalogue and a simulated sign-in):")
    plans = []
    for plan, label in (("business", "Business+"), ("pro", "Pro"), ("free", "Free")):
        other = SlackLab("acme", plan)
        for e in (owner, ana):
            other.add_member(e, primary_owner=e == owner)
        conn = Slack(_slack_cred(other, owner), web=other, scim=other, audit=other)
        steps = conn.catalog(Account(ids[0], "slack"))
        other.sign_in(ana, "new laptop")
        found = conn.events(Account(ids[0], "slack"), 0)
        api = [s.title.lower() for s in steps if s.tier is Tier.API]
        guided = [s.title.lower() for s in steps if s.tier is Tier.GUIDED]
        line = (f"{label}: `panic press` can {', '.join(api) if api else 'do nothing itself'}; the guard "
                + (f"sees a new sign-in only as a {found[0].severity} (\"{found[0].text}\")" if found else "reads nothing")
                + (", so nothing presses by itself" if not any(f.severity == "trigger" for f in found) else "")
                + f"; guided: {'; '.join(guided)}. ({ALLOWS[plan]})")
        print(f"    {line}")
        plans.append(line)
    rec = record("slack", "Slack", "acme", "organisation", before, attacked,
                 "Slack flagged a member's session as anomalous in its audit log.",
                 notes[0] if notes else None, acts, after,
                 [f"panic release: {lines[-1]}"] + plans)
    return rec, summary_row("Slack (Enterprise Grid)", outcome, acts)


# -- main ----------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--json", metavar="PATH", help="also write a machine-readable record of the run")
    a = p.parse_args(argv)
    print(SIMULATED)
    check, records, rows, failed, ctx = Checks(), {}, {}, [], {}
    with tempfile.TemporaryDirectory(prefix="panic-lab-") as tmp:
        root = Path(tmp)
        for name, run in (("github", github), ("outlook", outlook), ("m365", microsoft_365),
                          ("workspace", workspace), ("slack", slack), ("guided", guided)):
            try:
                records[name], rows[name] = run(root, check, ctx)
            except Failed as e:
                print(f"\n  SCENARIO STOPPED ({name}): {e}")
                failed.append(f"{name}: {e}")
    order = [k for k in ("github", "outlook", "m365", "workspace", "slack", "guided") if k in records]

    say("Summary")
    table = [["Service", "What triggered", "Done by itself", "Left to the owner"]] + [rows[k] for k in order]
    widths = [max(len(r[i]) for r in table) for i in range(4)]
    for r in table:
        print("  " + "  ".join(c.ljust(w) for c, w in zip(r, widths)))
    if a.json:
        Path(a.json).write_text(json.dumps({"simulated": True, "note": SIMULATED,
                                            "services": [records[k] for k in order]}, indent=2))
    if failed:
        print(f"Checked: {check.n} checks passed, but {len(failed)} scenario(s) stopped: {'; '.join(failed)}")
        return 1
    print(f"Checked: {len(order)} services ran as described; {check.n} checks on the simulated providers' state passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
