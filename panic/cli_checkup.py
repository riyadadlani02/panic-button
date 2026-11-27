"""`panic checkup`: reads every armed account, changes none, and asks what no API can see. Only the answers are saved."""
from panic import checkup
from panic.session import Session, _connectors


def run(a) -> int:
    s = Session(a)
    answers = checkup.ask(s.data.get("checkup", {}), a.now(), a.again)
    if answers:
        s.update(lambda d: d.setdefault("checkup", {}).update(answers))
    conns = _connectors(a, s.data, s)
    checks = [c for acct in s.accounts for c in checkup.posture(conns.get(acct.provider), acct)]
    print(checkup.render(checks + checkup.checklist(s.data.get("checkup", {}))))
    return 0  # a report, not a check: things to fix are not a failure
