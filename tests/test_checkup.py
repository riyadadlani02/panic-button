import json
from unittest.mock import MagicMock

import pytest
from fake import FakeConnector
import test_cli
from test_cli import armed, bare, cli, open_vault  # noqa: F401  (armed and bare are fixtures)
from test_github import FakeApi as GhApi
from test_github import gh
from test_google_personal import ACCT as GMAIL, make as gmail
from test_google_workspace import http_error
from test_graph_mail import FakeApi, canon, rule, to

from panic import checkup
from panic.checkup import Check
from panic.google_workspace import Workspace
from panic.http import ApiError
from panic.microsoft_365 import Microsoft365
from panic.microsoft_personal import MicrosoftPersonal
from panic.model import Account

DAY = 86400.0
T0 = 1_000_000_000.0


def statuses(checks):
    return {c.name: c.status for c in checks}


def unknown_only(checks, account):
    return len(checks) == 1 and checks[0].status == "unknown" and checks[0].account == account


# -- Microsoft 365 --------------------------------------------------------

U = "a@corp.test"
M365_CRED = {"tenant": "t", "client_id": "c", "client_secret": "s", "admin": "bg@corp.test", "domains": ["corp.test"]}
METHODS = f"/users/{U}/authentication/methods"


def m365(methods):
    return Microsoft365(M365_CRED, api=FakeApi({METHODS: methods if isinstance(methods, Exception) else {"value": methods}}),
                        token=lambda: "tok")


def method(kind, i="m1", **kw):
    return {"@odata.type": f"#microsoft.graph.{kind}AuthenticationMethod", "id": i, **kw}


def test_m365_only_phone_and_password_is_fix_and_shows_no_method_contents():
    conn = m365([method("password"), method("phone", "ph-1", phoneNumber="+44 7700 900123")])
    checks = checkup.posture(conn, Account(U, "microsoft_365"))
    assert statuses(checks) == {"second_factor": "fix"} and checks[0].account == U and checks[0].link
    text = checkup.render(checks)
    assert U in text and "900123" not in text and "ph-1" not in text


def test_m365_password_alone_is_fix_and_an_authenticator_is_good():
    assert statuses(checkup.posture(m365([method("password")]), Account(U, "microsoft_365"))) == {"second_factor": "fix"}
    good = m365([method("password"), method("phone"), method("microsoftAuthenticator", "m2")])
    assert statuses(checkup.posture(good, Account(U, "microsoft_365"))) == {"second_factor": "good"}


def test_m365_read_error_is_unknown():
    assert unknown_only(checkup.posture(m365(ApiError(403, "")), Account(U, "microsoft_365")), U)


# -- Google Workspace -------------------------------------------------------

def workspace(get):
    directory = MagicMock()
    if isinstance(get, Exception):
        directory.users().get().execute.side_effect = get
    else:
        directory.users().get().execute.return_value = get
    w = Workspace({}, "bg@corp.test", "corp.test", build=lambda *a, **k: directory, sleep=lambda s: None)
    w._dir = lambda: directory  # no service-account key needed for a fake
    return w


@pytest.mark.parametrize("user, status", [({"isEnrolledIn2Sv": True}, "good"), ({"isEnrolledIn2Sv": False}, "fix"),
                                          ({}, "unknown")])
def test_workspace_two_step(user, status):
    checks = checkup.posture(workspace(user), Account(U, "google_workspace"))
    assert statuses(checks) == {"two_step": status} and checks[0].account == U


def test_workspace_read_error_is_unknown():
    assert unknown_only(checkup.posture(workspace(http_error(403)), Account(U, "google_workspace")), U)


# -- GitHub ------------------------------------------------------------------

ME, ORG = Account("me", "github"), Account("org:acme", "github")
REPOS = {"/user/repos": [{"id": 11, "full_name": "me/r", "private": True}]}


def test_github_two_factor_and_readable_runners():
    api = GhApi({**REPOS, "/repos/me/r/actions/runners": []}, {"/user": {"two_factor_authentication": True}})
    assert statuses(checkup.posture(gh(api), ME)) == {"two_factor": "good", "runners": "good"}
    api.objs["/user"] = {"two_factor_authentication": False}
    checks = checkup.posture(gh(api), ME)
    assert statuses(checks)["two_factor"] == "fix" and all(c.link for c in checks if c.status != "good")


@pytest.mark.parametrize("err", [ApiError(403, "Resource not accessible"), ApiError(404, "")])
def test_github_runners_without_admin_rights_are_unknown_with_token_link(err):
    api = GhApi({**REPOS, "/repos/me/r/actions/runners": err}, {"/user": {"two_factor_authentication": True}})
    runners = next(c for c in checkup.posture(gh(api), ME) if c.name == "runners")
    assert runners.status == "unknown" and runners.link == "https://github.com/settings/tokens"


def test_github_rate_limit_is_a_read_error_not_missing_rights():
    limited = ApiError(403, "API rate limit exceeded", headers={"x-ratelimit-remaining": "0"})
    api = GhApi({**REPOS, "/repos/me/r/actions/runners": limited}, {"/user": {"two_factor_authentication": True}})
    assert unknown_only(checkup.posture(gh(api), ME), "me")


def test_github_org_requirement_and_runners():
    api = GhApi({"/orgs/acme/actions/runners": []}, {"/orgs/acme": {"two_factor_requirement_enabled": False}})
    assert statuses(checkup.posture(gh(api), ORG)) == {"two_factor": "fix", "runners": "good"}
    api.objs["/orgs/acme"] = {}  # not an owner: the field is hidden
    api.lists["/orgs/acme/actions/runners"] = ApiError(403, "")
    assert statuses(checkup.posture(gh(api), ORG)) == {"two_factor": "unknown", "runners": "unknown"}


def test_github_read_error_is_unknown():
    assert unknown_only(checkup.posture(gh(GhApi({}, {"/user": ApiError(401, "")})), ME), "me")


# -- Gmail and Outlook.com ---------------------------------------------------

def test_gmail_pop_and_forwarding():
    conn, _ = gmail()
    assert statuses(checkup.posture(conn, GMAIL)) == {"pop": "good", "forwarding": "good"}
    conn, _ = gmail(fwd={"enabled": True, "emailAddress": "x@evil.test"}, pop="allMail")
    checks = checkup.posture(conn, GMAIL)
    assert statuses(checks) == {"pop": "fix", "forwarding": "fix"} and all(c.link for c in checks)


def test_gmail_read_error_is_unknown():
    conn, svc = gmail()
    svc.users().settings().getPop().execute.side_effect = http_error(500)
    assert unknown_only(checkup.posture(conn, GMAIL), GMAIL.id)


OUTLOOK = Account("me@outlook.com", "microsoft_personal")
INBOX = "/me/mailFolders/inbox/messageRules"


def outlook(rules_):
    return MicrosoftPersonal({OUTLOOK.id: {"client_id": "c", "cache": "x"}},
                             api=FakeApi({INBOX: rules_ if isinstance(rules_, Exception) else {"value": rules_}}))


def test_outlook_forwarding_rule_is_fix_and_unreadable_forwarding_is_unknown():
    assert statuses(checkup.posture(outlook([rule("1", "m", {"moveToFolder": "x"})]), OUTLOOK)) == {
        "forwarding_rules": "good", "forwarding": "unknown"}
    fwd = rule("2", "f", {"forwardTo": [to("x@evil.test")]})
    assert statuses(checkup.posture(outlook([fwd]), OUTLOOK))["forwarding_rules"] == "fix"


def test_outlook_read_error_is_unknown():
    assert unknown_only(checkup.posture(outlook(ApiError(401, "")), OUTLOOK), OUTLOOK.id)


def test_a_connector_without_posture_gives_no_checks():
    assert checkup.posture(FakeConnector(), Account("x", "fake")) == []


# -- report --------------------------------------------------------------------

def test_render_groups_in_order_with_links():
    text = checkup.render([Check("a", "n", "good", "fine", None), Check("b", "n", "fix", "broken", "https://x.test"),
                           Check("c", "n", "unknown", "unread", None)])
    assert text.index("Fix now") < text.index("Unknown") < text.index("Good")
    assert "b: broken — https://x.test" in text and "a: fine\n" in text + "\n"


# -- the command -------------------------------------------------------------

ALL_NO = ("n",) * len(checkup.CHECKLIST)


def run(*args, answers=(), now=T0, connectors=None):
    return cli("checkup", *args, answers=answers, now=lambda: now, connectors=connectors)


def test_checkup_saves_answers_and_reports_with_exit_zero(armed, capsys):
    test_cli.fake.posture = lambda a: [Check(a.id, "x", "good", "fine", None)]
    assert run(answers=("y", "n", "u", "maybe", "y", "n")) == 0
    saved = open_vault()["checkup"]
    assert [v["answer"] for v in saved.values()] == ["yes", "no", "unsure", "yes", "no"]
    assert all(v["at"] == T0 for v in saved.values()) and list(saved) == [k for k, *_ in checkup.CHECKLIST]
    out = capsys.readouterr().out
    assert out.index("Fix now") < out.index("Unknown") < out.index("Good")
    assert "You: " in out and "mail: fine" in out and "bank: fine" in out


def test_checklist_is_not_reasked_within_90_days_but_is_after(armed, capsys):
    assert run(answers=ALL_NO) == 0
    assert run(now=T0 + 89 * DAY) == 0  # no answers given: any question would cancel the command
    assert "You: " in capsys.readouterr().out
    assert run(now=T0 + 91 * DAY) == 1  # due again
    assert run(answers=("y",) * len(ALL_NO), now=T0 + 91 * DAY) == 0
    assert {v["answer"] for v in open_vault()["checkup"].values()} == {"yes"}


def test_again_reasks(armed):
    assert run(answers=ALL_NO) == 0
    assert run("--again", now=T0 + DAY) == 1
    assert run("--again", answers=("y",) * len(ALL_NO), now=T0 + DAY) == 0
    assert all(v["at"] == T0 + DAY for v in open_vault()["checkup"].values())


def test_unreadable_account_is_unknown_never_good(armed, capsys):
    test_cli.fake.posture = lambda a: (_ for _ in ()).throw(RuntimeError("token expired"))
    assert run(answers=ALL_NO) == 0
    out = capsys.readouterr().out
    good = out[out.index("Good"):]
    assert "mail: " in out[out.index("Unknown"):out.index("Good")] and "mail: " not in good
    assert test_cli.fake.ran == []
