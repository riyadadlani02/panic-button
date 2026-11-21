from test_cli import armed, bare, cli, open_vault  # noqa: F401
from test_github import FakeApi, gh, personal_api

SECRET = "ghp_supersecrettoken"


def token_file(tmp_path, text=SECRET + "\n"):
    p = tmp_path / "gh.token"
    p.write_text(text)
    return str(p)


def arm(tmp_path, api, *args, answers=("y", "y", "mail"), tokens=None):
    conn = gh(api, tokens=tokens)
    return cli("arm", "--github", "me", "--token-file", token_file(tmp_path), *args, answers=answers,
               connectors={"github": conn})


def test_arm_refuses_a_token_for_another_login(armed, tmp_path, capsys):
    api = personal_api()
    api.objs["/user"] = {"login": "someone-else"}
    assert arm(tmp_path, api) == 1
    out = capsys.readouterr()
    assert "someone-else" in out.err and SECRET not in out.out + out.err
    assert "me" not in [a["id"] for a in open_vault()["accounts"]] and "github" not in open_vault()["credentials"]


def test_arm_with_org_refuses_a_non_admin(armed, tmp_path):
    api = FakeApi(objs={"/user": {"login": "me"}, "/user/memberships/orgs/acme": {"state": "active", "role": "member"}})
    assert arm(tmp_path, api, "--org", "acme", tokens={"org:acme": "t"}) == 1
    assert "org:acme" not in [a["id"] for a in open_vault()["accounts"]]


def test_arm_saves_account_baseline_edge_and_token_without_printing_it(armed, tmp_path, capsys):
    api = personal_api()
    api.objs["/user"] = {"login": "ME"}  # compared casefolded
    assert arm(tmp_path, api) == 0
    d, out = open_vault(), capsys.readouterr().out
    assert {"id": "me", "provider": "github", "protected": False} in d["accounts"]
    assert "ssh_keys" in d["baselines"]["me"] and ["mail", "me"] in d["edges"]
    assert d["credentials"]["github"] == {"me": SECRET} and SECRET not in out and "laptop" in out


def test_arm_org_stores_under_the_org_account_id(armed, tmp_path):
    api = FakeApi({"/orgs/acme/repos": []}, {"/user": {"login": "me"},
                  "/user/memberships/orgs/acme": {"state": "active", "role": "admin"}})
    assert arm(tmp_path, api, "--org", "acme", tokens={"org:acme": "t"}) == 0
    d = open_vault()
    assert d["credentials"]["github"] == {"org:acme": SECRET} and "outside_collaborators" in d["baselines"]["org:acme"]


def test_declined_baseline_saves_nothing(armed, tmp_path):
    api = personal_api()
    api.objs["/user"] = {"login": "me"}
    assert arm(tmp_path, api, answers=("y", "n")) == 1
    assert "github" not in open_vault()["credentials"]


def test_reconnect_replaces_only_the_token(armed, tmp_path):
    api = personal_api()
    api.objs["/user"] = {"login": "me"}
    assert arm(tmp_path, api) == 0
    before = open_vault()
    new = tmp_path / "new.token"
    new.write_text("ghp_new\n")
    assert cli("arm", "--github", "me", "--token-file", str(new), "--reconnect", connectors={"github": gh(api)}) == 0
    after = open_vault()
    assert after["credentials"]["github"] == {"me": "ghp_new"}
    assert {k: v for k, v in after.items() if k not in ("credentials", "saved_at", "version")} == \
           {k: v for k, v in before.items() if k not in ("credentials", "saved_at", "version")}


def test_reconnect_needs_an_armed_account_and_the_same_login(armed, tmp_path):
    api = personal_api()
    api.objs["/user"] = {"login": "me"}
    assert cli("arm", "--github", "me", "--token-file", token_file(tmp_path), "--reconnect",
               connectors={"github": gh(api)}) == 1
    arm(tmp_path, api)
    api.objs["/user"] = {"login": "other"}
    assert cli("arm", "--github", "me", "--token-file", token_file(tmp_path, "ghp_x"), "--reconnect",
               connectors={"github": gh(api)}) == 1
    assert open_vault()["credentials"]["github"] == {"me": SECRET}


def test_guard_keeps_the_github_connector_and_its_cache_between_passes(armed, tmp_path, monkeypatch):
    from unittest.mock import patch

    import test_cli
    from panic import github
    from panic.cli import main
    api = personal_api()
    api.objs["/user"] = {"login": "me"}
    assert arm(tmp_path, api) == 0
    made = []
    real_init = github.GitHub.__init__
    monkeypatch.setattr(github.GitHub, "__init__", lambda self, *a, **k: made.append(self) or real_init(self, *a, **k))
    monkeypatch.setattr(github, "Api", lambda base, headers: api)
    reads = api.reads.count("/user/repos")
    with patch("getpass.getpass", return_value=test_cli.PW):
        assert main(["--vault", str(test_cli.vpath), "--keyfile", str(test_cli.kpath), "guard", "--passes", "2"],
                    sleep=lambda s: None, notifier=lambda t, x: None) == 0
    assert len(made) == 1 and api.reads.count("/user/repos") == reads + 1
