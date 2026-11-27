from unittest.mock import patch

import pytest
from test_cli import armed, bare, cli, open_vault  # noqa: F401

import test_cli
from panic import cli_setup
from panic.cli import main
from panic.session import CliError


def ask(key, answers, opened=None):
    it = iter(answers)
    with patch("builtins.input", lambda prompt="": next(it)):
        return cli_setup.collect(key, (opened if opened is not None else []).append)


def test_menu_numbers_every_service():
    assert [k for k, *_ in cli_setup.SERVICES] == ["gmail", "outlook", "github", "workspace", "m365", "slack", "other"]


def test_github_answers_become_arm_arguments_and_pages_open_on_yes(tmp_path):
    token, opened = tmp_path / "token.txt", []
    token.write_text("t")
    argv = ask("github", ["y", "", "octo", "", str(token)], opened)
    assert argv == ["--github", "octo", "--token-file", str(token)]
    assert opened and opened[0].startswith("https://github.com/settings/tokens/new")


def test_github_organisation_is_optional(tmp_path):
    token = tmp_path / "token.txt"
    token.write_text("t")
    assert ask("github", ["n", "", "octo", "acme", str(token)]) == ["--github", "octo", "--org", "acme", "--token-file", str(token)]


def test_a_missing_file_is_asked_again_and_quotes_from_a_dragged_path_are_dropped(tmp_path):
    key = tmp_path / "sa key.json"
    key.write_text("{}")
    argv = ask("workspace", ["n", "", str(tmp_path / "nope.json"), f"'{key}'", "bg@x.test", "x.test"])
    assert argv == ["--workspace", "--sa-key", str(key), "--admin", "bg@x.test", "--domain", "x.test"]


def test_an_empty_answer_stops_that_service():
    with pytest.raises(CliError):
        ask("outlook", ["n", "", ""])


def test_setup_arms_a_guided_account_and_prints_the_command_and_next_steps(armed, capsys):
    # menu 7 = other; service, login; arm's own two questions; no further account
    assert cli("setup", answers=["7", "amazon", "me@x.test", "y", "mail", "n"]) == 0
    assert {"id": "amazon:me@x.test", "provider": "guided", "protected": False} in open_vault()["accounts"]
    out = capsys.readouterr().out
    assert "arm --guided amazon --id me@x.test" in out and "guard" in out and "rehearse" in out


def test_a_failed_arm_returns_to_the_menu_and_exits_1(armed, capsys):
    # an unknown menu number is asked again; the unknown service is refused; then stop
    assert cli("setup", answers=["9", "7", "nosuchservice", "u", "n"]) == 1
    assert "error:" in capsys.readouterr().err


def test_setup_asks_where_the_key_file_lives_when_none_is_given(armed, monkeypatch, capsys):
    monkeypatch.delenv("PANIC_KEYFILE", raising=False)
    it = iter([str(test_cli.kpath), "7", "amazon", "me@x.test", "y", "", "n"])
    with patch("getpass.getpass", return_value=test_cli.PW), patch("builtins.input", lambda prompt="": next(it)):
        assert main(["--vault", str(test_cli.vpath), "setup"], connectors={"fake": test_cli.fake}) == 0
    assert f"--keyfile {test_cli.kpath}" in capsys.readouterr().out


def test_another_service_question_is_grouped():
    from panic.guided import grouped_services
    q = next(s for s in cli_setup.SERVICES if s[0] == "other")[5][0][1]
    assert grouped_services() in q
