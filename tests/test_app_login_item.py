import plistlib

from panic.app import login_item


def test_install_writes_a_launch_agent_that_opens_the_app_at_login(tmp_path):
    login_item.install(tmp_path)
    p = tmp_path / "Library/LaunchAgents/com.panicbutton.app.plist"
    assert plistlib.loads(p.read_bytes()) == {"Label": "com.panicbutton.app", "RunAtLoad": True,
                                              "ProgramArguments": ["/usr/bin/open", "-a", "panic button"]}
    assert login_item.installed(tmp_path)


def test_install_and_remove_are_idempotent(tmp_path):
    assert not login_item.installed(tmp_path)
    login_item.remove(tmp_path)  # nothing there: no error
    login_item.install(tmp_path)
    login_item.install(tmp_path)
    assert len(list((tmp_path / "Library/LaunchAgents").iterdir())) == 1
    login_item.remove(tmp_path)
    login_item.remove(tmp_path)
    assert not login_item.installed(tmp_path)
