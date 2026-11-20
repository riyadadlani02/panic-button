import pytest

from panic import vault


def test_round_trip(tmp_path):
    key = vault.new_keyfile()
    vault.save(tmp_path / "v", {"a": 1}, "pw", key)
    out = vault.load(tmp_path / "v", "pw", key)
    assert out["a"] == 1 and out["version"] == 1 and "saved_at" in out


def test_version_increments(tmp_path):
    key = vault.new_keyfile(); p = tmp_path / "v"
    vault.save(p, {}, "pw", key)
    vault.save(p, vault.load(p, "pw", key), "pw", key)
    assert vault.load(p, "pw", key)["version"] == 2


@pytest.mark.parametrize("pw,swap_key", [("wrong", False), ("pw", True)])
def test_needs_both_pieces(tmp_path, pw, swap_key):
    key = vault.new_keyfile(); p = tmp_path / "v"
    vault.save(p, {"a": 1}, "pw", key)
    with pytest.raises(vault.VaultError):
        vault.load(p, pw, vault.new_keyfile() if swap_key else key)


def test_damaged_file(tmp_path):
    key = vault.new_keyfile(); p = tmp_path / "v"
    vault.save(p, {"a": 1}, "pw", key)
    p.write_bytes(p.read_bytes()[:-5] + b"xxxxx")
    with pytest.raises(vault.VaultError):
        vault.load(p, "pw", key)


def test_file_is_private_and_fresh_each_save(tmp_path):
    key = vault.new_keyfile(); p = tmp_path / "v"
    vault.save(p, {"a": 1}, "pw", key); first = p.read_bytes()
    vault.save(p, {"a": 1}, "pw", key)
    assert p.stat().st_mode & 0o777 == 0o600 and p.read_bytes() != first
