import json

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


@pytest.mark.parametrize("bad", [b"", b"short", bytes(33)])
def test_bad_keyfile_length(tmp_path, bad):
    key = vault.new_keyfile(); p = tmp_path / "v"
    with pytest.raises(ValueError):
        vault.save(p, {}, "pw", bad)
    vault.save(p, {}, "pw", key)
    with pytest.raises(vault.VaultError):
        vault.load(p, "pw", bad)


def test_missing_file_is_not_vault_error(tmp_path):
    with pytest.raises(FileNotFoundError):
        vault.load(tmp_path / "nope", "pw", vault.new_keyfile())


def test_header_is_authenticated(tmp_path):
    key = vault.new_keyfile(); p = tmp_path / "v"
    vault.save(p, {"a": 1}, "pw", key)
    raw = p.read_bytes()
    assert b'"format": 1' in raw
    p.write_bytes(raw.replace(b'"format": 1', b'"format": 2', 1))
    with pytest.raises(vault.VaultError):
        vault.load(p, "pw", key)


def test_salt_and_nonce_fresh_each_save(tmp_path):
    key = vault.new_keyfile(); p = tmp_path / "v"
    headers = []
    for _ in range(2):
        vault.save(p, {"a": 1}, "pw", key)
        headers.append(json.loads(p.read_bytes().split(b"\n", 1)[0]))
    assert headers[0]["salt"] != headers[1]["salt"]
    assert headers[0]["nonce"] != headers[1]["nonce"]
