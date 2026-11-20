import json

from panic import log


def test_chain_verifies(tmp_path):
    p = tmp_path / "log.jsonl"
    log.append(p, {"e": 1}); log.append(p, {"e": 2})
    lines = [json.loads(l) for l in p.read_text().splitlines()]
    assert lines[0]["prev"] == "" and lines[1]["prev"] != "" and "at" in lines[0]
    assert log.verify(p)


def test_edit_is_detected(tmp_path):
    p = tmp_path / "log.jsonl"
    log.append(p, {"e": 1}); log.append(p, {"e": 2})
    p.write_text(p.read_text().replace('"e": 1', '"e": 9'))
    assert not log.verify(p)


def test_torn_last_line_does_not_block_new_entries(tmp_path):
    p = tmp_path / "log.jsonl"
    log.append(p, {"e": 1})
    with p.open("a") as f: f.write('{"e": 2, "pre')
    log.append(p, {"e": 3})
    assert not log.verify(p)
    assert json.loads(p.read_text().splitlines()[-1])["e"] == 3


def test_head_is_digest_of_last_line(tmp_path):
    import hashlib
    p = tmp_path / "log.jsonl"
    assert log.head(p) == ""
    p.write_bytes(b"")
    assert log.head(p) == ""
    log.append(p, {"e": 1}); log.append(p, {"e": 2})
    assert log.head(p) == hashlib.sha256(p.read_bytes().splitlines()[-1]).hexdigest()
    log.append(p, {"e": 3})
    assert log.head(p) == hashlib.sha256(p.read_bytes().splitlines()[-1]).hexdigest()


def test_contains_finds_any_line_digest(tmp_path):
    import hashlib
    p = tmp_path / "log.jsonl"
    assert log.contains(p, "")
    log.append(p, {"e": 1})
    first = log.head(p)
    log.append(p, {"e": 2})
    assert log.contains(p, first) and log.contains(p, log.head(p))
    assert not log.contains(p, "") and not log.contains(p, hashlib.sha256(b"x").hexdigest())


def test_entries_skips_unreadable_lines(tmp_path):
    p = tmp_path / "log.jsonl"
    assert log.entries(p) == []
    log.append(p, {"e": 1})
    with p.open("a") as f: f.write("not json\n[1]\n")
    assert [e["e"] for e in log.entries(p)] == [1]
