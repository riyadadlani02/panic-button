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
