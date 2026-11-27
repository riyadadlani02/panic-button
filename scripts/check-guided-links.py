#!/usr/bin/env python3
"""Check each guided catalogue link: 2xx after redirects and still on the provider's own registrable domain.

Run `scripts/check-guided-links.py` to print a table, add `--write` to store the result in `verified`.
"""
import json
import sys
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

CATALOGUE = Path(__file__).resolve().parent.parent / "panic" / "guided_services.json"
# ponytail: small hand list, not the public suffix list; add a suffix here when a provider needs one
MULTI = {"co.uk", "org.uk", "co.in", "com.au", "co.jp", "com.br"}
UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"


def registrable(url: str) -> str:
    labels = (urlsplit(url).hostname or "").lower().split(".")
    return ".".join(labels[-3:] if ".".join(labels[-2:]) in MULTI else labels[-2:])


def check_entry(entry: dict, fetch) -> tuple[bool, list[str]]:
    """(verified, problems); verified only when every link is 2xx and its final URL stays on the link's own domain."""
    problems = []
    for kind, url in entry["links"].items():
        try:
            status, final = fetch(url)
        except Exception as e:
            problems.append(f"{kind}: {type(e).__name__}")
            continue
        if not 200 <= status < 300:
            problems.append(f"{kind}: HTTP {status}")
        elif registrable(final) != registrable(url):
            problems.append(f"{kind}: redirected off-domain to {final}")
    return not problems, problems


def fetch(url: str) -> tuple[int, str]:
    with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": UA}), timeout=15) as r:
        return r.status, r.geturl()


def main(argv: list[str]) -> int:
    services = json.loads(CATALOGUE.read_text())
    for key, entry in services.items():
        ok, problems = check_entry(entry, fetch)
        entry["verified"] = ok
        print(f"{key:14} {'OK' if ok else 'FAIL'}  " + "; ".join(problems))
    if "--write" in argv:
        CATALOGUE.write_text(json.dumps(services, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
