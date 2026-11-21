"""Account map: which accounts can reset which, and so what to lock first."""
from collections import defaultdict, deque

from panic.model import Edges


def _reach(start: str, adj: dict[str, list[str]]) -> set[str]:
    seen, queue = {start}, deque([start])
    while queue:
        for nxt in adj[queue.popleft()]:
            if nxt not in seen:
                seen.add(nxt)
                queue.append(nxt)
    return seen


def lock_order(accounts: list[str], edges: Edges) -> list[str]:
    adj: dict[str, list[str]] = defaultdict(list)
    for a, b in edges:
        adj[a].append(b)
    # Most reach first is root-first; mutual resetters tie and stay together.
    # ponytail: BFS per account, O(n^2); fine to thousands of accounts
    return sorted(accounts, key=lambda a: -len(_reach(a, adj)))


def resetters(account: str, edges: Edges) -> set[str]:
    rev: dict[str, list[str]] = defaultdict(list)
    for a, b in edges:
        rev[b].append(a)
    return _reach(account, rev) - {account}


def downstream(account: str, edges: Edges) -> list[str]:
    adj: dict[str, list[str]] = defaultdict(list)
    for a, b in edges:
        adj[a].append(b)
    rest = _reach(account, adj) - {account}
    return [account, *lock_order(sorted(rest), edges)]
