from panic import graph

E = [("mail", "bank"), ("mail", "social"), ("social", "forum")]


def test_root_first():
    order = graph.lock_order(["forum", "bank", "social", "mail"], E)
    assert order[0] == "mail" and order.index("social") < order.index("forum")


def test_mutual_recovery_does_not_loop():
    order = graph.lock_order(["a", "b", "c"], [("a", "b"), ("b", "a"), ("a", "c")])
    assert set(order[:2]) == {"a", "b"} and order[2] == "c"


def test_resetters_are_transitive():
    assert graph.resetters("forum", E) == {"social", "mail"}
    assert graph.resetters("mail", E) == set()


def test_unconnected_account_is_kept():
    order = graph.lock_order(["x", "mail", "bank"], E)
    assert order[0] == "mail" and sorted(order) == ["bank", "mail", "x"]
