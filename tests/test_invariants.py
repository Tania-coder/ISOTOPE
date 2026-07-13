import pytest

from isotope import Label, LineageError, Tracked
from isotope.invariants import verify_graph

PII = Label("pii")
RAW = Label("raw")


def diamond():
    s = Tracked.source(1, "s", labels=[PII, RAW])
    l = s.map("left", lambda v: v + 1)
    r = s.map("right", lambda v: v * 2)
    return Tracked.apply("join", lambda a, b: (a, b), l, r)


def test_verify_graph_passes_on_diamond():
    assert verify_graph(diamond().node) == ["I1", "I2", "I3", "I4"]


def test_declassify_removes_exactly_one_label_with_reason():
    t = diamond().declassify(PII, reason="aggregated above k-anonymity threshold")
    assert t.labels == frozenset({RAW})
    meta = dict(t.node.meta)
    assert meta["declassified"] == "pii"
    assert "reason" in meta
    verify_graph(t.node)


def test_declassify_requires_reason():
    t = diamond()
    with pytest.raises(ValueError):
        t.declassify(PII, reason="   ")


def test_declassify_requires_label_present():
    t = Tracked.source(1, "s", labels=[RAW])
    with pytest.raises(LineageError):
        t.declassify(PII, reason="not there")


def test_conservation_detects_silent_label_drop():
    # Build a corrupted node by hand: child drops parent's label without declassify.
    from isotope.lineage import Node, next_id

    parent = Tracked.source(1, "s", labels=[PII]).node
    bad = Node(id=next_id(), op="launder", parents=(parent,), labels=frozenset())
    with pytest.raises(LineageError):
        verify_graph(bad)


def test_nodes_are_immutable():
    n = Tracked.source(1, "s").node
    with pytest.raises(Exception):
        n.op = "tampered"
