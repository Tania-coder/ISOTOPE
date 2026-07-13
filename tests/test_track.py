import pytest

from isotope import Label, Tracked

PII = Label("pii")
RAW = Label("raw")


def test_source_carries_labels():
    t = Tracked.source("alice@example.com", "crm", labels=[PII])
    assert t.labels == frozenset({PII})
    assert t.node.op == "source:crm"
    assert t.node.parents == ()


def test_apply_unions_labels_and_records_parents():
    a = Tracked.source(2, "a", labels=[PII])
    b = Tracked.source(3, "b", labels=[RAW])
    c = Tracked.apply("add", lambda x, y: x + y, a, b)
    assert c.value == 5
    assert c.labels == frozenset({PII, RAW})
    assert {p.id for p in c.node.parents} == {a.node.id, b.node.id}


def test_apply_mixes_plain_and_tracked():
    a = Tracked.source(10, "a", labels=[RAW])
    c = Tracked.apply("scale", lambda x, k: x * k, a, 3)
    assert c.value == 30
    assert c.labels == frozenset({RAW})
    assert [p.id for p in c.node.parents] == [a.node.id]


def test_apply_requires_tracked_input():
    with pytest.raises(ValueError):
        Tracked.apply("nope", lambda x: x, 42)


def test_map_shorthand():
    a = Tracked.source("x", "a", labels=[PII])
    b = a.map("upper", str.upper)
    assert b.value == "X"
    assert b.labels == frozenset({PII})
