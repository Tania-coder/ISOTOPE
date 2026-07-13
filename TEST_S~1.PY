import pytest

from isotope import Label, LineageError, Tracked, from_dict, to_dict

PII = Label("pii")


def test_roundtrip_diamond_with_declassify():
    s = Tracked.source(1, "s", labels=[PII, Label("raw")])
    j = Tracked.apply(
        "join", lambda a, b: a + b, s.map("l", lambda v: v), s.map("r", lambda v: v)
    )
    d = j.declassify(PII, reason="aggregate")
    d1 = to_dict(d.node)
    d2 = to_dict(from_dict(d1))
    assert d1 == d2


def test_from_dict_rejects_unknown_parent():
    with pytest.raises(LineageError):
        from_dict(
            {
                "version": 1,
                "root": 2,
                "nodes": [
                    {"id": 2, "op": "x", "labels": [], "parents": [99], "meta": []}
                ],
            }
        )


def test_from_dict_rejects_bad_version():
    with pytest.raises(LineageError):
        from_dict({"version": 999, "root": 1, "nodes": []})
