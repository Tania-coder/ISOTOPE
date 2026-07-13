import pytest

from isotope import Label, PolicyViolation, Sink, Tracked

PII = Label("pii")
RAW = Label("raw")


def test_sink_rejects_forbidden_label():
    t = Tracked.source("secret", "db", labels=[PII])
    sink = Sink("export", forbidden=[PII])
    with pytest.raises(PolicyViolation) as e:
        sink.send(t)
    assert e.value.labels == frozenset({PII})


def test_sink_allows_clean_value():
    t = Tracked.source(42, "db", labels=[RAW])
    assert Sink("export", forbidden=[PII]).send(t) == 42


def test_sink_allows_after_declassify():
    t = Tracked.source("secret", "db", labels=[PII])
    ok = t.declassify(PII, reason="reviewed by DPO ticket #123")
    assert Sink("export", forbidden=[PII]).send(ok) == "secret"


def test_sink_rejects_untracked_values():
    with pytest.raises(TypeError):
        Sink("export", forbidden=[PII]).send("raw string")
