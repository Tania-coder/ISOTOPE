import pytest

yaml = pytest.importorskip("yaml")

from isotope import Label, PolicyViolation, Tracked
from isotope.policies import PolicyError, load_policies, parse_policies

GOOD = """
version: 1
labels:
  pii: Personally identifiable information
  secret: Credentials and keys
sinks:
  analytics_csv:
    forbidden: [pii, secret]
  internal_report:
    forbidden: [secret]
  public_docs:
    forbidden: []
"""


def test_load_from_yaml_string():
    reg = load_policies(GOOD)
    assert reg.version == 1
    assert reg.sink_names == ["analytics_csv", "internal_report", "public_docs"]
    assert reg.label("pii") == Label("pii")


def test_load_from_file(tmp_path):
    p = tmp_path / "policies.yaml"
    p.write_text(GOOD, encoding="utf-8")
    reg = load_policies(str(p))
    assert reg.sink("internal_report").forbidden == frozenset({Label("secret")})


def test_sinks_enforce_end_to_end():
    reg = load_policies(GOOD)
    email = Tracked.source("a@x.com", "crm", labels=[reg.label("pii")])
    with pytest.raises(PolicyViolation):
        reg.sink("analytics_csv").send(email)
    assert reg.sink("internal_report").send(email) == "a@x.com"


def test_unknown_sink_fails_loudly():
    reg = load_policies(GOOD)
    with pytest.raises(PolicyError, match="unknown sink"):
        reg.sink("analytics_cvs")  # typo must not silently disable enforcement


def test_unknown_label_reference_rejected():
    with pytest.raises(PolicyError, match="undeclared label"):
        parse_policies({
            "version": 1,
            "labels": {"pii": "desc"},
            "sinks": {"x": {"forbidden": ["secret"]}},
        })


def test_version_required():
    with pytest.raises(PolicyError, match="version"):
        parse_policies({"labels": {"pii": "d"}, "sinks": {"x": {"forbidden": []}}})


def test_label_description_required_for_audit():
    with pytest.raises(PolicyError, match="description"):
        parse_policies({"version": 1, "labels": {"pii": ""}, "sinks": {"x": {"forbidden": []}}})


def test_unknown_sink_keys_rejected():
    with pytest.raises(PolicyError, match="unknown keys"):
        parse_policies({
            "version": 1,
            "labels": {"pii": "d"},
            "sinks": {"x": {"forbidden": [], "allow_override": True}},
        })


def test_forbidden_must_be_list():
    with pytest.raises(PolicyError, match="forbidden"):
        parse_policies({
            "version": 1,
            "labels": {"pii": "d"},
            "sinks": {"x": {"forbidden": "pii"}},
        })
