import pytest

pd = pytest.importorskip("pandas")

from isotope import Label, LineageError, PolicyViolation, Sink
from isotope.invariants import verify_graph
from isotope.pandas_ext import TrackedFrame

PII = Label("pii")
RAW = Label("raw")


def crm():
    df = pd.DataFrame(
        {"email": ["a@x.com", "b@y.org"], "plan": ["free", "pro"], "mrr": [0, 49]}
    )
    return TrackedFrame.from_pandas(df, column_labels={"email": [PII], "mrr": [RAW]}, name="crm")


def test_from_pandas_sets_labels():
    tf = crm()
    assert tf.column_labels("email") == frozenset({PII})
    assert tf.column_labels("plan") == frozenset()
    assert tf.all_labels == frozenset({PII, RAW})


def test_from_pandas_rejects_unknown_columns():
    with pytest.raises(KeyError):
        TrackedFrame.from_pandas(pd.DataFrame({"a": [1]}), column_labels={"b": [PII]})


def test_select_narrows_columns_but_lineage_is_conservative():
    tf = crm().select(["plan", "mrr"])
    assert set(tf.labels) == {"plan", "mrr"}
    assert PII in tf.node.labels  # node labels never silently shrink (I2)
    verify_graph(tf.node)


def test_assign_with_declared_deps():
    tf = crm().assign(deps={"domain": ["email"]}, domain=lambda d: d.email.str.split("@").str[1])
    assert tf.column_labels("domain") == frozenset({PII})
    assert tf.column_labels("plan") == frozenset()


def test_assign_without_deps_is_conservative():
    tf = crm().assign(doubled=lambda d: d.mrr * 2)
    assert tf.column_labels("doubled") == frozenset({PII, RAW})


def test_merge_unions_labels():
    left = crm()
    right = TrackedFrame.from_pandas(
        pd.DataFrame({"plan": ["free", "pro"], "limit": [10, 1000]}),
        column_labels={"limit": [RAW]},
        name="plans",
    )
    tf = left.merge(right, on="plan")
    assert tf.column_labels("limit") == frozenset({RAW})
    assert tf.column_labels("email") == frozenset({PII})
    assert {p.id for p in tf.node.parents} == {left.node.id, right.node.id}
    verify_graph(tf.node)


def test_groupby_agg_inherits_key_labels():
    tf = crm().groupby_agg(by=["email"], aggs={"mrr": "sum"})
    assert PII in tf.column_labels("mrr")  # group keys leak into aggregates


def test_sink_blocks_pii_and_names_columns():
    export = Sink("csv_export", forbidden=[PII])
    with pytest.raises(PolicyViolation) as e:
        crm().send_to(export)
    assert "email" in str(e.value)


def test_declassify_column_then_send():
    export = Sink("csv_export", forbidden=[PII])
    tf = crm().select(["plan", "mrr"])  # PII column dropped, but lineage remembers
    assert tf.send_to(export) is not None  # no PII column present -> allowed
    tf2 = crm().declassify_column("email", PII, reason="hashed upstream, DPO-42")
    out = tf2.send_to(export)
    assert list(out.columns) == ["email", "plan", "mrr"]
    verify_graph(tf2.node)


def test_declassify_column_requires_reason_and_label():
    with pytest.raises(ValueError):
        crm().declassify_column("email", PII, reason=" ")
    with pytest.raises(LineageError):
        crm().declassify_column("plan", PII, reason="not there")


def test_frame_level_declassify_recorded_when_label_fully_removed():
    tf = crm().declassify_column("email", PII, reason="k-anonymized, DPO-7")
    assert PII not in tf.node.labels
    meta = dict(tf.node.meta)
    assert meta.get("declassified") == "pii"
    verify_graph(tf.node)
