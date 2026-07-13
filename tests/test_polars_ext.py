import pytest

pl = pytest.importorskip("polars")

from isotope import Label, LineageError, PolicyViolation, Sink
from isotope.invariants import verify_graph
from isotope.polars_ext import TrackedPolarsFrame

PII = Label("pii")
RAW = Label("raw")


def crm():
    df = pl.DataFrame(
        {"email": ["a@x.com", "b@y.org"], "plan": ["free", "pro"], "mrr": [0, 49]}
    )
    return TrackedPolarsFrame.from_polars(
        df, column_labels={"email": [PII], "mrr": [RAW]}, name="crm"
    )


def test_from_polars_sets_labels():
    tf = crm()
    assert tf.column_labels("email") == frozenset({PII})
    assert tf.column_labels("plan") == frozenset()
    assert tf.all_labels == frozenset({PII, RAW})


def test_from_polars_rejects_unknown_columns():
    with pytest.raises(KeyError):
        TrackedPolarsFrame.from_polars(pl.DataFrame({"a": [1]}), column_labels={"b": [PII]})


def test_select_narrows_columns_but_lineage_is_conservative():
    tf = crm().select(["plan", "mrr"])
    assert set(tf.labels) == {"plan", "mrr"}
    assert PII in tf.node.labels  # node labels never silently shrink (I2)
    verify_graph(tf.node)


def test_with_columns_declared_deps():
    tf = crm().with_columns(
        deps={"domain": ["email"]},
        domain=pl.col("email").str.split("@").list.get(1),
    )
    assert tf.column_labels("domain") == frozenset({PII})
    assert tf.column_labels("plan") == frozenset()


def test_with_columns_without_deps_is_conservative():
    tf = crm().with_columns(doubled=pl.col("mrr") * 2)
    assert tf.column_labels("doubled") == frozenset({PII, RAW})


def test_filter_rows_keeps_labels():
    tf = crm().filter_rows(pl.col("mrr") > 0)
    assert tf.df.height == 1
    assert tf.column_labels("email") == frozenset({PII})


def test_join_unions_labels():
    left = crm()
    right = TrackedPolarsFrame.from_polars(
        pl.DataFrame({"plan": ["free", "pro"], "limit": [10, 1000]}),
        column_labels={"limit": [RAW]},
        name="plans",
    )
    tf = left.join(right, on="plan")
    assert tf.column_labels("limit") == frozenset({RAW})
    assert tf.column_labels("email") == frozenset({PII})
    assert {p.id for p in tf.node.parents} == {left.node.id, right.node.id}
    verify_graph(tf.node)


def test_group_by_agg_inherits_key_labels():
    tf = crm().group_by_agg(by=["email"], aggs={"mrr": "sum"})
    assert PII in tf.column_labels("mrr")


def test_sink_blocks_pii_and_names_columns():
    export = Sink("csv_export", forbidden=[PII])
    with pytest.raises(PolicyViolation) as e:
        crm().send_to(export)
    assert "email" in str(e.value)


def test_declassify_column_then_send():
    export = Sink("csv_export", forbidden=[PII])
    assert crm().select(["plan", "mrr"]).send_to(export) is not None
    tf = crm().declassify_column("email", PII, reason="hashed upstream, DPO-42")
    assert tf.send_to(export).columns == ["email", "plan", "mrr"]
    verify_graph(tf.node)


def test_declassify_column_requires_reason_and_label():
    with pytest.raises(ValueError):
        crm().declassify_column("email", PII, reason=" ")
    with pytest.raises(LineageError):
        crm().declassify_column("plan", PII, reason="not there")


def test_frame_level_declassify_recorded_when_label_fully_removed():
    tf = crm().declassify_column("email", PII, reason="k-anonymized, DPO-7")
    assert PII not in tf.node.labels
    assert dict(tf.node.meta).get("declassified") == "pii"
    verify_graph(tf.node)
