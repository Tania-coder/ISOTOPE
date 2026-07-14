import pytest

pyspark = pytest.importorskip("pyspark")

from pyspark.sql import SparkSession
from pyspark.sql import functions as F

from isotope import Label, LineageError, PolicyViolation, Sink
from isotope.invariants import verify_graph
from isotope.spark_ext import TrackedSparkFrame

PII = Label("pii")
RAW = Label("raw")


@pytest.fixture(scope="module")
def spark():
    s = (
        SparkSession.builder.master("local[1]")
        .appName("isotope-tests")
        .config("spark.ui.enabled", "false")
        .config("spark.sql.shuffle.partitions", "1")
        .getOrCreate()
    )
    yield s
    s.stop()


@pytest.fixture()
def crm(spark):
    df = spark.createDataFrame(
        [("a@x.com", "free", 0), ("b@y.org", "pro", 49)],
        ["email", "plan", "mrr"],
    )
    return TrackedSparkFrame.from_spark(
        df, column_labels={"email": [PII], "mrr": [RAW]}, name="crm"
    )


def test_from_spark_sets_labels(crm):
    assert crm.column_labels("email") == frozenset({PII})
    assert crm.column_labels("plan") == frozenset()
    assert crm.all_labels == frozenset({PII, RAW})


def test_select_narrows_columns_but_lineage_is_conservative(crm):
    tf = crm.select(["plan", "mrr"])
    assert set(tf.labels) == {"plan", "mrr"}
    assert PII in tf.node.labels  # I2: node labels never silently shrink
    verify_graph(tf.node)


def test_with_columns_declared_deps(crm):
    tf = crm.with_columns(
        deps={"domain": ["email"]},
        domain=F.split(F.col("email"), "@").getItem(1),
    )
    assert tf.column_labels("domain") == frozenset({PII})
    assert tf.column_labels("plan") == frozenset()


def test_with_columns_without_deps_is_conservative(crm):
    tf = crm.with_columns(doubled=F.col("mrr") * 2)
    assert tf.column_labels("doubled") == frozenset({PII, RAW})


def test_filter_rows_keeps_labels(crm):
    tf = crm.filter_rows(F.col("mrr") > 0)
    assert tf.df.count() == 1
    assert tf.column_labels("email") == frozenset({PII})


def test_join_unions_labels(spark, crm):
    plans = spark.createDataFrame([("free", 10), ("pro", 1000)], ["plan", "limit"])
    right = TrackedSparkFrame.from_spark(plans, column_labels={"limit": [RAW]}, name="plans")
    tf = crm.join(right, on="plan")
    assert tf.column_labels("limit") == frozenset({RAW})
    assert tf.column_labels("email") == frozenset({PII})
    assert {p.id for p in tf.node.parents} == {crm.node.id, right.node.id}
    verify_graph(tf.node)


def test_group_by_agg_inherits_key_labels(crm):
    tf = crm.group_by_agg(by=["email"], aggs={"mrr": "sum"})
    assert "mrr" in tf.df.columns
    assert PII in tf.column_labels("mrr")


def test_sink_blocks_pii_and_names_columns(crm):
    export = Sink("csv_export", forbidden=[PII])
    with pytest.raises(PolicyViolation) as e:
        crm.send_to(export)
    assert "email" in str(e.value)


def test_declassify_column_then_send(crm):
    export = Sink("csv_export", forbidden=[PII])
    assert crm.select(["plan", "mrr"]).send_to(export) is not None
    tf = crm.declassify_column("email", PII, reason="hashed upstream, DPO-42")
    assert set(tf.send_to(export).columns) == {"email", "plan", "mrr"}
    verify_graph(tf.node)


def test_declassify_requires_reason_and_label(crm):
    with pytest.raises(ValueError):
        crm.declassify_column("email", PII, reason="  ")
    with pytest.raises(LineageError):
        crm.declassify_column("plan", PII, reason="not there")


def test_frame_level_declassify_recorded(crm):
    tf = crm.declassify_column("email", PII, reason="k-anonymized, DPO-7")
    assert PII not in tf.node.labels
    assert dict(tf.node.meta).get("declassified") == "pii"
    verify_graph(tf.node)
