import pytest

sqlalchemy = pytest.importorskip("sqlalchemy")

from sqlalchemy import (
    Column,
    Integer,
    MetaData,
    String,
    Table,
    create_engine,
    func,
    select,
)

from isotope import Label, LineageError, PolicyViolation, Sink
from isotope.invariants import verify_graph
from isotope.sqlalchemy_ext import TrackedSQLResult, column_labels, tracked_select

PII = Label("pii")
RAW = Label("raw")

metadata = MetaData()

users = Table(
    "users",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("email", String, info={"isotope_labels": [PII]}),
    Column("plan", String),
    Column("mrr", Integer, info={"isotope_labels": [RAW]}),
)

plans = Table(
    "plans",
    metadata,
    Column("plan", String, primary_key=True),
    Column("limit", Integer, info={"isotope_labels": [RAW]}),
)


@pytest.fixture()
def conn():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    metadata.create_all(engine)
    with engine.begin() as c:
        c.execute(users.insert(), [
            {"id": 1, "email": "a@x.com", "plan": "free", "mrr": 0},
            {"id": 2, "email": "b@y.org", "plan": "pro", "mrr": 49},
        ])
        c.execute(plans.insert(), [
            {"plan": "free", "limit": 10},
            {"plan": "pro", "limit": 1000},
        ])
    with engine.connect() as c:
        yield c


def test_column_labels_declared_in_info():
    assert column_labels(users.c.email) == frozenset({PII})
    assert column_labels(users.c.plan) == frozenset()


def test_select_tracks_labels_per_column(conn):
    tr = tracked_select(conn, select(users.c.email, users.c.plan))
    assert len(tr.rows) == 2
    assert tr.column_labels("email") == frozenset({PII})
    assert tr.column_labels("plan") == frozenset()
    verify_graph(tr.node)


def test_computed_expression_inherits_source_labels(conn):
    stmt = select(func.lower(users.c.email).label("email_lc"), users.c.plan)
    tr = tracked_select(conn, stmt)
    assert tr.column_labels("email_lc") == frozenset({PII})
    assert tr.column_labels("plan") == frozenset()


def test_join_tracks_labels_from_both_tables(conn):
    stmt = (
        select(users.c.email, plans.c.limit)
        .select_from(users.join(plans, users.c.plan == plans.c.plan))
    )
    tr = tracked_select(conn, stmt)
    assert tr.column_labels("email") == frozenset({PII})
    assert tr.column_labels("limit") == frozenset({RAW})


def test_clean_select_has_no_labels(conn):
    tr = tracked_select(conn, select(users.c.plan))
    assert tr.all_labels == frozenset()
    export = Sink("csv", forbidden=[PII])
    assert len(tr.send_to(export)) == 2


def test_sink_blocks_pii_and_names_columns(conn):
    tr = tracked_select(conn, select(users.c.email, users.c.mrr))
    export = Sink("external_api", forbidden=[PII])
    with pytest.raises(PolicyViolation) as e:
        tr.send_to(export)
    assert "email" in str(e.value)


def test_declassify_column_then_send(conn):
    tr = tracked_select(conn, select(users.c.email, users.c.mrr))
    ok = tr.declassify_column("email", PII, reason="hashed downstream, DPO-9")
    export = Sink("external_api", forbidden=[PII])
    rows = ok.send_to(export)
    assert len(rows) == 2
    verify_graph(ok.node)


def test_declassify_requires_reason_and_label(conn):
    tr = tracked_select(conn, select(users.c.email))
    with pytest.raises(ValueError):
        tr.declassify_column("email", PII, reason=" ")
    with pytest.raises(LineageError):
        tr.declassify_column("email", RAW, reason="not there")


def test_frame_level_declassify_recorded(conn):
    tr = tracked_select(conn, select(users.c.email))
    out = tr.declassify_column("email", PII, reason="k-anon, DPO-3")
    assert PII not in out.node.labels
    assert dict(out.node.meta).get("declassified") == "pii"
    verify_graph(out.node)


def test_repr_smoke(conn):
    tr = tracked_select(conn, select(users.c.email))
    assert isinstance(tr, TrackedSQLResult)
    assert "email" in repr(tr)
