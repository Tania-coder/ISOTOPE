"""Optional SQLAlchemy integration: column-level taint tracking for SQL results.

Labels are declared on table columns via Column.info:

    Column("email", String, info={"isotope_labels": [PII]})

tracked_select() executes a SELECT and returns a TrackedSQLResult whose
per-column labels are derived from the columns each output expression
actually references (SQLAlchemy expressions carry their dependencies,
so propagation here is precise, not conservative).
"""
from __future__ import annotations

from typing import Any, Dict, FrozenSet, Iterable, List, Mapping

from .labels import Label
from .lineage import LineageError, Node, next_id
from .policy import PolicyViolation, Sink
from .track import DECLASSIFY_OP

try:
    from sqlalchemy import Column
    from sqlalchemy.sql import visitors
except ImportError as e:  # pragma: no cover
    raise ImportError(
        "isotope.sqlalchemy_ext requires SQLAlchemy: pip install isotope-lineage[sqlalchemy]"
    ) from e

LABEL_INFO_KEY = "isotope_labels"
LabelMap = Dict[str, FrozenSet[Label]]


def column_labels(col: Column) -> FrozenSet[Label]:
    """Labels declared on a table column via Column.info."""
    return frozenset(col.info.get(LABEL_INFO_KEY, ()))


def _referenced_columns(expr) -> List[Column]:
    """All real table columns an expression references."""
    found: List[Column] = []

    def visit(element) -> None:
        if isinstance(element, Column):
            found.append(element)

    visitors.traverse(expr, {}, {"column": visit})
    return found


class TrackedSQLResult:
    """Rows fetched from a database, with per-column taint labels and lineage."""

    __slots__ = ("rows", "labels", "node")

    def __init__(self, rows: List[Mapping[str, Any]], labels: Mapping[str, Iterable[Label]],
                 node: Node) -> None:
        self.rows = rows
        self.labels: LabelMap = {c: frozenset(v) for c, v in labels.items()}
        self.node = node

    @property
    def all_labels(self) -> FrozenSet[Label]:
        out: FrozenSet[Label] = frozenset()
        for v in self.labels.values():
            out = out | v
        return out

    def column_labels(self, column: str) -> FrozenSet[Label]:
        return self.labels[column]

    # -- declassification (the ONLY way labels are removed) -------------

    def declassify_column(self, column: str, label: Label, reason: str) -> "TrackedSQLResult":
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("declassify_column() requires a non-empty reason")
        if column not in self.labels:
            raise KeyError(f"unknown column {column!r}")
        if label not in self.labels[column]:
            raise LineageError(f"label {label.name!r} not present on column {column!r}")
        new_labels = dict(self.labels)
        new_labels[column] = self.labels[column] - {label}
        col_union: FrozenSet[Label] = frozenset()
        for v in new_labels.values():
            col_union = col_union | v
        step_node = Node(
            id=next_id(),
            op=f"declassify_column:{column}",
            parents=(self.node,),
            labels=self.node.labels,  # cumulative at node level (I2)
            meta=(("column", column), ("declassified", label.name), ("reason", reason.strip())),
        )
        step = TrackedSQLResult(self.rows, new_labels, step_node)
        still_present = any(label in v for v in step.labels.values())
        if still_present or label not in step.node.labels:
            return step
        node = Node(
            id=next_id(),
            op=DECLASSIFY_OP,
            parents=(step.node,),
            labels=step.node.labels - {label},
            meta=(("declassified", label.name), ("reason", reason.strip())),
        )
        return TrackedSQLResult(step.rows, step.labels, node)

    # -- enforcement (I5) ------------------------------------------------

    def send_to(self, sink: Sink) -> List[Mapping[str, Any]]:
        """Return raw rows if no column carries a forbidden label."""
        hit = self.all_labels & sink.forbidden
        if hit:
            offenders = sorted(c for c, v in self.labels.items() if v & sink.forbidden)
            raise PolicyViolation(f"{sink.name} (columns: {', '.join(offenders)})", hit)
        return list(self.rows)

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        cols = {c: sorted(lb.name for lb in v) for c, v in self.labels.items()}
        return f"TrackedSQLResult(rows={len(self.rows)}, columns={cols}, node={self.node.id})"


def tracked_select(conn, stmt, name: str = "db") -> TrackedSQLResult:
    """Execute a SELECT and track labels per output column.

    Each output column's labels are the union of the labels of every real
    table column its expression references (exact dependency tracking).
    """
    result = conn.execute(stmt)
    rows = [dict(m) for m in result.mappings().all()]

    out_labels: LabelMap = {}
    all_deps: FrozenSet[Label] = frozenset()
    tables = set()
    for col in stmt.selected_columns:
        deps = _referenced_columns(col)
        lab: FrozenSet[Label] = frozenset()
        for dep in deps:
            lab = lab | column_labels(dep)
            if dep.table is not None and dep.table.name is not None:
                tables.add(str(dep.table.name))
        out_labels[col.key] = lab
        all_deps = all_deps | lab

    node = Node(
        id=next_id(),
        op=f"source:sql:{','.join(sorted(tables)) or name}",
        parents=(),
        labels=all_deps,
        meta=(("source", name),),
    )
    return TrackedSQLResult(rows, out_labels, node)
