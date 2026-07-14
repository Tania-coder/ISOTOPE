"""Optional PySpark integration: column-level taint tracking for Spark DataFrames.

Same design as isotope.pandas_ext / polars_ext:
* precise per-column labels, conservative (cumulative) node labels (I2);
* undeclared derived columns inherit ALL frame labels (safe over-approximation);
* labels leave the lineage only via an explicit, reasoned declassify.
"""
from __future__ import annotations

from typing import Dict, FrozenSet, Iterable, Mapping, Optional, Sequence

from .labels import Label
from .lineage import LineageError, Node, next_id
from .policy import PolicyViolation, Sink
from .track import DECLASSIFY_OP

try:
    from pyspark.sql import Column, DataFrame
except ImportError as e:  # pragma: no cover
    raise ImportError(
        "isotope.spark_ext requires pyspark: pip install isotope-lineage[spark]"
    ) from e

LabelMap = Dict[str, FrozenSet[Label]]


class TrackedSparkFrame:
    """A Spark DataFrame paired with per-column taint labels and lineage."""

    __slots__ = ("df", "labels", "node")

    def __init__(self, df: DataFrame, labels: Mapping[str, Iterable[Label]], node: Node) -> None:
        self.df = df
        self.labels: LabelMap = {c: frozenset(labels.get(c, frozenset())) for c in df.columns}
        self.node = node

    # -- constructors --------------------------------------------------

    @staticmethod
    def from_spark(
        df: DataFrame,
        column_labels: Optional[Mapping[str, Iterable[Label]]] = None,
        name: str = "dataframe",
    ) -> "TrackedSparkFrame":
        column_labels = dict(column_labels or {})
        unknown = set(column_labels) - set(df.columns)
        if unknown:
            raise KeyError(f"labels for unknown columns: {sorted(unknown)}")
        node_labels: FrozenSet[Label] = frozenset()
        for v in column_labels.values():
            node_labels = node_labels | frozenset(v)
        node = Node(id=next_id(), op=f"source:{name}", parents=(), labels=node_labels)
        return TrackedSparkFrame(
            df, {c: frozenset(column_labels.get(c, ())) for c in df.columns}, node
        )

    # -- introspection -------------------------------------------------

    @property
    def all_labels(self) -> FrozenSet[Label]:
        out: FrozenSet[Label] = frozenset()
        for v in self.labels.values():
            out = out | v
        return out

    def column_labels(self, column: str) -> FrozenSet[Label]:
        return self.labels[column]

    # -- internal ------------------------------------------------------

    def _derive(self, op: str, new_df: DataFrame, new_labels: LabelMap,
                extra_parents: Sequence[Node] = (), meta=()) -> "TrackedSparkFrame":
        parent_labels = self.node.labels
        for p in extra_parents:
            parent_labels = parent_labels | p.labels
        col_union: FrozenSet[Label] = frozenset()
        for v in new_labels.values():
            col_union = col_union | v
        node = Node(
            id=next_id(),
            op=op,
            parents=(self.node, *extra_parents),
            labels=parent_labels | col_union,  # cumulative: never silently shrinks (I2)
            meta=tuple(meta),
        )
        return TrackedSparkFrame(new_df, new_labels, node)

    # -- transforms ----------------------------------------------------

    def select(self, columns: Sequence[str]) -> "TrackedSparkFrame":
        cols = list(columns)
        return self._derive(f"select:{','.join(cols)}", self.df.select(*cols),
                            {c: self.labels[c] for c in cols})

    def filter_rows(self, condition) -> "TrackedSparkFrame":
        """condition: pyspark Column expression or SQL string."""
        return self._derive("filter_rows", self.df.filter(condition), dict(self.labels))

    def with_columns(self, deps: Optional[Mapping[str, Sequence[str]]] = None,
                     **named_exprs: Column) -> "TrackedSparkFrame":
        """df.withColumns() with label propagation.

        deps maps new column -> source columns it was derived from.
        Undeclared new columns conservatively inherit ALL frame labels.
        """
        deps = dict(deps or {})
        for k, cols in deps.items():
            missing = set(cols) - set(self.df.columns)
            if missing:
                raise KeyError(f"deps[{k!r}] references unknown columns {sorted(missing)}")
        new_df = self.df.withColumns(dict(named_exprs))
        new_labels: LabelMap = dict(self.labels)
        for k in named_exprs:
            if k in deps:
                lab: FrozenSet[Label] = frozenset()
                for c in deps[k]:
                    lab = lab | self.labels[c]
            else:
                lab = self.all_labels  # conservative
            new_labels[k] = lab
        return self._derive(f"with_columns:{','.join(named_exprs)}", new_df, new_labels)

    def join(self, other: "TrackedSparkFrame", on, how: str = "inner") -> "TrackedSparkFrame":
        if not isinstance(other, TrackedSparkFrame):
            raise TypeError("join() expects another TrackedSparkFrame")
        new_df = self.df.join(other.df, on=on, how=how)
        combined = self.all_labels | other.all_labels
        new_labels: LabelMap = {}
        for c in new_df.columns:
            if c in self.labels and c in other.labels:
                new_labels[c] = self.labels[c] | other.labels[c]
            elif c in self.labels:
                new_labels[c] = self.labels[c]
            elif c in other.labels:
                new_labels[c] = other.labels[c]
            else:
                new_labels[c] = combined
        return self._derive("join", new_df, new_labels, extra_parents=(other.node,))

    def group_by_agg(self, by: Sequence[str], aggs: Mapping[str, str]) -> "TrackedSparkFrame":
        """df.groupBy(by).agg({col: fn}) with label propagation.

        Group keys can leak the values of `by` columns, so every output
        column also inherits the labels of the grouping columns.
        Aggregated columns are aliased back to their source column name.
        """
        by = list(by)
        grouped = self.df.groupBy(*by).agg(dict(aggs))
        # spark names agg outputs like "sum(mrr)" -> rename back to "mrr"
        renames = {f"{fn}({col})": col for col, fn in aggs.items()}
        for old, new in renames.items():
            if old in grouped.columns:
                grouped = grouped.withColumnRenamed(old, new)
        by_labels: FrozenSet[Label] = frozenset()
        for c in by:
            by_labels = by_labels | self.labels[c]
        new_labels: LabelMap = {c: self.labels[c] for c in by}
        for c in aggs:
            new_labels[c] = self.labels[c] | by_labels
        return self._derive(f"group_by_agg:{','.join(by)}", grouped, new_labels)

    # -- declassification (the ONLY way labels are removed) -------------

    def declassify_column(self, column: str, label: Label, reason: str) -> "TrackedSparkFrame":
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("declassify_column() requires a non-empty reason")
        if column not in self.labels:
            raise KeyError(f"unknown column {column!r}")
        if label not in self.labels[column]:
            raise LineageError(f"label {label.name!r} not present on column {column!r}")
        new_labels = dict(self.labels)
        new_labels[column] = self.labels[column] - {label}
        step = self._derive(
            f"declassify_column:{column}",
            self.df,
            new_labels,
            meta=(("column", column), ("declassified", label.name), ("reason", reason.strip())),
        )
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
        return TrackedSparkFrame(step.df, step.labels, node)

    # -- enforcement (I5) ------------------------------------------------

    def send_to(self, sink: Sink) -> DataFrame:
        """Return the raw DataFrame if no column carries a forbidden label."""
        hit = self.all_labels & sink.forbidden
        if hit:
            offenders = sorted(c for c, v in self.labels.items() if v & sink.forbidden)
            raise PolicyViolation(f"{sink.name} (columns: {', '.join(offenders)})", hit)
        return self.df

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        cols = {c: sorted(lb.name for lb in v) for c, v in self.labels.items()}
        return f"TrackedSparkFrame(columns={cols}, node={self.node.id})"
