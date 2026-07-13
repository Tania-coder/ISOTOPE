"""Optional pandas integration: column-level taint tracking for DataFrames.

Design notes
------------
* Column labels are tracked precisely per column.
* The frame's lineage Node keeps a CONSERVATIVE (cumulative) label set:
  dropping a column narrows the column map but never silently shrinks the
  node's labels (I2). The only way a label leaves the lineage is an
  explicit declassify with a reason.
* Propagation through user code is conservative: if you do not declare
  which columns a new column was derived from, it inherits the labels of
  ALL columns in the frame. Declare dependencies to narrow this:
      tf.assign(deps={"domain": ["email"]}, domain=lambda d: ...)
  A false positive is safer than a missed leak.
"""
from __future__ import annotations

from typing import Callable, Dict, FrozenSet, Iterable, Mapping, Optional, Sequence

from .labels import Label
from .lineage import LineageError, Node, next_id
from .policy import PolicyViolation, Sink
from .track import DECLASSIFY_OP

try:
    import pandas as pd
except ImportError as e:  # pragma: no cover
    raise ImportError(
        "isotope.pandas_ext requires pandas: pip install isotope-lineage[pandas]"
    ) from e

LabelMap = Dict[str, FrozenSet[Label]]


class TrackedFrame:
    """A pandas DataFrame paired with per-column taint labels and lineage."""

    __slots__ = ("df", "labels", "node")

    def __init__(self, df: "pd.DataFrame", labels: Mapping[str, Iterable[Label]], node: Node) -> None:
        self.df = df
        self.labels: LabelMap = {
            c: frozenset(labels.get(c, frozenset())) for c in df.columns
        }
        self.node = node

    # -- constructors --------------------------------------------------

    @staticmethod
    def from_pandas(
        df: "pd.DataFrame",
        column_labels: Optional[Mapping[str, Iterable[Label]]] = None,
        name: str = "dataframe",
    ) -> "TrackedFrame":
        column_labels = dict(column_labels or {})
        unknown = set(column_labels) - set(df.columns)
        if unknown:
            raise KeyError(f"labels for unknown columns: {sorted(unknown)}")
        node_labels: FrozenSet[Label] = frozenset()
        for v in column_labels.values():
            node_labels = node_labels | frozenset(v)
        node = Node(id=next_id(), op=f"source:{name}", parents=(), labels=node_labels)
        return TrackedFrame(df.copy(), {c: frozenset(column_labels.get(c, ())) for c in df.columns}, node)

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

    def _derive(self, op: str, new_df: "pd.DataFrame", new_labels: LabelMap,
                extra_parents: Sequence[Node] = (), meta=()) -> "TrackedFrame":
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
        return TrackedFrame(new_df, new_labels, node)

    # -- transforms ----------------------------------------------------

    def select(self, columns: Sequence[str]) -> "TrackedFrame":
        new_df = self.df[list(columns)].copy()
        return self._derive(f"select:{','.join(columns)}", new_df,
                            {c: self.labels[c] for c in columns})

    def filter_rows(self, fn: Callable[["pd.DataFrame"], "pd.Series"]) -> "TrackedFrame":
        mask = fn(self.df)
        return self._derive("filter_rows", self.df[mask].copy(), dict(self.labels))

    def assign(self, deps: Optional[Mapping[str, Sequence[str]]] = None, **kwargs) -> "TrackedFrame":
        """pandas .assign() with label propagation.

        deps maps new column -> source columns it was derived from.
        Undeclared new columns conservatively inherit ALL frame labels.
        """
        deps = dict(deps or {})
        for k, cols in deps.items():
            missing = set(cols) - set(self.df.columns)
            if missing:
                raise KeyError(f"deps[{k!r}] references unknown columns {sorted(missing)}")
        new_df = self.df.assign(**kwargs)
        new_labels: LabelMap = dict(self.labels)
        for k in kwargs:
            if k in deps:
                lab: FrozenSet[Label] = frozenset()
                for c in deps[k]:
                    lab = lab | self.labels[c]
            else:
                lab = self.all_labels  # conservative
            new_labels[k] = lab
        return self._derive(f"assign:{','.join(kwargs)}", new_df, new_labels)

    def merge(self, other: "TrackedFrame", **kwargs) -> "TrackedFrame":
        if not isinstance(other, TrackedFrame):
            raise TypeError("merge() expects another TrackedFrame")
        new_df = self.df.merge(other.df, **kwargs)
        combined = self.all_labels | other.all_labels
        new_labels: LabelMap = {}
        for c in new_df.columns:
            if c in self.labels and c in other.labels:
                new_labels[c] = self.labels[c] | other.labels[c]
            elif c in self.labels:
                new_labels[c] = self.labels[c]
            elif c in other.labels:
                new_labels[c] = other.labels[c]
            else:  # suffixed or synthesized column
                new_labels[c] = combined
        return self._derive("merge", new_df, new_labels, extra_parents=(other.node,))

    def groupby_agg(self, by: Sequence[str], aggs: Mapping[str, str]) -> "TrackedFrame":
        """df.groupby(by).agg(aggs).reset_index() with label propagation.

        Group keys can leak the values of `by` columns, so every output
        column also inherits the labels of the grouping columns.
        """
        by = list(by)
        new_df = self.df.groupby(by).agg(dict(aggs)).reset_index()
        by_labels: FrozenSet[Label] = frozenset()
        for c in by:
            by_labels = by_labels | self.labels[c]
        new_labels: LabelMap = {c: self.labels[c] for c in by}
        for c in aggs:
            new_labels[c] = self.labels[c] | by_labels
        return self._derive(f"groupby_agg:{','.join(by)}", new_df, new_labels)

    # -- declassification (the ONLY way labels are removed) -------------

    def declassify_column(self, column: str, label: Label, reason: str) -> "TrackedFrame":
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
            self.df.copy(),
            new_labels,
            meta=(("column", column), ("declassified", label.name), ("reason", reason.strip())),
        )
        still_present = any(label in v for v in step.labels.values())
        if still_present or label not in step.node.labels:
            return step
        # Label left the whole frame: record a proper frame-level declassify (I2).
        node = Node(
            id=next_id(),
            op=DECLASSIFY_OP,
            parents=(step.node,),
            labels=step.node.labels - {label},
            meta=(("declassified", label.name), ("reason", reason.strip())),
        )
        return TrackedFrame(step.df, step.labels, node)

    # -- enforcement (I5) ------------------------------------------------

    def send_to(self, sink: Sink) -> "pd.DataFrame":
        """Return the raw DataFrame if no column carries a forbidden label."""
        hit = self.all_labels & sink.forbidden
        if hit:
            offenders = sorted(c for c, v in self.labels.items() if v & sink.forbidden)
            raise PolicyViolation(f"{sink.name} (columns: {', '.join(offenders)})", hit)
        return self.df.copy()

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        cols = {c: sorted(lb.name for lb in v) for c, v in self.labels.items()}
        return f"TrackedFrame(columns={cols}, node={self.node.id})"
