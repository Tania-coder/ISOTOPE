"""Tracked values: data plus its lineage node."""
from __future__ import annotations

from typing import Any, Callable, FrozenSet, Iterable

from .labels import Label
from .lineage import LineageError, Node, next_id

DECLASSIFY_OP = "declassify"


class Tracked:
    """A value paired with its provenance node."""

    __slots__ = ("value", "node")

    def __init__(self, value: Any, node: Node) -> None:
        self.value = value
        self.node = node

    @property
    def labels(self) -> FrozenSet[Label]:
        return self.node.labels

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        names = ",".join(sorted(lb.name for lb in self.labels))
        return f"Tracked({self.value!r}, labels={{{names}}}, node={self.node.id})"

    # -- constructors -------------------------------------------------

    @staticmethod
    def source(value: Any, name: str, labels: Iterable[Label] = ()) -> "Tracked":
        """Introduce a new root value into the lineage graph."""
        node = Node(
            id=next_id(),
            op=f"source:{name}",
            parents=(),
            labels=frozenset(labels),
        )
        return Tracked(value, node)

    @staticmethod
    def apply(
        op: str,
        fn: Callable[..., Any],
        *inputs: Any,
        extra_labels: Iterable[Label] = (),
    ) -> "Tracked":
        """Derive a new value from inputs; lineage records every Tracked input (I1)
        and the result carries the union of input labels (I2)."""
        tracked = [i for i in inputs if isinstance(i, Tracked)]
        if not tracked:
            raise ValueError("apply() requires at least one Tracked input")
        raw = [i.value if isinstance(i, Tracked) else i for i in inputs]
        value = fn(*raw)
        labels: FrozenSet[Label] = frozenset(extra_labels)
        for t in tracked:
            labels = labels | t.node.labels
        node = Node(
            id=next_id(),
            op=op,
            parents=tuple(t.node for t in tracked),
            labels=labels,
        )
        return Tracked(value, node)

    # -- transforms ---------------------------------------------------

    def map(self, op: str, fn: Callable[[Any], Any]) -> "Tracked":
        return Tracked.apply(op, fn, self)

    def declassify(self, label: Label, reason: str) -> "Tracked":
        """Remove exactly one label, explicitly and with a recorded reason (I2).

        This is the ONLY way a label may disappear from a lineage path.
        """
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("declassify() requires a non-empty reason")
        if label not in self.node.labels:
            raise LineageError(
                f"cannot declassify {label.name!r}: label not present"
            )
        node = Node(
            id=next_id(),
            op=DECLASSIFY_OP,
            parents=(self.node,),
            labels=self.node.labels - {label},
            meta=(("declassified", label.name), ("reason", reason.strip())),
        )
        return Tracked(self.value, node)
