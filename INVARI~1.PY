"""Runtime checkers for the ISOTOPE integrity invariants I1-I5.

I1 (completeness)   Every derived node's lineage references all of its inputs;
                    the reachable graph is closed under the parent relation.
I2 (conservation)   A node's labels are a superset of the union of its parents'
                    labels, EXCEPT an explicit declassify node, which removes
                    exactly one declared label and records a reason.
I3 (append-only DAG) The lineage graph is acyclic; nodes are immutable.
I4 (fidelity)       Serialization round-trips losslessly.
I5 (enforcement)    A sink must reject any value carrying a forbidden label.
                    (Checked behaviorally in tests and scripts/check_invariants.py.)
"""
from __future__ import annotations

from .labels import Label
from .lineage import LineageError, Node, assert_acyclic
from .serialize import from_dict, to_dict
from .track import DECLASSIFY_OP


def check_completeness(root: Node) -> None:
    """I1: the reachable set is closed; every parent is present and derived
    nodes have at least one parent."""
    graph = root.ancestors()
    for n in graph.values():
        for p in n.parents:
            if p.id not in graph:
                raise LineageError(f"node {n.id}: parent {p.id} missing from graph")
        if not n.parents and not (n.op.startswith("source:")):
            raise LineageError(f"node {n.id} ({n.op!r}) has no parents but is not a source")
        if n.parents and n.op.startswith("source:"):
            raise LineageError(f"source node {n.id} must not have parents")


def check_conservation(root: Node) -> None:
    """I2: labels never silently dropped; declassify is explicit and reasoned."""
    for n in root.ancestors().values():
        parent_union = frozenset()
        for p in n.parents:
            parent_union = parent_union | p.labels
        if n.op == DECLASSIFY_OP:
            meta = dict(n.meta)
            removed = meta.get("declassified")
            reason = meta.get("reason")
            if len(n.parents) != 1:
                raise LineageError(f"declassify node {n.id} must have exactly one parent")
            if not removed or not reason:
                raise LineageError(f"declassify node {n.id} lacks label/reason metadata")
            expected = n.parents[0].labels - {Label(removed)}
            if n.labels != expected:
                raise LineageError(f"declassify node {n.id} label set inconsistent")
        else:
            if not n.labels >= parent_union:
                dropped = sorted(l.name for l in parent_union - n.labels)
                raise LineageError(
                    f"node {n.id} ({n.op!r}) silently dropped labels: {dropped}"
                )


def check_acyclic(root: Node) -> None:
    """I3."""
    assert_acyclic(root)


def check_roundtrip(root: Node) -> None:
    """I4: to_dict(from_dict(to_dict(g))) == to_dict(g)."""
    d1 = to_dict(root)
    d2 = to_dict(from_dict(d1))
    if d1 != d2:
        raise LineageError("serialization round-trip mismatch")


def verify_graph(root: Node) -> list:
    """Run all structural invariant checks (I1-I4) on a graph. Returns names."""
    check_completeness(root)
    check_conservation(root)
    check_acyclic(root)
    check_roundtrip(root)
    return ["I1", "I2", "I3", "I4"]
