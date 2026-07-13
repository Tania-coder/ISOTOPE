"""Lineage graph: immutable, append-only DAG of provenance nodes."""
from __future__ import annotations

import itertools
import threading
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, Tuple

from .labels import Label

_counter = itertools.count(1)
_lock = threading.Lock()


class LineageError(Exception):
    """Raised when a lineage integrity rule is violated."""


def next_id() -> int:
    with _lock:
        return next(_counter)


@dataclass(frozen=True)
class Node:
    """A single immutable provenance node.

    Nodes are created with references to already-existing parent nodes,
    which makes the graph append-only and acyclic by construction (I3).
    """

    id: int
    op: str
    parents: Tuple["Node", ...]
    labels: FrozenSet[Label]
    meta: Tuple[Tuple[str, str], ...] = field(default_factory=tuple)

    def ancestors(self) -> Dict[int, "Node"]:
        """All nodes reachable from this node (including itself), by id."""
        seen: Dict[int, Node] = {}
        stack = [self]
        while stack:
            n = stack.pop()
            if n.id in seen:
                continue
            seen[n.id] = n
            stack.extend(n.parents)
        return seen


def assert_acyclic(root: Node) -> None:
    """Defensive cycle check over the graph reachable from root (I3)."""
    visiting: set = set()
    done: set = set()
    stack = [(root, 0)]
    while stack:
        node, i = stack.pop()
        if i == 0:
            if node.id in done:
                continue
            if node.id in visiting:
                raise LineageError(f"cycle detected at node {node.id}")
            visiting.add(node.id)
        if i < len(node.parents):
            stack.append((node, i + 1))
            p = node.parents[i]
            if p.id in visiting and p.id not in done:
                raise LineageError(f"cycle detected at node {p.id}")
            if p.id not in done:
                stack.append((p, 0))
        else:
            visiting.discard(node.id)
            done.add(node.id)


def topological_order(root: Node) -> list:
    """Nodes reachable from root, parents strictly before children."""
    order: list = []
    done: set = set()
    stack = [(root, 0)]
    while stack:
        node, i = stack.pop()
        if node.id in done:
            continue
        if i < len(node.parents):
            stack.append((node, i + 1))
            stack.append((node.parents[i], 0))
        else:
            done.add(node.id)
            order.append(node)
    return order
