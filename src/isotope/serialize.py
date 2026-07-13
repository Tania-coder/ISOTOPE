"""Lossless serialization of lineage graphs (I4)."""
from __future__ import annotations

from typing import Any, Dict

from .labels import Label
from .lineage import LineageError, Node, topological_order

FORMAT_VERSION = 1


def to_dict(root: Node) -> Dict[str, Any]:
    """Serialize the graph reachable from root. Deterministic output."""
    nodes = []
    for n in topological_order(root):
        nodes.append(
            {
                "id": n.id,
                "op": n.op,
                "labels": sorted(lb.name for lb in n.labels),
                "parents": [p.id for p in n.parents],
                "meta": [list(kv) for kv in n.meta],
            }
        )
    return {"version": FORMAT_VERSION, "root": root.id, "nodes": nodes}


def from_dict(data: Dict[str, Any]) -> Node:
    """Rebuild a lineage graph. Raises LineageError on malformed input."""
    if data.get("version") != FORMAT_VERSION:
        raise LineageError(f"unsupported format version: {data.get('version')!r}")
    built: Dict[int, Node] = {}
    for nd in data["nodes"]:
        if nd["id"] in built:
            raise LineageError(f"duplicate node id {nd['id']}")
        try:
            parents = tuple(built[pid] for pid in nd["parents"])
        except KeyError as e:
            raise LineageError(
                f"node {nd['id']} references unknown parent {e.args[0]}"
            ) from None
        built[nd["id"]] = Node(
            id=nd["id"],
            op=nd["op"],
            parents=parents,
            labels=frozenset(Label(s) for s in nd["labels"]),
            meta=tuple(tuple(kv) for kv in nd["meta"]),
        )
    root = built.get(data["root"])
    if root is None:
        raise LineageError(f"root {data['root']} not among nodes")
    return root
