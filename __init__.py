"""ISOTOPE: data lineage and taint-tracking with verifiable integrity invariants."""
from .labels import Label
from .lineage import LineageError, Node, assert_acyclic, topological_order
from .policy import PolicyViolation, Sink
from .serialize import from_dict, to_dict
from .track import Tracked
from . import invariants

__version__ = "0.1.0"

__all__ = [
    "Label",
    "LineageError",
    "Node",
    "PolicyViolation",
    "Sink",
    "Tracked",
    "assert_acyclic",
    "topological_order",
    "to_dict",
    "from_dict",
    "invariants",
    "__version__",
]
