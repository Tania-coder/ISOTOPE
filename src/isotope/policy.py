"""Policy sinks: enforcement points where forbidden labels are rejected (I5)."""
from __future__ import annotations

from typing import Any, FrozenSet, Iterable

from .labels import Label
from .track import Tracked


class PolicyViolation(Exception):
    def __init__(self, sink: str, labels: FrozenSet[Label]) -> None:
        self.sink = sink
        self.labels = labels
        names = ", ".join(sorted(lb.name for lb in labels))
        super().__init__(f"sink {sink!r} rejects labels: {names}")


class Sink:
    """A named egress point with a set of forbidden labels."""

    def __init__(self, name: str, forbidden: Iterable[Label]) -> None:
        self.name = name
        self.forbidden = frozenset(forbidden)

    def send(self, tracked: Tracked) -> Any:
        """Return the raw value if allowed; raise PolicyViolation otherwise.

        There is deliberately no 'force' flag: the only sanctioned path
        past a sink is an explicit, reasoned declassify() upstream.
        """
        if not isinstance(tracked, Tracked):
            raise TypeError("Sink.send() accepts only Tracked values")
        hit = tracked.labels & self.forbidden
        if hit:
            raise PolicyViolation(self.name, hit)
        return tracked.value
