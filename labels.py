"""Taint labels: immutable markers attached to tracked values."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, order=True)
class Label:
    """An immutable taint label, e.g. Label("pii") or Label("raw")."""

    name: str

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name:
            raise ValueError("Label name must be a non-empty string")

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return f"Label({self.name!r})"
