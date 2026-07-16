"""Centralized security policies loaded from YAML (Policy Server foundation).

Compliance teams edit a policy file; pipelines reference sinks by name and
never hardcode label rules:

    # policies.yaml
    version: 1
    labels:
      pii: Personally identifiable information
      secret: Credentials and keys
    sinks:
      analytics_csv:
        forbidden: [pii, secret]
      internal_report:
        forbidden: [secret]

    registry = load_policies("policies.yaml")
    export = registry.sink("analytics_csv")   # a regular isotope Sink

Every lookup is validated: unknown sink names and labels fail loudly —
a typo must never silently disable enforcement.
"""
from __future__ import annotations

from typing import Any, Dict, Mapping

from .labels import Label
from .policy import Sink

try:
    import yaml
except ImportError as e:  # pragma: no cover
    raise ImportError(
        "isotope.policies requires PyYAML: pip install isotope-lineage[policies]"
    ) from e

SUPPORTED_VERSION = 1


class PolicyError(Exception):
    """Raised when a policy document is malformed or references are invalid."""


class PolicyRegistry:
    """Validated, immutable view of a policy document."""

    __slots__ = ("version", "labels", "_sinks")

    def __init__(self, version: int, labels: Dict[str, Label], sinks: Dict[str, Sink]) -> None:
        self.version = version
        self.labels = dict(labels)
        self._sinks = dict(sinks)

    def sink(self, name: str) -> Sink:
        try:
            return self._sinks[name]
        except KeyError:
            raise PolicyError(
                f"unknown sink {name!r}; declared sinks: {sorted(self._sinks)}"
            ) from None

    def label(self, name: str) -> Label:
        try:
            return self.labels[name]
        except KeyError:
            raise PolicyError(
                f"unknown label {name!r}; declared labels: {sorted(self.labels)}"
            ) from None

    @property
    def sink_names(self):
        return sorted(self._sinks)

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return f"PolicyRegistry(v{self.version}, labels={sorted(self.labels)}, sinks={self.sink_names})"


def parse_policies(doc: Mapping[str, Any]) -> PolicyRegistry:
    """Validate a parsed policy document and build a registry."""
    if not isinstance(doc, Mapping):
        raise PolicyError("policy document must be a mapping")
    version = doc.get("version")
    if version != SUPPORTED_VERSION:
        raise PolicyError(f"unsupported policy version: {version!r} (expected {SUPPORTED_VERSION})")

    raw_labels = doc.get("labels")
    if not isinstance(raw_labels, Mapping) or not raw_labels:
        raise PolicyError("'labels' must be a non-empty mapping of name -> description")
    labels: Dict[str, Label] = {}
    for name, desc in raw_labels.items():
        if not isinstance(name, str) or not name:
            raise PolicyError(f"invalid label name: {name!r}")
        if not isinstance(desc, str) or not desc.strip():
            raise PolicyError(f"label {name!r} must have a non-empty description (audit requirement)")
        labels[name] = Label(name)

    raw_sinks = doc.get("sinks")
    if not isinstance(raw_sinks, Mapping) or not raw_sinks:
        raise PolicyError("'sinks' must be a non-empty mapping of name -> config")
    sinks: Dict[str, Sink] = {}
    for name, cfg in raw_sinks.items():
        if not isinstance(cfg, Mapping):
            raise PolicyError(f"sink {name!r} config must be a mapping")
        unknown_keys = set(cfg) - {"forbidden"}
        if unknown_keys:
            raise PolicyError(f"sink {name!r} has unknown keys: {sorted(unknown_keys)}")
        forbidden = cfg.get("forbidden")
        if not isinstance(forbidden, list):
            raise PolicyError(f"sink {name!r} must declare a 'forbidden' list (may be empty)")
        flabels = []
        for lname in forbidden:
            if lname not in labels:
                raise PolicyError(
                    f"sink {name!r} forbids undeclared label {lname!r}; "
                    f"declared labels: {sorted(labels)}"
                )
            flabels.append(labels[lname])
        sinks[name] = Sink(name, forbidden=flabels)

    return PolicyRegistry(version, labels, sinks)


def load_policies(source: str) -> PolicyRegistry:
    """Load policies from a YAML string (multi-line) or a YAML file path."""
    if "\n" in source:
        text = source
    else:
        with open(source, "r", encoding="utf-8") as f:
            text = f.read()
    doc = yaml.safe_load(text)
    return parse_policies(doc)
