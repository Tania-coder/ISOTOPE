# ISOTOPE

Data lineage and taint-tracking for Python pipelines, built around five
verifiable integrity invariants.

> **Status:** v0.1.0 — new implementation generated from the project brief
> (Path B). This is fresh, unverified-against-prior-work code, not a
> restoration of an earlier repository.

## Idea

Wrap values in `Tracked`. Every derivation records its inputs in an
immutable provenance DAG; taint labels (`pii`, `secret`, ...) propagate
automatically and can only be removed by an explicit, reasoned
`declassify()`. `Sink`s reject values that still carry forbidden labels.

```python
from isotope import Label, Sink, Tracked

PII = Label("pii")

email = Tracked.source("alice@example.com", "crm", labels=[PII])
domain = email.map("extract_domain", lambda e: e.split("@")[1])

export = Sink("analytics_export", forbidden=[PII])
# export.send(domain)  -> PolicyViolation: still tainted with pii

ok = domain.declassify(PII, reason="domain only, approved DPO-123")
export.send(ok)  # "example.com"
```

## Invariants

| # | Name | Guarantee |
|---|------|-----------|
| I1 | Completeness | Every derived node's lineage references all of its Tracked inputs; the graph is closed under the parent relation. |
| I2 | Label conservation | Labels are never silently dropped. The only removal path is `declassify()`, which removes exactly one declared label and records a reason in lineage metadata. |
| I3 | Append-only DAG | Lineage nodes are immutable and reference only pre-existing parents; the graph is acyclic by construction and checked defensively. |
| I4 | Serialization fidelity | `to_dict`/`from_dict` round-trip a graph losslessly and deterministically. |
| I5 | Sink enforcement | A `Sink` raises `PolicyViolation` for any value carrying a forbidden label. There is no bypass flag. |

Checkers live in `isotope.invariants`; `scripts/check_invariants.py`
exercises them over randomized operation sequences.

## Verification

```
make verify   # lint (compileall) + pytest + randomized invariant checks
```

**Project rule:** verification output is never fabricated or simulated.
A claim that `make verify` passed must come from an actual run, and the
summary line is only printed after all checks executed.

## Layout

```
src/isotope/     labels, lineage (DAG), track (Tracked), policy (Sink), serialize, invariants
tests/           unit tests per invariant
scripts/         randomized invariant verification
```

## License

MIT
