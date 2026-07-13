#!/usr/bin/env python3
"""Randomized invariant verification for ISOTOPE (I1-I5).

Builds random lineage graphs and checks every invariant after each step.
Exits non-zero on the first violation. Never fabricates results: the
summary line is printed only after all checks actually ran.
"""
from __future__ import annotations

import argparse
import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from isotope import Label, PolicyViolation, Sink, Tracked  # noqa: E402
from isotope.invariants import verify_graph  # noqa: E402

LABELS = [Label("pii"), Label("raw"), Label("secret"), Label("external")]


def run(iterations: int, seed: int) -> int:
    rng = random.Random(seed)
    pool = [Tracked.source(rng.randint(0, 100), f"seed{i}",
                           labels=rng.sample(LABELS, rng.randint(0, len(LABELS))))
            for i in range(3)]
    sink = Sink("export", forbidden=[Label("pii"), Label("secret")])
    checked = 0
    for step in range(iterations):
        action = rng.choice(["source", "map", "combine", "declassify"])
        if action == "source":
            t = Tracked.source(rng.randint(0, 100), f"s{step}",
                               labels=rng.sample(LABELS, rng.randint(0, 2)))
        elif action == "map":
            t = rng.choice(pool).map(f"map{step}", lambda v: v)
        elif action == "combine":
            a, b = rng.choice(pool), rng.choice(pool)
            t = Tracked.apply(f"join{step}", lambda x, y: (x, y), a, b)
        else:
            base = rng.choice(pool)
            if base.labels:
                t = base.declassify(rng.choice(sorted(base.labels)),
                                    reason=f"randomized audit step {step}")
            else:
                t = base
        pool.append(t)
        if len(pool) > 40:
            pool = pool[-40:]

        # I1-I4 structurally
        verify_graph(t.node)
        # I5 behaviorally: sink must reject iff a forbidden label is present
        forbidden_hit = bool(t.labels & sink.forbidden)
        try:
            sink.send(t)
            if forbidden_hit:
                print(f"FAIL I5: sink accepted forbidden labels at step {step}")
                return 1
        except PolicyViolation:
            if not forbidden_hit:
                print(f"FAIL I5: sink rejected clean value at step {step}")
                return 1
        checked += 1

    print(f"INVARIANTS OK: I1-I5 held over {checked} randomized operations (seed={seed})")
    return 0


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--iterations", type=int, default=200)
    p.add_argument("--seed", type=int, default=1337)
    args = p.parse_args()
    sys.exit(run(args.iterations, args.seed))
