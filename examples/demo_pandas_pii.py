#!/usr/bin/env python3
"""PoC demo: a pandas pipeline that CANNOT silently leak PII to a CSV.

Run:  python examples/demo_pandas_pii.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pandas as pd

from isotope import Label, PolicyViolation, Sink
from isotope.pandas_ext import TrackedFrame

PII = Label("pii")

print("1. Load customer data, mark the email column as PII")
df = pd.DataFrame({
    "email": ["alice@example.com", "bob@example.org"],
    "plan": ["free", "pro"],
    "mrr": [0, 49],
})
tf = TrackedFrame.from_pandas(df, column_labels={"email": [PII]}, name="crm")
print(f"   {tf}\n")

print("2. Ordinary pandas work: derive a domain column (declared deps)")
tf = tf.assign(deps={"domain": ["email"]}, domain=lambda d: d.email.str.split("@").str[1])
print(f"   domain labels: {sorted(l.name for l in tf.column_labels('domain'))}\n")

print("3. Try to export everything to CSV through a policy sink...")
export = Sink("analytics_csv", forbidden=[PII])
try:
    export_df = tf.send_to(export)
except PolicyViolation as e:
    print(f"   BLOCKED -> {e}\n")

print("4. Drop the PII columns and export only safe ones")
safe = tf.select(["plan", "mrr"])
out = safe.send_to(export)
out.to_csv("safe_export.csv", index=False)
print(f"   exported {len(out)} rows to safe_export.csv — no PII, audit trail in lineage")
