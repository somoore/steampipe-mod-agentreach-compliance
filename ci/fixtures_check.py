#!/usr/bin/env python3
"""Run controls against the agentreach_fixtures connection and compare the
statuses per host with the expectations.

Two sources:
  spec/controls.yaml      every core control, every fixture host
  test/expectations.yaml  regression checks for other controls and for
                          variable overrides (each entry may set `vars`)

A host's expectation is a set: the control must return exactly those
statuses for that host (`rows` can also pin the row count per host) (LT-03 returns one row per file, so a host can have
alarm and ok together). `reasons` pins text: some row for that host must
contain the string in its reason. Hosts with no expectation must return no rows.
Called by ci/fixtures.sh, which checks the tools.
"""
import csv
import io
import json
import os
import subprocess
import sys

import yaml

conn = sys.argv[1] if len(sys.argv) > 1 else "agentreach_fixtures"
checks = [dict(r, origin="core") for r in yaml.safe_load(open("spec/controls.yaml"))["controls"]]
if os.path.exists("test/expectations.yaml"):
    checks += [dict(r, origin="regression") for r in yaml.safe_load(open("test/expectations.yaml"))["checks"]]

bad = 0
for rec in checks:
    name = rec["control"]
    cmd = ["powerpipe", "control", "run", name, "--search-path-prefix", conn, "--output", "csv"]
    label = name
    for k, v in sorted((rec.get("vars") or {}).items()):
        cmd += ["--var", "%s=%s" % (k, v if isinstance(v, str) else json.dumps(v))]
        label += " [%s=%s]" % (k, v if isinstance(v, str) else json.dumps(v))
    r = subprocess.run(cmd, capture_output=True, text=True)
    got, count, reasons = {}, {}, {}
    for row in csv.DictReader(io.StringIO(r.stdout)):
        got.setdefault(row.get("host", ""), set()).add(row["status"])
        count[row.get("host", "")] = count.get(row.get("host", ""), 0) + 1
        reasons.setdefault(row.get("host", ""), []).append(row.get("reason", ""))
    if not got and rec["fixtures"]:
        print("  FAIL %-7s %s: no rows (exit %d) %s" % (rec["agentreach"], label, r.returncode, r.stderr.strip()[:300]))
        bad += 1
        continue
    diffs = []
    for host, want in sorted(rec["fixtures"].items()):
        have = got.pop(host, set())
        if have != set(want):
            diffs.append("%s: want %s, got %s" % (host, "/".join(sorted(want)), "/".join(sorted(have)) or "nothing"))
    for host, have in sorted(got.items()):
        diffs.append("%s: unexpected host with %s" % (host, "/".join(sorted(have))))
    # Optional row counts per host, for checks where the set of statuses
    # alone cannot show that a row was left out.
    for host, n in sorted((rec.get("rows") or {}).items()):
        if count.get(host, 0) != n:
            diffs.append("%s: %d rows, want %d" % (host, count.get(host, 0), n))
    for host, text in sorted((rec.get("reasons") or {}).items()):
        if not any(text in r for r in reasons.get(host, [])):
            diffs.append("%s: no reason contains %r" % (host, text))
    tag = "" if rec["origin"] == "core" else " (regression)"
    if diffs:
        bad += 1
        print("  FAIL %-7s %s%s" % (rec["agentreach"], label, tag))
        for d in diffs:
            print("         " + d)
    else:
        print("  ok   %-7s %s (%d hosts)%s" % (rec["agentreach"], label, len(rec["fixtures"]), tag))
sys.exit(1 if bad else 0)
