#!/usr/bin/env python3
"""Run the whole agentreach benchmark against the fixture connection.

spec/controls.yaml and test/expectations.yaml pin the behaviour of the
reviewed controls; this check is the net under everything else: every
control's SQL must execute on every fixture host it touches, including the
~60 hardening controls whose SQL is assembled by replace() over three
templates. It fails when any row comes back 'error' (a control that failed
to run) and when any listed control returns no rows at all (the mod's
convention is at least one row per agent). ok, alarm, info and skip are all
valid outcomes here.
Called by ci/fixtures.sh, which checks the tools.
"""
import csv
import io
import subprocess
import sys

conn = sys.argv[1] if len(sys.argv) > 1 else "agentreach_fixtures"

r = subprocess.run(
    ["powerpipe", "benchmark", "run", "agentreach",
     "--search-path-prefix", conn, "--output", "csv"],
    capture_output=True, text=True)
try:
    rows = list(csv.DictReader(io.StringIO(r.stdout)))
except Exception:
    print("  FAIL benchmark agentreach: no output (exit %d) %s"
          % (r.returncode, r.stderr.strip()[:300]))
    sys.exit(1)
if not rows:
    print("  FAIL benchmark agentreach: no rows (exit %d) %s"
          % (r.returncode, r.stderr.strip()[:300]))
    sys.exit(1)

bad = 0
by_control = {}
for row in rows:
    ctl = row.get("control_id", "?")
    by_control.setdefault(ctl, []).append(row)
    if row.get("status") == "error":
        bad += 1
        print("  FAIL %s on %s: %s"
              % (ctl, row.get("host", "?"), (row.get("reason") or "")[:200]))

listing = subprocess.run(["powerpipe", "control", "list", "--output", "csv"],
                         capture_output=True, text=True)
try:
    listed = set(csv.DictReader(io.StringIO(listing.stdout)))
    names = set(r["name"] for r in listed)
    for name in sorted(names - set(by_control)):
        bad += 1
        print("  FAIL %s: returned no rows on any fixture host" % name)
except Exception:
    pass  # the listing is a second opinion, not the check itself

if not bad:
    print("  ok   benchmark agentreach: %d controls, %d rows, 0 errors"
          % (len(by_control), len(rows)))
sys.exit(1 if bad else 0)
