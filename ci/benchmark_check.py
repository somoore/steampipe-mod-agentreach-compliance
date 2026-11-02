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
import json
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

listing = subprocess.run(["powerpipe", "control", "list", "--output", "json"],
                         capture_output=True, text=True)
# The listing is a second opinion on the benchmark: it names every installed
# control, so one that returns no rows on any fixture host is a FAIL even
# though it produced no error row. A listing that cannot be read is itself a
# failure; otherwise this check would silently do nothing.
try:
    if listing.returncode != 0:
        raise ValueError("exit %d %s" % (listing.returncode, listing.stderr.strip()[:300]))
    listed = json.loads(listing.stdout)
    names = {r["qualified_name"].split(".", 1)[-1]
             for r in listed if r.get("qualified_name")}
    for name in sorted(names - set(by_control)):
        bad += 1
        print("  FAIL %s: returned no rows on any fixture host" % name)
except (ValueError, KeyError, TypeError) as e:
    bad += 1
    print("  FAIL powerpipe control list: %s" % e)

if not bad:
    print("  ok   benchmark agentreach: %d controls, %d rows, 0 errors"
          % (len(by_control), len(rows)))
sys.exit(1 if bad else 0)
