#!/usr/bin/env python3
"""Render the posture dashboard for every fixture host and check it against
test/dashboard.yaml. Called by ci/fixtures.sh after the control checks.

A cold Steampipe service (just restarted after `make install`, or by
`fixtures.sh -i`) can fail a heavy render once while the per-connection
snapshot cache fills. The warm-up query below fills it before the checks
start, and a render whose panels report errors is retried, so a genuine
panel error still fails after three attempts while a cold-start blip does
not fail the run.
"""
import json
import re
import subprocess
import sys
import time

import yaml

conn = sys.argv[1] if len(sys.argv) > 1 else "agentreach_fixtures"
doc = yaml.safe_load(open("test/dashboard.yaml"))
spec = doc["hosts"]
spec_absent = doc.get("never") or []


def render(connection, host, variables=None):
    cmd = ["powerpipe", "dashboard", "run", "agentreach_posture", "--search-path-prefix", connection,
           "--arg", "host=" + host, "--arg", "path_id=", "--output", "snapshot"]
    for k, v in sorted((variables or {}).items()):
        cmd += ["--var", "%s=%s" % (k, v if isinstance(v, str) else json.dumps(v))]
    r = subprocess.run(cmd, capture_output=True, text=True)
    try:
        return json.loads(r.stdout)["panels"], ""
    except Exception:
        return None, "(exit %d) %s" % (r.returncode, r.stderr.strip()[:200])


def render_stable(connection, host, variables=None, attempts=3):
    """Render, retrying cold-cache failures; a real panel error still ends
    here after `attempts` tries."""
    panels, err = None, ""
    for i in range(attempts):
        panels, err = render(connection, host, variables)
        if panels is not None and not any(v.get("error") for v in panels.values()):
            return panels, err
        if i + 1 < attempts:
            time.sleep(1)
    return panels, err


# Warm the connection: the first query after a service start fills the
# plugin's snapshot cache.
subprocess.run(["steampipe", "query",
                "select count(*) from %s.agentreach_agent" % conn,
                "--output", "csv"], capture_output=True)


def data(panels):
    """Panel name -> sorted rows."""
    out = {}
    for k, v in panels.items():
        rows = (v.get("data") or {}).get("rows")
        if k.endswith(".input.host"):
            continue  # the machine picker lists every machine by design
        if rows is not None:
            out[k] = sorted(json.dumps(r, sort_keys=True) for r in rows)
    return out


# Variants render a host again with variables set: each entry has host,
# vars and the same checks as a host entry.
runs = [(host, host, want) for host, want in spec.items()]
for v in doc.get("variants") or []:
    runs.append((v["host"], "%s %s" % (v["host"], json.dumps(v["vars"], sort_keys=True)), v))

bad = 0
for host, label, want in runs:
    panels, err = render_stable(conn, host, want.get("vars"))
    problems = []
    if panels is None:
        print("  FAIL dashboard %s: no snapshot %s" % (label, err))
        bad += 1
        continue
    errs = [k for k, v in panels.items() if v.get("error")]
    if errs:
        problems.append("panel errors: " + ", ".join(errs))
    # Every fixture home is /home/<host>; a cell naming another host's home
    # means a query is not filtered to the selected machine.
    leaks = set()
    for k, v in panels.items():
        for row in (v.get("data") or {}).get("rows") or []:
            for cell in row.values():
                for other in re.findall(r"/home/(fx-[a-z-]+)", str(cell)):
                    if other != host:
                        leaks.add("%s shows %s" % (k.split(".")[-1], other))
    for s in spec_absent:
        for k, v in panels.items():
            for row in (v.get("data") or {}).get("rows") or []:
                if any(s in str(c) for c in row.values()):
                    leaks.add("%s says %r" % (k.split(".")[-1], s))
    if leaks:
        problems.append("on the page: " + ", ".join(sorted(leaks)[:5]))
    verdict = None
    for v in panels.values():
        rows = (v.get("data") or {}).get("rows") or []
        if rows and rows[0].get("label") == "Verdict":
            verdict = rows[0]
    if verdict is None:
        problems.append("no verdict card")
    else:
        if verdict["type"] != want["verdict"]:
            problems.append("verdict %s, want %s: %s" % (verdict["type"], want["verdict"], verdict["value"][:120]))
        if want.get("verdict_contains") and want["verdict_contains"] not in verdict["value"]:
            problems.append("verdict lacks %r" % want["verdict_contains"])
    for tab in want.get("tables") or []:
        vals = []
        for v in panels.values():
            if v.get("title", "").startswith(tab["title"]):
                vals += [str(row.get(tab["column"], "")) for row in (v.get("data") or {}).get("rows") or []]
        for s in tab.get("contains") or []:
            if not any(s in x for x in vals):
                problems.append("%s.%s: no row contains %r" % (tab["title"], tab["column"], s))
        for s in tab.get("lacks") or []:
            if any(s in x for x in vals):
                problems.append("%s.%s: a row contains %r" % (tab["title"], tab["column"], s))
        if "rows" in tab and len(vals) != tab["rows"]:
            problems.append("%s: %d rows, want %d" % (tab["title"], len(vals), tab["rows"]))
    if problems:
        bad += 1
        print("  FAIL dashboard %s" % label)
        for p in problems:
            print("         " + p)
    else:
        print("  ok   dashboard %s (%d panels)" % (label, len(panels)))
# Isolation: fx-open rendered from every fixture machine must equal fx-open
# rendered from a connection that holds only fx-open.
iso = doc.get("isolation")
if iso:
    a, err_a = render_stable(conn, iso["host"])
    b, err_b = render_stable(iso["connection"], iso["host"])
    if a is None or b is None:
        print("  FAIL dashboard isolation: no snapshot %s %s" % (err_a, err_b))
        bad += 1
    else:
        da, db = data(a), data(b)
        diff = sorted(k.split(".")[-1] for k in set(da) | set(db) if da.get(k) != db.get(k))
        if diff:
            bad += 1
            print("  FAIL dashboard isolation: %s differs between %s and %s in %s" % (iso["host"], conn, iso["connection"], ", ".join(diff)))
        else:
            print("  ok   dashboard isolation: %s shows the same %d panels from %s and %s" % (iso["host"], len(da), conn, iso["connection"]))
sys.exit(1 if bad else 0)
