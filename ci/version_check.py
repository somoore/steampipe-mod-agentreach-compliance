#!/usr/bin/env python3
"""The release version must be wired the same way everywhere the mod names it:

  mod.pp                min_version = "X.Y.Z"
  README.md             the local-build warning: agentreach@X.Y.Z
  spec/controls.yaml    "plugin: steampipe-plugin-agentreach vX.Y.Z ..."
  ci/fixtures.sh        "agentreach plugin (vX.Y.Z or newer)"

A release is only real when all of them move together; the interim tags that
shipped with a stale spec are why this check exists. A bump that misses one
place fails `ci/checks.sh` instead of drifting until someone reads it.
"""
import re
import sys

FILES = [
    ("mod.pp", r'min_version\s*=\s*"(\d+\.\d+\.\d+)"'),
    ("README.md", r"agentreach@(\d+\.\d+\.\d+)"),
    ("spec/controls.yaml", r"steampipe-plugin-agentreach v(\d+\.\d+\.\d+)"),
    ("ci/fixtures.sh", r"agentreach plugin \(v(\d+\.\d+\.\d+) or newer\)"),
]

found = {}
problems = []
for path, pat in FILES:
    try:
        t = open(path).read()
    except OSError as e:
        problems.append("%s: %s" % (path, e))
        continue
    seen = sorted(set(re.findall(pat, t)))
    if len(seen) != 1:
        problems.append("%s: expected one match for %s, found %s" % (path, pat, seen or "none"))
        continue
    found[path] = seen[0]

if not problems:
    versions = set(found.values())
    if len(versions) != 1:
        problems.append("versions disagree: " + ", ".join("%s=%s" % kv for kv in sorted(found.items())))
    else:
        print("release version %s is wired consistently (%d places)" % (versions.pop(), len(found)))

for p in problems:
    print(p)
sys.exit(1 if problems else 0)
