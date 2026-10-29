#!/usr/bin/env python3
"""Check spec/controls.yaml against the controls' tags.

  * every core record is complete;
  * its class and AISVS ids match the control's agentreach_class and aisvs tags;
  * every other control carries agentreach_class = "needs_validation";
  * aisvs tags use the pinned version's id form.

Prints one line per problem and exits 1 when there is any.
"""
import glob
import re
import sys

try:
    import yaml
except ImportError:
    print("PyYAML is missing: pip install pyyaml")
    sys.exit(1)

spec = yaml.safe_load(open("spec/controls.yaml"))
version = spec["primary_standard"]["version"]
id_re = re.compile(r"^v%s-(C|AC\.)\d+(\.\d+)+$" % re.escape(version))
hosts = set(spec["fixtures"]["hosts"])
statuses = {"ok", "alarm", "info", "skip", "error"}
problems = []


def need(rec, path):
    cur = rec
    for k in path.split("."):
        if not isinstance(cur, dict) or k not in cur or cur[k] in (None, ""):
            return None
        cur = cur[k]
    return cur


blocks = {}
for f in sorted(glob.glob("controls/*.pp")):
    t = open(f).read()
    for m in re.finditer(r'^control "([^"]+)" \{\n', t, re.M):
        end = t.index("\n}\n", m.start())
        blocks[m.group(1)] = (f, t[m.start():end])


def tag(block, key):
    m = re.search(r'\b%s\s*=\s*"([^"]*)"' % re.escape(key), block)
    return m.group(1) if m else None


core = {}
for rec in spec["controls"]:
    name = rec.get("control", "?")
    core[name] = rec
    for path in ("agentreach", "class", "threat", "evidence.pass", "evidence.fail", "evidence.unknown", "fixtures"):
        if need(rec, path) is None:
            problems.append("%s: spec record lacks %s" % (name, path))
    if "untested" not in rec or not isinstance(rec["untested"], list):
        problems.append("%s: spec record lacks an untested list (use [] when none)" % name)
    cls = rec.get("class")
    ids = need(rec, "aisvs.ids") or []
    ver = need(rec, "aisvs.verification")
    if cls == "mapped":
        if not ids:
            problems.append("%s: mapped but lists no aisvs ids" % name)
        if ver not in ("full", "supporting"):
            problems.append("%s: mapped needs aisvs.verification full or supporting" % name)
        if ver == "supporting" and not need(rec, "aisvs.gap"):
            problems.append("%s: supporting evidence needs aisvs.gap (what is missing for full)" % name)
    elif cls == "agentreach_extension":
        if ids:
            problems.append("%s: a agentreach_extension lists aisvs ids; put them under related" % name)
    else:
        problems.append("%s: class %r is not mapped or agentreach_extension" % (name, cls))
    for i in ids + [r for r in rec.get("related", []) if str(r).startswith("v")]:
        if not id_re.match(str(i)):
            problems.append("%s: %s is not a v%s AISVS id" % (name, i, version))
    fx = rec.get("fixtures") or {}
    if set(fx) != hosts:
        problems.append("%s: fixtures must list every host (%s); missing %s, extra %s"
                        % (name, len(hosts), sorted(hosts - set(fx)), sorted(set(fx) - hosts)))
    for h, ss in fx.items():
        if not ss or not set(ss) <= statuses:
            problems.append("%s: %s expects %r" % (name, h, ss))
    if name not in blocks:
        problems.append("%s: no such control in controls/*.pp" % name)
        continue
    f, b = blocks[name]
    if tag(b, "agentreach") != rec.get("agentreach"):
        problems.append("%s: agentreach tag %r, spec says %r" % (name, tag(b, "agentreach"), rec.get("agentreach")))
    if tag(b, "agentreach_class") != cls:
        problems.append("%s: agentreach_class tag %r, spec says %r" % (name, tag(b, "agentreach_class"), cls))
    want = ",".join(ids) if ids else None
    if tag(b, "aisvs") != want:
        problems.append("%s: aisvs tag %r, spec says %r" % (name, tag(b, "aisvs"), want))

for name, (f, b) in sorted(blocks.items()):
    if name in core:
        continue
    if tag(b, "agentreach_class") != "needs_validation":
        problems.append('%s (%s): not in spec/controls.yaml, so agentreach_class must be "needs_validation", found %r'
                        % (name, f, tag(b, "agentreach_class")))
    a = tag(b, "aisvs")
    if a is not None:
        problems.append("%s: carries an aisvs tag but has no spec record" % name)

# benchmark "core" must list exactly the spec's controls, so
# `powerpipe benchmark run core` is the reviewed profile.
bm = open("controls/benchmark.pp").read()
m = re.search(r'benchmark\s+"core"\s*\{.*?children\s*=\s*\[(.*?)\]', bm, re.S)
if not m:
    problems.append('controls/benchmark.pp: no benchmark "core"')
else:
    listed = set(re.findall(r"control\.(\w+)", m.group(1)))
    for name in sorted(set(core) - listed):
        problems.append('benchmark "core" is missing %s' % name)
    for name in sorted(listed - set(core)):
        problems.append('benchmark "core" lists %s, which has no spec record' % name)

# The benchmark descriptions must state the real counts (core reviewed,
# needs_validation not), so the story the README and the benchmark tell
# cannot drift from the spec.
nv_n = len(blocks) - len(core)
for bname, pats in (
    ("agentreach", ((r"(\d+) reviewed core controls", len(core)),
                    (r"(\d+) controls still marked needs_validation", nv_n))),
    ("core", ((r"(\d+) reviewed core controls", len(core)),
              (r"(\d+) controls still marked needs_validation", nv_n))),
):
    d = re.search(r'benchmark\s+"%s"\s*\{.*?description\s*=\s*"([^"]*)"' % bname, bm, re.S)
    if not d:
        problems.append('controls/benchmark.pp: benchmark "%s" has no description' % bname)
        continue
    for pat, want in pats:
        got = re.search(pat, d.group(1))
        if not got or int(got.group(1)) != want:
            problems.append('benchmark "%s" description: %s should say %d' % (bname, pat, want))

# The README states the same counts. Pin them so the prose cannot drift from
# the spec and the fixture set.
readme = open("README.md").read()
for pat, want, what in (
    (r"the (\d+) core controls", len(core), "core controls"),
    (r"The other (\d+) controls", nv_n, "needs_validation controls"),
    (r"(\d+) bundled fixture machines", len(hosts), "fixture machines"),
):
    got = re.search(pat, readme)
    if not got or int(got.group(1)) != want:
        problems.append("README.md: %s should say %d" % (what, want))

for p in problems:
    print(p)
counts = {}
for rec in spec["controls"]:
    counts[rec.get("class")] = counts.get(rec.get("class"), 0) + 1
counts["needs_validation"] = len(blocks) - len(core)
print("classes: " + ", ".join("%s %d" % kv for kv in sorted(counts.items())))
sys.exit(1 if problems else 0)
